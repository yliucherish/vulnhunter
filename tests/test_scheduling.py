"""v0.3.2 调度与爬虫回归测试——"黑洞端点拖垮整场扫描"事故的防护网。

背景（面试可讲）：DVWA captcha 页每请求 21s 且持有 PHP session 锁，
扫描器全程单会话 → 所有请求被串行化 → 超过 45s 客户端超时的请求被
静默放弃 → 一次 high 全站扫描 0 检出（60/100 任务超时失败），
而同代码的定向复测稳定命中。修复三处联动：
① 爬虫按表单字段名跳过危险表单（改密表单根本不该提交）；
② HTTP 层标记慢端点，引擎把慢端点后续请求转入容量 1 的串行通道；
③ 超时重试判别式：baseline×2 < 超时预算才重试（排队竞争才重试，
   目标固有慢不重试）。

本文件用本地靶场（含 session 锁中间件 + 9s 慢端点 + 改密表单）
与假检测器把这些行为全部锁死。
"""
import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import aiohttp
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vulnhunter.crawler import Crawler                                    # noqa: E402
from vulnhunter.detectors.base import InjectionPoint                      # noqa: E402
from vulnhunter.detectors._http import fetch_with, FetchError             # noqa: E402
from vulnhunter.engine import ScanEngine                                  # noqa: E402

TARGET_APP = ROOT / "tests" / "vulnerable_app.py"


@pytest.fixture(scope="module")
def target():
    """在本地回环拉起漏洞靶场（含 session 锁与慢端点）。"""
    def port_free():
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", 8888))
            return True
        except OSError:
            return False
        finally:
            s.close()

    proc = None
    if port_free():
        proc = subprocess.Popen(
            [sys.executable, str(TARGET_APP)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(30):
            time.sleep(0.3)
            if not port_free():
                break
    yield "http://127.0.0.1:8888"
    if proc:
        proc.terminate()


def _run(coro):
    return asyncio.run(coro)


# ================= ① 爬虫：按字段名跳过危险表单 =================

def test_crawler_skips_password_change_form():
    """改密表单（URL 无特征，但字段名暴露语义）不得产生注入点。

    这是 v0.3.2 的主修复：DVWA captcha 页的改密表单曾被提取出 5 个
    注入点，检测器每次 POST 触发 21s 的 reCAPTCHA 校验，把整场扫描
    串行化到全部超时。
    """
    html = """<html><body>
      <form method="post" action="/whatever">
        <input type="hidden" name="step" value="1">
        <input type="password" name="password_new">
        <input type="password" name="password_conf">
        <input type="submit" name="Change" value="Change">
      </form>
      <form method="get" action="/search"><input name="q"></form>
    </body></html>"""
    crawler = Crawler("http://unused")
    _, points = crawler._extract("http://unused/page", html)
    params = {p.param for p in points}
    assert "q" in params, "普通搜索表单应保留"
    assert not ({"step", "password_new", "password_conf", "Change"} & params), \
        f"改密表单字段不应产生注入点: {params}"


def test_crawler_keeps_login_style_form():
    """对照：含 password 字段的登录式表单仍应保留（登录框是可测的）。"""
    html = """<html><body>
      <form method="post" action="/login">
        <input name="username"><input type="password" name="password">
        <input type="submit" name="Login" value="Login">
      </form>
    </body></html>"""
    crawler = Crawler("http://unused")
    _, points = crawler._extract("http://unused/page", html)
    params = {p.param for p in points}
    assert {"username", "password", "Login"} <= params


# ================= ② HTTP 层：慢端点标记 =================

def test_fetch_with_marks_slow_point(target):
    """对 9s 慢端点的一次成功请求即把 point.slow 置 True，并记录 baseline。"""
    async def go():
        async with aiohttp.ClientSession() as s:
            point = InjectionPoint(url=f"{target}/slow", param="mode", method="GET")
            t0 = time.monotonic()
            await fetch_with(s, point, "1")
            dt = time.monotonic() - t0
            assert point.slow, "慢端点应被标记"
            assert point.baseline >= 8.0, f"baseline 应记录真实耗时，得到 {point.baseline}"
            assert dt >= 8.0
    _run(go())


def test_fetch_with_normal_point_not_marked(target):
    """对照：普通页面的快速请求不得标记为慢端点。"""
    async def go():
        async with aiohttp.ClientSession() as s:
            point = InjectionPoint(url=f"{target}/search", param="q", method="GET")
            await fetch_with(s, point, "x")
            assert not point.slow
            assert point.baseline < 8.0
    _run(go())


# ================= ③ 引擎：慢端点串行通道 =================

class _LaneProbe:
    """假检测器：detect() 固定耗时 0.3s，记录进入/离开时间。"""
    def __init__(self, name, priority):
        self.name = name
        self.priority = priority
        self.spans = []

    async def detect(self, session, point):
        t0 = time.monotonic()
        await asyncio.sleep(0.3)
        self.spans.append((t0, time.monotonic()))


def test_engine_serializes_slow_point_jobs():
    """已标记慢端点的多个任务必须串行执行（不重叠），总耗时叠加。"""
    async def go():
        engine = ScanEngine("http://unused", concurrency=4, timeout=10)
        point = InjectionPoint(url="http://unused/x", param="p")
        point.slow = True          # 模拟：该点已被先前慢请求标记
        d1, d2 = _LaneProbe("a", 10), _LaneProbe("b", 20)
        await asyncio.gather(
            engine._run_detector(None, d1, point, []),
            engine._run_detector(None, d2, point, []),
        )
        (a0, a1), (b0, b1) = d1.spans[0], d2.spans[0]
        overlap = min(a1, b1) - max(a0, b0)
        assert overlap <= 0.05, f"慢端点任务不应并发执行（重叠 {overlap:.3f}s）"
    _run(go())


def test_engine_runs_fast_point_jobs_concurrently():
    """对照：未标记的点仍应并发执行（不被串行通道拖慢）。"""
    async def go():
        engine = ScanEngine("http://unused", concurrency=4, timeout=10)
        point = InjectionPoint(url="http://unused/x", param="p")
        d1, d2 = _LaneProbe("a", 10), _LaneProbe("b", 20)
        t0 = time.monotonic()
        await asyncio.gather(
            engine._run_detector(None, d1, point, []),
            engine._run_detector(None, d2, point, []),
        )
        assert time.monotonic() - t0 < 0.55, "快端点任务应并发完成"
    _run(go())


# ================= ④ 引擎：超时重试判别式 =================

class _FlakyDetector:
    """第一次 detect() 抛 timeout，之后成功——模拟锁竞争导致的超时。"""
    def __init__(self):
        self.name = "flaky"
        self.priority = 50
        self.calls = 0

    async def detect(self, session, point):
        self.calls += 1
        if self.calls == 1:
            raise FetchError("http://unused/x 请求失败: TimeoutError", kind="timeout")
        return None


def test_engine_retries_contention_timeout():
    """baseline×2 < 超时预算 → 超时判为排队竞争 → 重试一次。

    21s 基线（DVWA captcha 同款）× 2 = 42 < 45s 预算：能超时说明
    前面至少排了 2 个请求，重试（走串行通道）即可恢复。
    """
    async def go():
        engine = ScanEngine("http://unused", timeout=45)
        point = InjectionPoint(url="http://unused/x", param="p")
        point.baseline = 21.0
        d = _FlakyDetector()
        await engine._run_detector(None, d, point, [])
        assert d.calls == 2, "排队竞争导致的超时应重试一次"
        # 失败可见性：重试前的超时也必须如实计数（不能假装没失败过）
        assert engine.stats["fetch_failures"] == 1
    _run(go())


def test_engine_no_retry_when_baseline_near_budget():
    """baseline×2 ≥ 超时预算 → 目标固有慢 → 不重试（重试只是再等一个周期）。"""
    async def go():
        engine = ScanEngine("http://unused", timeout=45)
        point = InjectionPoint(url="http://unused/x", param="p")
        point.baseline = 30.0
        d = _FlakyDetector()
        await engine._run_detector(None, d, point, [])
        assert d.calls == 1, "固有慢页面的超时不应重试"
    _run(go())


# ================= ⑤ 端到端：慢端点存在时快页面不受饿死 =================

class _CountingDetector:
    """每点仅一次请求的假检测器（请求走 fetch_with，慢端点会被标记）。"""
    def __init__(self, name, priority):
        self.name = name
        self.priority = priority

    async def detect(self, session, point):
        await fetch_with(session, point, "probe")
        return None


def test_engine_fast_points_survive_slow_endpoint(target):
    """旗舰场景回归：慢端点（9s，持 session 锁）不得饿死其他注入点。

    复现 v0.3.1 事故形态：多个检测器同时打到慢端点 → 请求在会话锁后
    排队 → 超过 20s 预算的任务超时被静默放弃（那次 high 全站扫描
    60/100 任务超时、0 检出）。修复后：
    - 全部任务最终完成（completed 全覆盖）——慢端点串行通道 + 超时重试
      的共同结果；去掉任一修复都会有任务掉队（3 个慢请求并发时，
      第 3 个在锁后排队 27s > 20s 预算）；
    - 慢端点被标记并如实计入 slow_points；
    - 首页改密表单不产生任何注入点（主修复①，由爬虫单测覆盖）。
    """
    async def go():
        engine = ScanEngine(target, depth=2, concurrency=4, timeout=20,
                            detectors=[_CountingDetector("d1", 10),
                                       _CountingDetector("d2", 20),
                                       _CountingDetector("d3", 30)])
        results = await engine.scan()
        points = engine.stats["points"]
        assert points >= 5, f"注入点数量异常: {points}"
        assert engine.stats["slow_points"] >= 1, "慢端点应被标记"
        assert engine.stats["completed"] == points * 3, (
            f"完成 {engine.stats['completed']}/{points * 3}，"
            f"失败 {engine.stats['fetch_failures']} 次——慢端点饿杀了其他注入点")
        assert not results  # 假检测器不产出漏洞
    _run(go())
