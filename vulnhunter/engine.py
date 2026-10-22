"""扫描引擎：爬虫发现注入点 → 并发调度检测器 → 汇总漏洞。

设计要点（面试可讲）：
- **失败可见性原则**：请求失败（超时/5xx/连接错误）绝不静默吞掉。
  引擎层统一做三件事：单点重试一次 → 累计失败计数 → 超过阈值**熔断**并
  在报告里如实标注"因目标无响应未完成检测的注入点数"。
  宁可报告"没扫完"，也不能假装扫过了（详见 _http.py 的踩坑记录）。
- 单点异常隔离：任一 (注入点, 检测器) 组合失败不影响其他组合。
- **慢端点串行通道（v0.3.2）**：PHP 等目标对同一会话加排他锁，一个慢请求
  （DVWA captcha 页每请求 21s）会阻塞同会话所有请求。若多个慢请求并发，
  它们互相排队等待锁，全部超过客户端总超时后被静默放弃——一次 high 全站
  扫描因此 0 检出（60/100 个任务超时失败，详见 _http.py 踩坑记录⑥）。
  修正：单次请求超过阈值的注入点被标记为慢端点，其后续请求改走
  **容量为 1 的串行通道**——快请求最多等待"一个慢请求"的时长，
  不会连锁超时。
- **超时重试策略（v0.3.2 修正）**：初版"超时一律不重试"的理由是
  "重试只是再等一个超时周期"——这对目标固有慢页成立，但对
  **瞬态锁竞争**不成立（超时是别的请求持有会话锁造成的，与本报点无关）。
  修正：以 point.baseline（该点最慢成功请求耗时）判别——
  baseline×2 < 超时预算说明本次超时是排队造成的（否则根本不会超时），
  重试一次；基线本身就接近预算才是固有慢，不重试。
"""
import asyncio
import time

import aiohttp

from .crawler import Crawler
from .detectors.sqli import SQLiDetector
from .detectors.xss import XSSDetector
from .detectors.cmdi import CommandInjectionDetector
from .detectors.ssrf import SSRFDetector
from .detectors.base import Vulnerability
from .detectors._http import FetchError, SLOW_REQUEST_THRESHOLD

# 连接类失败超过该值 → 判定目标不可达，提前熔断（超时类不计入，见 _http.py）
CONNECTION_BREAKER_THRESHOLD = 30


class ScanEngine:
    def __init__(self, target: str, depth: int = 2, concurrency: int = 10,
                 cookie: str | None = None, timeout: float = 45.0,
                 detectors: list | None = None):
        self.target = target
        self.depth = depth
        self.cookie = cookie
        self.sem = asyncio.Semaphore(concurrency)
        # 单次请求总超时（秒）。DVWA exec 页会把畸形 payload 拼进 ping，
        # DNS 解析可能挂起数十秒，超时太短会把这类"目标页面固有行为"
        # 误判为失败；45s 是实测折中。
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        # detectors 可注入：便于测试用假检测器验证调度策略
        #（慢端点串行化 / 超时重试），不必依赖真实检测器的请求量。
        self.detectors = detectors if detectors is not None else [
            SQLiDetector(), XSSDetector(),
            CommandInjectionDetector(), SSRFDetector()]
        # 运行统计（供报告如实呈现覆盖率）
        self.stats = {
            "pages": 0, "points": 0, "completed": 0,
            "fetch_failures": 0, "connection_failures": 0,
            "error_samples": [], "tripped": False, "slow_points": 0,
        }
        # 慢端点串行通道（容量 1）：被标记为慢端点的注入点，其所有后续
        # 请求都经由此通道串行执行。锁序恒为 slow_lane → sem，不会死锁。
        self.slow_lane = asyncio.Semaphore(1)

    async def _run_detector(self, session, detector, point, results):
        # point.slow 可能在任意一次尝试期间被 HTTP 层置位（首轮慢请求
        # 即触发），因此每次尝试前都重新判断——重试也会自动落入串行通道。
        for attempt in (1, 2):
            if point.slow:
                async with self.slow_lane:
                    if await self._attempt(session, detector, point, results, attempt):
                        return
            else:
                if await self._attempt(session, detector, point, results, attempt):
                    return

    async def _attempt(self, session, detector, point, results, attempt: int) -> bool:
        """单次检测尝试。

        Returns:
            True  = 该组合已终结（成功/放弃），False = 需要重试。
        """
        async with self.sem:
            try:
                vuln = await detector.detect(session, point)
                self.stats["completed"] += 1
                if vuln:
                    results.append(vuln)
                    print(f"  [+] {vuln.vuln_type} @ {vuln.url} (param={vuln.param})")
                return True
            except FetchError as e:
                self.stats["fetch_failures"] += 1
                if e.kind == "connection":
                    self.stats["connection_failures"] += 1
                samples = self.stats.setdefault("error_samples", [])
                if len(samples) < 5:
                    samples.append(f"[{e.kind}] {e}")
                # 重试策略（v0.3.2 修正，见模块 docstring）：
                # 超时分两种——目标固有慢（本报点单独跑也会超时）与瞬态锁竞争
                # （排在 PHP session 锁后面，与本报点无关）。判别依据是
                # point.baseline（该点观测到的最慢成功请求耗时）：
                #   baseline×2 < 超时预算 → 本次超时大概率是排队造成的
                #     （k 个请求排在前面才会超时，而 k≥2 时必然成立），
                #     重试一次——该点此时必已被标记慢端点，重试自动走串行
                #     通道，不会再排队；
                #   否则基线本身就接近预算 → 固有慢 → 重试无意义，放弃。
                if e.kind == "timeout":
                    if point.baseline * 2 >= self.timeout.total:
                        return True
                return attempt == 2
            except Exception:
                return True   # 检测器自身异常：跳过该点

    async def scan(self) -> list[Vulnerability]:
        # force_close：每次请求新建连接。Apache 默认 keep-alive 超时 5s，
        # 并发扫描时连接池里的长连接常已被目标关闭，复用即报
        # ServerDisconnectedError——曾被误判为"目标过载"（见 _http.py 踩坑记录）。
        connector = aiohttp.TCPConnector(force_close=True)
        headers = {"User-Agent": "VulnHunter/0.3 (authorized testing only)"}
        if self.cookie:
            headers["Cookie"] = self.cookie  # 登录态：扫 DVWA 等需认证页面

        async with aiohttp.ClientSession(timeout=self.timeout, headers=headers,
                                         connector=connector) as session:
            print(f"[*] 爬取目标: {self.target} (depth={self.depth}"
                  f"{', 已注入登录 Cookie' if self.cookie else ''})")

            # SSRF 检测器的回调服务需要生命周期管理
            for det in self.detectors:
                if hasattr(det, "setup"):
                    await det.setup()

            try:
                crawler = Crawler(self.target, max_depth=self.depth)
                pages, points = await crawler.crawl(session)
                self.stats["pages"] = pages
                self.stats["points"] = len(points)
                print(f"[*] 爬取 {pages} 个页面，发现 {len(points)} 个注入点")

                results: list[Vulnerability] = []
                # 按检测器优先级排序创建任务：快检测器（XSS/SSRF）先获得
                # 并发信号量，避免被慢检测器（时间盲注/ping 挂起）饿死
                # （实测：混合负载下 PHP session 锁会让快请求排队超时，见踩坑记录）。
                ordered = sorted(
                    [(det, point) for point in points for det in self.detectors],
                    key=lambda dp: (dp[0].priority, points.index(dp[1])),
                )
                tasks = [
                    asyncio.ensure_future(
                        self._run_detector(session, det, point, results))
                    for det, point in ordered
                ]
                # 并发执行，同时监控熔断：每完成一批就检查累计失败数，
                # 超阈值则取消剩余任务（目标不可用/过载时空跑毫无意义）。
                pending = set(tasks)
                while pending:
                    done, pending = await asyncio.wait(
                        pending, return_when=asyncio.FIRST_COMPLETED)
                    # 只有"连接类失败"累计超阈值才熔断——超时可能只是目标页面
                    # 固有行为（如 exec 页 ping 挂起），不能误判为目标不可用。
                    if self.stats["connection_failures"] >= CONNECTION_BREAKER_THRESHOLD:
                        self.stats["tripped"] = True
                        print(f"[!] 连接类失败累计 {self.stats['connection_failures']} 次，"
                              f"目标可能不可达——提前中止剩余检测")
                        for t in pending:
                            t.cancel()
                        break

                total_jobs = len(points) * len(self.detectors)
                slow = [p for p in points if p.slow]
                self.stats["slow_points"] = len(slow)
                print(f"[*] 扫描完成：发现 {len(results)} 个漏洞；"
                      f"完成检测 {self.stats['completed']}/{total_jobs}，"
                      f"请求失败 {self.stats['fetch_failures']} 次"
                      f"（连接类 {self.stats['connection_failures']} 次）"
                      f"{'（已熔断）' if self.stats['tripped'] else ''}")
                if slow:
                    print(f"[*] 慢端点 {len(slow)} 个（单次请求 >{SLOW_REQUEST_THRESHOLD}s，"
                          f"已转入串行通道）:")
                    for p in slow:
                        print(f"      - {p.url} (param={p.param}) 基线 {p.baseline:.1f}s")
                if self.stats["error_samples"]:
                    print("[*] 失败样本（前 5 条）:")
                    for s in self.stats["error_samples"]:
                        print(f"      - {s}")
                return results
            finally:
                for det in self.detectors:
                    if hasattr(det, "teardown"):
                        await det.teardown()
