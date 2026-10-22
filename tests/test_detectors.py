"""VulnHunter 检测器回归测试集。

设计说明（面试可讲）：
- 每个检测器两类用例：**真阳性**（对内置漏洞靶场必须检出）与
  **真阴性**（对反射型/干净页面绝不误报）。
  这两类用例的对称设计，正是漏扫工具质量保障的核心思路——
  只测"能检出"的扫描器会退化成"见啥报啥"。
- 靶场：tests/vulnerable_app.py（子进程拉起，含 XSS/SQLi/命令注入/SSRF/登录态五类场景）。
  全部在本地回环地址运行，不触碰任何外部目标。

运行：
    pytest tests/test_detectors.py -v
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

from vulnhunter.detectors.sqli import SQLiDetector          # noqa: E402
from vulnhunter.detectors.xss import XSSDetector            # noqa: E402
from vulnhunter.detectors.cmdi import CommandInjectionDetector  # noqa: E402
from vulnhunter.detectors.base import InjectionPoint         # noqa: E402

TARGET_APP = ROOT / "tests" / "vulnerable_app.py"


@pytest.fixture(scope="session")
def target():
    """在本地回环拉起漏洞靶场，测试结束后自动关闭。"""
    # 确认端口未被占用（例如手工开着靶场时直接复用）
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


# ---------------- SQL 注入 ----------------
def test_sqli_error_based_detected(target):
    async def go():
        async with aiohttp.ClientSession() as s:
            point = InjectionPoint(url=f"{target}/user", param="id", method="GET")
            v = await SQLiDetector().detect(s, point)
            assert v is not None and "SQL Injection" in v.vuln_type
    _run(go())


def test_sqli_no_false_positive_on_reflective_page(target):
    """反射型页面（原样回显输入）不得被判为 SQL 注入。"""
    async def go():
        async with aiohttp.ClientSession() as s:
            point = InjectionPoint(url=f"{target}/search", param="q", method="GET")
            v = await SQLiDetector().detect(s, point)
            assert v is None, f"反射页出现 SQLi 误报: {v}"
    _run(go())


# ---------------- XSS ----------------
def test_xss_reflected_detected(target):
    async def go():
        async with aiohttp.ClientSession() as s:
            point = InjectionPoint(url=f"{target}/search", param="q", method="GET")
            v = await XSSDetector().detect(s, point)
            assert v is not None and "XSS" in v.vuln_type
    _run(go())


def test_xss_no_false_positive_on_non_reflecting_page(target):
    """不回显参数的页面（/user 只回显查询结果）不得报 XSS。"""
    async def go():
        async with aiohttp.ClientSession() as s:
            point = InjectionPoint(url=f"{target}/user", param="id", method="GET")
            v = await XSSDetector().detect(s, point)
            assert v is None, f"出现 XSS 误报: {v}"
    _run(go())


# ---------------- 命令注入 ----------------
def test_cmdi_echo_detected(target):
    async def go():
        async with aiohttp.ClientSession() as s:
            point = InjectionPoint(url=f"{target}/ping", param="host", method="GET")
            v = await CommandInjectionDetector().detect(s, point)
            assert v is not None and "Command Injection" in v.vuln_type
    _run(go())


def test_cmdi_no_false_positive_on_reflective_page(target):
    """反射页不得因 payload 被回显而误报命令注入。"""
    async def go():
        async with aiohttp.ClientSession() as s:
            point = InjectionPoint(url=f"{target}/search", param="q", method="GET")
            v = await CommandInjectionDetector().detect(s, point)
            assert v is None, f"反射页出现命令注入误报: {v}"
    _run(go())
