"""调试脚本：复现引擎 XSS 检测路径，打印 canary 响应细节。

用法: python tests/debug_xss.py
目的：定位"canary 请求 200 但 _context_payload 返回 None"的根因。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import aiohttp

from dvwa_login import login
from vulnhunter.crawler import Crawler
from vulnhunter.detectors.xss import XSSDetector
from vulnhunter.detectors._http import fetch_with


async def main():
    cookie = await login("high")
    print(f"[*] cookie 前 60 字符: {cookie[:60]}...")

    timeout = aiohttp.ClientTimeout(total=45)
    connector = aiohttp.TCPConnector(force_close=True)
    headers = {"User-Agent": "VulnHunter/0.3 (authorized testing only)",
               "Cookie": cookie}

    async with aiohttp.ClientSession(timeout=timeout, headers=headers,
                                     connector=connector) as session:
        crawler = Crawler("http://127.0.0.1", max_depth=3)
        pages, points = await crawler.crawl(session)
        print(f"[*] 爬取 {pages} 页 / {len(points)} 个注入点")

        for p in points:
            if "xss_r" in p.url or "captcha" in p.url:
                print(f"    POINT url={p.url} param={p.param} method={p.method} data={p.data}")

        det = XSSDetector()
        for p in points:
            if "xss_r" in p.url and p.param == "name":
                marker = "dbg" + "a1b2c3d4e5"
                body = await fetch_with(session, p, marker)
                print(f"[*] canary 响应长度: {len(body)}")
                idx = body.find(marker)
                print(f"[*] marker 在响应中: {idx != -1} (idx={idx})")
                if idx >= 0:
                    print(f"[*] 上下文: ...{body[max(0, idx - 120):idx + 60]!r}...")
                    chosen = det._context_payload(body, marker)
                    print(f"[*] _context_payload 选择: {chosen}")
                else:
                    print(f"[!!!] 响应头部 800 字符:\n{body[:800]}")
                v = await det.detect(session, p)
                print(f"[*] detect() 结果: {v}")
                break


if __name__ == "__main__":
    asyncio.run(main())
