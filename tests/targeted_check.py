"""定向验证脚本：排查「DVWA high 全站扫描 0 检出」的归因。

思路：全站扫描一遍要 40 分钟且受并发/会话状态干扰，这里用爬虫自己的
_extract() 逻辑提取关键页面的注入点（与真实扫描的点构造完全一致），
在新登录的会话上逐个跑对应检测器，隔离变量：

- 若这里能命中 → 全站扫描的 0 检出是**环境因素**（会话过期/并发阻塞等）；
- 若这里也 miss → 是**检测逻辑/payload 覆盖**问题，需改代码。

用法：
    python tests/targeted_check.py [low|medium|high]
"""
import asyncio
import sys

sys.path.insert(0, ".")

import aiohttp

from scripts.dvwa_login import login
from vulnhunter.crawler import Crawler
from vulnhunter.detectors.cmdi import CommandInjectionDetector
from vulnhunter.detectors.sqli import SQLiDetector
from vulnhunter.detectors.xss import XSSDetector

# 页面 → 负责的检测器（与真实引擎一致：每个点会过所有检测器，
# 这里按相关性裁剪以缩短诊断时间）
PAGE_DETECTORS = {
    "xss_r": [XSSDetector()],
    "xss_s": [XSSDetector()],
    "sqli": [SQLiDetector()],
    "sqli_blind": [SQLiDetector()],
    "exec": [CommandInjectionDetector()],
    "brute": [SQLiDetector()],
}


async def main():
    level = sys.argv[1] if len(sys.argv) > 1 else "high"
    cookie = await login(level)
    print(f"[*] 等级={level} 会话就绪")
    async with aiohttp.ClientSession(headers={"Cookie": cookie}) as s:
        crawler = Crawler("http://127.0.0.1")
        for page, detectors in PAGE_DETECTORS.items():
            url = f"http://127.0.0.1/vulnerabilities/{page}/"
            async with s.get(url) as r:
                html = await r.text(errors="ignore")
            if "login.php" in str(r.url):
                print(f"[!] {page}: 被重定向到登录页，会话未生效！")
                continue
            _, pts = crawler._extract(url, html)
            seen, uniq = set(), []
            for p in pts:
                key = (p.url, p.param, p.method)
                if key not in seen:
                    seen.add(key)
                    uniq.append(p)
            print(f"\n=== {page} ({len(uniq)} 个注入点) ===")
            for p in uniq:
                print(f"    {p.method:4} {p.param}")
            for p in uniq:
                for det in detectors:
                    try:
                        r = await det.detect(s, p)
                    except Exception as e:
                        print(f"    [ERR] {det.name} {p.param}: {type(e).__name__} {e}")
                        continue
                    if r:
                        print(f"    [HIT] {det.name} / {p.param}: {r.vuln_type}")
                        print(f"         证据: {r.evidence[:90]}")
                    else:
                        print(f"    [miss] {det.name} / {p.param}")


asyncio.run(main())
