"""命令行入口：
    python -m vulnhunter.cli http://target --depth 2 --cookie "PHPSESSID=xxx" --report report.html

⚠️ 仅用于授权测试（本地靶场如 DVWA / pikachu / vulhub）。
"""
import argparse
import asyncio

from .engine import ScanEngine
from .report import generate


def main():
    parser = argparse.ArgumentParser(description="VulnHunter Web 漏洞扫描器（仅限授权测试）")
    parser.add_argument("target", help="目标 URL，如 http://localhost/dvwa")
    parser.add_argument("--depth", type=int, default=2, help="爬取深度（默认 2）")
    parser.add_argument("--concurrency", type=int, default=10, help="并发数（默认 10）")
    parser.add_argument("--timeout", type=float, default=45.0,
                        help="单次请求总超时秒数（默认 45；目标有固有慢页时可调大）")
    parser.add_argument("--cookie", default=None,
                        help="登录态 Cookie，格式 'PHPSESSID=xxx; security=low'")
    parser.add_argument("--report", default="report.html", help="报告输出路径")
    args = parser.parse_args()

    print("⚠️  请确认你对目标拥有授权。未授权扫描属违法行为。")
    engine = ScanEngine(args.target, depth=args.depth,
                        concurrency=args.concurrency, cookie=args.cookie,
                        timeout=args.timeout)
    vulns = asyncio.run(engine.scan())
    out = generate(vulns, args.target, args.report, stats=engine.stats)
    print(f"[*] 报告已生成: {out}")


if __name__ == "__main__":
    main()
