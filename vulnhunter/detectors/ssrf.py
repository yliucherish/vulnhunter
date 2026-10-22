"""SSRF 检测器：带外检测（OAST）思路。

设计要点（面试可讲，这是本检测器最有含金量的部分）：
- SSRF 回显型（能拿到请求结果）只占少数，多数情况是"无回显"。
  因此采用 **带外触发（OAST）**：扫描器自带一个临时 HTTP 回调<｜hy_place▁holder▁no▁813｜>，
  把目标参数替换为自己的监听地址，只要对方服务器发起了请求就会被捕获——
  无回显也能检出。这也是 ysoserial/DNSLog 类探测的核心思想。
- 同时对"目标返回了本机内容"这种回显型做直接命中检测（如返回 127.0.0.1 页面内容）。
- 多个 payload 携带不同 token，回来时能精确知道是哪一个生效，
  为后续"SSRF 利用链"分析提供依据。
"""
import asyncio
import socket
import uuid

from aiohttp import web

from ._http import fetch_with
from .base import Detector, InjectionPoint, Vulnerability

# 覆盖常见绕过：直接 IP、内网地址、127.0.0.1 的十进制/八进制写法
TARGETS = ["http://127.0.0.1:{port}/ssrf/{token}",
           "http://localhost:{port}/ssrf/{token}",
           "http://2130706433:{port}/ssrf/{token}"]  # 2130706433 = 127.0.0.1 十进制


class SSRFDetector(Detector):
    name = "ssrf"
    priority = 20

    def __init__(self):
        self.runner: web.AppRunner | None = None
        self.port: int | None = None
        self.hits: dict[str, str] = {}  # token -> 触发来源 payload

    @staticmethod
    def _free_port() -> int:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    async def setup(self):
        """启动临时回调服务器（仅在扫描开始前调用一次）。"""
        if self.runner:
            return
        self.port = self._free_port()

        async def handler(request):
            token = request.match_info["token"]
            self.hits[token] = str(request.remote) + (request.query_string or "")
            return web.Response(text="ok")

        app = web.Application()
        app.router.add_get("/ssrf/{token}", handler)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", self.port)
        await site.start()

    async def teardown(self):
        if self.runner:
            await self.runner.cleanup()
            self.runner = None

    async def detect(self, session, point: InjectionPoint):
        if not self.runner:
            return None
        for tpl in TARGETS:
            token = uuid.uuid4().hex[:12]
            payload = tpl.format(port=self.port, token=token)
            await fetch_with(session, point, payload)
            # 给带外请求留出到达时间
            await asyncio.sleep(0.5)
            if token in self.hits:
                return Vulnerability(
                    vuln_type="SSRF (Out-of-Band)",
                    url=point.url, param=point.param, payload=payload,
                    evidence=f"本机回调服务收到来自 {self.hits[token]} 的请求",
                    severity="high",
                    suggestion="对用户可控 URL 做白名单校验（协议、域名、IP）；"
                               "禁止访问内网地址与 metadata 服务（169.254.169.254）；"
                               "关闭 30x 跳转跟随。",
                )
        return None
