"""反射型 XSS 检测器：上下文感知的 payload 探测。

设计要点（面试可讲）：
- 先注入唯一标记串（canary）确认参数被反射，再判断反射点所在上下文
  （HTML 文本 / 标签属性 / JS 字符串），不同上下文用不同 payload。
- 不直接弹窗验证，而是检查 payload 是否未被编码地原样出现在响应中——
  这是扫描器区别于"打 payload 看弹窗"的自动化判定思路。
"""
import re
import uuid
from typing import Optional

from ._http import fetch_with
from .base import Detector, InjectionPoint, Vulnerability

PAYLOAD_HTML = '<svg/onload=alert({marker})>'
PAYLOAD_ATTR = '" onmouseover="alert({marker})'
PAYLOAD_JS = "';alert({marker})//"


class XSSDetector(Detector):
    name = "xss"
    priority = 10   # 快检测器：每点仅 2-4 个请求，优先调度

    # 统一走 _http.fetch_with：请求失败会抛 FetchError，由引擎层重试/统计，
    # 不再静默吞掉（详见 _http.py 的设计红线）。
    _fetch = staticmethod(fetch_with)

    def _context_payload(self, body: str, marker: str) -> Optional[tuple[str, str]]:
        """根据 canary 所在上下文选择 payload，返回 (payload, evidence_context)。"""
        idx = body.find(marker)
        if idx == -1:
            return None
        window = body[max(0, idx - 200):idx]
        # 在 <script> 内的 JS 字符串里
        if re.search(r"<script[^>]*>[^<]*['\"][^'\"]*$", window, re.IGNORECASE):
            return PAYLOAD_JS.format(marker=marker), "JS 字符串上下文"
        # 在标签属性里
        if re.search(r"<[a-zA-Z][^>]*$", window):
            return PAYLOAD_ATTR.format(marker=marker), "HTML 属性上下文"
        return PAYLOAD_HTML.format(marker=marker), "HTML 文本上下文"

    async def detect(self, session, point: InjectionPoint) -> Optional[Vulnerability]:
        marker = uuid.uuid4().hex[:10]
        probe = await self._fetch(session, point, marker)
        chosen = self._context_payload(probe, marker)
        if not chosen:
            return None
        payload, ctx = chosen
        body = await self._fetch(session, point, payload)
        if payload in body:
            return Vulnerability(
                vuln_type="Reflected XSS",
                url=point.url, param=point.param, payload=payload,
                evidence=f"payload 在 {ctx} 中未被编码，原样反射",
                severity="medium",
                suggestion="对输出按上下文编码（HTML/属性/JS 分别处理）；启用 CSP；输入侧白名单过滤。",
            )
        return None
