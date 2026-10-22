"""检测器抽象基类：所有漏洞检测器实现此接口即可接入扫描引擎。"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InjectionPoint:
    """一个可注入点：URL + 参数 + 请求方法。"""
    url: str
    param: str
    method: str = "GET"
    data: dict = field(default_factory=dict)  # POST 表单数据（除目标参数外）
    # ---- 运行时状态（由 HTTP 层/引擎填充，非爬虫产出）----
    # slow：该点出现过耗时超过 SLOW_REQUEST_THRESHOLD 的请求（如 DVWA
    #   captcha 页每请求 21s）。标记后引擎把该点后续请求转入串行通道，
    #   避免慢请求持有目标会话锁导致其他请求排队超时（v0.3.2）。
    # baseline：该点观测到的最慢**成功**请求耗时（秒）。引擎据此判别
    #   "超时是目标固有慢还是锁竞争排队"——baseline×2 < 超时预算才重试。
    slow: bool = False
    baseline: float = 0.0


@dataclass
class Vulnerability:
    vuln_type: str
    url: str
    param: str
    payload: str
    evidence: str           # 判定依据（响应片段/差异说明）
    severity: str = "medium"
    suggestion: str = ""


class Detector(ABC):
    """检测器基类。

    priority：调度优先级（数字越小越先执行）。
    为什么需要它：目标站（如 PHP 文件 session）会对同一会话的请求加排他锁，
    一个慢请求（如 exec 页 ping 挂起）会阻塞同会话的其他请求。
    让"快"的检测器（XSS/SSRF，每点 2-4 个请求）先跑完，
    "慢"的检测器（含时间盲注的 SQLi/CMDi）后跑，避免快检测被慢请求饿死。
    """
    name: str = "base"
    priority: int = 100

    @abstractmethod
    async def detect(self, session, point: InjectionPoint) -> Optional[Vulnerability]:
        """对单个注入点执行检测，命中则返回 Vulnerability，否则 None。"""
        ...
