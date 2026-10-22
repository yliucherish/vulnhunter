"""公共工具函数：请求发送（带登录态）与反射检测，供各检测器复用。

⚠️ 设计红线（踩坑记录）：初版 fetch_with 把所有请求异常 catch 后**返回空字符串**，
看起来"没漏洞"，实则是静默漏报——一次 73 分钟的 DVWA high 全站扫描因此
0 检出（目标站在并发压力下大量请求超时，全部被吞掉）。
修正：请求失败必须**显式抛出 FetchError**，由引擎层统一重试/熔断/统计，
最终在报告里如实体现"因目标无响应未完成检测的注入点数量"。
**扫描器可以漏报，但不能假装扫过了。**

⚠️ 踩坑记录⑥（v0.3.2）——"黑洞端点"拖垮整场扫描：
v0.3.1 的 high 全站扫描依然 0 检出，而同一份代码的定向复测稳定命中。
根因不是检测逻辑，而是**目标架构与扫描器调度的冲突**：
1. DVWA captcha 页内嵌改密表单，爬虫按 URL 特征放行 → 提取出 5 个注入点；
2. 该页每次 POST 触发 reCAPTCHA 远端校验（容器无外网，每次固定 21s 超时）；
3. PHP 对同一会话加排他文件锁——扫描器全程单会话，**所有请求被 21s 的
   captcha 请求串行化**；
4. 引擎客户端总超时 45s，排在锁后面的请求大量超时；而当时的策略是
   "超时不重试" → 请求被静默放弃，连 Apache 访问日志都没有记录；
5. 表象：XSS 的 canary 请求成功返回（200，页面正常反射 marker），
   但 payload 请求再也没发出去——扫描器"只探针、不开火"。
修复（三处联动）：
a. 爬虫按**表单字段名**判定危险表单（见 crawler._form_is_dangerous）；
b. fetch_with 在本收敛点测量**单次请求耗时**，超过 SLOW_REQUEST_THRESHOLD
   即把注入点标记为慢端点，引擎随即将该点后续请求转入串行通道；
c. 引擎修正重试策略：非慢端点的超时允许重试一次（可能是瞬态锁竞争），
   慢端点的超时才是目标固有行为，不重试。
"""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Optional

import aiohttp

from .base import InjectionPoint

# 单次请求耗时超过该值（秒）→ 注入点标记为慢端点。
# 取值依据：DVWA 正常页 <1s；exec 页因 ping -c 3 基线约 3.9s；
# captcha 页 21s。8s 能区分"固有慢页"与"黑洞端点"。
SLOW_REQUEST_THRESHOLD = 8.0


class FetchError(Exception):
    """请求层失败。

    kind（熔断与重试策略的依据）：
      - "timeout"     请求超时。可能是目标页面固有行为（如 DVWA exec 页把
                      畸形 payload 拼进 ping，DNS 解析挂起），**不代表目标不可用**，
                      只计数、不触发熔断，也不重试（重试只是再等一个超时周期）。
      - "connection"  连接层失败（拒绝连接/DNS 失败/连接被重置）。这才说明
                      目标不可达，累计超阈值应熔断。
      - "other"       协议错误等，重试一次有意义。
    """

    def __init__(self, message: str, kind: str = "other"):
        super().__init__(message)
        self.kind = kind


def make_cookie_header(cookie_str: Optional[str]) -> Optional[dict]:
    """把 'a=1; b=2' 形式转换为请求头。"""
    return {"Cookie": cookie_str} if cookie_str else None


async def fetch_with(session, point: InjectionPoint, payload: str) -> str:
    """向注入点发送一次带 payload 的请求，返回响应正文。

    登录态 Cookie 由 session 构造时统一注入（见 engine.py），此处不额外处理。
    任何请求层失败都会抛出 FetchError（绝不静默返回空内容）。

    副作用：测量单次请求耗时，超过 SLOW_REQUEST_THRESHOLD 时把
    point.slow 置 True——慢端点由此进入引擎的串行调度通道
    （踩坑记录⑥：21s 的 captcha 请求曾把整场扫描串行化到全部超时）。
    """
    params_or_data = {**point.data, point.param: payload}
    start = time.monotonic()
    try:
        if point.method.upper() == "GET":
            async with session.get(point.url, params=params_or_data) as r:
                # 注意：HTTP 5xx 不算请求失败——数据库错误页恰恰常以 500 返回
                # （本地靶场与大量真实框架皆如此），错误信息就在 body 里。
                # 只有连接错误/超时才算 FetchError。
                body = await r.text(errors="ignore")
        else:
            async with session.post(point.url, data=params_or_data) as r:
                body = await r.text(errors="ignore")
    except Exception as e:
        # asyncio.TimeoutError 在 3.11+ 即内置 TimeoutError
        if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
            kind = "timeout"
        elif isinstance(e, aiohttp.ClientConnectorError):
            # 连不上（拒绝/路由不可达/DNS 失败）才算目标不可达
            kind = "connection"
        else:
            # ServerDisconnectedError 等：服务端关了连接，重试一次通常即成功
            kind = "other"
        raise FetchError(f"{point.url} 请求失败: {type(e).__name__}", kind=kind) from e
    # 慢端点判定放在成功分支：失败请求的耗时不代表页面固有行为
    # （超时恰恰是被锁挡住的结果，会把每个点都误标成慢端点）。
    # baseline 记录所有成功请求的最慢耗时——它是引擎"超时是固有慢还是
    # 排队竞争"的判别依据（见 engine._attempt 重试策略）。
    dt = time.monotonic() - start
    if dt > point.baseline:
        point.baseline = dt
    if dt > SLOW_REQUEST_THRESHOLD and not point.slow:
        point.slow = True
    return body


async def reflects_input(session, point: InjectionPoint) -> bool:
    """该注入点是否会把输入内容**原样**反射到响应中。

    这是所有"产物判定"类检测的前置检查（踩坑三次换来的教训，见 _timing/_union 注释）：
    - 若页面反射输入，则注入的 marker/payload 原文会出现在响应里，
      "产物判据"（如 UNION 的 marker 数字）就会被假命中污染；
    - 此时只能依赖"页面自身不可能产生的证据"（如数据库报错、列数错误）。
    """
    canary = f"vh{uuid.uuid4().hex[:20]}"
    try:
        body = await fetch_with(session, point, canary)
    except FetchError:
        return False
    return canary in body
