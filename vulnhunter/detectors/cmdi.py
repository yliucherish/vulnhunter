"""命令注入检测器：回显型 + 时间延迟型 + payload 变形。

设计要点（面试可讲）：
- **为什么不用「注入 echo <标记串> 看回显」这种常见做法？**
  因为会误报！若目标页面本身就是反射型回显参数（如搜索框），那么你注入的所有内容
  ——包括标记串本身——都会被原样反射回来，于是"命中"了却根本没执行任何命令。
  本实现的做法是：注入 `echo $((a*b))` 这类**算术表达式**，只检测其**计算结果**
  （一个只可能由命令执行产生的数字）是否出现在响应中。payload 原文里没有这个数字，
  因此判定依据是"命令真的被执行了"——这是很多自研扫描器会踩的坑，务必讲清楚。
- **payload 变形**：DVWA medium/high 用 `str_replace` 黑名单删掉 `;&|` 等字符，
  单一形态的 payload 全部被吃。因此每个 payload 同时生成多个形态
  （大小写、引号包裹、编码变形、命令替换嵌套）批量尝试。
- **时间盲注复用 `_timing.py`**：基线 3 次取中位数 + 疑似命中后退避隔离复验，
  与 SQL 时间盲注共用同一判别逻辑（公共能力抽象，见 _timing.py 的 docstring）。
"""
import random

from ._http import fetch_with
from ._timing import detect_time_based
from .base import Detector, InjectionPoint, Vulnerability

# 常见命令分隔符：分号、双与、管道、换行、命令替换
# ⚠️ 换行必须是真实字符 "\n"：写成字面 "%0a" 会被 aiohttp 二次编码为 %250a，
# 服务端解码后得到的是字面文本 "%0a" 而非换行，该分隔符将永远失效
# （曾因此漏掉 DVWA high 档命令注入，见 SPEC 踩坑记录⑤）。
SEPARATORS = [";{cmd}", " && {cmd}", " | {cmd}", "\n{cmd}", "$({cmd})"]


class CommandInjectionDetector(Detector):
    name = "command-injection"
    priority = 40   # 最慢（含时间盲注与可能挂起的命令执行探测），最后调度

    # ---------- payload 变形：应对黑名单过滤 ----------
    @staticmethod
    def _variants(base: str) -> list[str]:
        """同一个命令的多种注入形态。

        应对 str_replace 黑名单的常见思路：
        - 字符大小写（linux 命令大小写敏感，Windows 不敏感，但黑名单常按小写写死）
        - 命令替换嵌套 `$(...)`，可绕过只过滤 `;` 的场景
        - 反引号替换（另一种命令替换写法，黑名单未必覆盖）
        """
        return [
            base,
            f"$({base})",
            f"`{base}`",
            f"'$({base})'",
        ]

    # ---------- 回显型 ----------
    async def _echo_probe(self, session, point):
        for sep in SEPARATORS:
            a = random.randint(9000, 9999)
            b = random.randint(9000, 9999)
            expected = str(a * b)
            cmd = f"echo $(({a}*{b}))"
            payload = f"test{sep.format(cmd=cmd)}"
            body = await fetch_with(session, point, payload)
            if body and expected in body:
                return Vulnerability(
                    vuln_type="Command Injection (Echo)",
                    url=point.url, param=point.param, payload=payload,
                    evidence=f"命令被执行：响应中出现计算结果 {expected}（payload 原文不含该值）",
                    severity="critical",
                    suggestion="禁止将用户输入拼接进 shell；改用 subprocess 列表参数形式；"
                               "必要时做严格的白名单过滤。",
                )
        return None

    # ---------- 时间型（走公共判别逻辑） ----------
    async def _time_probe(self, session, point):
        # 逐个分隔符尝试时间盲注。为什么需要多个：str_replace 类黑名单会删掉
        # `; & |` 等字符（DVWA high exec 即如此），但换行符与单独使用的 `|`
        # 常被遗漏——`test\nsleep 5` 在 high 档可稳定制造与注入时长成比例的延迟。
        # 成本说明：对不存在注入的点，各分隔符的请求都会快速失败（无 sleep 发生），
        # 额外开销仅几次毫秒级请求；只有真命中才会付出 sleep 的等待时间。
        for sep in (";{cmd}", "\n{cmd}", "|{cmd}"):
            hit = await detect_time_based(
                session, point,
                make_payload=lambda sec, s=sep: "test" + s.format(cmd=f"sleep {sec}"),
            )
            if not hit:
                continue
            payload, evidence = hit
            return Vulnerability(
                vuln_type="Command Injection (Time-based Blind)",
                url=point.url, param=point.param, payload=payload,
                evidence=evidence,
                severity="critical",
                suggestion="禁止拼接用户输入到系统命令；使用参数化 API 替代 shell 调用。",
            )
        return None

    async def detect(self, session, point: InjectionPoint):
        # 1) 回显型（快且准），命中即返回
        vuln = await self._echo_probe(session, point)
        if vuln:
            return vuln

        # 2) 回显型失败时，对首个分隔符做多形态变形尝试
        #    （黑名单删掉 ; & | 的场景，这里换 command substitution 形态再试）
        #    ⚠️ 教训：初版用固定的 7*8=56，结果 security.php 页面里本来就含 "56"，
        #    造成十几个参数的批量误报。凡是"数字判据"必须用随机唯一值。
        for variant in self._variants("echo $((7*8))"):
            a = random.randint(9000, 9999)
            b = random.randint(9000, 9999)
            expected = str(a * b)
            variant = variant.replace("7*8", f"{a}*{b}")
            body = await fetch_with(session, point, f"test;{variant}")
            if body and expected in body:
                return Vulnerability(
                    vuln_type="Command Injection (Echo, Obfuscated)",
                    url=point.url, param=point.param,
                    payload=f"test;{variant}",
                    evidence=f"变形后的命令替换被执行，响应中出现随机计算结果 {expected}",
                    severity="critical",
                    suggestion="禁止拼接用户输入到系统命令；必要时用严格白名单过滤。",
                )

        # 3) 时间盲注（无回显场景的通用兜底）
        return await self._time_probe(session, point)
