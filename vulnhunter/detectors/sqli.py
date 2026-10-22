"""SQL 注入检测器：报错注入 + 布尔盲注 + Union 注入 + 时间盲注。

设计要点（面试可讲）：
- 报错注入：注入报错 payload，匹配常见数据库错误特征串（MySQL/MSSQL/Oracle/PG）。
- 布尔盲注的**两道关**（详见模块尾部的 `_normalize` / 稳定性校验注释）。
- **Union 注入（本版本新增）**：当页面错误回显被抹除时（DVWA high 的错误页
  统一返回 "Something went wrong."），报错型无从下手，此时用
  `UNION SELECT <marker>,...` 的方式判定：只有数据库真的执行了注入的 UNION，
  页面才会出现我们预置的**随机标记数字**（原始查询结果里不可能有）。
  判定依据同样是"漏洞执行产物"，不是"回显的输入"。
- **时间型 SQL 盲注（本版本新增）**：复用 `_timing.py` 的公共判别逻辑
  （基线 3 次中位数 + 疑似后退避隔离复验），与命令注入共用——
  这就是"公共能力抽象"在检测器层的落地。
- **上下文双形态 payload**：布尔盲注与时间盲注都同时构造字符型（引号闭合）
  与数值型（无引号）两种 payload。`mysqli_real_escape_string` 只会转义引号，
  在 `WHERE user_id = $id` 这类数值上下文里无引号 payload 依然注入成功
  （DVWA medium sqli_blind 由漏报转命中的原因，见 tests/dvwa_results.md）。
"""
import difflib
import random
import re
from typing import Optional

from ._http import fetch_with, reflects_input
from ._timing import detect_time_based
from .base import Detector, InjectionPoint, Vulnerability

ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
    r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"Microsoft OLE DB Provider for (SQL Server|ODBC Drivers)",
    r"Unclosed quotation mark after the character string",
    r"ORA-\d{5}", r"Oracle error",
    r"PostgreSQL.*ERROR", r"pg_query\(\)",
    r"SQLite3::", r"sqlite_error",
]
ERROR_RE = re.compile("|".join(ERROR_PATTERNS), re.IGNORECASE)

# UNION 试探中数据库可能返回的提示信息——它本身就是"注入生效"的铁证
UNION_ERROR_RE = re.compile(
    r"different number of columns|Unknown column|SELECTs to the left|number of columns",
    re.IGNORECASE,
)

# 动态内容：16 位以上十六进制串（CSRF token / session id / 随机 nonce），以及 DVWA 的 user_token
DYNAMIC_HEX_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
DYNAMIC_TOKEN_RE = re.compile(r"(name=[\"']user_token[\"'][^>]*value=[\"'])[^\"']+", re.IGNORECASE)
WHITESPACE_RE = re.compile(r"\s+")

TRUE_PAYLOAD = "1' AND '1'='1"
FALSE_PAYLOAD = "1' AND '1'='2"
# 数值型上下文（无引号）变体：应对 mysqli_real_escape_string 类转义。
# 转义只处理引号字符，而数值上下文（WHERE user_id = $id，值不加引号）下
# 无引号 payload 无需逃逸即可执行——DVWA medium sqli_blind 实测：
# 引号型 payload 被转义后语法错误又被 @ 抑制（页面无报错），
# 但 1 AND SLEEP(5) / 1 AND 1=1 照样注入成功。
TRUE_PAYLOAD_NUMERIC = "1 AND 1=1"
FALSE_PAYLOAD_NUMERIC = "1 AND 1=2"
DIFF_THRESHOLD = 0.05    # 恒真/恒假差异阈值
STABLE_THRESHOLD = 0.95  # 同一条件两次响应的稳定性下限
MAX_COLUMNS = 8          # UNION 列数探测上限


class SQLiDetector(Detector):
    name = "sqli"
    priority = 30

    # ============ 响应归一化 ============
    @staticmethod
    def _normalize(body: str) -> str:
        """剔除动态噪声，避免页面本身抖动造成误判。"""
        body = DYNAMIC_TOKEN_RE.sub(r"\1TOKEN", body)
        body = DYNAMIC_HEX_RE.sub("TOKEN", body)
        return WHITESPACE_RE.sub(" ", body).strip()[:8000]

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        return difflib.SequenceMatcher(None, a, b).ratio()

    # ============ Union 注入 ============
    @staticmethod
    def _marker_is_result(body: str, marker: str) -> bool:
        """marker 出现在响应中时，判断它是「输入回显」还是「数据库执行产物」。

        ⚠️ 踩坑记录（同一类坑第三次踩到，务必作为面试素材）：
        初版只判断"marker 数字出现在响应中"，结果在 DVWA 的 xss_r/xss_s 页面上
        **大量误报**——这些页面会把输入原样反射，marker 数字随 payload 原文一起
        被回显，看起来就像 UNION 执行成功了。
        第二轮修正走极端：反射页直接禁用 marker 判据，结果又把 DVWA medium 的
        真 SQLi 漏掉了（该页面既反射输入、又真的有注入）。
        最终方案：**看 marker 的上下文**——若 marker 周围是 payload 原文特征
        （UNION/SELECT 关键字），说明只是输入被回显；若 marker 干净地出现在
        页面结果区（如 First name: 111111），才是数据库执行产物。
        """
        idx = body.find(marker)
        while idx != -1:
            ctx = body[max(0, idx - 80): idx + 80]
            if not re.search(r"UNION|SELECT", ctx, re.IGNORECASE):
                return True   # 至少有一处干净出现 → 执行产物
            idx = body.find(marker, idx + 1)
        return False

    async def _union_probe(self, session, point) -> Optional[Vulnerability]:
        """列数探测 + 标记数字判定（带上下文区分的产物判定）。"""
        baseline = self._normalize(await fetch_with(session, point, "1"))
        marker = random.randint(100000, 999999)
        marker_s = str(marker)

        for ncols in range(1, MAX_COLUMNS + 1):
            selects = ",".join([marker_s] + [str(random.randint(100000, 999999)) for _ in range(ncols - 1)])
            # 字符型上下文：闭合单引号再 UNION
            candidates = [
                f"1' UNION SELECT {selects} -- -",
                f"1 UNION SELECT {selects} -- -",  # 数字型上下文
                f"1' UNION ALL SELECT {selects} -- -",
            ]
            for payload in candidates:
                body = await fetch_with(session, point, payload)
                if not body:
                    continue
                # marker 干净出现（非输入回显）→ 数据库执行了注入的 UNION
                if marker_s not in baseline and self._marker_is_result(body, marker_s):
                    return Vulnerability(
                        vuln_type="SQL Injection (UNION-based)",
                        url=point.url, param=point.param, payload=payload,
                        evidence=f"注入 UNION SELECT 的标记数字 {marker_s} 干净地出现在"
                                 f"页面结果区（非输入回显位置）→ 数据库执行了注入的 UNION 语句",
                        severity="high",
                        suggestion="使用参数化查询；对 UNION 关键词做输入侧过滤只是缓解手段，"
                                   "根本方案仍是预编译 + 最小权限数据库账号。",
                    )
                # 数据库抛出列数不匹配的错误——同样是注入生效的铁证
                m = UNION_ERROR_RE.search(body)
                if m and not UNION_ERROR_RE.search(baseline):
                    return Vulnerability(
                        vuln_type="SQL Injection (UNION-based, column mismatch)",
                        url=point.url, param=point.param, payload=payload,
                        evidence=f"数据库返回 UNION 列数错误：{m.group(0)}",
                        severity="high",
                        suggestion="同上：参数化查询是唯一根治手段。",
                    )
        return None

    # ============ 时间型 SQL 盲注 ============
    async def _time_probe(self, session, point) -> Optional[Vulnerability]:
        # 字符型与数值型两种上下文都试：引号型 payload 会被 escape_string 转义
        # 失效，但数值上下文里无引号 payload 依然注入成功（见 TRUE_PAYLOAD_NUMERIC 注释）。
        for make in (lambda sec: f"1' AND SLEEP({sec}) -- -",
                     lambda sec: f"1 AND SLEEP({sec})"):
            hit = await detect_time_based(session, point, make_payload=make)
            if not hit:
                continue
            payload, evidence = hit
            return Vulnerability(
                vuln_type="SQL Injection (Time-based Blind)",
                url=point.url, param=point.param, payload=payload,
                evidence=evidence,
                severity="high",
                suggestion="使用参数化查询；限制数据库账号权限（禁止 SLEEP 等高权限函数需按需评估）。",
            )
        return None

    # ============ 主入口 ============
    async def detect(self, session, point: InjectionPoint) -> Optional[Vulnerability]:
        baseline = self._normalize(await fetch_with(session, point, "1"))

        # 1) 报错注入
        error_norm = self._normalize(await fetch_with(session, point, "'"))
        m = ERROR_RE.search(error_norm)
        if m and not ERROR_RE.search(baseline):
            return Vulnerability(
                vuln_type="SQL Injection (Error-based)",
                url=point.url, param=point.param, payload="'",
                evidence=f"数据库错误特征: {m.group(0)}",
                severity="high",
                suggestion="使用参数化查询/预编译语句，禁止拼接 SQL；对输入做类型与白名单校验。",
            )

        # 2) Union 注入（错误页被抹平时的主力手段）
        vuln = await self._union_probe(session, point)
        if vuln:
            return vuln

        # 3) 布尔盲注（归一化 + 双次稳定性校验）：字符型与数值型两种上下文
        #    数值型变体用于 escape_string 场景（转义只挡引号，挡不住无引号 payload）
        for true_p, false_p in ((TRUE_PAYLOAD, FALSE_PAYLOAD),
                                (TRUE_PAYLOAD_NUMERIC, FALSE_PAYLOAD_NUMERIC)):
            true_1 = self._normalize(await fetch_with(session, point, true_p))
            false_1 = self._normalize(await fetch_with(session, point, false_p))
            true_2 = self._normalize(await fetch_with(session, point, true_p))
            false_2 = self._normalize(await fetch_with(session, point, false_p))

            stable_true = self._similarity(true_1, true_2)
            stable_false = self._similarity(false_1, false_2)
            cross = self._similarity(true_1, false_1)

            if stable_true >= STABLE_THRESHOLD and stable_false >= STABLE_THRESHOLD \
                    and cross < 1 - DIFF_THRESHOLD:
                return Vulnerability(
                    vuln_type="SQL Injection (Boolean-based Blind)",
                    url=point.url, param=point.param,
                    payload=f"{true_p} / {false_p}",
                    evidence=f"归一化后：恒真自洽度 {stable_true:.3f}，恒假自洽度 {stable_false:.3f}，"
                             f"两者相似度仅 {cross:.3f}（阈值 {1-DIFF_THRESHOLD}），差异稳定可复现",
                    severity="high",
                    suggestion="使用参数化查询；ORM 中避免原生 SQL 拼接；对错误信息统一兜底。",
                )

        # 4) 时间型 SQL 盲注（最后兜底，最慢）
        return await self._time_probe(session, point)
