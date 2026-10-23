---
title: "从零实现一个 SQL 注入检测引擎：报错注入与布尔盲注的误报控制"
tags: 网络安全,SQL注入,漏洞扫描,Python,安全研发
categories: 后端
---

# 从零实现一个 SQL 注入检测引擎：报错注入与布尔盲注的误报控制

> 这篇文章讲我从零写 Web 漏洞扫描器时，在 SQL 注入检测上踩过的坑。
> 结论先说：**写检测器真正的难点不是"怎么检出"，而是"怎么不误报"。**
> 我为了一个误报问题改了四版方案，其中同一个坑踩了三次。
> 所有代码和实测数据都开源，DVWA 三档实测 low 8 / medium 7 / high 3，**0 误报**。

---

## 一、为什么误报控制是核心难题

大部分教程教你怎么写 payload 打穿 DVWA。但如果你要写的是**扫描器**，
问题立刻变了：

- 页面本身会反射输入（搜索框、错误页）——"payload 出现在响应里"不等于"SQL 被执行了"
- 页面有动态内容（CSRF token、session id、时间戳）——两次响应永远不相等
- 并发扫描时系统负载会抖动——"响应变慢了"不等于"注入了 sleep"
- 同一个页面既反射输入、又真的有注入——你收紧规则就会漏报

我在 DVWA 上实测的检出率数字是 low 8 / medium 7 / high 3，
但这些数字背后更重要的是：**每一次判定都必须能回答"为什么报"**。
下面按检测手段从轻到重讲。

---

## 二、报错注入：最简单的起点，也有两个细节

```python
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
```

做法：注入一个单引号 `'`，看响应里是否出现数据库错误特征串。

两个容易忽略的细节：

**1. 要与基线对比。**
```python
baseline = self._normalize(await fetch_with(session, point, "1"))
error_norm = self._normalize(await fetch_with(session, point, "'"))
m = ERROR_RE.search(error_norm)
if m and not ERROR_RE.search(baseline):   # ← 关键
```
有些页面**本来就带着 SQL 错误**（比如别人的报错被缓存在页面里）。
不加 `not ERROR_RE.search(baseline)` 这一条，扫任何站都会报。

**2. payload 只是一个引号。**
不要一上来就扔 `' OR 1=1--`。报错注入只需要破坏语法结构，
一个引号足够，且对业务数据的破坏最小——扫描器应该尽量"轻"。

---

## 三、Union 注入：错误页被抹平时的主力，也是我踩坑最深的地方

DVWA high 档把错误页统一返回 `Something went wrong.`，报错型无从下手。
这时候要用 **UNION SELECT 标记数字**：只有数据库真的执行了注入的 UNION，
页面才会出现我们预置的随机标记。

### 三次踩同一个坑

**第一版**：只判断"标记数字出现在响应中"。
结果在 DVWA 的 `xss_r`/`xss_s` 页面**大量误报**——这些页面把输入原样反射，
标记数字跟着 payload 原文一起被回显回来，看起来就像 UNION 成功了。

**第二版**：走极端——反射页直接禁用标记判据。
结果把 DVWA medium 的真 SQLi **漏掉了**：那个页面既反射输入、又真的有注入。

**第三版（最终方案）：看标记的上下文。**

```python
def _marker_is_result(body: str, marker: str) -> bool:
    """判断 marker 是「输入回显」还是「数据库执行产物」。"""
    idx = body.find(marker)
    while idx != -1:
        ctx = body[max(0, idx - 80): idx + 80]
        # marker 周围没有 UNION/SELECT 关键字 → 不是随 payload 回显的 → 是执行产物
        if not re.search(r"UNION|SELECT", ctx, re.IGNORECASE):
            return True
        idx = body.find(marker, idx + 1)
    return False
```

逻辑很朴素：**如果标记数字是"输入回显"，它周围一定跟着 payload 原文**
（`UNION SELECT 111111,...` 这些字）；如果它干净地出现在页面结果区
（比如 `First name: 111111`），那只能是数据库执行的结果。

再加一条双保险——**数据库自己说列数不对，也是铁证**：

```python
UNION_ERROR_RE = re.compile(
    r"different number of columns|Unknown column|SELECTs to the left|number of columns",
    re.IGNORECASE)
```
页面返回 `The used SELECT statements have a different number of columns`，
说明注入的 UNION 已经进到数据库解析器了。这比标记数字更硬。

> **这个坑的本质**：判据必须是"**漏洞的执行产物**"，不能是"**输入的回显**"。
> 这一条在命令注入检测里同样适用（下一篇会讲 `echo $((a*b))` 为什么优于标记串）。

---

## 四、布尔盲注：两道关，缺一不可

恒真 `1' AND '1'='1` vs 恒假 `1' AND '1'='2`，比较两次响应的差异。
听起来很简单，实际上有两道关。

### 第一道关：归一化——剔除动态噪声

```python
DYNAMIC_HEX_RE  = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)   # CSRF token / session id
DYNAMIC_TOKEN_RE = re.compile(r"(name=[\"']user_token[\"'][^>]*value=[\"'])[^\"']+", re.IGNORECASE)

@staticmethod
def _normalize(body: str) -> str:
    """剔除动态噪声，避免页面本身抖动造成误判。"""
    body = DYNAMIC_TOKEN_RE.sub(r"\1TOKEN", body)
    body = DYNAMIC_HEX_RE.sub("TOKEN", body)
    return WHITESPACE_RE.sub(" ", body).strip()[:8000]
```

不归一化会怎样？**每一次请求的响应都不一样**（token 变了），
恒真和恒假的相似度都是 0.9x，永远分不出差异——检测直接失效。

### 第二道关：稳定性校验——同一条件测两次

```python
STABLE_THRESHOLD = 0.95   # 同一条件两次响应的相似度下限
DIFF_THRESHOLD   = 0.05   # 恒真/恒假差异阈值

true_1 = normalize(fetch(true_p));  false_1 = normalize(fetch(false_p))
true_2 = normalize(fetch(true_p));  false_2 = normalize(fetch(false_p))

stable_true  = sim(true_1, true_2)    # 恒真条件自身可复现吗
stable_false = sim(false_1, false_2)  # 恒假条件自身可复现吗
cross        = sim(true_1, false_1)   # 两者差异够大吗

if stable_true >= 0.95 and stable_false >= 0.95 and cross < 0.95:
    # 成立
```

三个条件必须同时满足。为什么？
- `cross < 0.95` 说明两次响应有差异——但**差异可能来自页面抖动**（广告、随机推荐）；
- `stable_* >= 0.95` 说明"恒真"和"恒假"各自是**稳定可复现**的——
  只有"条件真的影响了 SQL 执行"，差异才稳定。

### 关键增强：双形态 payload（字符型 + 数值型）

```python
TRUE_PAYLOAD         = "1' AND '1'='1"
FALSE_PAYLOAD        = "1' AND '1'='2"
TRUE_PAYLOAD_NUMERIC = "1 AND 1=1"      # ← 无引号变体
FALSE_PAYLOAD_NUMERIC= "1 AND 1=2"
```

为什么需要无引号版本？因为 `mysqli_real_escape_string` **只转义引号**。
在 `WHERE user_id = $id` 这种数值上下文里，无引号 payload 无需逃逸即可执行。

DVWA medium 的 `sqli_blind` 就是这样从漏转命中的：引号型 payload 被转义后
语法错误又被 `@` 抑制（页面无报错），但 `1 AND SLEEP(5)` 照样注入成功。

> 面试可以这么讲：**"转义函数防的是字符，不是逻辑。"**
> 参数化查询之所以是唯一根治手段，就是因为它把"数据"和"逻辑"彻底分开。

---

## 五、时间盲注：三道防线，把"系统忙"和"真延迟"分开

时间盲注是所有无回显漏洞的通用兜底手段，但也是误报重灾区——
**并发扫描时其他请求会拖慢目标，让个别响应"看起来变慢"**。

我的方案是三道防线：

```python
BASELINE_RUNS = 3       # 基线测 3 次取中位数（不是平均值，抗单次毛刺）
SLEEP_PAIR    = (3, 5)  # 注入两个不同时长
DIFF_THRESHOLD = 1.5    # 长短耗时差下限

async def one_round(order):
    baseline = statistics.median([await measure("test") for _ in range(3)])
    times = {sec: await measure(payloads[sec]) for sec in order}
    ok = (times[3] - baseline > 2.0
          and times[5] - baseline > 2.0
          and times[5] - times[3] > 1.5)   # ← 核心
    return ok, baseline, times

ok, base, t = await one_round((3, 5))
if not ok: return None
await asyncio.sleep(1.0)
ok2, base2, t2 = await one_round((5, 3))   # 换序复验
if not ok2: return None
```

**第二道防线是整个设计的核心**：注入 sleep(3) 和 sleep(5) 两个时长，
要求**两者都慢，且耗时差与时长差成比例**（>1.5s）。

道理很直白：并发负载会**同等**拖慢两个请求，但拖不出"差值"来。
只有 sleep 真的被执行了，才会出现"长请求比短请求多等约 2 秒"。

**第三道防线是换序复验**：疑似命中后反序再测一轮（5→3），
排除"先测的快、后测的慢"这类顺序效应。

### 这里我踩过一个坑

初版只做"退避 1 秒再测一次"，结果在 DVWA 扫描中**依然误报**。
原因：复验期间**同一批并发任务还在打目标站**，系统依然忙。
**在噪声源没消失的情况下复验是没有意义的**——要么换序复验（顺序效应被抵消），
要么把疑似命中点隔离到低并发通道重测。

---

## 六、实测数据（DVWA v1.10，v0.3.2 复扫）

| 安全等级 | 爬取页面 | 注入点 | 检出 | 检测完成度 | 误报 |
|---|---|---|---|---|---|
| low | 38 | 25 | **8** | 100/100 | 0 |
| medium | 38 | 25 | **7** | 100/100 | 0 |
| high | 38 | 21 | **3** | 82/84 | 0 |

几个数字背后的故事（这些比数字本身更值得讲）：

- **medium 的 `sqli_blind` 时间盲注成功检出**——它早期版本是被并发超时丢掉的，
  不是检测能力问题。修复慢端点串行化后自然就检出了。
- **high 档检出了命令注入时间盲注**——证明换行符 payload 变形在黑名单下有效。
- **high 档的 SQLi 检出为 0 是正确行为**：DVWA high 的 sqli 参数改由 session 提供，
  HTTP 层没有攻击面。扫描器报不了不是缺陷，**报不了还能解释为什么，才是能力**。

---

## 七、给面试官的三个要点

1. **判据必须是"漏洞的执行产物"，不能是"输入的回显"。**
   这是我在 UNION 检测上踩了三次才记住的，也是误报控制的总纲。
2. **转义函数防的是字符，不是逻辑。**
   所以要构造无引号的数值型 payload；根治只有参数化查询。
3. **时间型检测要区分"真延迟"与"系统忙"。**
   双时长差值 + 换序复验是关键；在噪声源没消失时复验没有意义。

---

## 合规声明

所有测试均在本地授权的 DVWA 靶场完成。文中 payload 仅用于安全研究与
授权环境下的防御工具开发。

---

> 完整代码：`vulnhunter/vulnhunter/detectors/sqli.py`（报错/Union/布尔/时间四种手段）
> 与 `_timing.py`（时间型公共判别逻辑，SQL 与命令注入共用）。
> 15 个单元测试覆盖判据边界，测试代码比检测代码更能说明设计意图。
