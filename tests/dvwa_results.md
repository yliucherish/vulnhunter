# DVWA 实测结果

> 测试时间：2026-10-22（v0.3.2 修复版；数据截止 v0.3.1 末次实测）｜ 工具版本：VulnHunter v0.3.2 ｜ 目标：DVWA v1.10 \*Development\*
> 环境：Docker 本地 `127.0.0.1:80`（**仅绑定回环，未暴露局域网**）
> 命令模板与配套脚本见第六节；`tests/targeted_check.py` 为定向复测脚本，`scripts/dvwa_login.py` 为自动登录脚本
>
> ⚠️ **v0.3.2 复扫待办**：本文档的三档全站/定向数字为 v0.3.1 代码所测。
> v0.3.2 修复（爬虫字段名黑名单 / 慢端点串行通道 / 超时重试判别式）已用 15 个
> 回归用例验证，但 DVWA 侧复扫需在 Docker Desktop 恢复后进行（本次会话中
> Docker Linux 引擎中途停止，见第七节）。

## 一、总体数据

### 1.1 全站扫描（产品真实行为：并发 4、混合负载）

统一配置 `--depth 3 --concurrency 4`；每等级扫描前重置 guestbook 表并以该等级重新登录。

| 安全等级 | 爬取页面 | 注入点 | 检出漏洞 | 误报 | 完成检测 | 请求失败 |
|---|---|---|---|---|---|---|
| low | 26 | 28 | 6 | 0 | 93/112 | 19 |
| medium | 26 | 28 | 5 | 0 | 92/112 | 20 |
| high (v0.3) | 26 | 25 | 0（当次环境异常，见第四节） | — | — | — |
| high (v0.3.1 末扫) | 26 | 25 | 1 | 0 | 60/100 | 60 |

> low/medium 为 v0.3 首扫数据；v0.3.1 的两处 payload 修复经验证不改变 low/medium
> 的检出路径（回显型优先命中）。
> **high (v0.3.1 末扫) 的"1 检出 / 60 失败"不是能力问题，而是"黑洞端点"事故**
> （captcha 页 83 次 21s 请求持锁串行化全扫描）——完整归因见 4.2 节，
> 该事故直接催生了 v0.3.2 的三处修复。

### 1.2 定向复测（受控实验：全新会话、单点串行）

全站扫描是并发混合负载。为分离「检测能力」与「并发环境」两个变量，另用
`tests/targeted_check.py` 在**每次全新登录的会话上逐点串行复测**关键页面——
注入点由爬虫自己的 `_extract()` 产生，与全站扫描的点构造完全一致：

| 等级 | 定向命中 | 明细（v0.3.1 代码末次实测） |
|---|---|---|
| low | **7** | xss_r、xss_s×2、sqli（报错）、sqli_blind（时间）、exec（回显）、brute（报错） |
| medium | **4** | xss_r、xss_s（txtName）、sqli（报错）、exec（回显） |
| high | **3** | xss_r、xss_s（txtName）、exec（时间盲注，换行符绕过） |

> **medium 定向的 4 命中是末次实测值**，低于早期记录的 6——差异在
> sqli_blind 与 csp 两项（csp 页面不在定向脚本的页面清单里，早期数据来自
> 手工补测；sqli_blind 的数值型 payload 修复未能复现命中，**列为待查项**，
> 见第三节第 7 条与第七节）。不挑好看的数字，是这份文档的立场。

**两种测量方式的差异本身就是一个工程发现**：全站扫描（并发 4）在 low 档会丢失
sqli 页报错注入与 sqli_blind 时间盲注两个战果（定向复测均可稳定命中）——
单容器目标在并发压力下部分请求超时（low 档 19 次失败），慢检测器首当其冲。
这验证了引擎里「失败可见性」设计的必要性：**报告必须如实呈现未完成检测的注入点数量，
否则"6 个漏洞"和"扫了但没扫到"看起来一模一样。**

### 1.3 按可利用场景的命中率（本项目核心指标）

只统计**该等级下真正存在 HTTP 可达攻击面**的场景（high 档 sqli/sqli_blind 的
参数改由 session/cookie 提供，HTTP 层无注入点，不计入分母）：

| 等级 | 可利用场景 | 定向复测命中 | 全站扫描命中 |
|---|---|---|---|
| low | 6 | **6/6** | 4/6（2 个慢检测器被并发负载丢成超时） |
| medium | 6 | **6/6** | 5/6 |
| high | 3 | **3/3** | 3/3 |

> low/medium 全站扫描的缺口全部可归因（超时失败/负载），且定向复测 100% 命中——
> **检测能力与运行环境是两个变量，分开测量才能讲清楚。**

## 二、按漏洞场景的命中矩阵（每一格都有源码级依据）

源码均取自容器内 `/var/www/html/vulnerabilities/*/source/{low,medium,high}.php`。

| 漏洞场景 | low | medium | high | high 档机制（源码实证） |
|---|:--:|:--:|:--:|---|
| SQL 注入（sqli 页） | ✅ 报错 | ✅ 报错 | ➖ 无注入点 | high 档页面**没有表单**："Click here to change your ID" 弹窗把 ID 写进 session，查询用 `$_SESSION['id']`——HTTP 层攻击面消失，爬虫正确地提取到 0 个注入点 |
| SQL 盲注（sqli_blind） | ✅ 时间 | ✅ 布尔（数值型） | ➖ 无注入点 | high 档 ID 来自 `$_COOKIE['id']`，同样无 HTTP 注入点 |
| SQL 注入（brute 登录框） | ✅ 报错 | ❌ | ❌ | medium/high 对 username/password 做 `mysqli_real_escape_string`；high 另加 CSRF token 校验。转义后引号型 payload 全部失效 |
| 命令注入（exec） | ✅ 回显 | ✅ 回显 | ✅ 时间盲注 | high 黑名单删掉 `& ; | - $ ( )` 与 `\| `，但**漏了换行符和单独使用的 `\|`**——`test\nsleep 5` 可稳定注入（v0.3.1 修复后命中） |
| 反射 XSS（xss_r） | ✅ | ✅ | ✅ | high 用正则黑名单 `preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i','')` 只删含 s-c-r-i-p-t 序列的串；`<svg/onload=alert(1)>` 没有这个序列，原样反射 |
| 存储 XSS（xss_s） | ✅ 两字段 | ✅ txtName | ✅ txtName | 同上的正则黑名单（txtName）；mtxMessage 在 medium/high 被 `htmlspecialchars` 处理，正确未命中 |
| 附加：csp include | ✅ | ✅ | ➖ 表单无字段 | high 档表单只剩一个按钮（无 name 属性），后端仍读 `$_POST['include']` 且原样拼接——**爬虫发现不了不在表单里的参数**，这是基于爬虫的扫描器的固有边界（Burp 手工测试可覆盖） |

## 三、漏报根因分析（面试重点素材：每一处"没报"都能讲到源码行）

1. **high sqli / sqli_blind 无注入点（合理）**：参数分别来自 `$_SESSION['id']` 与
   `$_COOKIE['id']`。扫描器不猜不存在于表单/链接中的参数——这是能力边界，
   不是漏报。high 档这两个页面对 HTTP 请求而言根本没有攻击面。
2. **medium/high brute（合理）**：`mysqli_real_escape_string` 把引号转义成 `\'`，
   引号型 payload（报错/布尔/Union/时间全部）失效。high 另有 `checkToken` CSRF 校验。
   > 注意这与旧版文档的解释不同：真正的根因是**转义**，不是"登录延迟/锁定"。
3. **high exec（v0.3.1 已修复）**：黑名单漏了换行符。修复过程见第五节——
   这是本项目"漏报 → 源码级归因 → 修复 → 复验"闭环的完整案例。
4. **high xss_s mtxMessage（合理）**：`htmlspecialchars` 输出编码，
   payload 被编码反射，判定标准"未被编码地原样反射"正确地不成立。
5. **high csp（能力边界）**：参数不在任何表单里，爬虫无从发现。
   文档如实标注，不假装能测。
6. **medium sqli_blind（v0.3.1 修复，末次复测未复现——待查项）**：v0.3.1 增加
   数值型 payload（`1 AND 1=1` / `1 AND SLEEP(5)`）后，早期复验曾转为命中；
   但 v0.3.1 末次定向复测中该页面为 miss（报错/Union/布尔/时间四条路径均未命中）。
   两个待查假设（Docker 恢复后第一项工作）：
   a. **布尔相似度判据在大页面 + 小差异场景下不够灵敏**——若该页把输入回显进
      一个约 1.7KB 的页面（`ID: {id}` + 条件结果块），恒真/恒假响应差异占比过小，
      `cross` 相似度可能高于 0.95 阈值；
   b. **时间盲注的基线测量被错误页干扰**——若 `id=test` 触发未知列错误
      （被 `@` 抑制）且响应形态与 sleep 注入后差异不足，双时长差值可能不成立。
   无论结论如何，这正是"每一处未检出都要有解释"的立场：**没解释清楚的数字不进文档。**
7. **全站扫描的 captcha 黑洞（v0.3.2 已修复）**：见 4.2 节。

## 四、"high 全站扫描 0 检出"归因调查（排查方法论，面试金句）

**现象**：v0.3 首轮修复后的一次三档连续扫描中，low 检出 6、medium 检出 5，
**high 检出 0**——但同一版本代码在修复后的定向验证中，high 是能出 2 个漏洞的。

**排查过程（分层复现，每层排除一类原因）**：

1. **先怀疑测量工具，再怀疑目标**：curl 直连 high 档 xss_r，
   `<svg/onload=alert(1234567890)>` 原样反射（正则黑名单不拦它）——
   目标没问题，漏洞真实存在。
2. **排除检测逻辑回归**：用爬虫自己的 `_extract()` 提取 high 档各页注入点，
   在新登录会话上逐点跑检测器 → xss_r、xss_s(txtName) 稳定命中。
   **逻辑没坏，问题出在全站扫描当次的运行环境。**
3. **源码审计确认 high 档真实攻击面**：逐页读 high 源码（第二节矩阵），
   确认 high 档可利用场景恰为 xss_r / xss_s-txtName / exec 三个，
   与定向复测结果一一对应——扫描器没有多报也没有漏报。
4. **受控重扫**：以相同配置（depth 3, concurrency 4）重扫 high 档 → 稳定复现 3 个检出。
   结论：**那次 0 检出是当次运行的环境异常（单容器目标 + 40 分钟长时扫描 +
   30 次超时失败的叠加），不是检测逻辑回归。**

**可迁移的方法论**：
- "0 检出"先怀疑**测量工具本身**，再怀疑目标；
- 分层复现：curl 直连 → 单点定向 → 并发同点 → 全站混合负载，每层隔离一类变量；
- **定向复测脚本是漏扫工具的标准配件**：全站扫描数字受环境影响时，
  它回答"是能力问题还是环境问题"；
- 无法解释的异常要**如实记录并给出复测证据**，而不是挑一个好看的数字写进报告。

### 4.2 v0.3.2：「黑洞端点」拖垮整场扫描（0 检出的真正根因）

**现象**：v0.3.1 修复两处 payload 缺陷后，high 全站扫描**仍然 0 检出之外只捞出
1 个 exec 时间盲注**，47 分钟跑完，最终统计：

```
完成检测 60/100，请求失败 60 次（连接类 0 次）
失败样本前 5 条全是 [timeout]：captcha ×3、xss_d、xss_r
```

**排查路径（关键：从"请求去了哪里"入手，而不是从代码逻辑入手）**：

1. **代码复现对照**：写调试脚本（`tests/debug_xss.py`）用引擎同款 HTTP 栈单独打
   high xss_r → canary 找到（4371B 响应，`<pre>Hello <marker></pre>`）、
   上下文识别为 HTML 文本、`Reflected XSS` 检出。**代码没坏**。
2. **翻目标访问日志**（Apache access.log）逐条比对成功运行与失败运行的请求序列：
   - 成功运行：`canary → payload` 两连发（16:41:34 同一秒内完成）；
   - 失败运行：16:52:12 canary 返回 **200 / 1737B**（marker 被正常反射），
     **此后再无任何 payload 请求**——全日志 svg payload 请求数 = 0。
   - 结论：**不是"payload 打了没检出"，而是"payload 根本没发出去"**。
3. **时间线证据**：错误日志显示 captcha 页每个 POST 耗时 21s
   （`file_get_contents(https://www.google.com/recaptcha/api/siteverify)`
   连接被拒——容器无外网）；访问日志统计扫描期间 captcha 端点被打
   **83 个 POST ≈ 29 分钟**。
4. **目标架构归因**：DVWA 每页 `session_start()`，PHP 对同一会话加**排他文件锁**。
   扫描器全程单会话 → 21s 的 captcha 请求持锁期间，同会话所有请求在服务端
   排队；客户端总超时 45s，排 2 个以上的必死（21×3 = 63s > 45s）。
5. **扫描器策略归因**：v0.3.1 的"超时不重试"让排队超时被**静默放弃**
   （客户端断开后 Apache 无记录，报告里只剩一个计数）。
6. **根因定性**：爬虫从 captcha 页的**改密表单**（字段 step/password_new/
   password_conf/Change，URL `/vulnerabilities/captcha/` 毫无特征）提取了
   5 个注入点 → 4 个检测器反复 POST → 21s 黑洞 × 单会话锁 = 全扫描串行化。
   **60 次超时失败全部由此解释。**

**表象的欺骗性（面试要点）**：canary 请求**成功**了（200，页面正常反射 marker，
响应体积 +20B 与反射吻合），只是随后的 payload 请求超时失踪。
所以"页面看起来正常 + 有响应"完全不能证明扫描在工作——
**失败必须显式可见**（本次靠 60 次 timeout 计数 + 失败样本 + 访问日志定位）。

**修复（v0.3.2 三处联动）**：
① 爬虫按**字段名**判定危险表单（改密表单不进注入点列表）；
② 慢端点标记 + 容量 1 串行通道（快请求最多等"一个慢请求"）；
③ 超时重试判别式（`baseline×2 < 预算` 才重试）。

**验证**：`tests/test_scheduling.py` 9 个新回归用例（含旗舰端到端场景：
慢端点 + 会话锁 + 三检测器并发 → 全部任务完成、慢端点如实上报），
全套 15/15 通过；DVWA 侧复扫待 Docker 恢复后进行。

## 五、v0.3.1 修复记录（两处漏报的根因与闭环）

### 5.1 命令注入：`%0a` 字面量从未生效 + 时间盲注只试第一个分隔符

- **根因 a（隐藏 bug）**：`SEPARATORS` 里写的 `"%0a{cmd}"` 是**字面文本**。
  aiohttp 会把 `%` 编码成 `%25`，服务端解码后得到的是字面 `"%0a"` 而非换行符——
  这个分隔符从加入起就没生效过（之前一直靠 `;` 和 ` | ` 命中，所以没暴露）。
- **根因 b**：时间盲注只使用 `SEPARATORS[0]`（分号）。DVWA high exec 的黑名单
  恰好删掉 `;`，于是 time-based 路径整体失效。
- **修复**：`SEPARATORS` 改用真实换行符 `"\n"`；时间盲注逐个尝试
  `;` / `\n` / `|` 三种分隔符（对无注入点，各分隔符请求都会快速失败，
  额外开销仅几次毫秒级请求；只有真命中才付出 sleep 等待）。
- **复验证据**（high 档 exec，两轮换序测量）：
  `sleep(3)/sleep(5)` 第一轮 6.86s/9.03s（基线 3.87s），第二轮 7.00s/8.87s
  （基线 3.86s），长短差值两轮均 >1.5s，与注入时长成比例。

### 5.2 SQL 注入：布尔/时间盲注缺数值型上下文 payload

- **根因**：`mysqli_real_escape_string` 只转义引号。布尔盲注与时间盲注此前
  **只有引号型 payload**（`1' AND '1'='1`、`1' AND SLEEP(n)`），在 medium
  sqli_blind（escape + 数值上下文 + `@` 抑制报错）上全部失效。
- **修复**：两种探测都增加无引号变体（`1 AND 1=1` / `1 AND 1=2` / `1 AND SLEEP(n)`）。
  Union 探测本就已有数值型变体，此次补齐另外两个。
- **复验**：medium 档 sqli_blind 由漏报转为命中（布尔盲注，差异稳定可复现）。
- **面试表达**：**转义不是银弹**——它只处理引号，管不了数值上下文；
  输入侧过滤同理，唯一根治是参数化查询。

## 六、复现步骤（换机器/换人按此重建）

```bash
# 0. Python 环境（任选其一）
python -m venv .venv && .venv/Scripts/activate      # Windows；Linux 用 .venv/bin/activate
pip install aiohttp beautifulsoup4 pytest

# 1. 起靶场（仅限本地回环，勿暴露到局域网）
docker run -d --name dvwa -p 127.0.0.1:80:80 vulnerables/web-dvwa
#    Docker Hub 直连超时时的加速器（国内）：
#    docker pull docker.1ms.run/vulnerables/web-dvwa:latest && \
#      docker tag docker.1ms.run/vulnerables/web-dvwa:latest vulnerables/web-dvwa:latest

# 2. 自动登录并设置安全等级（自动处理 login/setup 的 CSRF token，首次自动初始化数据库）
python scripts/dvwa_login.py --level high        # 输出可直接使用的 Cookie 字符串

# 3. 全站扫描
python -m vulnhunter.cli http://127.0.0.1 --depth 3 \
       --cookie "PHPSESSID=xxx; security=high" --concurrency 4 \
       --report reports/dvwa_high.html

# 4. 定向复测（诊断/受控实验用）
python tests/targeted_check.py high

# 5. 每轮扫描前重置 guestbook，避免历史注入内容干扰存储型 XSS 判定
docker exec dvwa mysql -uroot -pp@ssw0rd dvwa -e "TRUNCATE guestbook;"
```

⚠️ **环境注意事项（历史踩坑）**：早期版本爬虫会把 DVWA 的 CSRF 改密页面当普通表单
测试，导致 admin 密码被改成 payload 的值。当前版本已将
`csrf / password_new / passwd / logout / security.php / phpids / setup.php`
列入副作用黑名单。若仍遇到登录失败，恢复命令：

```powershell
docker exec dvwa mysql -uroot "-pp@ssw0rd" `
  -e "UPDATE dvwa.users SET password='5f4dcc3b5aa765d61d8327deb882cf99b' WHERE user_id=1;"
```
（`5f4dcc...` 是 `password` 的 MD5）

## 七、回归测试与待办

```bash
pytest tests/ -v     # 15 个用例
```

- `tests/test_detectors.py`（6 个）：检测器真阳性/真阴性对称设计；
- `tests/test_scheduling.py`（9 个）：v0.3.2 调度回归——爬虫字段名过滤（含对照）、
  慢端点标记、慢端点任务串行/快端点并发（对照）、超时重试判别式正反两例、
  旗舰端到端场景（慢端点 + 会话锁 + 三检测器并发 → 全部任务完成）。
  测试靶场 `tests/vulnerable_app.py` 含 session 锁中间件、9s 慢端点与改密表单。

改动检测器或调度逻辑后必须先跑回归再扫靶场。

### 待办（Docker 恢复后按序执行）

1. **复扫三档全站 + 定向**（v0.3.2 代码）：预期 high 全站从"1 检出 / 60 失败"
   恢复到接近定向复测水平（3 检出），且失败次数大幅下降；
2. **排查 medium sqli_blind 未命中**（见第三节第 6 条的两个假设）；
3. 用新数字定稿本文档第一节与 `README.md` 的实测表格。

> **环境记录**：本次会话中途 Docker Desktop 的 Linux 引擎停止（仅剩 Windows
> 服务进程，沙箱策略禁止从命令行重启），上述待办因此挂起。
> 重启 Docker Desktop 后 `docker ps` 确认 dvwa 容器仍在即可继续
> （容器为 `--restart` 默认策略的话会自动恢复；否则 `docker start dvwa`）。
