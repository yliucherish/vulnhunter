"""本地漏洞靶场（仅用于自测扫描器），模拟：
- /search?q=      反射型 XSS（原样回显）
- /user?id=       报错注入 + 布尔差异
- /ping?host=     命令注入（回显分隔符 ; | && 及换行）
- /fetch?url=     SSRF（服务端请求任意 URL）
- /admin?action=  需登录态 Cookie 才能访问（验证 --cookie 是否生效）
- /slow?mode=     慢端点：每请求耗时 SLOW_SECS 秒（模拟 DVWA captcha 的
                  21s 黑洞），且**全程持有 SESSION_LOCK**——模拟 PHP 对
                  同一会话的排他文件锁：任何其他请求都必须等它让锁。
- /                首页含一个改密表单（step/password_new/password_conf），
                  用于验证爬虫按**字段名**跳过危险表单（v0.3.2 修复①）。

运行: python vulnerable_app.py  →  http://127.0.0.1:8888
"""
import asyncio
import re
import sys

from aiohttp import web

SESSION_COOKIE = "PHPSESSID=authorized"
SLOW_SECS = 9            # 慢端点单请求耗时（> 引擎 SLOW_REQUEST_THRESHOLD=8s）
SESSION_LOCK = asyncio.Lock()   # 模拟 PHP session 文件锁：全局串行化


@web.middleware
async def session_lock_middleware(request, handler):
    """模拟 PHP session 锁：同一"会话"的请求全局串行。

    真实场景（DVWA）：PHP 对每个会话加排他文件锁，扫描器全程单会话，
    一个 21s 的 captcha 请求会把同会话所有请求串行化，排后面的请求
    超过客户端超时被静默放弃——v0.3.2 要修的就是这类"架构冲突"。
    客户端主动断开时（超时）立即让锁，模拟 PHP ignore_user_abort=false。
    """
    async with SESSION_LOCK:
        return await handler(request)


async def index(request):
    return web.Response(content_type="text/html", text="""
    <html><body>
      <a href="/search?q=test">搜索</a>
      <a href="/user?id=1">用户</a>
      <a href="/ping?host=127.0.0.1">Ping</a>
      <a href="/fetch?url=http://example.com">抓取</a>
      <a href="/admin?action=list">管理后台（需登录）</a>
      <a href="/slow?mode=1">慢页面</a>
      <form method="get" action="/search"><input name="q"></form>
      <form method="post" action="/slow">
        <input type="hidden" name="step" value="1">
        <input type="password" name="password_new">
        <input type="password" name="password_conf">
        <input type="submit" name="Change" value="Change">
      </form>
    </body></html>""")


async def search(request):
    # 故意不做任何转义 → 反射型 XSS
    return web.Response(content_type="text/html",
                        text=f"<html><body>搜索结果: {request.query.get('q','')}</body></html>")


async def user(request):
    uid = request.query.get("id", "1")
    if "'" in uid and "1'='2" not in uid:
        return web.Response(status=500, content_type="text/html",
                            text="You have an error in your SQL syntax; check the manual "
                                 "that corresponds to your MySQL server version")
    if "1'='2" in uid:
        return web.Response(content_type="text/html", text="<html><body>无此用户</body></html>")
    return web.Response(content_type="text/html",
                        text="<html><body>用户: admin, 邮箱: admin@test.com, "
                             "注册时间: 2026-01-01, 积分: 100</body></html>")


async def ping(request):
    """命令注入：把用户输入直接拼进 shell 命令。

    注意：本项目在 Windows 上开发，本地靶场**模拟 Linux 的行为**，
    使得沉睡延迟（sleep）与算术求值（echo $((a*b))）两条检测路径都能被验证：
      - 含 `sleep N`    → 真实等待 N 秒（对应时间盲注）
      - 含 `echo $((a*b))` → 返回乘积结果（对应回显型）
    """
    host = request.query.get("host", "")

    m = re.search(r"sleep\s+(\d+)", host)
    if m:
        await asyncio.sleep(min(int(m.group(1)), 20))
        return web.Response(content_type="text/html",
                            text="<html><body><pre>done</pre></body></html>")

    m = re.search(r"echo\s+\$\(\(\s*(\d+)\s*\*\s*(\d+)\s*\)\)", host)
    if m:
        result = int(m.group(1)) * int(m.group(2))
        return web.Response(content_type="text/html",
                            text=f"<html><body><pre>{result}</pre></body></html>")

    # 命令未生效：原样回显（模拟拼接到 echo 后的原始输出）
    return web.Response(content_type="text/html",
                        text=f"<html><body><pre>{host}</pre></body></html>")


async def fetch_url(request):
    """SSRF：服务端请求用户可控 URL。"""
    import aiohttp
    target = request.query.get("url", "")
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(target, timeout=aiohttp.ClientTimeout(total=5)) as r:
                body = await r.text(errors="ignore")
                return web.Response(content_type="text/html",
                                    text=f"<html><body>{body[:500]}</body></html>")
    except Exception as e:
        return web.Response(content_type="text/html", text=f"error: {e}")


async def admin(request):
    """需要登录态 Cookie 才能扫到的页面（含注入点）。"""
    cookie = request.headers.get("Cookie", "")
    if SESSION_COOKIE not in cookie:
        return web.Response(status=302, headers={"Location": "/login"},
                            content_type="text/html", text="redirect")
    # 登录后才可见的 XSS 注入点
    return web.Response(content_type="text/html",
                        text=f"<html><body>管理后台，关键字: {request.query.get('action','')}"
                             f"<a href='/log?file=app.log'>日志</a></body></html>")


async def login(request):
    return web.Response(content_type="text/html",
                        text="<html><body>请登录</body></html>")


async def slow(request):
    """慢端点：在会话锁（由中间件持有）内沉睡 SLOW_SECS 秒。

    忠实模拟两类真实行为：
    1. DVWA captcha 页每次请求 21s（reCAPTCHA 远端校验超时）；
    2. PHP ignore_user_abort=false——客户端超时断开后服务端尽快收尾，
       不会继续占着会话锁（这里用 0.1s 粒度轮询连接状态实现）。

    ⚠️ 注意：会话锁由 session_lock_middleware 统一持有，处理器内
    **不可再获取**——asyncio.Lock 不可重入，会直接死锁。
    """
    for _ in range(SLOW_SECS * 10):
        if request.transport is None or request.transport.is_closing():
            break
        await asyncio.sleep(0.1)
    return web.Response(content_type="text/html",
                        text="<html><body>slow done</body></html>")


app = web.Application(middlewares=[session_lock_middleware])
app.router.add_get("/", index)
app.router.add_get("/search", search)
app.router.add_get("/user", user)
app.router.add_get("/ping", ping)
app.router.add_get("/fetch", fetch_url)
app.router.add_get("/admin", admin)
app.router.add_get("/login", login)
app.router.add_get("/slow", slow)
app.router.add_post("/slow", slow)

if __name__ == "__main__":
    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    web.run_app(app, host="127.0.0.1", port=8888, print=None)
