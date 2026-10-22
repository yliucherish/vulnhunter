"""DVWA 自动登录：获取会话 Cookie 并设置安全等级。

DVWA 的登录表单带 CSRF token（user_token），不能直接 POST 账号密码，
必须先 GET 登录页取出 token 再回传 —— 这也是写漏扫工具时常遇到的坑。

用法:
    python scripts/dvwa_login.py                # 返回 low 等级的 Cookie
    python scripts/dvwa_login.py --level medium
"""
import argparse
import asyncio
import re
import sys

import aiohttp

BASE = "http://127.0.0.1"
USER, PASSWORD = "admin", "password"


async def _token(html: str) -> str:
    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", html)
    return m.group(1) if m else ""


async def setup_database(session) -> None:
    """初始化 DVWA 数据库（等价于在 Setup 页点 Create/Reset）。

    setup.php 同样有 Anti-CSRF 校验（源码里 checkToken($_REQUEST['user_token'],
    $_SESSION['session_token'], 'setup.php')），所以必须先 GET 取 token 再回传。
    """
    async with session.get(f"{BASE}/setup.php") as r:
        token = await _token(await r.text())
    async with session.post(f"{BASE}/setup.php", data={
        "create_db": "Create / Reset Database",
        "user_token": token,
    }, allow_redirects=True) as r:
        await r.text()


async def login(level: str = "low") -> str:
    jar = aiohttp.CookieJar(unsafe=True)
    async with aiohttp.ClientSession(cookie_jar=jar) as s:
        async with s.get(f"{BASE}/login.php") as r:
            token = await _token(await r.text())

        async with s.post(f"{BASE}/login.php", data={
            "username": USER, "password": PASSWORD,
            "Login": "Login", "user_token": token,
        }, allow_redirects=True) as r:
            html = await r.text()

        if "setup.php" in str(r.url):
            print("[*] 检测到 DVWA 未初始化数据库，正在自动初始化...", file=sys.stderr)
            await setup_database(s)
            # 初始化后重新取 token 并登录
            async with s.post(f"{BASE}/login.php", data={
                "username": USER, "password": PASSWORD,
                "Login": "Login", "user_token": await _token(
                    await (await s.get(f"{BASE}/login.php")).text()),
            }, allow_redirects=True) as r:
                html = await r.text()

        if "Login failed" in html or "login.php" in str(r.url):
            print("[-] 登录失败：DVWA 可能未初始化数据库。"
                  "请浏览器打开 http://127.0.0.1/setup.php 点击 Create/Reset Database 再重试。",
                  file=sys.stderr)
            sys.exit(1)

        async with s.get(f"{BASE}/security.php") as r:
            html = await r.text()
            token = await _token(html)

        async with s.post(f"{BASE}/security.php", data={
            "security": level, "seclev_submit": "Submit", "user_token": token,
        }, allow_redirects=True) as r:
            await r.text()

    cookies = {c.key: c.value for c in jar}
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return cookie_str


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", default="low", choices=["low", "medium", "high"])
    args = ap.parse_args()
    print(asyncio.run(login(args.level)))
