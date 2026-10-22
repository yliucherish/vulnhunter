"""异步爬虫：发现页面中的注入点（URL 参数与表单）。"""
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from .detectors.base import InjectionPoint


class Crawler:
    # 会产生副作用的路径关键字：登出 / 删除 / 重置 / 密码修改 / CSRF 换密码页面 /
    # 安全设置页（DVWA 的 security.php 可通过 ?phpids=on 打开 PHPIDS，且该状态
    # 存于 session——扫描器一旦访问过，同一会话后续所有攻击 payload 都会被
    # WAF 静默过滤，表现为"0 检出但页面一切正常"，极难排查）等
    DANGEROUS_KEYWORDS = (
        "logout", "logoff", "signout", "sign_out", "delete", "destroy",
        "reset_password", "drop_database",
        "csrf", "password_new", "password_conf", "passwd",
        "security.php", "phpids", "setup.php",
    )

    def __init__(self, base_url: str, max_depth: int = 2, max_pages: int = 50):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: set[str] = set()

    def _same_host(self, url: str) -> bool:
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def _is_dangerous(self, url: str) -> bool:
        """过滤会产生副作用的 URL。

        ⚠️ 踩坑：爬虫一旦点到 logout.php 之类的地址，登录会话立刻失效，
        后续所有请求都被重定向回登录页 —— 表面看就是"扫描器一个漏洞都扫不出来"。
        真实漏扫工具同样必须避免触发登出、删除、转账等状态变更操作。
        """
        u = url.lower()
        return any(k in u for k in self.DANGEROUS_KEYWORDS)

    def _form_is_dangerous(self, action: str, fields: dict) -> bool:
        """表单是否应整个跳过：**同时**检查 action URL 与字段名。

        ⚠️ 踩坑记录⑥（v0.3.2）：初版只检查 action URL，漏掉了"URL 无特征、
        字段名暴露语义"的情况。DVWA captcha 页（URL: /vulnerabilities/captcha/）
        内嵌两步改密表单，字段为 step/password_new/password_conf/Change：
        - 爬虫照常提取出 5 个注入点，检测器每次 POST 都触发 reCAPTCHA
          远端校验（容器无外网 → 每次固定 21s 超时才返回）；
        - PHP 对同一会话加排他锁，扫描器全程单会话 → 所有请求被 captcha
          请求串行化，排在锁后的请求超过 45s 客户端总超时被静默放弃；
        - 一次 high 全站扫描因此 0 检出，而定向复测（绕过该页）稳定命中。
        修正：危险关键字必须覆盖表单字段名——**看到 password_new 字段，
        就该知道这是改密表单，扫不得也碰不得**（真实扫描器同样不提交
        改密/注销/删除类表单：既有状态风险，也拿不到有效响应）。
        """
        if self._is_dangerous(action):
            return True
        for name in fields:
            low = name.lower()
            if any(k in low for k in self.DANGEROUS_KEYWORDS):
                return True
        return False

    def _extract(self, url: str, html: str):
        """从页面提取链接与注入点。"""
        soup = BeautifulSoup(html, "html.parser")
        links, points = [], []

        # URL 查询参数 → GET 注入点
        qs = parse_qs(urlparse(url).query)
        for param in qs:
            points.append(InjectionPoint(url=url.split("?")[0], param=param, method="GET"))

        # 表单 → GET/POST 注入点
        # ⚠️ 踩坑：DVWA 等站点的表单常写成 action="#"，直接 urljoin 会把 "#"
        # 当成 fragment 拼接，导致后续请求参数丢失（漏报）。
        # 因此 action 为空或 "#" 时必须回退到当前页面 URL，并去掉 fragment。
        for form in soup.find_all("form"):
            raw_action = (form.get("action") or "").strip()
            if not raw_action or raw_action in ("#", "?"):
                action = url
            else:
                action = urljoin(url, raw_action)
            action = action.split("#")[0]
            if not self._same_host(action):
                continue
            method = (form.get("method") or "get").upper()
            fields = {}
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name")
                if name:
                    fields[name] = inp.get("value", "1") or "1"

            # <select> 下拉框也是注入点载体（DVWA medium 的 SQLi 就是 select）。
            # 取第一个非空 option 作为默认值提交，否则表单会被后端判为参数缺失。
            for sel in form.find_all("select"):
                name = sel.get("name")
                if not name:
                    continue
                opts = [o.get("value") for o in sel.find_all("option") if o.get("value")]
                fields[name] = opts[0] if opts else "1"

            # 危险表单整体跳过：URL 与**字段名**双重判定（踩坑记录⑥，
            # DVWA captcha 改密表单的 URL 毫无特征，但字段名暴露语义）。
            if self._form_is_dangerous(action, fields):
                continue
            for name in fields:
                others = {k: v for k, v in fields.items() if k != name}
                points.append(InjectionPoint(url=action, param=name, method=method, data=others))

        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"]).split("#")[0]
            if self._same_host(link) and not self._is_dangerous(link):
                links.append(link)
        return links, points

    async def crawl(self, session):
        """BFS 爬取，返回 (页面数, 注入点列表)。"""
        queue = deque([(self.base_url, 0)])
        points: list[InjectionPoint] = []
        pages = 0

        while queue and pages < self.max_pages:
            url, depth = queue.popleft()
            if url in self.visited or depth > self.max_depth:
                continue
            self.visited.add(url)
            try:
                async with session.get(url, timeout=10) as r:
                    if "text/html" not in r.headers.get("Content-Type", ""):
                        continue
                    html = await r.text(errors="ignore")
            except Exception:
                continue
            pages += 1
            links, pts = self._extract(url, html)
            points.extend(pts)
            if depth < self.max_depth:
                for link in links:
                    if link not in self.visited:
                        queue.append((link, depth + 1))

        # 按 (url, param, method) 去重
        seen, unique = set(), []
        for p in points:
            key = (p.url, p.param, p.method)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return pages, unique
