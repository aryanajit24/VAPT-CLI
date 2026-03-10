
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse, urlunparse


@dataclass
class CrawlForm:

    url: str
    action: str
    method: str
    inputs: list[dict] = field(default_factory=list)
    id: str = ""
    name: str = ""


@dataclass
class CrawlEndpoint:

    url: str
    method: str = "GET"
    source: str = ""
    params: list[str] = field(default_factory=list)


@dataclass
class CrawlResult:

    target: str = ""
    pages_crawled: int = 0
    urls: list[str] = field(default_factory=list)
    forms: list[CrawlForm] = field(default_factory=list)
    endpoints: list[CrawlEndpoint] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    elapsed: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "pages_crawled": self.pages_crawled,
            "unique_urls": len(set(self.urls)),
            "forms_found": len(self.forms),
            "endpoints_found": len(self.endpoints),
            "js_files": len(self.js_files),
            "technologies": self.technologies,
            "elapsed_seconds": round(self.elapsed, 2),
        }


_ENDPOINT_PATTERNS = [
    re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*['"`]([^'"`\s]+)['"`]"""),
    re.compile(r"""(?:url|endpoint|api|href|action|src)\s*[:=]\s*['"`]([^'"`\s]{5,})['"`]"""),
    re.compile(r"""/api/[a-zA-Z0-9_/\-]+"""),
    re.compile(r"""/v[0-9]+/[a-zA-Z0-9_/\-]+"""),
    re.compile(r"""/graphql\b"""),
    re.compile(r"""/rest/[a-zA-Z0-9_/\-]+"""),
]

_TECH_SIGNATURES = {
    "React": [r"react", r"__NEXT_DATA__", r"_reactRoot"],
    "Angular": [r"ng-version", r"ng-app", r"angular\."],
    "Vue.js": [r"__vue__", r"Vue\."],
    "jQuery": [r"jquery", r"\$\.ajax"],
    "Next.js": [r"__NEXT_DATA__", r"_next/static"],
    "Nuxt.js": [r"__NUXT__", r"_nuxt/"],
    "WordPress": [r"wp-content", r"wp-includes"],
    "Laravel": [r"laravel", r"csrf-token"],
    "Django": [r"csrfmiddlewaretoken", r"django"],
    "Express": [r"X-Powered-By.*Express"],
    "Spring": [r"Whitelabel Error", r"actuator"],
    "ASP.NET": [r"__VIEWSTATE", r"aspnet"],
    "GraphQL": [r"graphql", r"__schema"],
    "Firebase": [r"firebaseapp", r"firebaseio"],
    "AWS": [r"amazonaws\.com", r"aws-sdk"],
}


class Crawler:

    def __init__(
        self,
        target: str,
        *,
        max_depth: int = 3,
        max_pages: int = 100,
        headless: bool = True,
        timeout: int = 30,
        delay: float = 0.5,
        respect_robots: bool = True,
        allowed_domains: Optional[list[str]] = None,
        excluded_extensions: Optional[list[str]] = None,
        custom_headers: Optional[dict] = None,
        cookies: Optional[list[dict]] = None,
        auth_state: Optional[str] = None,
    ):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.headless = headless
        self.timeout = timeout * 1000
        self.delay = delay
        self.respect_robots = respect_robots
        self.custom_headers = custom_headers or {}
        self.cookies = cookies or []
        self.auth_state = auth_state

        parsed = urlparse(self.target)
        self.base_domain = parsed.netloc
        self.allowed_domains = set(allowed_domains or [self.base_domain])
        self.excluded_extensions = set(
            excluded_extensions
            or [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2",
                ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".pdf", ".zip", ".tar", ".gz"]
        )

        self.visited: set[str] = set()
        self.queue: list[tuple[str, int]] = [(self.target, 0)]
        self.result = CrawlResult(target=self.target)
        self._disallowed: set[str] = set()

    def _is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc not in self.allowed_domains:
            return False
        path_lower = parsed.path.lower()
        for ext in self.excluded_extensions:
            if path_lower.endswith(ext):
                return False
        if any(d in parsed.path for d in self._disallowed):
            return False
        return True

    def _normalize_url(self, url: str, base: str) -> Optional[str]:
        if not url or url.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            return None
        absolute = urljoin(base, url)
        parsed = urlparse(absolute)
        normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        return normalized

    async def _fetch_robots(self, page) -> None:
        if not self.respect_robots:
            return
        try:
            robots_url = f"{urlparse(self.target).scheme}://{self.base_domain}/robots.txt"
            resp = await page.goto(robots_url, timeout=5000)
            if resp and resp.ok:
                text = await resp.text()
                for line in text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            self._disallowed.add(path)
        except Exception:
            pass

    async def _extract_links(self, page) -> list[str]:
        links = set()
        try:
            hrefs = await page.eval_on_selector_all(
                "a[href]", "elements => elements.map(e => e.getAttribute('href'))"
            )
            for href in hrefs:
                normalized = self._normalize_url(href, page.url)
                if normalized and self._is_allowed(normalized):
                    links.add(normalized)
        except Exception:
            pass
        return list(links)

    async def _extract_forms(self, page) -> list[CrawlForm]:
        forms = []
        try:
            form_data = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('form')).map(form => ({
                    action: form.action || '',
                    method: (form.method || 'GET').toUpperCase(),
                    id: form.id || '',
                    name: form.name || '',
                    inputs: Array.from(form.querySelectorAll('input, textarea, select')).map(inp => ({
                        name: inp.name || '',
                        type: inp.type || 'text',
                        value: inp.value || '',
                        required: inp.required || false,
                        placeholder: inp.placeholder || '',
                    }))
                }));
            }""")
            for fd in form_data:
                action = self._normalize_url(fd["action"], page.url) or page.url
                forms.append(CrawlForm(
                    url=page.url,
                    action=action,
                    method=fd["method"],
                    inputs=fd["inputs"],
                    id=fd.get("id", ""),
                    name=fd.get("name", ""),
                ))
        except Exception:
            pass
        return forms

    async def _extract_js_files(self, page) -> list[str]:
        js_files = set()
        try:
            srcs = await page.eval_on_selector_all(
                "script[src]", "elements => elements.map(e => e.src)"
            )
            for src in srcs:
                if src and not src.startswith("data:"):
                    js_files.add(src)
        except Exception:
            pass
        return list(js_files)

    async def _extract_endpoints_from_js(self, page, js_url: str) -> list[CrawlEndpoint]:
        endpoints = []
        try:
            resp = await page.request.get(js_url, timeout=10000)
            if resp.ok:
                text = await resp.text()
                seen = set()
                for pattern in _ENDPOINT_PATTERNS:
                    for match in pattern.finditer(text):
                        ep = match.group(1) if match.lastindex else match.group(0)
                        if ep not in seen and len(ep) > 2:
                            seen.add(ep)
                            endpoints.append(CrawlEndpoint(url=ep, source=js_url))
        except Exception:
            pass
        return endpoints

    async def _detect_technologies(self, page) -> list[str]:
        techs = []
        try:
            html = await page.content()
            headers_raw = ""
            resp = await page.request.get(page.url, timeout=5000)
            if resp:
                headers_raw = str(dict(resp.headers))

            combined = html + headers_raw
            for tech, patterns in _TECH_SIGNATURES.items():
                for pat in patterns:
                    if re.search(pat, combined, re.IGNORECASE):
                        techs.append(tech)
                        break
        except Exception:
            pass
        return techs

    async def _crawl_page(self, page, url: str, depth: int) -> None:
        if url in self.visited or len(self.visited) >= self.max_pages:
            return
        if depth > self.max_depth:
            return

        self.visited.add(url)

        try:
            response = await page.goto(url, wait_until="networkidle", timeout=self.timeout)
            if not response:
                return

            await page.wait_for_timeout(int(self.delay * 1000))

            self.result.urls.append(url)
            self.result.pages_crawled += 1

            links = await self._extract_links(page)
            forms = await self._extract_forms(page)
            js_files = await self._extract_js_files(page)

            self.result.forms.extend(forms)

            for js_url in js_files:
                if js_url not in self.result.js_files:
                    self.result.js_files.append(js_url)
                    endpoints = await self._extract_endpoints_from_js(page, js_url)
                    self.result.endpoints.extend(endpoints)

            if self.result.pages_crawled == 1:
                techs = await self._detect_technologies(page)
                self.result.technologies = techs

            for link in links:
                if link not in self.visited and len(self.visited) < self.max_pages:
                    self.queue.append((link, depth + 1))

        except Exception as exc:
            self.result.errors.append(f"{url}: {exc}")

    async def crawl(
        self,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> CrawlResult:
        start_time = time.time()

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.result.errors.append("Playwright not installed: pip install playwright && playwright install")
            return self.result

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(
                extra_http_headers=self.custom_headers,
                ignore_https_errors=True,
            )

            if self.cookies:
                await context.add_cookies(self.cookies)

            if self.auth_state:
                try:
                    import json
                    from pathlib import Path
                    state = json.loads(Path(self.auth_state).read_text())
                    await context.add_cookies(state.get("cookies", []))
                except Exception:
                    pass

            page = await context.new_page()

            if self.respect_robots:
                await self._fetch_robots(page)

            while self.queue and len(self.visited) < self.max_pages:
                url, depth = self.queue.pop(0)
                if url in self.visited:
                    continue

                if progress_callback:
                    progress_callback(len(self.visited) + 1, self.max_pages, url)

                await self._crawl_page(page, url, depth)

            try:
                cookies = await context.cookies()
                self.result.cookies = [
                    {"name": c["name"], "domain": c["domain"], "path": c["path"],
                     "secure": c["secure"], "httpOnly": c["httpOnly"]}
                    for c in cookies
                ]
            except Exception:
                pass

            await browser.close()

        self.result.elapsed = time.time() - start_time
        return self.result

    def run(
        self,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> CrawlResult:
        import asyncio
        return asyncio.run(self.crawl(progress_callback))


class CrawlerLight:

    def __init__(
        self,
        target: str,
        *,
        max_depth: int = 3,
        max_pages: int = 50,
        timeout: int = 10,
        delay: float = 0.5,
        headers: Optional[dict] = None,
        verify_ssl: bool = False,
    ):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.delay = delay
        self.headers = headers or {"User-Agent": "VAPT-CLI Crawler/9.0"}
        self.verify_ssl = verify_ssl

        parsed = urlparse(self.target)
        self.base_domain = parsed.netloc
        self.visited: set[str] = set()
        self.result = CrawlResult(target=self.target)

    def run(
        self,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> CrawlResult:
        import requests
        from bs4 import BeautifulSoup

        start_time = time.time()
        queue: list[tuple[str, int]] = [(self.target, 0)]
        session = requests.Session()
        session.headers.update(self.headers)
        session.verify = self.verify_ssl

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.pop(0)
            if url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(url)

            if progress_callback:
                progress_callback(len(self.visited), self.max_pages, url)

            try:
                resp = session.get(url, timeout=self.timeout, allow_redirects=True)
                self.result.urls.append(url)
                self.result.pages_crawled += 1

                if "text/html" not in resp.headers.get("content-type", ""):
                    continue

                soup = BeautifulSoup(resp.text, "lxml")

                for a in soup.find_all("a", href=True):
                    href = urljoin(url, a["href"])
                    parsed = urlparse(href)
                    if parsed.netloc == self.base_domain and href not in self.visited:
                        clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
                        queue.append((clean, depth + 1))

                for script in soup.find_all("script", src=True):
                    src = urljoin(url, script["src"])
                    if src not in self.result.js_files:
                        self.result.js_files.append(src)

                for form in soup.find_all("form"):
                    action = urljoin(url, form.get("action", ""))
                    method = (form.get("method") or "GET").upper()
                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        inputs.append({
                            "name": inp.get("name", ""),
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        })
                    self.result.forms.append(CrawlForm(url=url, action=action, method=method, inputs=inputs))

                if self.delay > 0:
                    time.sleep(self.delay)

            except Exception as exc:
                self.result.errors.append(f"{url}: {exc}")

        self.result.elapsed = time.time() - start_time
        return self.result
