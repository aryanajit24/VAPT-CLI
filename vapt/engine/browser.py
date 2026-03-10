
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rich.console import Console

console = Console()

_BROWSER_INSTANCE = None
_CONTEXT_INSTANCE = None


async def _ensure_browser():
    global _BROWSER_INSTANCE, _CONTEXT_INSTANCE
    if _BROWSER_INSTANCE is not None:
        return _BROWSER_INSTANCE, _CONTEXT_INSTANCE
    try:
        from playwright.async_api import async_playwright
        pw = await async_playwright().start()
        _BROWSER_INSTANCE = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        )
        _CONTEXT_INSTANCE = await _BROWSER_INSTANCE.new_context(
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1920, "height": 1080},
            java_script_enabled=True,
            ignore_https_errors=True,
        )
        return _BROWSER_INSTANCE, _CONTEXT_INSTANCE
    except Exception as exc:
        raise RuntimeError(
            "Playwright is not installed or browsers are missing. "
            "Run: pip install playwright && playwright install chromium"
        ) from exc


async def shutdown_browser():
    global _BROWSER_INSTANCE, _CONTEXT_INSTANCE
    if _CONTEXT_INSTANCE:
        await _CONTEXT_INSTANCE.close()
        _CONTEXT_INSTANCE = None
    if _BROWSER_INSTANCE:
        await _BROWSER_INSTANCE.close()
        _BROWSER_INSTANCE = None


class BrowserEngine:

    def __init__(self):
        self.network_log: list[dict[str, Any]] = []
        self.console_log: list[str] = []
        self.cookies: list[dict[str, Any]] = []
        self.local_storage: dict[str, str] = {}
        self.session_storage: dict[str, str] = {}

    def _run(self, coro):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return asyncio.run(coro)

    async def _new_page(self):
        _, ctx = await _ensure_browser()
        page = await ctx.new_page()
        self.network_log.clear()
        self.console_log.clear()

        page.on("request", lambda req: self.network_log.append({
            "type": "request",
            "method": req.method,
            "url": req.url,
            "headers": dict(req.headers),
        }))
        page.on("response", lambda resp: self.network_log.append({
            "type": "response",
            "url": resp.url,
            "status": resp.status,
            "headers": dict(resp.headers),
        }))
        page.on("console", lambda msg: self.console_log.append(msg.text))
        return page

    async def _render_async(self, url: str, wait_ms: int = 3000) -> dict[str, Any]:
        page = await self._new_page()
        try:
            resp = await page.goto(url, wait_until="networkidle", timeout=30000)
            await page.wait_for_timeout(wait_ms)

            html = await page.content()
            title = await page.title()
            current_url = page.url

            self.cookies = await page.context.cookies()

            self.local_storage = await page.evaluate(
                "() => { let d = {}; for (let i = 0; i < localStorage.length; i++) "
                "{ let k = localStorage.key(i); d[k] = localStorage.getItem(k); } return d; }"
            )
            self.session_storage = await page.evaluate(
                "() => { let d = {}; for (let i = 0; i < sessionStorage.length; i++) "
                "{ let k = sessionStorage.key(i); d[k] = sessionStorage.getItem(k); } return d; }"
            )

            return {
                "url": current_url,
                "status": resp.status if resp else 0,
                "title": title,
                "html": html,
                "html_length": len(html),
                "cookies": self.cookies,
                "local_storage": self.local_storage,
                "session_storage": self.session_storage,
                "network_requests": len(self.network_log),
                "console_messages": self.console_log[:50],
            }
        finally:
            await page.close()

    def render(self, url: str, wait_ms: int = 3000) -> dict[str, Any]:
        return self._run(self._render_async(url, wait_ms))

    async def _screenshot_async(self, url: str, output_path: str) -> str:
        page = await self._new_page()
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
            await page.wait_for_timeout(2000)
            await page.screenshot(path=output_path, full_page=True)
            return output_path
        finally:
            await page.close()

    def screenshot(self, url: str, output_path: str) -> str:
        return self._run(self._screenshot_async(url, output_path))

    async def _test_xss_async(
        self, url: str, param: str, payloads: list[str] | None = None
    ) -> list[dict[str, Any]]:
        if payloads is None:
            payloads = [
                '<img src=x onerror=alert("VAPT-XSS-1")>',
                '<svg/onload=alert("VAPT-XSS-2")>',
                '"><script>alert("VAPT-XSS-3")</script>',
                "javascript:alert('VAPT-XSS-4')",
                '<details open ontoggle=alert("VAPT-XSS-5")>',
            ]

        confirmed = []
        for payload in payloads:
            page = await self._new_page()
            try:
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}{param}={payload}"

                dialog_fired = []
                page.on("dialog", lambda d: (dialog_fired.append(d.message), d.dismiss()))

                await page.goto(test_url, wait_until="networkidle", timeout=15000)
                await page.wait_for_timeout(2000)

                if dialog_fired:
                    screenshot_path = f"/tmp/xss_confirmed_{len(confirmed)}.png"
                    await page.screenshot(path=screenshot_path)
                    confirmed.append({
                        "type": "xss",
                        "severity": "high",
                        "confidence": "confirmed",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "alert_text": dialog_fired[0],
                        "screenshot": screenshot_path,
                        "evidence": f"JavaScript alert() fired with text: {dialog_fired[0]}",
                    })
            except Exception:
                pass
            finally:
                await page.close()

        return confirmed

    def test_xss(
        self, url: str, param: str, payloads: list[str] | None = None
    ) -> list[dict[str, Any]]:
        return self._run(self._test_xss_async(url, param, payloads))

    async def _crawl_spa_async(
        self, url: str, max_pages: int = 50
    ) -> list[dict[str, Any]]:
        visited: set[str] = set()
        pages_data: list[dict[str, Any]] = []
        queue = [url]
        base_domain = urlparse(url).netloc

        while queue and len(visited) < max_pages:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            page = await self._new_page()
            try:
                resp = await page.goto(current, wait_until="networkidle", timeout=20000)
                await page.wait_for_timeout(1500)

                html = await page.content()
                title = await page.title()

                links = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(h => h.startsWith('http'))
                """)

                forms = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('form')).map(f => ({
                        action: f.action,
                        method: f.method,
                        inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                            name: i.name, type: i.type, value: i.value
                        }))
                    }))
                """)

                pages_data.append({
                    "url": current,
                    "status": resp.status if resp else 0,
                    "title": title,
                    "html_length": len(html),
                    "links_found": len(links),
                    "forms_found": len(forms),
                    "forms": forms,
                })

                for link in links:
                    parsed = urlparse(link)
                    if parsed.netloc == base_domain and link not in visited:
                        queue.append(link)
            except Exception:
                pass
            finally:
                await page.close()

        return pages_data

    def crawl_spa(self, url: str, max_pages: int = 50) -> list[dict[str, Any]]:
        return self._run(self._crawl_spa_async(url, max_pages))

    async def _extract_api_calls_async(self, url: str) -> list[dict[str, Any]]:
        page = await self._new_page()
        api_calls: list[dict[str, Any]] = []
        try:
            page.on("request", lambda req: api_calls.append({
                "method": req.method,
                "url": req.url,
                "resource_type": req.resource_type,
                "headers": dict(req.headers),
            }) if req.resource_type in ("xhr", "fetch") else None)

            await page.goto(url, wait_until="networkidle", timeout=30000)
            await page.wait_for_timeout(3000)

            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(2000)

            return api_calls
        finally:
            await page.close()

    def extract_api_calls(self, url: str) -> list[dict[str, Any]]:
        return self._run(self._extract_api_calls_async(url))

    async def _set_cookies_async(self, cookies: list[dict[str, Any]]) -> None:
        _, ctx = await _ensure_browser()
        await ctx.add_cookies(cookies)

    def set_cookies(self, cookies: list[dict[str, Any]]) -> None:
        self._run(self._set_cookies_async(cookies))

    async def _set_auth_headers_async(self, headers: dict[str, str]) -> None:
        _, ctx = await _ensure_browser()
        await ctx.set_extra_http_headers(headers)

    def set_auth_headers(self, headers: dict[str, str]) -> None:
        self._run(self._set_auth_headers_async(headers))

    async def _execute_js_async(self, url: str, script: str) -> Any:
        page = await self._new_page()
        try:
            await page.goto(url, wait_until="networkidle", timeout=20000)
            result = await page.evaluate(script)
            return result
        finally:
            await page.close()

    def execute_js(self, url: str, script: str) -> Any:
        return self._run(self._execute_js_async(url, script))

    async def _test_clickjacking_async(self, url: str) -> dict[str, Any]:
        page = await self._new_page()
        try:
            resp = await page.goto(url, wait_until="networkidle", timeout=20000)
            headers = dict(resp.headers) if resp else {}

            x_frame = headers.get("x-frame-options", "").upper()
            csp = headers.get("content-security-policy", "")

            frameable = True
            if x_frame in ("DENY", "SAMEORIGIN"):
                frameable = False
            if "frame-ancestors" in csp:
                fa = re.search(r"frame-ancestors\s+([^;]+)", csp)
                if fa and ("'none'" in fa.group(1) or "'self'" in fa.group(1)):
                    frameable = False

            result = {
                "url": url,
                "frameable": frameable,
                "x_frame_options": x_frame or "MISSING",
                "csp_frame_ancestors": "present" if "frame-ancestors" in csp else "MISSING",
            }

            if frameable:
                result["severity"] = "medium"
                result["type"] = "clickjacking"
                result["title"] = f"Clickjacking: {urlparse(url).netloc}"
                result["evidence"] = (
                    f"No X-Frame-Options or CSP frame-ancestors header. "
                    f"Page can be embedded in an attacker-controlled iframe."
                )
            return result
        finally:
            await page.close()

    def test_clickjacking(self, url: str) -> dict[str, Any]:
        return self._run(self._test_clickjacking_async(url))
