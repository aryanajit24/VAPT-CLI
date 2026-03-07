"""Deep JavaScript analysis for API endpoints, secrets, and DOM sinks."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

from vapt.utils.helpers import sanitize_target


API_CALL_PATTERNS = [
    re.compile(r"""fetch\s*\(\s*['"`]([^'"`\s]+?)['"`]""", re.IGNORECASE),
    re.compile(r"""fetch\s*\(\s*`([^`]+?)`""", re.IGNORECASE),
    re.compile(r"""axios\s*\.\s*(?:get|post|put|patch|delete|options|head)\s*\(\s*['"`]([^'"`\s]+?)['"`]""", re.IGNORECASE),
    re.compile(r"""axios\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+?)['"`]""", re.IGNORECASE | re.DOTALL),
    re.compile(r"""\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`\s]+?)['"`]""", re.IGNORECASE),
    re.compile(r"""\$\s*\.\s*(?:ajax|get|post|put|getJSON)\s*\(\s*['"`]([^'"`\s]+?)['"`]""", re.IGNORECASE),
    re.compile(r"""url\s*:\s*['"`](\/[^'"`\s]+?)['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](\/api\/[^'"`\s]{3,100})['"`]"""),
    re.compile(r"""['"`](\/v[1-9]\/[^'"`\s]{3,100})['"`]"""),
    re.compile(r"""['"`](\/graphql[^'"`\s]*)['"`]"""),
    re.compile(r"""`(/api/[^`\s]{3,100})`"""),
    re.compile(r"""`(/v[1-9]/[^`\s]{3,100})`"""),
    re.compile(r"""(?:superagent|request)\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]+?)['"`]""", re.IGNORECASE),
]

ROUTE_PATTERNS = [
    re.compile(r"""<Route[^>]*path\s*=\s*['"`]([^'"`]+?)['"`]""", re.IGNORECASE),
    re.compile(r"""path\s*:\s*['"`](\/[^'"`]+?)['"`]"""),
    re.compile(r"""(?:routes|route)\s*:\s*\[[\s\S]*?path\s*:\s*['"`]([^'"`]+?)['"`]""", re.IGNORECASE),
    re.compile(r"""(?:path|redirectTo)\s*:\s*['"`]([^'"`]+?)['"`]"""),
    re.compile(r"""(?:href|to|push|replace)\s*[=(]\s*['"`](\/[^'"`]+?)['"`]"""),
    re.compile(r"""(?:navigate|redirect|router\.push|router\.replace|history\.push)\s*\(\s*['"`]([^'"`]+?)['"`]""", re.IGNORECASE),
]

GRAPHQL_PATTERNS = [
    re.compile(r"""(?:query|mutation|subscription)\s+(\w+)[\s\(]"""),
    re.compile(r"""gql\s*`\s*(query|mutation|subscription)\s+(\w+)"""),
    re.compile(r"""fragment\s+(\w+)\s+on\s+(\w+)"""),
    re.compile(r"""__typename\s*[=:]\s*['"`](\w+)['"`]"""),
]

CONFIG_PATTERNS = [
    re.compile(r"""process\.env\.(\w+)"""),
    re.compile(r"""NEXT_PUBLIC_(\w+)"""),
    re.compile(r"""REACT_APP_(\w+)"""),
    re.compile(r"""VUE_APP_(\w+)"""),
    re.compile(r"""(?:baseURL|baseUrl|apiUrl|apiBase|API_URL|API_BASE)\s*[:=]\s*['"`]([^'"`]+?)['"`]"""),
    re.compile(r"""(?:environment|config|settings)\s*[:=]\s*\{([^}]{10,500})\}""", re.DOTALL),
]

WEBSOCKET_PATTERNS = [
    re.compile(r"""new\s+WebSocket\s*\(\s*['"`]([^'"`]+?)['"`]"""),
    re.compile(r"""(?:ws|wss):\/\/[^'"`\s]+"""),
    re.compile(r"""socket\.(?:connect|io)\s*\(\s*['"`]([^'"`]+?)['"`]"""),
]

CHUNK_PATTERNS = [
    re.compile(r"""(?:__webpack_require__|webpackChunk)\w*\s*\.\s*push"""),
    re.compile(r"""['"`]((?:static/|_next/|chunks?/|assets?/)[^'"`]*?\.(?:js|mjs))['"`]"""),
    re.compile(r"""import\s*\(\s*['"`]([^'"`]+?)['"`]\s*\)"""),
    re.compile(r"""(?:chunkMapping|chunks?)\s*[:=]\s*\{([^}]+)\}"""),
    re.compile(r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+)"""),
]

INTERNAL_URL_PATTERNS = [
    re.compile(r"""https?://(?:internal|staging|dev|test|uat|qa|sandbox|preview|canary|admin|debug|local)[.-][^\s'"`<>]{5,100}""", re.IGNORECASE),
    re.compile(r"""https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:\d/]*"""),
    re.compile(r"""https?://localhost[:\d/]*"""),
    re.compile(r"""https?://[^'"`\s]*\.(?:internal|local|corp|intra|private)[.'"`\s/]""", re.IGNORECASE),
]

PARAM_PATTERNS = [
    re.compile(r"""(?:params|data|body|payload|query)\s*[:=]\s*\{([^}]{5,500})\}""", re.DOTALL),
    re.compile(r"""URLSearchParams\s*\(\s*\{([^}]+)\}"""),
    re.compile(r"""formData\.append\s*\(\s*['"`](\w+)['"`]"""),
    re.compile(r"""[?&](\w+)=(?:\$\{|['"`])"""),
]


class DeepJSRecon:
    """
    Deep JavaScript reconnaissance engine.
    
    Goes beyond simple secret scanning to map the entire attack surface
    from JavaScript source code.
    """

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: int = 15,
        max_js_files: int = 100,
        max_chunks: int = 50,
        mine_source_maps: bool = True,
    ) -> None:
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
        self.timeout = timeout
        self.max_js_files = max_js_files
        self.max_chunks = max_chunks
        self.mine_source_maps = mine_source_maps
        
        self.js_files: list[dict] = []
        self.api_endpoints: list[dict] = []
        self.client_routes: list[str] = []
        self.graphql_operations: list[dict] = []
        self.websocket_urls: list[str] = []
        self.internal_urls: list[str] = []
        self.config_objects: list[dict] = []
        self.hidden_params: list[dict] = []
        self.source_maps: list[dict] = []
        self.webpack_chunks: list[str] = []
        self.findings: list[dict] = []

    def run(self, target: str) -> dict[str, Any]:
        """
        Run deep JS reconnaissance.
        
        Returns comprehensive recon data including ALL API endpoints,
        routes, GraphQL operations, configs, and findings.
        """
        target = sanitize_target(target)
        started = time.time()
        
        js_urls = self._discover_js_files(target)
        
        for js_url in js_urls[:self.max_js_files]:
            self._analyze_js_file(js_url, target)
        
        self._mine_webpack_chunks(target)
        
        if self.mine_source_maps:
            self._check_source_maps()
        
        self._deduplicate_endpoints(target)
        
        self._generate_findings(target)
        
        elapsed = time.time() - started
        
        return {
            "module": "Deep JS Recon",
            "target": target,
            "duration_sec": round(elapsed, 2),
            "js_files_analyzed": len(self.js_files),
            "api_endpoints": self.api_endpoints,
            "client_routes": self.client_routes,
            "graphql_operations": self.graphql_operations,
            "websocket_urls": self.websocket_urls,
            "internal_urls": self.internal_urls,
            "config_objects": self.config_objects,
            "hidden_params": self.hidden_params,
            "source_maps": self.source_maps,
            "webpack_chunks_loaded": len(self.webpack_chunks),
            "findings": self.findings,
        }

    def _discover_js_files(self, target: str) -> list[str]:
        """Discover all JavaScript files from the target."""
        js_urls: set[str] = set()
        
        try:
            resp = self.session.get(target, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            
            for script in soup.find_all("script", src=True):
                src = script["src"]
                full_url = urljoin(target, src)
                if full_url.endswith((".js", ".mjs", ".jsx", ".ts")) or "/chunk" in full_url:
                    js_urls.add(full_url)
            
            # not fetched, analyzed in-place
            for script in soup.find_all("script", src=False):
                if script.string and len(script.string) > 100:
                    self.js_files.append({
                        "url": f"{target}#inline",
                        "content": script.string,
                        "size": len(script.string),
                        "type": "inline",
                    })
            
            for link in soup.find_all("link", rel=True):
                rel = " ".join(link.get("rel", []))
                href = link.get("href", "")
                if ("preload" in rel or "prefetch" in rel) and href.endswith((".js", ".mjs")):
                    js_urls.add(urljoin(target, href))
            
            html_text = resp.text
            js_in_html = re.findall(r'["\']((?:https?://[^"\']*|/[^"\']*?)\.(?:js|mjs)(?:\?[^"\']*)?)["\']', html_text)
            for js_ref in js_in_html:
                full_url = urljoin(target, js_ref)
                if urlparse(full_url).netloc == urlparse(target).netloc or "cdn" in urlparse(full_url).netloc.lower():
                    js_urls.add(full_url)
                    
        except RequestException:
            pass
        
        common_paths = [
            "/main.js", "/app.js", "/bundle.js", "/vendor.js",
            "/runtime.js", "/polyfill.js", "/chunk.js",
            "/_next/static/chunks/main.js",
            "/_next/static/chunks/webpack.js",
            "/_next/static/chunks/framework.js",
            "/static/js/main.js", "/static/js/bundle.js",
            "/assets/js/app.js", "/dist/main.js",
            "/build/static/js/main.js",
        ]
        
        for path in common_paths:
            url = urljoin(target, path)
            try:
                resp = self.session.head(url, timeout=5, verify=False)
                if resp.status_code == 200 and "javascript" in resp.headers.get("Content-Type", "").lower():
                    js_urls.add(url)
            except RequestException:
                pass
        
        return list(js_urls)

    def _analyze_js_file(self, js_url: str, target: str) -> None:
        """Fetch and deeply analyze a JavaScript file."""
        try:
            resp = self.session.get(js_url, timeout=self.timeout, verify=False)
            if resp.status_code != 200:
                return
            
            content = resp.text
            if not content or len(content) < 50:
                return
            
            self.js_files.append({
                "url": js_url,
                "size": len(content),
                "type": "external",
            })
            
            self._extract_api_endpoints(content, js_url, target)
            
            self._extract_routes(content)
            
            self._extract_graphql(content, js_url)
            
            self._extract_websockets(content)
            
            self._extract_internal_urls(content)
            
            self._extract_configs(content, js_url)
            
            self._extract_params(content, js_url)
            
            self._extract_chunk_urls(content, js_url, target)
            
            source_map_match = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', content)
            if source_map_match:
                map_url = urljoin(js_url, source_map_match.group(1))
                self.source_maps.append({
                    "js_url": js_url,
                    "map_url": map_url,
                    "status": "discovered",
                })
                
        except RequestException:
            pass

    def _extract_api_endpoints(self, content: str, source: str, target: str) -> None:
        """Extract all API endpoint references from JS content."""
        target_host = urlparse(target).netloc
        
        for pattern in API_CALL_PATTERNS:
            for match in pattern.finditer(content):
                endpoint = match.group(1) if match.lastindex else match.group(0)
                endpoint = endpoint.strip()
                
                if len(endpoint) < 3 or len(endpoint) > 200:
                    continue
                if endpoint.startswith(("#", "data:", "blob:", "javascript:")):
                    continue
                if endpoint.endswith((".css", ".png", ".jpg", ".svg", ".gif", ".ico", ".woff", ".ttf")):
                    continue
                
                if endpoint.startswith("/"):
                    full_url = urljoin(target, endpoint)
                elif endpoint.startswith("http"):
                    full_url = endpoint
                else:
                    continue
                
                context_start = max(0, match.start() - 100)
                context = content[context_start:match.start() + len(endpoint) + 10]
                method = "GET"
                if re.search(r'\.post\s*\(|method.*["\']POST|POST', context, re.IGNORECASE):
                    method = "POST"
                elif re.search(r'\.put\s*\(|method.*["\']PUT|PUT', context, re.IGNORECASE):
                    method = "PUT"
                elif re.search(r'\.patch\s*\(|method.*["\']PATCH|PATCH', context, re.IGNORECASE):
                    method = "PATCH"
                elif re.search(r'\.delete\s*\(|method.*["\']DELETE|DELETE', context, re.IGNORECASE):
                    method = "DELETE"
                
                requires_auth = bool(re.search(
                    r'auth|bearer|token|session|cookie|credential', context, re.IGNORECASE
                ))
                
                self.api_endpoints.append({
                    "endpoint": endpoint,
                    "full_url": full_url,
                    "method": method,
                    "source_file": source,
                    "requires_auth": requires_auth,
                    "context": context.strip()[:200],
                })

    def _extract_routes(self, content: str) -> None:
        """Extract client-side routes from JS content."""
        for pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                route = match.group(1)
                if route and route.startswith("/") and len(route) > 1:
                    if route not in self.client_routes:
                        self.client_routes.append(route)

    def _extract_graphql(self, content: str, source: str) -> None:
        """Extract GraphQL operations from JS content."""
        for pattern in GRAPHQL_PATTERNS:
            for match in pattern.finditer(content):
                groups = match.groups()
                if len(groups) >= 2:
                    op_type = groups[0]
                    op_name = groups[1]
                elif len(groups) == 1:
                    op_name = groups[0]
                    op_type = "query"
                else:
                    continue
                
                start = match.start()
                end = min(len(content), start + 500)
                context = content[start:end]
                
                self.graphql_operations.append({
                    "type": op_type,
                    "name": op_name,
                    "source_file": source,
                    "context": context[:300],
                })

    def _extract_websockets(self, content: str) -> None:
        """Extract WebSocket URLs from JS content."""
        for pattern in WEBSOCKET_PATTERNS:
            for match in pattern.finditer(content):
                ws_url = match.group(1) if match.lastindex else match.group(0)
                if ws_url and ws_url not in self.websocket_urls:
                    self.websocket_urls.append(ws_url)

    def _extract_internal_urls(self, content: str) -> None:
        """Extract internal/staging/dev URLs from JS content."""
        for pattern in INTERNAL_URL_PATTERNS:
            for match in pattern.finditer(content):
                url = match.group(0).strip("'\"` <>")
                if url and url not in self.internal_urls:
                    self.internal_urls.append(url)

    def _extract_configs(self, content: str, source: str) -> None:
        """Extract configuration objects from JS content."""
        for pattern in CONFIG_PATTERNS:
            for match in pattern.finditer(content):
                config_text = match.group(1) if match.lastindex else match.group(0)
                self.config_objects.append({
                    "source_file": source,
                    "config": config_text[:500],
                    "type": "environment" if "env" in match.group(0).lower() else "config",
                })

    def _extract_params(self, content: str, source: str) -> None:
        """Extract hidden/undocumented parameters from JS content."""
        for pattern in PARAM_PATTERNS:
            for match in pattern.finditer(content):
                param_text = match.group(1) if match.lastindex else match.group(0)
                

                param_names = re.findall(r'["\'](\w+)["\']', param_text)
                if not param_names:
                    param_names = re.findall(r'(\w+)\s*:', param_text)
                
                for param in param_names:
                    if len(param) > 2 and param not in (
                        "type", "data", "url", "method", "headers",
                        "body", "params", "query", "true", "false", "null",
                        "undefined", "function", "return", "const", "let", "var",
                    ):
                        self.hidden_params.append({
                            "param": param,
                            "source_file": source,
                            "context": param_text[:200],
                        })

    def _extract_chunk_urls(self, content: str, source: str, target: str) -> None:
        """Extract webpack chunk URLs for additional mining."""
        for pattern in CHUNK_PATTERNS:
            for match in pattern.finditer(content):
                text = match.group(1) if match.lastindex else match.group(0)
                
                js_refs = re.findall(r'["\']((?:[^"\']*?)\.(?:js|mjs)(?:\?[^"\']*)?)["\']', text)
                for ref in js_refs:
                    chunk_url = urljoin(target if not ref.startswith("http") else "", ref)
                    if chunk_url not in self.webpack_chunks:
                        self.webpack_chunks.append(chunk_url)

    def _mine_webpack_chunks(self, target: str) -> None:
        """Fetch and analyze discovered webpack chunks."""
        for chunk_url in self.webpack_chunks[:self.max_chunks]:
            if any(js["url"] == chunk_url for js in self.js_files):
                continue  # Already analyzed
            
            try:
                if not chunk_url.startswith("http"):
                    chunk_url = urljoin(target, chunk_url)
                
                resp = self.session.get(chunk_url, timeout=self.timeout, verify=False)
                if resp.status_code == 200 and len(resp.text) > 50:
                    self.js_files.append({
                        "url": chunk_url,
                        "size": len(resp.text),
                        "type": "webpack_chunk",
                    })
                    
                    self._extract_api_endpoints(resp.text, chunk_url, target)
                    self._extract_routes(resp.text)
                    self._extract_graphql(resp.text, chunk_url)
                    self._extract_websockets(resp.text)
                    self._extract_internal_urls(resp.text)
                    self._extract_configs(resp.text, chunk_url)
                    self._extract_params(resp.text, chunk_url)
            except RequestException:
                continue

    def _check_source_maps(self) -> None:
        """Check if source maps are accessible (massive info disclosure)."""
        for sm in self.source_maps:
            try:
                resp = self.session.get(sm["map_url"], timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    try:
                        map_data = resp.json()
                        sm["status"] = "accessible"
                        sm["sources_count"] = len(map_data.get("sources", []))
                        sm["sources"] = map_data.get("sources", [])[:50]
                        
                        self.findings.append({
                            "id": f"JS-SMAP-{hashlib.md5(sm['map_url'].encode()).hexdigest()[:8]}",
                            "title": f"Source Map Exposed: {sm['sources_count']} source files accessible",
                            "category": "info_disclosure",
                            "severity": "high",
                            "cvss": 7.5,
                            "url": sm["map_url"],
                            "description": (
                                f"JavaScript source map is publicly accessible at {sm['map_url']}. "
                                f"Contains {sm['sources_count']} original source files, exposing the "
                                f"complete application source code including business logic, API "
                                f"endpoints, authentication flows, and potentially hardcoded secrets."
                            ),
                            "evidence": {
                                "map_url": sm["map_url"],
                                "sources_count": sm["sources_count"],
                                "sample_sources": sm["sources"][:10],
                            },
                            "impact": (
                                "Complete application source code disclosure. Attackers can identify "
                                "all API endpoints, authentication logic, business rules, and "
                                "potential vulnerabilities from the original source code."
                            ),
                            "remediation": "Remove source maps from production. Use hidden source maps for debugging.",
                            "requires_auth": False,
                        })
                        
                        source_content = json.dumps(map_data.get("sourcesContent", [""]))
                        self._extract_api_endpoints(source_content, sm["map_url"], sm["js_url"])
                        self._extract_internal_urls(source_content)
                        
                    except (json.JSONDecodeError, ValueError):
                        sm["status"] = "accessible_but_invalid"
                else:
                    sm["status"] = "not_accessible"
            except RequestException:
                sm["status"] = "error"

    def _deduplicate_endpoints(self, target: str) -> None:
        """Remove duplicate endpoints and normalize URLs."""
        seen = set()
        unique_endpoints = []
        
        for ep in self.api_endpoints:
            key = f"{ep['method']}:{ep['endpoint']}"
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)
        
        self.api_endpoints = unique_endpoints
        
        seen_params = set()
        unique_params = []
        for p in self.hidden_params:
            if p["param"] not in seen_params:
                seen_params.add(p["param"])
                unique_params.append(p)
        self.hidden_params = unique_params

    def _generate_findings(self, target: str) -> None:
        """Generate security findings from the recon data."""
        
        if self.internal_urls:
            self.findings.append({
                "id": f"JS-INTERNAL-{hashlib.md5(target.encode()).hexdigest()[:8]}",
                "title": f"Internal/Staging URLs Found: {len(self.internal_urls)} URLs in JS source",
                "category": "info_disclosure",
                "severity": "medium",
                "cvss": 5.3,
                "url": target,
                "description": (
                    f"Found {len(self.internal_urls)} internal/staging/dev URLs in JavaScript source code. "
                    f"These could be used for SSRF attacks or to discover unprotected internal services."
                ),
                "evidence": {
                    "internal_urls": self.internal_urls[:20],
                },
                "impact": "Internal service discovery, SSRF target identification.",
            })
        
        graphql_endpoints = [ep for ep in self.api_endpoints if "graphql" in ep["endpoint"].lower()]
        if graphql_endpoints:
            self.findings.append({
                "id": f"JS-GQL-{hashlib.md5(target.encode()).hexdigest()[:8]}",
                "title": f"GraphQL Endpoints Discovered: {len(graphql_endpoints)} in JS + {len(self.graphql_operations)} operations",
                "category": "endpoint_disclosure",
                "severity": "medium",
                "cvss": 5.3,
                "url": graphql_endpoints[0]["full_url"],
                "description": (
                    f"Found {len(graphql_endpoints)} GraphQL endpoints and "
                    f"{len(self.graphql_operations)} operations (queries/mutations) in JS source. "
                    f"Operations: {', '.join(op['name'] for op in self.graphql_operations[:10])}"
                ),
                "evidence": {
                    "endpoints": [ep["full_url"] for ep in graphql_endpoints],
                    "operations": self.graphql_operations[:20],
                },
                "impact": "Full GraphQL attack surface exposed. Test for IDOR, auth bypass, injection.",
            })
        
        if self.websocket_urls:
            self.findings.append({
                "id": f"JS-WS-{hashlib.md5(target.encode()).hexdigest()[:8]}",
                "title": f"WebSocket Endpoints: {len(self.websocket_urls)} discovered",
                "category": "endpoint_disclosure",
                "severity": "medium",
                "cvss": 5.3,
                "url": target,
                "description": (
                    f"Found {len(self.websocket_urls)} WebSocket endpoints in JS source. "
                    f"Test for CSWSH (Cross-Site WebSocket Hijacking), auth bypass, and injection."
                ),
                "evidence": {"websocket_urls": self.websocket_urls},
                "impact": "WebSocket attack surface. Test for CSWSH and auth bypass.",
            })
        
        if len(self.api_endpoints) > 10:
            auth_endpoints = [ep for ep in self.api_endpoints if ep.get("requires_auth")]
            unauth_endpoints = [ep for ep in self.api_endpoints if not ep.get("requires_auth")]
            
            self.findings.append({
                "id": f"JS-API-{hashlib.md5(target.encode()).hexdigest()[:8]}",
                "title": f"API Surface: {len(self.api_endpoints)} endpoints discovered ({len(auth_endpoints)} auth, {len(unauth_endpoints)} unauth)",
                "category": "endpoint_disclosure",
                "severity": "info",
                "cvss": 3.7,
                "url": target,
                "description": (
                    f"Deep JS analysis discovered {len(self.api_endpoints)} API endpoints. "
                    f"This is the complete attack surface for targeted testing."
                ),
                "evidence": {
                    "total_endpoints": len(self.api_endpoints),
                    "authenticated_endpoints": len(auth_endpoints),
                    "unauthenticated_endpoints": len(unauth_endpoints),
                    "endpoints": [
                        {"method": ep["method"], "path": ep["endpoint"]}
                        for ep in self.api_endpoints[:50]
                    ],
                },
                "impact": "Complete API attack surface for targeted vulnerability testing.",
            })

    def get_endpoints_for_scanning(self) -> list[str]:
        """Return a list of discovered endpoint URLs for use by other scanners."""
        return list({ep["full_url"] for ep in self.api_endpoints if ep.get("full_url")})

    def get_sensitive_endpoints(self) -> list[dict]:
        """Return endpoints that likely handle sensitive operations."""
        from vapt.engine.elite_intelligence import SENSITIVE_ENDPOINT_PATTERNS
        
        sensitive = []
        for ep in self.api_endpoints:
            for ep_type, config in SENSITIVE_ENDPOINT_PATTERNS.items():
                for pattern in config["patterns"]:
                    if re.search(pattern, ep["endpoint"], re.IGNORECASE):
                        sensitive.append({
                            **ep,
                            "sensitivity_type": ep_type,
                            "priority": config["priority"],
                            "test_for": config["test_for"],
                        })
                        break
        
        return sensitive
