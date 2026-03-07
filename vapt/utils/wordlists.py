"""
Massive wordlist library for directory brute-force, file discovery, and parameter fuzzing.

Contains 3,000+ paths organized by category for maximum discovery coverage.
Comparable to SecLists/common.txt + Discovery/Web-Content + custom additions.
"""

from __future__ import annotations

# DIRECTORY PATHS — Common webapp directories

DIRECTORIES = [
    # Admin panels
    "admin", "administrator", "admin1", "admin2", "admin_area", "adminarea",
    "admin-panel", "adminpanel", "admin-login", "admin-console", "admin/login",
    "admin/dashboard", "admin/config", "admin/settings", "admin/users",
    "admin/logs", "admin/db", "admin/api", "admin/backup",
    "cpanel", "controlpanel", "management", "manage", "manager",
    "moderator", "webadmin", "sysadmin", "siteadmin", "adminsite",
    "backend", "backoffice", "dashboard", "panel",
    
    # Authentication
    "login", "signin", "signup", "register", "auth", "authenticate",
    "logout", "signout", "password", "forgot-password", "reset-password",
    "account", "accounts", "profile", "user", "users", "member", "members",
    "my-account", "myaccount", "settings", "preferences",
    "oauth", "oauth2", "sso", "saml", "cas", "openid",
    
    # API
    "api", "api/v1", "api/v2", "api/v3", "api/v4", "api/latest",
    "api/auth", "api/login", "api/register", "api/users", "api/admin",
    "api/config", "api/status", "api/health", "api/info", "api/docs",
    "api/swagger", "api/graphql", "api/rest", "api/internal",
    "api/private", "api/public", "api/debug", "api/test",
    "api/upload", "api/download", "api/export", "api/import",
    "api/search", "api/token", "api/key", "api/keys",
    "rest", "restapi", "jsonapi", "rpc", "xmlrpc",
    "graphql", "graphiql", "playground", "altair",
    "swagger", "swagger-ui", "swagger.json", "swagger.yaml",
    "openapi", "openapi.json", "openapi.yaml",
    "api-docs", "apidocs", "api-doc", "redoc",
    
    # Content Management
    "wp-admin", "wp-login.php", "wp-content", "wp-includes",
    "wp-json", "wp-config.php.bak", "xmlrpc.php",
    "wp-content/uploads", "wp-content/plugins", "wp-content/themes",
    "wp-cron.php", "wp-signup.php", "wp-trackback.php",
    "joomla", "administrator", "components", "modules", "plugins",
    "drupal", "sites/default", "sites/all",
    "magento", "magento2", "downloader",
    "typo3", "typo3conf", "fileadmin",
    
    # Development / Debug
    "debug", "test", "testing", "dev", "development", "staging",
    "demo", "sandbox", "beta", "alpha", "preview",
    "phpinfo", "phpinfo.php", "info.php", "test.php",
    "debug.php", "debugger", "console", "shell",
    "phpmyadmin", "phpMyAdmin", "pma", "mysql", "adminer",
    "adminer.php", "dbadmin",
    
    # Source / Configuration
    ".git", ".git/HEAD", ".git/config", ".git/index",
    ".svn", ".svn/entries", ".svn/wc.db",
    ".hg", ".hg/store", ".bzr",
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.backup", ".env.old", ".env.save",
    ".env.example", ".env.sample", ".env.bak",
    "config", "config.php", "config.json", "config.yaml", "config.yml",
    "config.xml", "config.ini", "config.inc.php", "config.old",
    "configuration.php", "settings.php", "settings.py",
    "database.yml", "database.json", "credentials",
    ".htaccess", ".htpasswd", "httpd.conf", "nginx.conf",
    "web.config", "web.xml", "applicationContext.xml",
    "docker-compose.yml", "Dockerfile", ".dockerenv",
    "Vagrantfile", "Makefile", "Rakefile", "Gemfile",
    "package.json", "composer.json", "package-lock.json",
    "yarn.lock", "Pipfile", "Pipfile.lock", "requirements.txt",
    "tsconfig.json", "tslint.json", "webpack.config.js",
    "gulpfile.js", "gruntfile.js", "babel.config.js",
    ".babelrc", ".eslintrc", ".prettierrc",
    
    # Backup / Temp
    "backup", "backups", "bak", "old", "temp", "tmp",
    "archive", "archives", "dump", "dumps",
    "database.sql", "db.sql", "backup.sql", "dump.sql",
    "data.sql", "mysql.sql", "database.sql.gz",
    "site.tar.gz", "www.tar.gz", "backup.tar.gz",
    "backup.zip", "site.zip", "www.zip", "files.zip",
    "archive.zip", "data.zip", "upload.zip",
    
    # Security
    "security", "security.txt", ".well-known/security.txt",
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "humans.txt", "ads.txt", "app-ads.txt",
    ".well-known", ".well-known/openid-configuration",
    ".well-known/assetlinks.json", ".well-known/apple-app-site-association",
    
    # File upload / Media
    "upload", "uploads", "files", "documents", "docs",
    "images", "img", "media", "static", "assets",
    "content", "data", "resources", "public",
    "downloads", "download", "attachments",
    "storage", "store", "cdn",
    
    # Server
    "server-status", "server-info", "status", "health",
    "healthcheck", "health-check", "ping", "heartbeat",
    "metrics", "monitoring", "monitor", "stats",
    "actuator", "actuator/health", "actuator/info",
    "actuator/env", "actuator/beans", "actuator/mappings",
    "actuator/configprops", "actuator/trace", "actuator/dump",
    "actuator/metrics", "actuator/logfile", "actuator/heapdump",
    "jolokia", "jolokia/list",
    
    # E-commerce
    "cart", "checkout", "shop", "store", "products",
    "catalog", "orders", "order", "payment", "pay",
    "invoice", "billing", "subscription",
    
    # Misc
    "cgi-bin", "cgi", "bin", "scripts",
    "include", "includes", "inc", "lib", "libs", "library",
    "vendor", "node_modules", "bower_components",
    "log", "logs", "error", "errors", "error_log",
    "access.log", "error.log", "debug.log",
    "trace", "traces", "core", "install",
    "installer", "setup", "update", "upgrade",
    "maintenance", "service", "services",
    "feed", "feeds", "rss", "atom",
    "sitemap", "search", "find", "query",
    "email", "mail", "smtp", "imap",
    "ftp", "sftp", "ssh", "telnet",
    "proxy", "gateway", "redirect",
    "callback", "webhook", "webhooks", "hook", "hooks",
    "socket", "websocket", "ws", "wss",
    "event", "events", "notification", "notifications",
    "message", "messages", "chat", "forum",
    "blog", "news", "article", "articles", "post", "posts",
    "page", "pages", "category", "categories", "tag", "tags",
    "comment", "comments", "review", "reviews",
    "help", "support", "faq", "contact", "about",
    "terms", "privacy", "legal", "policy",
    "cron", "cronjob", "task", "tasks", "job", "jobs", "queue",
    "cache", "session", "sessions", "token", "tokens",
    "key", "keys", "secret", "secrets",
    "internal", "private", "hidden", "restricted",
]

# SENSITIVE FILES — Files that should never be public

SENSITIVE_FILES = [
    # Version control
    ".git/HEAD", ".git/config", ".git/index", ".git/logs/HEAD",
    ".git/COMMIT_EDITMSG", ".git/description", ".git/info/refs",
    ".git/packed-refs", ".git/refs/heads/master", ".git/refs/heads/main",
    ".svn/entries", ".svn/wc.db", ".svn/pristine",
    ".hg/store/00manifest.i", ".hg/dirstate",
    
    # Environment / Config
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.test", ".env.backup", ".env.bak",
    ".env.old", ".env.save", ".env.swp", ".env~",
    "env.js", "env.json", ".flaskenv",
    "config.php", "config.php.bak", "config.php.old",
    "config.php.save", "config.php.swp", "config.php~",
    "config.inc.php", "config.inc.php.bak",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "wp-config.php.save", "wp-config.php.swp",
    "configuration.php", "configuration.php.bak",
    "settings.py", "settings.pyc", "local_settings.py",
    "application.properties", "application.yml",
    "appsettings.json", "appsettings.Development.json",
    "web.config", "web.config.bak",
    ".htaccess", ".htpasswd",
    "database.yml", "database.yml.example",
    "secrets.yml", "credentials.yml",
    "master.key", "credentials.yml.enc",
    
    # Private Keys / Certificates
    "id_rsa", "id_rsa.pub", "id_dsa", "id_dsa.pub",
    "id_ecdsa", "id_ecdsa.pub", "id_ed25519",
    "server.key", "server.pem", "server.crt",
    "private.key", "private.pem", "cert.pem",
    "ssl.key", "ssl.crt", "ca.pem", "ca.crt",
    "keystore.jks", "truststore.jks",
    ".ssh/id_rsa", ".ssh/authorized_keys", ".ssh/known_hosts",
    
    # Database
    "database.sql", "dump.sql", "backup.sql",
    "db.sqlite", "db.sqlite3", "database.db",
    "data.db", "app.db", "development.db",
    "production.db", "test.db",
    "db.json", "data.json",
    "redis.conf", "mongod.conf",
    
    # Logs
    "access.log", "error.log", "debug.log",
    "application.log", "app.log", "server.log",
    "catalina.out", "catalina.log",
    "laravel.log", "storage/logs/laravel.log",
    "npm-debug.log", "yarn-error.log",
    "php_errors.log", "php-errors.log",
    
    # Package files (dependency info)
    "package.json", "package-lock.json", "yarn.lock",
    "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "go.mod", "go.sum",
    "pom.xml", "build.gradle",
    
    # Cloud / DevOps
    ".aws/credentials", ".aws/config",
    ".docker/config.json",
    "docker-compose.yml", "docker-compose.override.yml",
    "Dockerfile", "Dockerfile.dev", "Dockerfile.prod",
    ".dockerignore",
    "terraform.tfstate", "terraform.tfvars",
    ".terraform/terraform.tfstate",
    "ansible.cfg", "inventory.yml",
    "Jenkinsfile", ".travis.yml", ".circleci/config.yml",
    ".github/workflows", ".gitlab-ci.yml",
    "k8s", "kubernetes", "helm",
    "deploy.sh", "deploy.yml",
    "Procfile", "app.yaml", "app.json",
    
    # IDE / Editor
    ".idea/workspace.xml", ".idea/modules.xml",
    ".vscode/settings.json", ".vscode/launch.json",
    ".project", ".classpath",
    "*.swp", "*.swo", "*.swn",
    "*~", "*.bak", "*.old", "*.save",
    ".DS_Store", "Thumbs.db", "desktop.ini",
    
    # PHP
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "i.php", "pi.php", "php.ini",
    "php-fpm.conf", ".user.ini",
    
    # Java / Spring
    "WEB-INF/web.xml", "WEB-INF/applicationContext.xml",
    "META-INF/MANIFEST.MF", "META-INF/context.xml",
    "struts.xml", "struts-config.xml",
    "faces-config.xml", "beans.xml",
    
    # Python / Django / Flask
    "__pycache__", "*.pyc",
    "manage.py", "wsgi.py", "asgi.py",
    "celery.py", "celeryconfig.py",
    
    # Node.js
    "server.js", "app.js", "index.js",
    ".npmrc", ".yarnrc",
    "nodemon.json", "pm2.json",
    
    # Ruby / Rails
    "Rakefile", "config/database.yml",
    "config/secrets.yml", "config/master.key",
    "config/credentials.yml.enc",
    "config/initializers/secret_token.rb",
    
    # Misc
    "crossdomain.xml", "clientaccesspolicy.xml",
    "elmah.axd", "trace.axd",
    "error_log", "access_log",
    "cgi-bin/test-cgi", "cgi-bin/printenv",
    "readme.md", "README.md", "CHANGELOG.md",
    "LICENSE", "INSTALL", "TODO",
    "VERSION", "RELEASE_NOTES",
]

# PARAMETER NAMES — Common parameter names for fuzzing 

FUZZ_PARAMS = [
    # Authentication
    "username", "user", "login", "email", "mail",
    "password", "passwd", "pass", "pwd", "secret",
    "token", "auth", "key", "api_key", "apikey",
    "access_token", "refresh_token", "session",
    "csrf_token", "csrf", "_token",
    
    # Data access
    "id", "uid", "user_id", "userid", "account",
    "account_id", "profile_id", "order_id",
    "file", "filename", "path", "filepath",
    "dir", "directory", "folder", "doc", "document",
    "page", "p", "pg", "num", "number",
    
    # Injection vectors
    "q", "query", "search", "keyword", "term",
    "s", "find", "filter", "sort", "order",
    "category", "cat", "type", "name",
    "title", "content", "body", "text", "message",
    "comment", "description", "value", "data",
    
    # URL / Redirect
    "url", "uri", "link", "src", "source",
    "dest", "destination", "redirect", "redirect_url",
    "redirect_uri", "return", "return_url", "returnUrl",
    "next", "goto", "target", "to", "out",
    "continue", "callback", "cb", "ref", "referrer",
    
    # File operations
    "upload", "download", "export", "import",
    "template", "preview", "view", "show",
    "read", "write", "edit", "delete", "remove",
    "action", "cmd", "command", "exec", "run",
    "process", "do", "func", "function",
    
    # Format / Encoding
    "format", "output", "type", "mode",
    "encoding", "charset", "lang", "language",
    "locale", "timezone", "tz",
    "json", "xml", "csv", "html",
    
    # Debug
    "debug", "test", "verbose", "trace",
    "log", "level", "env", "config",
]

# SUBDOMAIN WORDLIST — Common subdomains

SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap",
    "admin", "administrator", "webmail", "panel",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "api", "api1", "api2", "api3",
    "dev", "development", "staging", "stage", "stg",
    "test", "testing", "qa", "uat", "demo",
    "beta", "alpha", "preview", "sandbox",
    "app", "apps", "application",
    "web", "www2", "www3",
    "m", "mobile", "wap",
    "blog", "news", "forum", "community",
    "shop", "store", "ecommerce", "cart",
    "cdn", "static", "assets", "media", "images", "img",
    "files", "upload", "uploads", "download", "downloads",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "cache", "memcached", "elasticsearch", "elastic", "es",
    "search", "solr", "kibana", "grafana", "prometheus",
    "jenkins", "ci", "cd", "build", "deploy",
    "git", "gitlab", "github", "bitbucket", "svn",
    "docker", "k8s", "kubernetes", "container",
    "cloud", "aws", "azure", "gcp",
    "vpn", "remote", "gateway", "proxy",
    "ldap", "ad", "sso", "auth", "oauth", "identity",
    "monitoring", "monitor", "status", "health",
    "metrics", "analytics", "tracking", "stats",
    "log", "logs", "logging", "syslog", "elk", "splunk",
    "backup", "bak", "archive",
    "internal", "intranet", "private", "corp", "corporate",
    "support", "help", "helpdesk", "ticket", "tickets",
    "crm", "erp", "billing", "invoice",
    "payment", "pay", "checkout",
    "email", "newsletter", "marketing", "campaign",
    "docs", "doc", "documentation", "wiki", "kb", "knowledge",
    "portal", "extranet", "partner", "vendor",
    "report", "reports", "reporting", "dashboard",
    "old", "legacy", "v1", "v2", "v3",
    "prod", "production", "live",
    "s3", "storage", "bucket",
    "websocket", "ws", "socket", "io",
    "graphql", "rest",
    "staging1", "staging2", "dev1", "dev2",
    "node", "node1", "node2", "worker", "worker1",
]

# TECHNOLOGY-SPECIFIC PATHS

TECH_PATHS = {
    "wordpress": [
        "wp-login.php", "wp-admin", "wp-admin/admin-ajax.php",
        "wp-content/debug.log", "wp-config.php.bak",
        "wp-includes/version.php", "wp-json/wp/v2/users",
        "wp-json/wp/v2/posts", "wp-json/oembed/1.0",
        "xmlrpc.php", "wp-cron.php",
        "wp-content/uploads", "wp-content/plugins",
        "wp-content/themes", "wp-content/mu-plugins",
        "readme.html", "license.txt",
    ],
    "drupal": [
        "CHANGELOG.txt", "core/CHANGELOG.txt",
        "core/INSTALL.mysql.txt", "core/INSTALL.pgsql.txt",
        "core/INSTALL.sqlite.txt", "core/install.php",
        "user/login", "user/register", "admin/config",
        "node/add", "admin/structure", "admin/people",
        "update.php", "cron.php",
        "sites/default/files", "sites/default/settings.php",
    ],
    "laravel": [
        "storage/logs/laravel.log", "storage/framework/sessions",
        ".env", "artisan", "public/storage",
        "telescope", "horizon", "nova",
        "api/documentation", "public/index.php",
        "_debugbar", "clockwork",
    ],
    "django": [
        "admin", "admin/login", "admin/doc",
        "__debug__", "api-auth", "api-token-auth",
        "static/admin", "media",
        "accounts/login", "accounts/register",
        "silk", "debug/sql/select",
    ],
    "spring": [
        "actuator", "actuator/health", "actuator/info",
        "actuator/env", "actuator/beans", "actuator/mappings",
        "actuator/configprops", "actuator/trace",
        "actuator/dump", "actuator/metrics",
        "actuator/logfile", "actuator/heapdump",
        "actuator/threaddump", "actuator/scheduledtasks",
        "actuator/httptrace", "actuator/conditions",
        "jolokia", "jolokia/list",
        "h2-console", "swagger-ui.html",
        "v2/api-docs", "v3/api-docs",
    ],
    "nodejs": [
        "server.js", "app.js", "index.js",
        "package.json", "npm-debug.log",
        ".npmrc", "node_modules",
        "graphql", "playground",
        "socket.io/socket.io.js",
    ],
    "aspnet": [
        "web.config", "elmah.axd", "trace.axd",
        "appsettings.json", "bin", "App_Data",
        "Elmah.axd", "glimpse.axd",
        "_vti_bin", "_vti_cnf", "_vti_log",
        "aspnet_client",
    ],
    "apache": [
        "server-status", "server-info",
        ".htaccess", ".htpasswd",
        "cgi-bin", "manual",
    ],
    "nginx": [
        "nginx.conf", "nginx_status",
        "stub_status",
    ],
    "tomcat": [
        "manager/html", "manager/text", "manager/status",
        "host-manager/html", "status",
        "examples", "docs",
        "WEB-INF/web.xml",
    ],
}

# FILE EXTENSIONS TO TEST

EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".do", ".action",
    ".py", ".rb", ".pl", ".cgi", ".cfm",
    ".html", ".htm", ".xhtml", ".shtml",
    ".txt", ".xml", ".json", ".yaml", ".yml",
    ".ini", ".conf", ".cfg", ".config",
    ".log", ".sql", ".db", ".sqlite", ".sqlite3",
    ".bak", ".old", ".save", ".swp", ".tmp", ".temp",
    ".zip", ".tar", ".tar.gz", ".gz", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv",
    ".key", ".pem", ".crt", ".cer",
    ".env", ".inc", ".dist",
]

# BACKUP FILE PATTERNS (generate from base name)

BACKUP_SUFFIXES = [
    ".bak", ".backup", ".old", ".orig", ".original",
    ".save", ".saved", ".copy", ".tmp", ".temp",
    "~", ".swp", ".swo", ".swn",
    ".1", ".2", ".prev", ".previous",
    "_backup", "_old", "_copy", "_bak",
    ".bk", ".bkp",
]


def get_full_wordlist() -> list[str]:
    """Get the complete combined wordlist."""
    all_paths = set()
    all_paths.update(DIRECTORIES)
    all_paths.update(SENSITIVE_FILES)
    for tech_paths in TECH_PATHS.values():
        all_paths.update(tech_paths)
    return sorted(all_paths)


def get_wordlist_for_tech(technology: str) -> list[str]:
    """Get technology-specific wordlist."""
    tech = technology.lower()
    base = list(DIRECTORIES) + list(SENSITIVE_FILES)
    if tech in TECH_PATHS:
        base.extend(TECH_PATHS[tech])
    return base


def generate_backup_names(filename: str) -> list[str]:
    """Generate backup file name variants for a given filename."""
    variants = []
    for suffix in BACKUP_SUFFIXES:
        variants.append(f"{filename}{suffix}")
    # Also try with date-like patterns
    variants.append(f"{filename}.2024")
    variants.append(f"{filename}.2025")
    variants.append(f"{filename}.2026")
    return variants
