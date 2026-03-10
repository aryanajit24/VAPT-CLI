
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from vapt.database.db import get_session, init_db
from vapt.database.models import ComplianceMapping, KnowledgeEntry


KB_ENTRIES: list[dict] = [


    {
        "vuln_id": "WEB-001",
        "category": "injection",
        "title": "SQL Injection",
        "description": (
            "The application constructs SQL queries using unsanitised user input, "
            "allowing attackers to manipulate database queries.  This can lead to "
            "full database compromise, data exfiltration, or privilege escalation."
        ),
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A03:2021 – Injection",
        "how_it_works": (
            "User-controlled data (form fields, URL params, cookies) is concatenated "
            "directly into a SQL statement.  The attacker terminates the intended query "
            "and appends their own — reading, modifying, or deleting data at will."
        ),
        "impact": (
            "Complete loss of data confidentiality and integrity.  Attackers can dump "
            "credentials, modify records, escalate to OS-level commands via xp_cmdshell "
            "or LOAD_FILE, and pivot deeper into the network."
        ),
        "remediation": (
            "Use parameterised queries or prepared statements.  Apply an ORM with "
            "strict type checking.  Validate and sanitise all user-supplied input.  "
            "Enforce least-privilege DB accounts."
        ),
        "code_example_fix": (
            "# VULNERABLE\n"
            "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
            "# FIXED — parameterised query\n"
            "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
        ),
        "cve_ids": "CVE-2018-1002105,CVE-2019-2725,CVE-2017-5638",
        "references": "https://owasp.org/www-community/attacks/SQL_Injection",
        "compliance_tags": "OWASP-A03,PCI-DSS-6.3,ISO27001-A.14.2,NIS2-Article21",
        "detection_pattern": r"(error in your SQL syntax|you have an error in your SQL|unclosed quotation mark)",
        "false_positive_indicators": "Generic error pages, CMS debug output with 'SQL' in text",
        "nis2_control": "Article 21 – Risk-management measures",
        "iso27001_control": "A.14.2 – Security in development and support processes",
    },
    {
        "vuln_id": "WEB-001a",
        "category": "injection",
        "title": "Blind SQL Injection (Boolean-Based)",
        "description": (
            "The application is vulnerable to SQL injection but does not return "
            "error messages.  Instead, the attacker infers data by observing "
            "differences in the application's behaviour (true vs false responses)."
        ),
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A03:2021 – Injection",
        "how_it_works": (
            "The attacker sends payloads like ' AND 1=1-- and ' AND 1=2-- and "
            "watches whether the page changes.  By iterating character-by-character "
            "they extract entire databases without ever seeing an error."
        ),
        "impact": "Same as classic SQLi — full database compromise, just slower.",
        "remediation": "Parameterise all queries.  WAF signatures alone won't reliably catch blind variants.",
        "code_example_fix": (
            "# Use SQLAlchemy ORM — no raw string interpolation\n"
            "user = session.query(User).filter(User.id == user_id).first()"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
        "compliance_tags": "OWASP-A03,PCI-DSS-6.3",
        "detection_pattern": r"(AND\s+\d+=\d+|OR\s+\d+=\d+|SLEEP\(|BENCHMARK\()",
        "false_positive_indicators": "Analytics strings containing AND/OR in URLs",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },
    {
        "vuln_id": "WEB-001b",
        "category": "injection",
        "title": "Blind SQL Injection (Time-Based)",
        "description": (
            "A variant of blind SQL injection where the attacker uses time-delay "
            "functions (SLEEP, WAITFOR DELAY, pg_sleep) to infer query results "
            "based on response timing."
        ),
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A03:2021 – Injection",
        "how_it_works": (
            "The attacker injects IF(condition, SLEEP(5), 0).  If the page takes "
            "5 seconds to respond the condition was true.  Repeat per character to "
            "extract data."
        ),
        "impact": "Full database compromise; also enables denial-of-service via heavy sleep calls.",
        "remediation": "Parameterised queries.  Set aggressive query timeouts as a secondary defence.",
        "code_example_fix": "cursor.execute(\"SELECT * FROM users WHERE email = %s\", (email,))",
        "cve_ids": None,
        "references": "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
        "compliance_tags": "OWASP-A03,PCI-DSS-6.3",
        "detection_pattern": r"(SLEEP\(\d+\)|WAITFOR\s+DELAY|pg_sleep\()",
        "false_positive_indicators": "Slow network, unrelated latency spikes",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },
    {
        "vuln_id": "WEB-001c",
        "category": "injection",
        "title": "SQL Injection (UNION-Based)",
        "description": (
            "The attacker appends a UNION SELECT to the original query, combining "
            "results from another table into the application's normal output."
        ),
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A03:2021 – Injection",
        "how_it_works": (
            "The attacker first determines the column count with ORDER BY, then crafts "
            "a UNION SELECT with matching columns to pull data from information_schema "
            "or other tables."
        ),
        "impact": "Direct data exfiltration — usernames, password hashes, credit cards.",
        "remediation": "Parameterised queries.  Restrict DB user privileges so UNION is useless.",
        "code_example_fix": "cursor.execute(\"SELECT name FROM products WHERE id = %s\", (product_id,))",
        "cve_ids": None,
        "references": "https://portswigger.net/web-security/sql-injection/union-attacks",
        "compliance_tags": "OWASP-A03,PCI-DSS-6.3",
        "detection_pattern": r"(UNION\s+(ALL\s+)?SELECT)",
        "false_positive_indicators": "Legitimate use of 'union' as a word in page content",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },
    {
        "vuln_id": "WEB-001d",
        "category": "injection",
        "title": "NoSQL Injection",
        "description": (
            "Injection attacks targeting NoSQL databases (MongoDB, CouchDB).  "
            "Attackers exploit JSON/BSON query operators to bypass authentication "
            "or extract data."
        ),
        "severity": "high",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "owasp_category": "A03:2021 – Injection",
        "how_it_works": (
            "The attacker sends JSON payloads with MongoDB operators like $gt, $ne, "
            "$regex in login forms.  {\"username\":\"admin\",\"password\":{\"$ne\":\"\"}} "
            "bypasses the password check entirely."
        ),
        "impact": "Authentication bypass, data exfiltration from document stores.",
        "remediation": (
            "Validate and sanitise input types — reject objects where strings are expected.  "
            "Use ODM libraries with schema enforcement."
        ),
        "code_example_fix": (
            "# VULNERABLE (Express + Mongoose)\n"
            "User.find({ username: req.body.username, password: req.body.password })\n\n"
            "# FIXED — explicitly cast to string\n"
            "User.find({ username: String(req.body.username), password: String(req.body.password) })"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
        "compliance_tags": "OWASP-A03",
        "detection_pattern": r'(\$gt|\$ne|\$regex|\$where)',
        "false_positive_indicators": "Dollar signs in non-JSON contexts",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },
    {
        "vuln_id": "WEB-001e",
        "category": "injection",
        "title": "OS Command Injection",
        "description": (
            "The application passes user input to a system shell without proper "
            "escaping, allowing the attacker to execute arbitrary OS commands."
        ),
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A03:2021 – Injection",
        "how_it_works": (
            "The attacker injects shell metacharacters (; | && ` $()) into a parameter "
            "that ends up in os.system(), subprocess with shell=True, or similar.  "
            "For example: ping -c1 <user_input> becomes ping -c1 ; cat /etc/passwd."
        ),
        "impact": "Full server compromise — arbitrary command execution as the web server user.",
        "remediation": (
            "Never use shell=True.  Use subprocess with a list of arguments.  "
            "Better yet, use native Python libraries instead of shelling out."
        ),
        "code_example_fix": (
            "# VULNERABLE\n"
            "os.system(f'ping -c1 {host}')\n\n"
            "# FIXED\n"
            "subprocess.run(['ping', '-c1', host], capture_output=True)"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/www-community/attacks/Command_Injection",
        "compliance_tags": "OWASP-A03,NIS2-Article21",
        "detection_pattern": r"(;|\||\$\(|`).*(cat|ls|whoami|id|uname|wget|curl)",
        "false_positive_indicators": "Shell-like syntax in documentation or code samples on pages",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },
    {
        "vuln_id": "WEB-001f",
        "category": "injection",
        "title": "Server-Side Template Injection (SSTI)",
        "description": (
            "User input is embedded directly into a server-side template engine "
            "(Jinja2, Twig, Freemarker) allowing the attacker to execute arbitrary "
            "code on the server."
        ),
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A03:2021 – Injection",
        "how_it_works": (
            "The attacker sends {{7*7}} and the page returns 49, confirming template "
            "evaluation.  From there, they escalate to RCE via template builtins "
            "like __import__('os').popen('id').read()."
        ),
        "impact": "Remote code execution, full server compromise.",
        "remediation": (
            "Never pass raw user input into template rendering contexts.  "
            "Use sandboxed template environments.  Prefer logic-less templates."
        ),
        "code_example_fix": (
            "# VULNERABLE (Jinja2)\n"
            "return render_template_string(user_input)\n\n"
            "# FIXED\n"
            "return render_template('greeting.html', name=user_input)"
        ),
        "cve_ids": None,
        "references": "https://portswigger.net/web-security/server-side-template-injection",
        "compliance_tags": "OWASP-A03",
        "detection_pattern": r"(\{\{.*\}\}|\$\{.*\}|<%.*%>)",
        "false_positive_indicators": "Legitimate template syntax in static content, Angular/Vue double-brace syntax",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },


    {
        "vuln_id": "WEB-002",
        "category": "xss",
        "title": "Cross-Site Scripting (XSS) — Reflected",
        "description": (
            "User input is immediately reflected in the server's response without "
            "proper encoding, allowing attackers to inject client-side scripts "
            "that execute in victims' browsers."
        ),
        "severity": "high",
        "cvss_score": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        "owasp_category": "A03:2021 – Injection",
        "how_it_works": (
            "The attacker crafts a URL containing a script tag or event handler.  "
            "When a victim clicks the link the payload executes in their browser "
            "session, stealing cookies or performing actions on their behalf."
        ),
        "impact": "Session hijacking, credential theft, phishing, defacement.",
        "remediation": (
            "Context-aware output encoding (HTML, JS, URL, CSS).  Deploy a strict "
            "Content-Security-Policy header.  Validate input on both client and server."
        ),
        "code_example_fix": (
            "<!-- VULNERABLE -->\n"
            "<p>Hello, {{ user_input }}</p>\n\n"
            "<!-- FIXED (Jinja2 autoescaping) -->\n"
            "<p>Hello, {{ user_input | e }}</p>"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/www-community/attacks/xss/",
        "compliance_tags": "OWASP-A03,PCI-DSS-6.3",
        "detection_pattern": r"<script>|javascript:|onerror=|onload=",
        "false_positive_indicators": "Inline JS in source code comments, benign event handlers",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },
    {
        "vuln_id": "WEB-002a",
        "category": "xss",
        "title": "Cross-Site Scripting (XSS) — Stored",
        "description": (
            "Malicious scripts are persisted in the application's data store (database, "
            "message board, comment field) and served to every user who views the "
            "affected page."
        ),
        "severity": "high",
        "cvss_score": 8.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N",
        "owasp_category": "A03:2021 – Injection",
        "how_it_works": (
            "The attacker posts a comment or profile bio containing <script>evil()</script>.  "
            "The server saves it.  Every subsequent visitor's browser now executes the script."
        ),
        "impact": "Mass session hijacking, worm propagation, persistent phishing.",
        "remediation": "Sanitise on input AND encode on output.  Use a library like DOMPurify for HTML content.",
        "code_example_fix": (
            "import bleach\n"
            "clean = bleach.clean(user_comment, tags=['b', 'i', 'a'], attributes={'a': ['href']})"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/www-community/attacks/xss/",
        "compliance_tags": "OWASP-A03,PCI-DSS-6.3",
        "detection_pattern": r"<script|<iframe|<object|<embed|onerror\s*=",
        "false_positive_indicators": "Escaped HTML entities in page source, documentation references",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },
    {
        "vuln_id": "WEB-002b",
        "category": "xss",
        "title": "Cross-Site Scripting (XSS) — DOM-Based",
        "description": (
            "The vulnerability exists entirely in client-side JavaScript.  The DOM "
            "is manipulated using unsafe sinks (innerHTML, document.write) with data "
            "from attacker-controlled sources (location.hash, URL params)."
        ),
        "severity": "high",
        "cvss_score": 7.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "owasp_category": "A03:2021 – Injection",
        "how_it_works": (
            "Client-side JS reads window.location.hash and writes it to innerHTML.  "
            "The attacker crafts a URL with a hash containing a script payload."
        ),
        "impact": "Session theft, keylogging, redirection — harder to detect server-side.",
        "remediation": "Use textContent instead of innerHTML.  Avoid document.write.  Sanitise DOM sources.",
        "code_example_fix": (
            "// VULNERABLE\n"
            "document.getElementById('out').innerHTML = location.hash.slice(1);\n\n"
            "// FIXED\n"
            "document.getElementById('out').textContent = location.hash.slice(1);"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/www-community/attacks/DOM_Based_XSS",
        "compliance_tags": "OWASP-A03",
        "detection_pattern": r"(document\.write|innerHTML\s*=|\.html\()",
        "false_positive_indicators": "React/Vue virtual DOM updates, sanitised innerHTML usage",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },


    {
        "vuln_id": "WEB-003",
        "category": "authentication",
        "title": "Broken Authentication",
        "description": (
            "Weak session management, credential stuffing exposure, or missing "
            "brute-force protection allows unauthorised account access."
        ),
        "severity": "high",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "how_it_works": (
            "Attackers exploit weak passwords, predictable session IDs, missing "
            "account lockout, or session fixation to gain access to other users' accounts."
        ),
        "impact": "Account takeover, identity theft, unauthorised data access.",
        "remediation": (
            "Implement MFA.  Enforce strong password policies.  Use secure, random "
            "session tokens.  Invalidate sessions on logout.  Rate-limit login attempts."
        ),
        "code_example_fix": (
            "# Rate-limit logins with Flask-Limiter\n"
            "@limiter.limit('5/minute')\n"
            "@app.route('/login', methods=['POST'])\n"
            "def login(): ..."
        ),
        "cve_ids": None,
        "references": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "compliance_tags": "OWASP-A07,ISO27001-A.9,NIS2-Article21",
        "detection_pattern": None,
        "false_positive_indicators": "Login pages with CAPTCHA already present",
        "nis2_control": "Article 21",
        "iso27001_control": "A.9 – Access Control",
    },
    {
        "vuln_id": "WEB-003a",
        "category": "authentication",
        "title": "Default or Weak Credentials",
        "description": (
            "The application or its components ship with default usernames and "
            "passwords (admin/admin, root/toor) that were never changed."
        ),
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "how_it_works": "Attacker tries well-known default credentials from online databases.",
        "impact": "Instant administrative access to the target system.",
        "remediation": "Force password change on first login.  Remove default accounts entirely.",
        "code_example_fix": "# Force password reset on first login\nif user.must_change_password:\n    return redirect('/change-password')",
        "cve_ids": None,
        "references": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials",
        "compliance_tags": "OWASP-A07,CIS-5.2",
        "detection_pattern": None,
        "false_positive_indicators": "Honeypot login pages designed to look vulnerable",
        "nis2_control": "Article 21",
        "iso27001_control": "A.9",
    },
    {
        "vuln_id": "WEB-003b",
        "category": "authentication",
        "title": "Missing Multi-Factor Authentication",
        "description": (
            "Critical accounts or sensitive operations lack a second authentication "
            "factor, making password-only attacks viable."
        ),
        "severity": "medium",
        "cvss_score": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "how_it_works": "Compromised credentials (phishing, breaches) are used directly without any additional challenge.",
        "impact": "Account takeover if passwords are leaked or guessed.",
        "remediation": "Require TOTP, WebAuthn, or push-based MFA for privileged accounts and sensitive actions.",
        "code_example_fix": "# Use pyotp for TOTP verification\nimport pyotp\ntotp = pyotp.TOTP(user.mfa_secret)\nif not totp.verify(request.form['token']):\n    abort(403)",
        "cve_ids": None,
        "references": "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
        "compliance_tags": "OWASP-A07,NIS2-Article21,ISO27001-A.9",
        "detection_pattern": None,
        "false_positive_indicators": "MFA enforced at a higher layer (SSO/IdP) not visible to scanner",
        "nis2_control": "Article 21",
        "iso27001_control": "A.9",
    },
    {
        "vuln_id": "WEB-003c",
        "category": "authentication",
        "title": "Session Fixation",
        "description": (
            "The application does not regenerate session IDs after login, allowing "
            "an attacker who sets a known session ID to hijack the authenticated session."
        ),
        "severity": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "how_it_works": (
            "The attacker sends the victim a link with a pre-set session cookie.  "
            "The victim logs in; the application keeps the same session ID.  "
            "The attacker now uses that ID to access the authenticated session."
        ),
        "impact": "Session hijacking, full account compromise.",
        "remediation": "Regenerate session ID after every privilege change (login, role switch).",
        "code_example_fix": "# Flask\n@app.after_request\ndef regen_session(response):\n    session.regenerate()\n    return response",
        "cve_ids": None,
        "references": "https://owasp.org/www-community/attacks/Session_fixation",
        "compliance_tags": "OWASP-A07",
        "detection_pattern": None,
        "false_positive_indicators": "Tokens that look static but are cryptographically bound to the user",
        "nis2_control": "Article 21",
        "iso27001_control": "A.9",
    },
    {
        "vuln_id": "WEB-003d",
        "category": "authentication",
        "title": "Insecure Password Storage",
        "description": (
            "Passwords are stored as plaintext, MD5, SHA-1, or with no salt, "
            "making them trivial to crack if the database is breached."
        ),
        "severity": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "how_it_works": "After a database breach the attacker runs rainbow tables or hashcat against weak hashes.",
        "impact": "Mass credential compromise, credential stuffing across other services.",
        "remediation": "Use bcrypt, scrypt, or Argon2id with per-user salts and high work factors.",
        "code_example_fix": (
            "import bcrypt\n"
            "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))"
        ),
        "cve_ids": None,
        "references": "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
        "compliance_tags": "OWASP-A02,PCI-DSS-8.3,ISO27001-A.10",
        "detection_pattern": None,
        "false_positive_indicators": "Hashed values that look short but use a strong KDF",
        "nis2_control": "Article 21",
        "iso27001_control": "A.10 – Cryptography",
    },


    {
        "vuln_id": "WEB-006",
        "category": "access_control",
        "title": "Broken Access Control",
        "description": (
            "Users can act outside their intended permissions — accessing other "
            "users' data, modifying records they shouldn't, or escalating roles."
        ),
        "severity": "critical",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "owasp_category": "A01:2021 – Broken Access Control",
        "how_it_works": (
            "The attacker changes an object ID in a URL (/api/users/42 → /api/users/43) "
            "or tampers with a role field in a JWT to escalate privileges."
        ),
        "impact": "Unauthorised data access, privilege escalation, full application compromise.",
        "remediation": (
            "Enforce server-side access control on every request.  "
            "Default-deny.  Log and alert on access-control failures."
        ),
        "code_example_fix": (
            "# Check ownership before returning data\n"
            "if record.owner_id != current_user.id:\n"
            "    abort(403)"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "compliance_tags": "OWASP-A01,ISO27001-A.9,NIS2-Article21",
        "detection_pattern": None,
        "false_positive_indicators": "Public-by-design endpoints, open-data APIs",
        "nis2_control": "Article 21",
        "iso27001_control": "A.9 – Access Control",
    },


    {
        "vuln_id": "WEB-005",
        "category": "security_misconfiguration",
        "title": "Security Misconfiguration",
        "description": (
            "Default credentials, unnecessary services, verbose error messages, or "
            "missing security headers expose the application to attack."
        ),
        "severity": "medium",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "how_it_works": (
            "Attackers scan for default pages (phpinfo, /server-status), verbose stack "
            "traces, open admin panels, or directory listings that reveal internal details."
        ),
        "impact": "Information disclosure, easier exploitation of other vulnerabilities.",
        "remediation": (
            "Harden server configurations.  Remove default accounts.  Set security "
            "headers (CSP, HSTS, X-Frame-Options).  Suppress verbose errors in production."
        ),
        "code_example_fix": (
            "# Nginx — add security headers\n"
            "add_header X-Content-Type-Options nosniff;\n"
            "add_header X-Frame-Options DENY;\n"
            "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\";"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "compliance_tags": "OWASP-A05,CIS-Benchmark",
        "detection_pattern": None,
        "false_positive_indicators": "Intentionally verbose dev/staging environments behind VPN",
        "nis2_control": "Article 21",
        "iso27001_control": "A.12 – Operations Security",
    },


    {
        "vuln_id": "WEB-007",
        "category": "cryptography",
        "title": "Sensitive Data Exposure — Weak Cryptography",
        "description": (
            "The application uses outdated or weak cryptographic algorithms (MD5, "
            "SHA-1, DES, RC4) or transmits sensitive data in cleartext."
        ),
        "severity": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "how_it_works": (
            "Sensitive data is encrypted with a broken algorithm or transmitted over HTTP.  "
            "Attackers intercept or crack the data."
        ),
        "impact": "Exposure of PII, credentials, API keys, financial data.",
        "remediation": (
            "Use AES-256-GCM for encryption at rest.  Enforce TLS 1.2+ for transit.  "
            "Replace MD5/SHA-1 with SHA-256+ for integrity checks."
        ),
        "code_example_fix": (
            "from cryptography.fernet import Fernet\n"
            "key = Fernet.generate_key()\n"
            "f = Fernet(key)\n"
            "encrypted = f.encrypt(sensitive_data.encode())"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "compliance_tags": "OWASP-A02,PCI-DSS-4.1,ISO27001-A.10",
        "detection_pattern": None,
        "false_positive_indicators": "MD5 used for non-security purposes (cache keys, ETags)",
        "nis2_control": "Article 21",
        "iso27001_control": "A.10 – Cryptography",
    },


    {
        "vuln_id": "WEB-004",
        "category": "ssrf",
        "title": "Server-Side Request Forgery (SSRF)",
        "description": (
            "The server can be induced to make requests to internal or external "
            "resources controlled by an attacker, bypassing firewalls and ACLs."
        ),
        "severity": "high",
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "owasp_category": "A10:2021 – Server-Side Request Forgery",
        "how_it_works": (
            "The attacker provides a URL pointing to an internal service "
            "(http://169.254.169.254/ for cloud metadata, http://localhost:6379/ for Redis).  "
            "The server fetches it and returns the response."
        ),
        "impact": "Internal network scanning, cloud metadata theft (AWS keys), service abuse.",
        "remediation": (
            "Whitelist allowed URLs and IP ranges.  Block requests to private IP space.  "
            "Use a network-level egress firewall.  Disable HTTP redirects in server-side fetches."
        ),
        "code_example_fix": (
            "from urllib.parse import urlparse\n"
            "import ipaddress\n\n"
            "parsed = urlparse(user_url)\n"
            "ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\n"
            "if ip.is_private:\n"
            "    raise ValueError('Blocked: private IP')"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "compliance_tags": "OWASP-A10,NIS2-Article21",
        "detection_pattern": r"(127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|::1)",
        "false_positive_indicators": "Localhost references in documentation, health-check endpoints",
        "nis2_control": "Article 21",
        "iso27001_control": "A.13 – Communications Security",
    },


    {
        "vuln_id": "WEB-008",
        "category": "xxe",
        "title": "XML External Entity Injection (XXE)",
        "description": (
            "The application parses XML input with external entity processing enabled, "
            "allowing attackers to read local files, perform SSRF, or cause DoS."
        ),
        "severity": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "how_it_works": (
            "The attacker sends XML with a DOCTYPE declaring an external entity "
            "pointing to file:///etc/passwd.  The parser resolves it and includes "
            "the file contents in the response."
        ),
        "impact": "Local file read, internal network scanning, denial of service (billion laughs).",
        "remediation": (
            "Disable DTDs and external entities in all XML parsers.  Use JSON where possible.  "
            "If XML is required, use defusedxml in Python."
        ),
        "code_example_fix": (
            "# VULNERABLE\n"
            "from xml.etree.ElementTree import parse\n\n"
            "# FIXED\n"
            "import defusedxml.ElementTree as ET\n"
            "tree = ET.parse(xml_file)"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        "compliance_tags": "OWASP-A05",
        "detection_pattern": r"(<!ENTITY|<!DOCTYPE.*SYSTEM|file:///)",
        "false_positive_indicators": "SVG files with benign DOCTYPE declarations",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },


    {
        "vuln_id": "WEB-009",
        "category": "csrf",
        "title": "Cross-Site Request Forgery (CSRF)",
        "description": (
            "State-changing forms lack anti-CSRF tokens, allowing an attacker to "
            "trick a logged-in user into submitting unintended requests."
        ),
        "severity": "medium",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "owasp_category": "A01:2021 – Broken Access Control",
        "how_it_works": (
            "The attacker hosts a page with an auto-submitting form targeting the "
            "victim app.  If the victim is logged in, the browser sends their session "
            "cookie and the action completes."
        ),
        "impact": "Unwanted state changes — password resets, fund transfers, email changes.",
        "remediation": (
            "Use synchroniser tokens (one per session or per request).  "
            "Set SameSite=Strict on session cookies.  Require re-authentication for critical actions."
        ),
        "code_example_fix": (
            "<!-- Django template -->\n"
            "<form method='post'>\n"
            "    {% csrf_token %}\n"
            "    <input type='submit' value='Transfer'>\n"
            "</form>"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/www-community/attacks/csrf",
        "compliance_tags": "OWASP-A01",
        "detection_pattern": r"<form[^>]*method=['\"]?post[^>]*>(?!.*csrf)",
        "false_positive_indicators": "API-only endpoints using Bearer tokens (no cookies)",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },


    {
        "vuln_id": "API-001",
        "category": "api",
        "title": "Broken Object Level Authorisation (BOLA)",
        "description": (
            "API endpoints accept arbitrary object IDs without verifying that the "
            "requesting user owns or is allowed to access the referenced object."
        ),
        "severity": "critical",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "owasp_category": "OWASP API Top 10 – API1",
        "how_it_works": "Attacker increments /api/orders/1001 to /api/orders/1002 and gets another user's order.",
        "impact": "Mass data theft, privacy violations.",
        "remediation": "Enforce object-level authorisation checks.  Use indirect references.  Validate ownership.",
        "code_example_fix": (
            "order = Order.query.get(order_id)\n"
            "if order.user_id != current_user.id:\n"
            "    abort(403)"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        "compliance_tags": "OWASP-API1,ISO27001-A.9",
        "detection_pattern": None,
        "false_positive_indicators": "Endpoints that are intentionally public",
        "nis2_control": "Article 21",
        "iso27001_control": "A.9",
    },
    {
        "vuln_id": "API-002",
        "category": "api",
        "title": "Excessive Data Exposure",
        "description": (
            "API responses include more fields than the client needs, leaking "
            "sensitive data like passwords, tokens, or PII."
        ),
        "severity": "medium",
        "cvss_score": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "owasp_category": "OWASP API Top 10 – API3",
        "how_it_works": "The API serialises the entire database model to JSON, including internal fields.",
        "impact": "Credential leakage, PII exposure, GDPR violations.",
        "remediation": "Use explicit response schemas.  Never return password hashes, tokens, or internal IDs.",
        "code_example_fix": (
            "# Use Pydantic response model\n"
            "class UserOut(BaseModel):\n"
            "    id: int\n"
            "    name: str\n"
            "    # password, secret_key etc. deliberately omitted"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        "compliance_tags": "OWASP-API3,GDPR-Art5",
        "detection_pattern": r"(password|secret|token|api_key|ssn|credit_card)",
        "false_positive_indicators": "Field names that describe non-secret things (e.g. 'password_policy')",
        "nis2_control": "Article 21",
        "iso27001_control": "A.8 – Asset Management",
    },
    {
        "vuln_id": "API-003",
        "category": "api",
        "title": "Missing Rate Limiting",
        "description": (
            "API endpoints have no rate limiting, allowing attackers to brute-force "
            "credentials, enumerate resources, or cause denial of service."
        ),
        "severity": "medium",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "owasp_category": "OWASP API Top 10 – API4",
        "how_it_works": "The attacker floods the endpoint with thousands of requests per second without being throttled.",
        "impact": "Brute-force success, resource exhaustion, increased infrastructure costs.",
        "remediation": "Implement rate limiting per IP and per user.  Use token buckets or sliding windows.",
        "code_example_fix": (
            "from flask_limiter import Limiter\n"
            "limiter = Limiter(app, default_limits=['100/minute'])"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
        "compliance_tags": "OWASP-API4",
        "detection_pattern": None,
        "false_positive_indicators": "Rate limiting handled by upstream WAF/CDN not visible to the scanner",
        "nis2_control": "Article 21",
        "iso27001_control": "A.12 – Operations Security",
    },
    {
        "vuln_id": "API-004",
        "category": "api",
        "title": "Broken Function Level Authorisation",
        "description": (
            "Administrative API endpoints are accessible to regular users because "
            "the app relies on client-side UI hiding rather than server-side checks."
        ),
        "severity": "high",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "owasp_category": "OWASP API Top 10 – API5",
        "how_it_works": "A regular user discovers /api/admin/deleteUser via API docs and calls it directly.",
        "impact": "Privilege escalation, mass data deletion, system configuration changes.",
        "remediation": "Enforce role-based access control (RBAC) on every endpoint.  Default-deny for admin routes.",
        "code_example_fix": (
            "@app.route('/api/admin/users', methods=['DELETE'])\n"
            "@require_role('admin')\n"
            "def delete_user(user_id): ..."
        ),
        "cve_ids": None,
        "references": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
        "compliance_tags": "OWASP-API5,ISO27001-A.9",
        "detection_pattern": None,
        "false_positive_indicators": "Admin endpoints protected by middleware not visible in response",
        "nis2_control": "Article 21",
        "iso27001_control": "A.9",
    },
    {
        "vuln_id": "API-005",
        "category": "api",
        "title": "Mass Assignment / Excessive Mass Assignment",
        "description": (
            "The API binds request data directly to internal models without filtering, "
            "allowing attackers to set fields they shouldn't (e.g. is_admin=True)."
        ),
        "severity": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "owasp_category": "OWASP API Top 10 – API6",
        "how_it_works": (
            "The attacker adds {\"role\":\"admin\"} to a profile-update request.  "
            "Because the API does User(**request.json).save() without a whitelist, "
            "the role field is overwritten."
        ),
        "impact": "Privilege escalation, data corruption.",
        "remediation": "Use explicit allow-lists for writable fields.  Never bind raw input to models.",
        "code_example_fix": (
            "# Use a Pydantic model to whitelist fields\n"
            "class UserUpdate(BaseModel):\n"
            "    name: str\n"
            "    email: str\n"
            "    # 'role' is NOT here — can't be mass-assigned"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
        "compliance_tags": "OWASP-API6",
        "detection_pattern": None,
        "false_positive_indicators": "PATCH endpoints that intentionally accept all model fields for admins",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },


    {
        "vuln_id": "NET-001",
        "category": "network",
        "title": "Open Unnecessary Ports",
        "description": (
            "Services listening on unnecessary ports expand the attack surface "
            "and may expose vulnerable or unpatched daemons."
        ),
        "severity": "medium",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp_category": "N/A",
        "how_it_works": "An attacker port-scans the target and finds services (telnet, FTP, RDP) that shouldn't be public.",
        "impact": "Expanded attack surface, potential exploitation of unpatched services.",
        "remediation": (
            "Close or firewall any port not required for the application.  "
            "Implement network segmentation and least-privilege service exposure."
        ),
        "code_example_fix": "# iptables — allow only 80 and 443\niptables -A INPUT -p tcp --dport 80 -j ACCEPT\niptables -A INPUT -p tcp --dport 443 -j ACCEPT\niptables -A INPUT -p tcp -j DROP",
        "cve_ids": None,
        "references": "https://www.cisecurity.org/controls/",
        "compliance_tags": "CIS-9.2,NIS2-Article21,ISO27001-A.13",
        "detection_pattern": None,
        "false_positive_indicators": "Honeypot ports, management ports behind VPN",
        "nis2_control": "Article 21 – Network security",
        "iso27001_control": "A.13 – Communications Security",
    },
    {
        "vuln_id": "NET-002",
        "category": "tls",
        "title": "Weak TLS Configuration",
        "description": (
            "The server supports deprecated TLS versions (SSL 3.0, TLS 1.0/1.1) "
            "or weak cipher suites, enabling downgrade and BEAST/POODLE attacks."
        ),
        "severity": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "how_it_works": (
            "The attacker performs a man-in-the-middle and forces a protocol downgrade "
            "to a version with known vulnerabilities (POODLE, BEAST, CRIME)."
        ),
        "impact": "Traffic decryption, session hijacking, credential theft.",
        "remediation": (
            "Enforce TLS 1.2 minimum, prefer TLS 1.3.  Disable RC4, 3DES, NULL ciphers.  "
            "Use certificate pinning where applicable."
        ),
        "code_example_fix": (
            "# Nginx TLS hardening\n"
            "ssl_protocols TLSv1.2 TLSv1.3;\n"
            "ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\n"
            "ssl_prefer_server_ciphers on;"
        ),
        "cve_ids": "CVE-2014-3566,CVE-2011-3389",
        "references": "https://www.ssllabs.com/projects/best-practices/",
        "compliance_tags": "PCI-DSS-4.1,ISO27001-A.14,NIST-SP800-52",
        "detection_pattern": None,
        "false_positive_indicators": "Internal services that require legacy TLS for compatibility",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14 – System acquisition, development, maintenance",
    },
    {
        "vuln_id": "NET-003",
        "category": "network",
        "title": "DNS Zone Transfer Allowed",
        "description": (
            "The DNS server allows unrestricted zone transfers (AXFR), leaking "
            "the entire domain's DNS records to any requester."
        ),
        "severity": "medium",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp_category": "N/A",
        "how_it_works": "The attacker sends an AXFR query to the nameserver, which responds with every A, CNAME, MX, TXT record.",
        "impact": "Full subdomain enumeration, internal hostname disclosure, easier reconnaissance.",
        "remediation": "Restrict zone transfers to authorised secondary nameservers only.",
        "code_example_fix": "# BIND — restrict AXFR\nallow-transfer { 192.0.2.1; };  // secondary NS only",
        "cve_ids": None,
        "references": "https://www.acunetix.com/blog/articles/dns-zone-transfer-axfr/",
        "compliance_tags": "CIS-9.2,NIS2-Article21",
        "detection_pattern": None,
        "false_positive_indicators": "Intentional public zones (e.g. some CDN providers)",
        "nis2_control": "Article 21",
        "iso27001_control": "A.13",
    },


    {
        "vuln_id": "OSINT-001",
        "category": "osint",
        "title": "Sensitive Information in Public Sources",
        "description": (
            "OSINT reconnaissance reveals sensitive details — exposed employee emails, "
            "leaked credentials, technology stack details, or internal hostnames "
            "visible in certificate transparency logs, GitHub, or Shodan."
        ),
        "severity": "medium",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp_category": "N/A",
        "how_it_works": (
            "The attacker harvests emails via Hunter.io, finds subdomains via crt.sh "
            "and SecurityTrails, discovers open services via Shodan — all without "
            "touching the target directly."
        ),
        "impact": "Targeted phishing, subdomain takeover, expanded attack surface awareness.",
        "remediation": (
            "Monitor CT logs.  Use email aliases for public-facing contacts.  "
            "Regularly audit Shodan and GitHub for leaked assets."
        ),
        "code_example_fix": "# Monitor your org on Shodan\nshodan alert create 'My Org' 203.0.113.0/24",
        "cve_ids": None,
        "references": "https://osintframework.com/",
        "compliance_tags": "NIS2-Article21",
        "detection_pattern": None,
        "false_positive_indicators": "Intentionally public information (marketing pages, open-source projects)",
        "nis2_control": "Article 21",
        "iso27001_control": "A.7 – Human Resource Security",
    },


    {
        "vuln_id": "CVE-001",
        "category": "cve",
        "title": "Known CVE in Detected Component",
        "description": (
            "A software component with a publicly known CVE was identified.  "
            "Exploitation may allow remote code execution, privilege escalation, "
            "or information disclosure depending on the specific CVE."
        ),
        "severity": "critical",
        "cvss_score": 9.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A06:2021 – Vulnerable and Outdated Components",
        "how_it_works": "Publicly available exploit code targets the exact version detected in the target's banners or headers.",
        "impact": "Depends on the CVE — ranges from info disclosure to full RCE.",
        "remediation": (
            "Update affected components to the latest patched version immediately.  "
            "Subscribe to vendor security advisories.  Use SCA tools in CI/CD."
        ),
        "code_example_fix": "# Keep dependencies updated\npip install --upgrade <package>\n\n# Or pin and audit\npip-audit",
        "cve_ids": None,
        "references": "https://nvd.nist.gov/",
        "compliance_tags": "CIS-7.1,PCI-DSS-6.3,OWASP-A06",
        "detection_pattern": None,
        "false_positive_indicators": "Backported patches (RHEL, Debian) where version looks old but is patched",
        "nis2_control": "Article 21",
        "iso27001_control": "A.12.6 – Technical Vulnerability Management",
    },


    {
        "vuln_id": "WEB-010",
        "category": "injection",
        "title": "Insecure Deserialization",
        "description": (
            "The application deserialises untrusted data using pickle, Java "
            "ObjectInputStream, or similar, allowing remote code execution."
        ),
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        "how_it_works": (
            "The attacker crafts a serialised object with a malicious __reduce__ "
            "(Python) or readObject (Java) method.  When deserialised the payload executes."
        ),
        "impact": "Remote code execution, full server compromise.",
        "remediation": (
            "Never deserialise untrusted data.  Use safe formats (JSON).  "
            "If pickle is unavoidable, use hmac-signed payloads and a restricted unpickler."
        ),
        "code_example_fix": (
            "# VULNERABLE\n"
            "data = pickle.loads(request.data)\n\n"
            "# FIXED\n"
            "data = json.loads(request.data)"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "compliance_tags": "OWASP-A08",
        "detection_pattern": r"(pickle\.loads|yaml\.load\(|ObjectInputStream)",
        "false_positive_indicators": "Internal-only services with signed payloads",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },


    {
        "vuln_id": "WEB-011",
        "category": "security_misconfiguration",
        "title": "Insufficient Logging & Monitoring",
        "description": (
            "Security-relevant events (failed logins, access-control failures, "
            "input validation errors) are not logged or monitored, making breaches "
            "harder to detect and investigate."
        ),
        "severity": "medium",
        "cvss_score": 5.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "owasp_category": "A09:2021 – Security Logging and Monitoring Failures",
        "how_it_works": "Without logs, attackers operate undetected for weeks or months.",
        "impact": "Delayed incident response, inability to perform forensics, regulatory fines.",
        "remediation": (
            "Log authentication events, access-control failures, and server-side input "
            "validation failures.  Send logs to a SIEM.  Set up real-time alerting."
        ),
        "code_example_fix": (
            "import logging\n"
            "logger = logging.getLogger('security')\n"
            "logger.warning('Failed login attempt for user=%s from ip=%s', username, request.remote_addr)"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        "compliance_tags": "OWASP-A09,NIS2-Article23,ISO27001-A.12.4",
        "detection_pattern": None,
        "false_positive_indicators": "Logging handled at infrastructure layer (ELK, CloudWatch) not visible to app scanner",
        "nis2_control": "Article 23 – Reporting obligations",
        "iso27001_control": "A.12.4 – Logging and Monitoring",
    },


    {
        "vuln_id": "WEB-012",
        "category": "injection",
        "title": "Path Traversal / Directory Traversal",
        "description": (
            "The application uses user input to construct file paths without "
            "sanitisation, allowing attackers to read arbitrary files."
        ),
        "severity": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp_category": "A01:2021 – Broken Access Control",
        "how_it_works": (
            "The attacker sends ../../etc/passwd in a filename parameter.  "
            "The application's open(base_dir + user_input) resolves to a file "
            "outside the intended directory."
        ),
        "impact": "Read sensitive files (config, credentials, source code).",
        "remediation": (
            "Use os.path.realpath() and verify the result starts with the base directory.  "
            "Use an allow-list of valid filenames."
        ),
        "code_example_fix": (
            "import os\n"
            "real = os.path.realpath(os.path.join(base, user_filename))\n"
            "if not real.startswith(os.path.realpath(base)):\n"
            "    abort(403)"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/www-community/attacks/Path_Traversal",
        "compliance_tags": "OWASP-A01",
        "detection_pattern": r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)",
        "false_positive_indicators": "Relative paths in CSS/JS asset references",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14.2",
    },


    {
        "vuln_id": "WEB-013",
        "category": "security_misconfiguration",
        "title": "Open Redirect",
        "description": (
            "The application redirects users to a URL specified in a parameter "
            "without validating it, enabling phishing attacks."
        ),
        "severity": "low",
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "owasp_category": "A01:2021 – Broken Access Control",
        "how_it_works": (
            "The attacker crafts https://legit.com/redirect?url=https://evil.com.  "
            "The victim trusts the legit domain and clicks through to the phishing site."
        ),
        "impact": "Credential theft via phishing, OAuth token theft.",
        "remediation": "Validate redirect URLs against an allow-list of internal paths.  Never redirect to arbitrary external URLs.",
        "code_example_fix": (
            "from urllib.parse import urlparse\n"
            "parsed = urlparse(redirect_url)\n"
            "if parsed.netloc and parsed.netloc != 'myapp.com':\n"
            "    abort(400)"
        ),
        "cve_ids": None,
        "references": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "compliance_tags": "OWASP-A01",
        "detection_pattern": r"(redirect|url|next|return_to|redir)=https?://",
        "false_positive_indicators": "OAuth callback URLs, legitimate deep links",
        "nis2_control": None,
        "iso27001_control": "A.14.2",
    },


    {
        "vuln_id": "WEB-014",
        "category": "security_misconfiguration",
        "title": "Information Disclosure via Error Messages",
        "description": (
            "Detailed stack traces, database errors, or framework debug pages are "
            "exposed to end users, revealing internal architecture details."
        ),
        "severity": "low",
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "how_it_works": "The attacker triggers an error (invalid input, 404) and reads the stack trace to learn framework, DB, file paths.",
        "impact": "Reconnaissance advantage, targeted exploitation of discovered technologies.",
        "remediation": "Return generic error pages in production.  Log detailed errors server-side only.",
        "code_example_fix": (
            "# Flask — disable debug mode in production\n"
            "app.config['DEBUG'] = False\n"
            "app.config['PROPAGATE_EXCEPTIONS'] = False"
        ),
        "cve_ids": None,
        "references": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/",
        "compliance_tags": "OWASP-A05",
        "detection_pattern": r"(Traceback \(most recent|<b>Warning</b>:|Stack Trace:|Exception in thread)",
        "false_positive_indicators": "Error pages in dev/staging environments not externally accessible",
        "nis2_control": None,
        "iso27001_control": "A.12 – Operations Security",
    },


    {
        "vuln_id": "NET-004",
        "category": "network",
        "title": "Subdomain Takeover",
        "description": (
            "A DNS record (CNAME) points to a third-party service (S3 bucket, "
            "Heroku app, GitHub Pages) that no longer exists, allowing an attacker "
            "to claim it."
        ),
        "severity": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "owasp_category": "N/A",
        "how_it_works": (
            "The attacker finds a dangling CNAME (e.g. blog.example.com → example.herokuapp.com).  "
            "They create a Heroku app with that name and now control the subdomain."
        ),
        "impact": "Phishing under the victim's domain, cookie theft, reputation damage.",
        "remediation": "Audit DNS records regularly.  Remove CNAME entries when decommissioning services.",
        "code_example_fix": "# Check for dangling CNAMEs\ndig +short CNAME blog.example.com\n# If it resolves to a dead service → remove the record",
        "cve_ids": None,
        "references": "https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers",
        "compliance_tags": "NIS2-Article21",
        "detection_pattern": None,
        "false_positive_indicators": "CNAMEs to active services that return expected content",
        "nis2_control": "Article 21",
        "iso27001_control": "A.13",
    },


    {
        "vuln_id": "API-006",
        "category": "api",
        "title": "CORS Misconfiguration",
        "description": (
            "The API sets Access-Control-Allow-Origin to * or reflects the Origin "
            "header without validation, allowing any website to read responses."
        ),
        "severity": "medium",
        "cvss_score": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "how_it_works": (
            "An attacker's site issues a cross-origin fetch to the API.  Because "
            "the API allows any origin, the browser permits reading the response."
        ),
        "impact": "Cross-origin data theft from authenticated API sessions.",
        "remediation": (
            "Set explicit allowed origins.  Never reflect the Origin header blindly.  "
            "Avoid Access-Control-Allow-Credentials with wildcard origins."
        ),
        "code_example_fix": (
            "# Flask-CORS — explicit origins\n"
            "CORS(app, origins=['https://myapp.com', 'https://admin.myapp.com'])"
        ),
        "cve_ids": None,
        "references": "https://portswigger.net/web-security/cors",
        "compliance_tags": "OWASP-A05",
        "detection_pattern": r"Access-Control-Allow-Origin:\s*\*",
        "false_positive_indicators": "Public APIs that intentionally allow all origins",
        "nis2_control": None,
        "iso27001_control": "A.14.2",
    },


    {
        "vuln_id": "WEB-015",
        "category": "security_misconfiguration",
        "title": "Missing or Weak Content Security Policy",
        "description": (
            "The application does not set a Content-Security-Policy header, or "
            "sets one with unsafe-inline / unsafe-eval, failing to mitigate XSS."
        ),
        "severity": "medium",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "how_it_works": "Without CSP, even if an XSS payload lands, there's no browser-level defence to block execution.",
        "impact": "XSS exploitation success rate increases dramatically.",
        "remediation": (
            "Deploy a strict CSP: default-src 'self'; script-src 'self'; style-src 'self'.  "
            "Use nonces or hashes instead of 'unsafe-inline'."
        ),
        "code_example_fix": "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-abc123'; style-src 'self'",
        "cve_ids": None,
        "references": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        "compliance_tags": "OWASP-A05",
        "detection_pattern": None,
        "false_positive_indicators": "CSP set via meta tag instead of header",
        "nis2_control": None,
        "iso27001_control": "A.14.2",
    },


    {
        "vuln_id": "WEB-016",
        "category": "security_misconfiguration",
        "title": "Insecure Cookie Configuration",
        "description": (
            "Session cookies lack Secure, HttpOnly, or SameSite attributes, "
            "making them vulnerable to interception and XSS-based theft."
        ),
        "severity": "medium",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "how_it_works": (
            "Without Secure, cookies travel over HTTP.  Without HttpOnly, JavaScript "
            "can read them.  Without SameSite, they're sent on cross-origin requests."
        ),
        "impact": "Session hijacking via network sniffing or XSS.",
        "remediation": "Set Secure; HttpOnly; SameSite=Strict (or Lax) on all session cookies.",
        "code_example_fix": (
            "# Flask\n"
            "app.config['SESSION_COOKIE_SECURE'] = True\n"
            "app.config['SESSION_COOKIE_HTTPONLY'] = True\n"
            "app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'"
        ),
        "cve_ids": None,
        "references": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        "compliance_tags": "OWASP-A05",
        "detection_pattern": None,
        "false_positive_indicators": "Non-session cookies (analytics, preferences) that intentionally lack HttpOnly",
        "nis2_control": None,
        "iso27001_control": "A.14.2",
    },


    {
        "vuln_id": "NET-005",
        "category": "tls",
        "title": "SSL Certificate Expiring Soon",
        "description": (
            "The target's SSL/TLS certificate expires within 30 days, risking "
            "service disruption and browser security warnings."
        ),
        "severity": "medium",
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "how_it_works": "An expired certificate causes browsers to show scary warnings, which users may click through, or services to break entirely.",
        "impact": "Service outage, user trust erosion, potential MitM if users bypass warnings.",
        "remediation": "Set up automated certificate renewal (Let's Encrypt / certbot).  Monitor expiry dates.",
        "code_example_fix": "# Auto-renew with certbot\ncertbot renew --quiet --deploy-hook 'systemctl reload nginx'",
        "cve_ids": None,
        "references": "https://letsencrypt.org/docs/",
        "compliance_tags": "PCI-DSS-4.1,ISO27001-A.14",
        "detection_pattern": None,
        "false_positive_indicators": "Self-signed certificates in dev environments",
        "nis2_control": "Article 21",
        "iso27001_control": "A.14",
    },
]


COMPLIANCE_MAPPINGS: list[dict] = [
    {
        "framework": "NIS2",
        "control_id": "Article-21",
        "control_title": "Cybersecurity risk management measures",
        "vuln_category": "network",
        "description": "Organisations must implement appropriate technical measures to manage cybersecurity risks.",
    },
    {
        "framework": "NIS2",
        "control_id": "Article-23",
        "control_title": "Reporting obligations",
        "vuln_category": "security_misconfiguration",
        "description": "Significant incidents must be reported to the relevant CSIRT within 24 hours.",
    },
    {
        "framework": "ISO27001",
        "control_id": "A.14.2",
        "control_title": "Security in development and support processes",
        "vuln_category": "injection",
        "description": "Secure development lifecycle including code review and security testing.",
    },
    {
        "framework": "ISO27001",
        "control_id": "A.9",
        "control_title": "Access Control",
        "vuln_category": "authentication",
        "description": "Control access to information and information processing facilities.",
    },
    {
        "framework": "ISO27001",
        "control_id": "A.10",
        "control_title": "Cryptography",
        "vuln_category": "cryptography",
        "description": "Ensure proper and effective use of cryptography to protect confidentiality, integrity and authenticity.",
    },
    {
        "framework": "ISO27001",
        "control_id": "A.12.4",
        "control_title": "Logging and Monitoring",
        "vuln_category": "security_misconfiguration",
        "description": "Record events, generate evidence, and monitor for anomalies.",
    },
    {
        "framework": "ISO27001",
        "control_id": "A.12.6",
        "control_title": "Technical Vulnerability Management",
        "vuln_category": "cve",
        "description": "Obtain timely information about technical vulnerabilities and take appropriate measures.",
    },
    {
        "framework": "ISO27001",
        "control_id": "A.13",
        "control_title": "Communications Security",
        "vuln_category": "tls",
        "description": "Ensure the protection of information in networks and supporting information transfer facilities.",
    },
    {
        "framework": "PCI-DSS",
        "control_id": "6.3",
        "control_title": "Protect web-facing applications against known attacks",
        "vuln_category": "xss",
        "description": "Use a web application firewall and address OWASP Top 10 vulnerabilities.",
    },
    {
        "framework": "PCI-DSS",
        "control_id": "4.1",
        "control_title": "Strong cryptography for transmission",
        "vuln_category": "tls",
        "description": "Use strong cryptography and security protocols to safeguard sensitive data during transmission.",
    },
    {
        "framework": "PCI-DSS",
        "control_id": "8.3",
        "control_title": "Strong authentication for all access",
        "vuln_category": "authentication",
        "description": "Secure all individual non-console administrative access with multi-factor authentication.",
    },
    {
        "framework": "NIST-SP800-53",
        "control_id": "SC-8",
        "control_title": "Transmission Confidentiality and Integrity",
        "vuln_category": "tls",
        "description": "Implement cryptographic mechanisms to prevent unauthorised disclosure of information.",
    },
    {
        "framework": "NIST-SP800-53",
        "control_id": "SI-10",
        "control_title": "Information Input Validation",
        "vuln_category": "injection",
        "description": "Check the validity of information inputs to prevent injection and other input-based attacks.",
    },
    {
        "framework": "OWASP",
        "control_id": "OWASP-A03",
        "control_title": "Injection",
        "vuln_category": "injection",
        "description": "Prevent injection flaws including SQL, NoSQL, OS command, and LDAP injection.",
    },
    {
        "framework": "OWASP",
        "control_id": "OWASP-A03-XSS",
        "control_title": "Cross-Site Scripting",
        "vuln_category": "xss",
        "description": "Prevent XSS by encoding output and validating input.",
    },
    {
        "framework": "OWASP",
        "control_id": "OWASP-A01",
        "control_title": "Broken Access Control",
        "vuln_category": "access_control",
        "description": "Enforce access control policies so users cannot act outside their intended permissions.",
    },
    {
        "framework": "OWASP",
        "control_id": "OWASP-A07",
        "control_title": "Identification and Authentication Failures",
        "vuln_category": "authentication",
        "description": "Confirm the user's identity, authentication, and session management.",
    },
    {
        "framework": "OWASP",
        "control_id": "OWASP-A10",
        "control_title": "Server-Side Request Forgery",
        "vuln_category": "ssrf",
        "description": "Prevent server-side request forgery by validating and restricting outbound requests.",
    },
]


def seed(db_path: str | None = None) -> None:
    init_db(db_path)
    session = get_session(db_path)

    upserted_kb = 0
    for entry in KB_ENTRIES:
        existing = (
            session.query(KnowledgeEntry)
            .filter_by(vuln_id=entry["vuln_id"])
            .first()
        )
        if existing:
            for key, value in entry.items():
                setattr(existing, key, value)
        else:
            session.add(KnowledgeEntry(**entry))
        upserted_kb += 1

    upserted_cm = 0
    for mapping in COMPLIANCE_MAPPINGS:
        existing = (
            session.query(ComplianceMapping)
            .filter_by(framework=mapping["framework"], control_id=mapping["control_id"])
            .first()
        )
        if existing:
            for key, value in mapping.items():
                setattr(existing, key, value)
        else:
            session.add(ComplianceMapping(**mapping))
        upserted_cm += 1

    session.commit()
    session.close()
    print(f"[seed_kb] Upserted {upserted_kb} KB entries and {upserted_cm} compliance mappings.")


if __name__ == "__main__":
    seed()
