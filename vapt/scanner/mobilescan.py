"""Mobile application security scanner for Android APK and iOS IPA."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


SECRET_PATTERNS = [
    # AWS
    (r"AKIA[A-Z0-9]{16}", "AWS Access Key"),
    (r"(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", "AWS Secret Key"),
    # Google
    (r"AIza[a-zA-Z0-9_-]{35}", "Google API Key"),
    (r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client"),
    # Firebase
    (r"[a-zA-Z0-9_-]+\.firebaseio\.com", "Firebase Database URL"),
    (r"[a-zA-Z0-9_-]+\.firebaseapp\.com", "Firebase App URL"),
    # Stripe
    (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe Secret Key"),
    (r"pk_live_[a-zA-Z0-9]{24,}", "Stripe Publishable Key"),
    (r"rk_live_[a-zA-Z0-9]{24,}", "Stripe Restricted Key"),
    # Generic
    (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Private Key"),
    (r"-----BEGIN CERTIFICATE-----", "Certificate"),
    (r"Bearer\s+eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+", "JWT Token"),
    # API keys in common formats
    (r"(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]", "API Key"),
    (r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]", "Hardcoded Password"),
    (r"(?:secret|token)\s*[=:]\s*['\"]([a-zA-Z0-9_/+=.:-]{16,})['\"]", "Secret/Token"),
    # Cloud
    (r"https?://[^/]*\.s3\.amazonaws\.com", "S3 Bucket URL"),
    (r"https?://storage\.googleapis\.com/[a-zA-Z0-9._-]+", "GCS Bucket URL"),
    # Twilio
    (r"SK[a-f0-9]{32}", "Twilio API Key"),
    (r"AC[a-f0-9]{32}", "Twilio Account SID"),
    # Slack
    (r"xox[bpors]-[0-9]{10,}-[a-zA-Z0-9-]+", "Slack Token"),
    # GitHub
    (r"gh[ps]_[A-Za-z0-9_]{36,}", "GitHub Token"),
    # SendGrid
    (r"SG\.[a-zA-Z0-9_.-]{22,}\.[a-zA-Z0-9_.-]{22,}", "SendGrid API Key"),
]

# Patterns that are usually false positives (example code, tests, etc.)
FP_INDICATORS = [
    "example", "test", "sample", "dummy", "placeholder",
    "your_api_key", "xxx", "INSERT_", "CHANGE_ME", "<your",
]


class MobileScanner:
    """Mobile application security scanner (Android APK & iOS IPA)."""

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout
        self.findings: list[dict] = []

    def run(self, target: str) -> dict[str, Any]:
        """
        Run mobile security scan on APK or IPA file.

        Args:
            target: Path to APK or IPA file
        """
        target_path = Path(target)
        if not target_path.exists():
            return {"findings": [], "error": f"File not found: {target}"}

        ext = target_path.suffix.lower()
        if ext == ".apk":
            self._scan_android(target_path)
        elif ext == ".ipa":
            self._scan_ios(target_path)
        else:
            return {"findings": [], "error": f"Unsupported file type: {ext}. Expected .apk or .ipa"}

        return {"findings": self.findings}

    # ANDROID APK ANALYSIS

    def _scan_android(self, apk_path: Path) -> None:
        """Full static analysis of Android APK."""
        tmpdir = tempfile.mkdtemp(prefix="vapt_apk_")
        try:
            # Extract APK (it's a ZIP)
            with zipfile.ZipFile(apk_path, "r") as zf:
                zf.extractall(tmpdir)

            extracted = Path(tmpdir)

            # Parse AndroidManifest.xml (try plaintext first, then binary)
            manifest = self._parse_android_manifest(extracted, apk_path)
            if manifest:
                self._check_exported_components(manifest, apk_path)
                self._check_backup_enabled(manifest, apk_path)
                self._check_debuggable(manifest, apk_path)
                self._check_cleartext_traffic(manifest, apk_path)
                self._check_deeplinks(manifest, apk_path)
                self._check_permissions(manifest, apk_path)

            # Decompile with jadx if available
            source_dir = self._decompile_with_jadx(apk_path, tmpdir)

            # Search for secrets in all text content
            self._search_secrets_in_dir(
                source_dir or extracted, apk_path, "android"
            )

            # Check network security config
            self._check_network_security_config(extracted, apk_path)

            # Check for WebView usage patterns
            if source_dir:
                self._check_webview_android(source_dir, apk_path)

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _parse_android_manifest(self, extracted: Path, apk_path: Path) -> ElementTree.Element | None:
        """Parse AndroidManifest.xml from extracted APK."""
        # Try to use aapt2 or aapt for binary XML
        manifest_path = extracted / "AndroidManifest.xml"
        if not manifest_path.exists():
            return None

        # Try parsing as plaintext XML first
        try:
            tree = ElementTree.parse(manifest_path)
            return tree.getroot()
        except ElementTree.ParseError:
            pass

        # Binary XML — use aapt if available
        for tool in ("aapt2", "aapt"):
            if shutil.which(tool):
                try:
                    result = subprocess.run(
                        [tool, "dump", "xmltree", str(apk_path), "AndroidManifest.xml"],
                        capture_output=True, text=True, timeout=30,
                    )
                    if result.returncode == 0:
                        # Parse aapt output for key attributes
                        self._parse_aapt_manifest(result.stdout, apk_path)
                        return None  # Already processed via aapt
                except (subprocess.SubprocessError, OSError):
                    pass

        # Try apktool if available
        if shutil.which("apktool"):
            try:
                apktool_dir = extracted / "apktool_out"
                subprocess.run(
                    ["apktool", "d", str(apk_path), "-o", str(apktool_dir), "-f", "-s"],
                    capture_output=True, timeout=60,
                )
                decoded_manifest = apktool_dir / "AndroidManifest.xml"
                if decoded_manifest.exists():
                    tree = ElementTree.parse(decoded_manifest)
                    return tree.getroot()
            except (subprocess.SubprocessError, ElementTree.ParseError, OSError):
                pass

        return None

    def _parse_aapt_manifest(self, output: str, apk_path: Path) -> None:
        """Parse aapt dump output for security-relevant attributes."""
        lines = output.lower()

        if "android:debuggable" in lines and 'true' in lines.split("debuggable")[1][:50]:
            self.findings.append(self._make_finding(
                vuln_id="ANDROID-009", title="Debug Mode Enabled in Production APK",
                severity="high", target=str(apk_path),
                evidence="android:debuggable=true found in AndroidManifest.xml via aapt",
                category="mobile_android",
            ))

        if "android:allowbackup" in lines and 'true' in lines.split("allowbackup")[1][:50]:
            self.findings.append(self._make_finding(
                vuln_id="ANDROID-008", title="App Backup Enabled (android:allowBackup=true)",
                severity="medium", target=str(apk_path),
                evidence="android:allowBackup=true in AndroidManifest.xml",
                category="mobile_android",
            ))

        # Check for exported components
        if "exported" in lines and "true" in lines:
            self.findings.append(self._make_finding(
                vuln_id="ANDROID-002", title="Exported Components Found",
                severity="medium", target=str(apk_path),
                evidence="One or more components with exported=true found in manifest",
                category="mobile_android",
            ))

    def _check_exported_components(self, root: ElementTree.Element, apk_path: Path) -> None:
        """Check for exported Activities, Services, Receivers, Providers."""
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        component_types = ["activity", "service", "receiver", "provider"]
        exported = []

        for comp_type in component_types:
            for comp in root.iter(comp_type):
                name = comp.get(f"{{{ns['android']}}}name", comp.get("android:name", ""))
                is_exported = comp.get(f"{{{ns['android']}}}exported", comp.get("android:exported", ""))

                # Components with intent-filters are exported by default (pre-Android 12)
                has_intent_filter = comp.find("intent-filter") is not None

                if is_exported == "true" or (has_intent_filter and is_exported != "false"):
                    exported.append(f"{comp_type}: {name}")

        if exported:
            self.findings.append(self._make_finding(
                vuln_id="ANDROID-002",
                title=f"Exported Components ({len(exported)} found)",
                severity="high" if len(exported) > 5 else "medium",
                target=str(apk_path),
                evidence=f"Exported components:\n" + "\n".join(f"  - {c}" for c in exported[:20]),
                category="mobile_android",
                remediation="Set exported=false for components that don't need external access. Add permission requirements.",
            ))

    def _check_backup_enabled(self, root: ElementTree.Element, apk_path: Path) -> None:
        """Check if app allows backup."""
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        app = root.find("application")
        if app is not None:
            backup = app.get(f"{{{ns['android']}}}allowBackup", app.get("android:allowBackup", ""))
            if backup.lower() == "true":
                self.findings.append(self._make_finding(
                    vuln_id="ANDROID-008",
                    title="App Backup Enabled (android:allowBackup=true)",
                    severity="medium",
                    target=str(apk_path),
                    evidence="android:allowBackup=true in AndroidManifest.xml allows ADB backup of app data.",
                    category="mobile_android",
                    remediation="Set android:allowBackup=\"false\" in AndroidManifest.xml.",
                ))

    def _check_debuggable(self, root: ElementTree.Element, apk_path: Path) -> None:
        """Check if app is debuggable."""
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        app = root.find("application")
        if app is not None:
            debuggable = app.get(f"{{{ns['android']}}}debuggable", app.get("android:debuggable", ""))
            if debuggable.lower() == "true":
                self.findings.append(self._make_finding(
                    vuln_id="ANDROID-009",
                    title="Debug Mode Enabled in Production APK",
                    severity="high",
                    target=str(apk_path),
                    evidence="android:debuggable=true — app can be debugged with ADB, enabling memory inspection and method hooking.",
                    category="mobile_android",
                    remediation="Set android:debuggable=\"false\" in release builds.",
                ))

    def _check_cleartext_traffic(self, root: ElementTree.Element, apk_path: Path) -> None:
        """Check for cleartext (HTTP) traffic allowance."""
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        app = root.find("application")
        if app is not None:
            cleartext = app.get(
                f"{{{ns['android']}}}usesCleartextTraffic",
                app.get("android:usesCleartextTraffic", "")
            )
            if cleartext.lower() == "true":
                self.findings.append(self._make_finding(
                    vuln_id="ANDROID-003",
                    title="Cleartext HTTP Traffic Allowed",
                    severity="high",
                    target=str(apk_path),
                    evidence="android:usesCleartextTraffic=true — app allows unencrypted HTTP traffic, enabling MITM.",
                    category="mobile_android",
                    remediation="Set usesCleartextTraffic=\"false\". Use network security config to allow specific domains only.",
                ))

    def _check_deeplinks(self, root: ElementTree.Element, apk_path: Path) -> None:
        """Extract and analyze deeplink schemes."""
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        deeplinks = []

        for activity in root.iter("activity"):
            name = activity.get(f"{{{ns['android']}}}name", activity.get("android:name", ""))
            for intent_filter in activity.iter("intent-filter"):
                for data in intent_filter.iter("data"):
                    scheme = data.get(f"{{{ns['android']}}}scheme", data.get("android:scheme", ""))
                    host = data.get(f"{{{ns['android']}}}host", data.get("android:host", ""))
                    path = data.get(f"{{{ns['android']}}}path", data.get("android:path", ""))
                    if scheme and scheme not in ("http", "https"):
                        deeplinks.append(f"{scheme}://{host}{path} → {name}")

        if deeplinks:
            self.findings.append(self._make_finding(
                vuln_id="ANDROID-007",
                title=f"Custom Deeplink Schemes ({len(deeplinks)} found)",
                severity="medium",
                target=str(apk_path),
                evidence=f"Deeplink schemes:\n" + "\n".join(f"  - {dl}" for dl in deeplinks[:15]),
                category="mobile_android",
                remediation="Validate deeplink parameters. Prefer App Links (verified HTTPS) over custom schemes.",
            ))

    def _check_permissions(self, root: ElementTree.Element, apk_path: Path) -> None:
        """Check for dangerous permissions."""
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        dangerous_perms = {
            "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION", "READ_CONTACTS", "WRITE_CONTACTS",
            "READ_SMS", "SEND_SMS", "READ_CALL_LOG", "WRITE_CALL_LOG",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
            "ACCESS_BACKGROUND_LOCATION", "READ_PHONE_STATE",
        }
        found_dangerous = []
        for perm in root.iter("uses-permission"):
            name = perm.get(f"{{{ns['android']}}}name", perm.get("android:name", ""))
            short = name.split(".")[-1]
            if short in dangerous_perms:
                found_dangerous.append(name)

        if found_dangerous:
            self.findings.append(self._make_finding(
                vuln_id="ANDROID-001",
                title=f"Dangerous Permissions Requested ({len(found_dangerous)})",
                severity="low",
                target=str(apk_path),
                evidence="Dangerous permissions:\n" + "\n".join(f"  - {p}" for p in found_dangerous),
                category="mobile_android",
                remediation="Review each permission for necessity. Request permissions at runtime, not upfront.",
            ))

    def _check_network_security_config(self, extracted: Path, apk_path: Path) -> None:
        """Check network_security_config.xml for insecure settings."""
        config_path = extracted / "res" / "xml" / "network_security_config.xml"
        if not config_path.exists():
            return

        try:
            content = config_path.read_text(errors="ignore")
            if "cleartextTrafficPermitted" in content and '"true"' in content:
                self.findings.append(self._make_finding(
                    vuln_id="ANDROID-003",
                    title="Network Security Config Allows Cleartext Traffic",
                    severity="medium",
                    target=str(apk_path),
                    evidence=f"network_security_config.xml allows cleartext:\n{content[:500]}",
                    category="mobile_android",
                ))
            if "<trust-anchors>" in content and "user" in content:
                self.findings.append(self._make_finding(
                    vuln_id="ANDROID-005",
                    title="Network Security Config Trusts User Certificates",
                    severity="medium",
                    target=str(apk_path),
                    evidence=f"Config trusts user-installed CA certs (proxy interception possible):\n{content[:500]}",
                    category="mobile_android",
                ))
        except OSError:
            pass

    def _check_webview_android(self, source_dir: Path, apk_path: Path) -> None:
        """Check for insecure WebView patterns in decompiled source."""
        dangerous_patterns = [
            (r"\.addJavascriptInterface\(", "addJavascriptInterface — JS-to-native bridge"),
            (r"setJavaScriptEnabled\(\s*true\s*\)", "JavaScript enabled in WebView"),
            (r"setAllowFileAccess\(\s*true\s*\)", "File access enabled in WebView"),
            (r"setAllowUniversalAccessFromFileURLs\(\s*true\s*\)", "Universal file access in WebView"),
            (r"setAllowFileAccessFromFileURLs\(\s*true\s*\)", "File-to-file access in WebView"),
        ]

        issues = []
        for java_file in source_dir.rglob("*.java"):
            try:
                content = java_file.read_text(errors="ignore")
                for pattern, desc in dangerous_patterns:
                    if re.search(pattern, content):
                        issues.append(f"{desc} in {java_file.name}")
            except OSError:
                continue

        if issues:
            severity = "high" if any("addJavascriptInterface" in i for i in issues) else "medium"
            self.findings.append(self._make_finding(
                vuln_id="ANDROID-006",
                title=f"Insecure WebView Configuration ({len(issues)} issues)",
                severity=severity,
                target=str(apk_path),
                evidence="WebView issues:\n" + "\n".join(f"  - {i}" for i in issues[:15]),
                category="mobile_android",
                remediation=(
                    "Avoid addJavascriptInterface on API < 17. Disable file access. "
                    "Validate all URLs loaded in WebView. Use @JavascriptInterface annotation."
                ),
            ))

    def _decompile_with_jadx(self, apk_path: Path, tmpdir: str) -> Path | None:
        """Decompile APK to Java source with jadx."""
        if not shutil.which("jadx"):
            return None

        out_dir = Path(tmpdir) / "jadx_out"
        try:
            subprocess.run(
                ["jadx", "-d", str(out_dir), str(apk_path), "--no-imports", "--no-debug-info"],
                capture_output=True, timeout=120,
            )
            if out_dir.exists():
                return out_dir
        except (subprocess.SubprocessError, OSError):
            pass
        return None

    # iOS IPA ANALYSIS

    def _scan_ios(self, ipa_path: Path) -> None:
        """Full static analysis of iOS IPA."""
        tmpdir = tempfile.mkdtemp(prefix="vapt_ipa_")
        try:
            # IPA is a ZIP file
            with zipfile.ZipFile(ipa_path, "r") as zf:
                zf.extractall(tmpdir)

            extracted = Path(tmpdir)
            payload = extracted / "Payload"
            if not payload.exists():
                return

            # Find .app directory
            app_dirs = list(payload.glob("*.app"))
            if not app_dirs:
                return
            app_dir = app_dirs[0]

            # Parse Info.plist
            self._check_info_plist(app_dir, ipa_path)

            # Search for secrets in all files
            self._search_secrets_in_dir(app_dir, ipa_path, "ios")

            # Check binary strings
            self._check_binary_strings(app_dir, ipa_path)

            # Check for entitlements
            self._check_entitlements(app_dir, ipa_path)

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _check_info_plist(self, app_dir: Path, ipa_path: Path) -> None:
        """Analyze Info.plist for security issues."""
        plist_path = app_dir / "Info.plist"
        if not plist_path.exists():
            return

        try:
            # Try using plutil to convert to XML
            result = subprocess.run(
                ["plutil", "-convert", "xml1", "-o", "-", str(plist_path)],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return

            content = result.stdout

            # Check ATS exceptions
            if "NSAppTransportSecurity" in content:
                if "NSAllowsArbitraryLoads" in content and "<true/>" in content.split("NSAllowsArbitraryLoads")[1][:100]:
                    self.findings.append(self._make_finding(
                        vuln_id="IOS-003",
                        title="App Transport Security Disabled (NSAllowsArbitraryLoads=true)",
                        severity="high",
                        target=str(ipa_path),
                        evidence="Info.plist has NSAllowsArbitraryLoads=true. All cleartext HTTP traffic allowed.",
                        category="mobile_ios",
                        remediation="Remove NSAllowsArbitraryLoads. Add specific domain exceptions if needed.",
                    ))
                elif "NSExceptionAllowsInsecureHTTPLoads" in content:
                    self.findings.append(self._make_finding(
                        vuln_id="IOS-003",
                        title="ATS Exceptions Allow Insecure HTTP for Specific Domains",
                        severity="medium",
                        target=str(ipa_path),
                        evidence="Domain-specific ATS exceptions found in Info.plist.",
                        category="mobile_ios",
                    ))

            # Check URL schemes
            if "CFBundleURLSchemes" in content:
                schemes = re.findall(r"<string>([^<]+)</string>", content.split("CFBundleURLSchemes")[1][:500])
                custom_schemes = [s for s in schemes if s not in ("http", "https", "mailto", "tel")]
                if custom_schemes:
                    self.findings.append(self._make_finding(
                        vuln_id="IOS-004",
                        title=f"Custom URL Schemes ({len(custom_schemes)} found)",
                        severity="medium",
                        target=str(ipa_path),
                        evidence=f"URL schemes: {', '.join(custom_schemes)}",
                        category="mobile_ios",
                        remediation="Prefer Universal Links over custom URL schemes. Validate all URL scheme input.",
                    ))

        except (subprocess.SubprocessError, OSError):
            pass

    def _check_binary_strings(self, app_dir: Path, ipa_path: Path) -> None:
        """Run strings on binary to find secrets."""
        # Find the main binary (same name as .app directory without extension)
        app_name = app_dir.stem
        binary_path = app_dir / app_name
        if not binary_path.exists():
            # Try finding any Mach-O binary
            for f in app_dir.iterdir():
                if f.is_file() and not f.suffix:
                    try:
                        with open(f, "rb") as fh:
                            magic = fh.read(4)
                            if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
                                binary_path = f
                                break
                    except OSError:
                        continue

        if binary_path.exists():
            try:
                result = subprocess.run(
                    ["strings", str(binary_path)],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    self._scan_text_for_secrets(result.stdout, str(binary_path), ipa_path, "ios")
            except (subprocess.SubprocessError, OSError):
                pass

    def _check_entitlements(self, app_dir: Path, ipa_path: Path) -> None:
        """Check for dangerous entitlements."""
        # Look for embedded.mobileprovision
        provision = app_dir / "embedded.mobileprovision"
        if provision.exists():
            try:
                result = subprocess.run(
                    ["security", "cms", "-D", "-i", str(provision)],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    content = result.stdout
                    dangerous = [
                        "get-task-allow",
                        "com.apple.private",
                    ]
                    for d in dangerous:
                        if d in content and "<true/>" in content.split(d)[1][:50]:
                            self.findings.append(self._make_finding(
                                vuln_id="IOS-005",
                                title=f"Dangerous Entitlement: {d}",
                                severity="high" if d == "get-task-allow" else "medium",
                                target=str(ipa_path),
                                evidence=f"Entitlement {d} is true in provisioning profile.",
                                category="mobile_ios",
                            ))
            except (subprocess.SubprocessError, OSError):
                pass

    # SHARED UTILITIES

    def _search_secrets_in_dir(self, directory: Path, target_path: Path, platform: str) -> None:
        """Recursively search for secrets in all text files."""
        text_extensions = {
            ".java", ".kt", ".swift", ".m", ".h", ".xml", ".json",
            ".plist", ".yaml", ".yml", ".properties", ".gradle",
            ".strings", ".js", ".html", ".txt", ".cfg", ".conf",
        }

        for fpath in directory.rglob("*"):
            if not fpath.is_file() or fpath.suffix.lower() not in text_extensions:
                continue
            if fpath.stat().st_size > 5_000_000:  # Skip files > 5MB
                continue

            try:
                content = fpath.read_text(errors="ignore")
                self._scan_text_for_secrets(content, str(fpath), target_path, platform)
            except OSError:
                continue

    def _scan_text_for_secrets(
        self, content: str, source_file: str, target_path: Path, platform: str,
    ) -> None:
        """Scan text content for hardcoded secrets."""
        vuln_id = "ANDROID-004" if platform == "android" else "IOS-002"
        category = f"mobile_{platform}"

        for pattern, secret_type in SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            if not matches:
                continue

            # Filter false positives
            real_matches = []
            for match in matches[:5]:  # Limit per pattern per file
                match_str = match if isinstance(match, str) else str(match)
                if not any(fp in match_str.lower() for fp in FP_INDICATORS):
                    real_matches.append(match_str)

            if real_matches:
                self.findings.append(self._make_finding(
                    vuln_id=vuln_id,
                    title=f"Hardcoded {secret_type} in {Path(source_file).name}",
                    severity="high",
                    target=str(target_path),
                    evidence=(
                        f"Secret type: {secret_type}\n"
                        f"File: {source_file}\n"
                        f"Matches: {', '.join(m[:20] + '...' for m in real_matches)}"
                    ),
                    category=category,
                    remediation=(
                        f"Remove hardcoded {secret_type}. Use secure storage (Android Keystore / iOS Keychain). "
                        "Rotate the exposed credential immediately."
                    ),
                ))

    def _make_finding(
        self,
        vuln_id: str,
        title: str,
        severity: str,
        target: str,
        evidence: str,
        category: str,
        remediation: str = "",
    ) -> dict:
        """Build a standardized finding dict."""
        cvss_map = {
            "critical": 9.5, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0,
        }
        return {
            "vuln_id": vuln_id,
            "title": title,
            "severity": severity,
            "cvss_score": cvss_map.get(severity, 0),
            "category": category,
            "url": target,
            "evidence": evidence,
            "remediation": remediation,
            "scanner": "mobilescan",
            "confidence": 0.85,
        }
