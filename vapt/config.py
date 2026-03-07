"""Configuration management with encrypted storage."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

import requests
import typer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

# Where all VAPT config files live.  Created automatically on first run.
CONFIG_DIR = Path.home() / ".vapt"
CONFIG_FILE = CONFIG_DIR / "config.json"
ENC_FILE = CONFIG_DIR / "config.enc"   # encrypted API keys (AES-256-GCM)
KEY_FILE = CONFIG_DIR / ".key"         # encryption key (chmod 0600)

console = Console()

# Each entry describes one API key the tool can use.  The setup wizard
# iterates over this list, prompts the user, and validates live.
API_KEY_DEFINITIONS: list[dict] = [
    {
        "name": "SHODAN_API_KEY",
        "internal": "shodan",
        "label": "Shodan",
        "purpose": "External asset discovery and exposed service detection",
        "url": "https://shodan.io",
        "validator": "_validate_shodan",
    },
    {
        "name": "VIRUSTOTAL_API_KEY",
        "internal": "virustotal",
        "label": "VirusTotal",
        "purpose": "Malware and reputation checking of IPs and domains",
        "url": "https://virustotal.com",
        "validator": "_validate_virustotal",
    },
    {
        "name": "SECURITYTRAILS_API_KEY",
        "internal": "securitytrails",
        "label": "SecurityTrails",
        "purpose": "Historical DNS, subdomain enumeration and asset discovery",
        "url": "https://securitytrails.com",
        "validator": "_validate_securitytrails",
    },
    {
        "name": "HUNTER_API_KEY",
        "internal": "hunter",
        "label": "Hunter.io",
        "purpose": "Email harvesting and OSINT during recon phase",
        "url": "https://hunter.io",
        "validator": "_validate_hunter",
    },
    {
        "name": "NVD_API_KEY",
        "internal": "nvd",
        "label": "NVD (National Vulnerability Database)",
        "purpose": "CVE lookups with full CVSS data from NIST",
        "url": "https://nvd.nist.gov/developers/request-an-api-key",
        "validator": None,  # NVD API key not easily testable without a query
    },
    {
        "name": "SENDGRID_API_KEY",
        "internal": "sendgrid",
        "label": "SendGrid (optional)",
        "purpose": "Emailing reports automatically after scan completion",
        "url": "https://sendgrid.com",
        "validator": "_validate_sendgrid",
        "optional": True,
    },
]


# AES-256-GCM provides both confidentiality and integrity.  The 12-byte
# nonce is prepended to the ciphertext so we can decrypt in one step.

def _get_or_create_key() -> bytes:
    """Return the AES-256 encryption key, creating it on first run.

    The key file is chmod 0600 so only the current user can read it.
    """
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = AESGCM.generate_key(bit_length=256)
    KEY_FILE.write_bytes(key)
    KEY_FILE.chmod(0o600)
    return key


def _encrypt(plaintext: str) -> str:
    """Encrypt a string value using AES-256-GCM and return base64-encoded ciphertext."""
    key = _get_or_create_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def _decrypt(token: str) -> str:
    """Decrypt a value previously encrypted by _encrypt."""
    key = _get_or_create_key()
    aesgcm = AESGCM(key)
    raw = base64.b64decode(token)
    nonce, ciphertext = raw[:12], raw[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


def _load_enc() -> dict[str, Any]:
    """Load encrypted config (API keys) from config.enc."""
    if not ENC_FILE.exists():
        return {}
    try:
        return json.loads(_decrypt(ENC_FILE.read_text()))
    except Exception:
        return {}


def _save_enc(data: dict[str, Any]) -> None:
    """Write encrypted config to config.enc."""
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    ENC_FILE.write_text(_encrypt(json.dumps(data, indent=2)))
    ENC_FILE.chmod(0o600)


def load_config() -> dict[str, Any]:
    """Load non-sensitive configuration from disk. Returns empty dict if not found."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_config(cfg: dict[str, Any]) -> None:
    """Persist non-sensitive configuration to disk."""
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    CONFIG_FILE.chmod(0o600)


def get_api_key(name: str) -> str | None:
    """Retrieve and decrypt an API key by its internal name.

    Returns None if the key isn't configured or decryption fails
    (e.g. the .key file was regenerated).  Callers should always
    handle None gracefully.
    """
    enc_data = _load_enc()
    encrypted = enc_data.get("api_keys", {}).get(name)
    if encrypted is None:
        return None
    try:
        return _decrypt(encrypted)
    except Exception:
        return None


def set_api_key(name: str, value: str) -> None:
    """Encrypt and store an API key by its internal name."""
    enc_data = _load_enc()
    enc_data.setdefault("api_keys", {})[name] = _encrypt(value)
    _save_enc(enc_data)


# Each validator hits a lightweight endpoint on the provider's API
# to confirm the key is active.  This gives immediate feedback in
# the setup wizard rather than failing silently during a scan.

def _validate_shodan(key: str) -> tuple[bool, str]:
    """Verify the Shodan API key with a lightweight account info call."""
    try:
        r = requests.get(
            f"https://api.shodan.io/api-info?key={key}", timeout=8
        )
        if r.status_code == 200:
            return True, "Shodan key valid."
        return False, f"Shodan rejected key (HTTP {r.status_code})."
    except requests.RequestException as exc:
        return False, f"Network error validating Shodan key: {exc}"


def _validate_virustotal(key: str) -> tuple[bool, str]:
    """Verify the VirusTotal API key with a lightweight ping call."""
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/users/me",
            headers={"x-apikey": key},
            timeout=8,
        )
        if r.status_code == 200:
            return True, "VirusTotal key valid."
        return False, f"VirusTotal rejected key (HTTP {r.status_code})."
    except requests.RequestException as exc:
        return False, f"Network error validating VirusTotal key: {exc}"


def _validate_securitytrails(key: str) -> tuple[bool, str]:
    """Verify the SecurityTrails API key with a ping call."""
    try:
        r = requests.get(
            "https://api.securitytrails.com/v1/ping",
            headers={"APIKEY": key},
            timeout=8,
        )
        if r.status_code == 200:
            return True, "SecurityTrails key valid."
        return False, f"SecurityTrails rejected key (HTTP {r.status_code})."
    except requests.RequestException as exc:
        return False, f"Network error validating SecurityTrails key: {exc}"


def _validate_hunter(key: str) -> tuple[bool, str]:
    """Verify the Hunter.io API key with an account call."""
    try:
        r = requests.get(
            f"https://api.hunter.io/v2/account?api_key={key}", timeout=8
        )
        if r.status_code == 200:
            return True, "Hunter.io key valid."
        return False, f"Hunter.io rejected key (HTTP {r.status_code})."
    except requests.RequestException as exc:
        return False, f"Network error validating Hunter.io key: {exc}"


def _validate_sendgrid(key: str) -> tuple[bool, str]:
    """Verify the SendGrid API key."""
    try:
        r = requests.get(
            "https://api.sendgrid.com/v3/user/account",
            headers={"Authorization": f"Bearer {key}"},
            timeout=8,
        )
        if r.status_code == 200:
            return True, "SendGrid key valid."
        return False, f"SendGrid rejected key (HTTP {r.status_code})."
    except requests.RequestException as exc:
        return False, f"Network error validating SendGrid key: {exc}"


_VALIDATORS: dict[str, Any] = {
    "_validate_shodan": _validate_shodan,
    "_validate_virustotal": _validate_virustotal,
    "_validate_securitytrails": _validate_securitytrails,
    "_validate_hunter": _validate_hunter,
    "_validate_sendgrid": _validate_sendgrid,
}


# The wizard runs on first use (or `vapt config setup`).  It walks
# users through each API key, validates live, and saves encrypted.

def run_setup_wizard() -> None:  # noqa: C901
    """Interactive guided configuration wizard.

    Prompts for general settings (output dir, threads, timeouts) then
    walks through each API key, validating against the provider before
    encrypting and saving.
    """
    console.print(
        Panel.fit(
            "[bold cyan]VAPT CLI — First-Run Configuration Wizard[/bold cyan]\n"
            "[dim]All API keys are stored AES-256 encrypted in ~/.vapt/config.enc[/dim]",
            border_style="cyan",
        )
    )

    cfg = load_config()

    console.print("\n[bold]General Settings[/bold]")

    cfg["output_dir"] = Prompt.ask(
        "Default output directory for reports",
        default=cfg.get("output_dir", str(Path.home() / "vapt-reports")),
    )

    cfg["default_format"] = Prompt.ask(
        "Default report format",
        choices=["pdf", "html", "json"],
        default=cfg.get("default_format", "html"),
    )

    cfg["threads"] = int(
        Prompt.ask("Max concurrent scan threads", default=str(cfg.get("threads", 10)))
    )

    cfg["timeout"] = int(
        Prompt.ask("Network request timeout (seconds)", default=str(cfg.get("timeout", 10)))
    )

    cfg["notification_email"] = Prompt.ask(
        "Notification email address (for reports)",
        default=cfg.get("notification_email", ""),
    )

    console.print("\n[bold]API Key Setup[/bold]")
    console.print("[dim]Each key is validated live before saving.[/dim]\n")

    for key_def in API_KEY_DEFINITIONS:
        is_optional = key_def.get("optional", False)
        label = key_def["label"]
        purpose = key_def["purpose"]
        get_url = key_def["url"]

        console.print(
            f"[bold yellow]{key_def['name']}[/bold yellow]"
            f"{'  [dim](optional)[/dim]' if is_optional else ''}"
        )
        console.print(f"  Purpose : {purpose}")
        console.print(f"  Get it  : [link={get_url}]{get_url}[/link]")

        raw = Prompt.ask(
            f"  Enter {label} API key (blank to skip)",
            default="",
            password=True,
        )
        raw = raw.strip()

        if not raw:
            console.print(f"  [dim]Skipped {label}.[/dim]\n")
            continue

        # Validate if a validator is defined
        validator_name = key_def.get("validator")
        if validator_name and validator_name in _VALIDATORS:
            console.print(f"  [dim]Validating {label} key…[/dim]")
            ok, msg = _VALIDATORS[validator_name](raw)
            if ok:
                console.print(f"  [green]✓ {msg}[/green]")
            else:
                console.print(f"  [yellow]⚠ {msg}[/yellow]")
                retry = Prompt.ask("  Save anyway?", choices=["y", "n"], default="n")
                if retry == "n":
                    console.print(f"  [dim]Skipped {label}.[/dim]\n")
                    continue
        else:
            console.print(f"  [dim]No live validation available for {label}; saving as-is.[/dim]")

        set_api_key(key_def["internal"], raw)
        console.print(f"  [green]✓ {label} key saved (encrypted).[/green]\n")

    save_config(cfg)
    console.print(
        f"\n[bold green]✓ Configuration saved![/bold green]\n"
        f"  Settings  → {CONFIG_FILE}\n"
        f"  API keys  → {ENC_FILE} (AES-256-GCM encrypted)"
    )


app = typer.Typer(help="Manage VAPT CLI configuration.")


@app.command("show")
def cmd_show() -> None:
    """Display current configuration (keys are masked)."""
    cfg = load_config()
    enc_data = _load_enc()
    if not cfg and not enc_data:
        console.print("[yellow]No configuration found. Run 'vapt config --setup' first.[/yellow]")
        return
    display = dict(cfg)
    if "api_keys" in enc_data:
        display["api_keys"] = {k: "***" for k in enc_data["api_keys"]}
    console.print_json(json.dumps(display, indent=2))


@app.command("setup")
def cmd_setup() -> None:
    """Run the interactive setup wizard."""
    run_setup_wizard()


@app.command("set")
def cmd_set(key: str = typer.Argument(...), value: str = typer.Argument(...)) -> None:
    """Set a configuration value: vapt config set <key> <value>."""
    cfg = load_config()
    cfg[key] = value
    save_config(cfg)
    console.print(f"[green]Set {key} = {value}[/green]")


@app.command("set-key")
def cmd_set_key(
    name: str = typer.Argument(..., help="Internal key name e.g. shodan, virustotal"),
    value: str = typer.Argument(...),
) -> None:
    """Update a single API key: vapt config set-key shodan <KEY>."""
    set_api_key(name, value)
    console.print(f"[green]API key '{name}' updated (encrypted).[/green]")
