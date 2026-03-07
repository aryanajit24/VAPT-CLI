"""Alert dispatch via Slack, Discord, and email."""

from __future__ import annotations

import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import requests
from rich.console import Console

console = Console(stderr=True)


def notify_console(message: str, level: str = "info") -> None:
    """Print a styled notification to the console."""
    style_map = {
        "info": "bold cyan",
        "warning": "bold yellow",
        "error": "bold red",
        "success": "bold green",
    }
    style = style_map.get(level.lower(), "white")
    console.print(f"[{style}][{level.upper()}][/{style}] {message}")


def notify_webhook(
    url: str,
    payload: dict[str, Any],
    timeout: int = 10,
) -> bool:
    """
    POST a JSON payload to a webhook URL.

    Returns True on success, False otherwise.
    """
    try:
        response = requests.post(url, json=payload, timeout=timeout)
        response.raise_for_status()
        return True
    except requests.RequestException as exc:
        console.print(f"[bold red][WEBHOOK ERROR][/bold red] {exc}")
        return False


def notify_slack(
    webhook_url: str,
    text: str,
    risk_level: str = "info",
    timeout: int = 10,
) -> bool:
    """Send a Slack webhook notification."""
    emoji_map = {
        "critical": ":red_circle:",
        "high": ":orange_circle:",
        "medium": ":yellow_circle:",
        "low": ":blue_circle:",
        "info": ":white_circle:",
    }
    emoji = emoji_map.get(risk_level.lower(), ":white_circle:")
    payload = {"text": f"{emoji} *VAPT CLI Alert* — {text}"}
    return notify_webhook(webhook_url, payload, timeout=timeout)


def notify_email(
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    recipient: str,
    subject: str,
    body: str,
    use_tls: bool = True,
) -> bool:
    """
    Send an email notification via SMTP.

    Returns True on success, False otherwise.
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = username
        msg["To"] = recipient
        msg.attach(MIMEText(body, "plain"))

        if use_tls:
            with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                server.login(username, password)
                server.sendmail(username, [recipient], msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.login(username, password)
                server.sendmail(username, [recipient], msg.as_string())
        return True
    except (smtplib.SMTPException, OSError) as exc:
        console.print(f"[bold red][EMAIL ERROR][/bold red] {exc}")
        return False


def dispatch_alerts(
    scan_result: dict[str, Any],
    config: dict[str, Any],
) -> None:
    """
    Fan out notifications to every channel the user has configured.

    Console alerts always fire.  Webhook, Slack, and email only trigger
    if the matching config key is present.  This means zero setup
    is needed for basic usage — fancy integrations are opt-in.
    """
    risk_level = scan_result.get("risk_level", "info")
    target = scan_result.get("target", "unknown")
    score = scan_result.get("overall_score", 0)
    message = f"Scan of {target!r} complete. Risk level: {risk_level.upper()} (score: {score})"

    notify_console(message, level=risk_level if risk_level != "info" else "info")

    if webhook_url := config.get("webhook_url"):
        notify_webhook(webhook_url, scan_result)

    if slack_url := config.get("slack_webhook"):
        notify_slack(slack_url, message, risk_level=risk_level)

    email_cfg = config.get("email", {})
    if email_cfg.get("enabled") and email_cfg.get("recipient"):
        notify_email(
            smtp_host=email_cfg.get("smtp_host", "localhost"),
            smtp_port=int(email_cfg.get("smtp_port", 465)),
            username=email_cfg.get("username", ""),
            password=email_cfg.get("password", ""),
            recipient=email_cfg["recipient"],
            subject=f"VAPT CLI Alert — {risk_level.upper()}",
            body=message,
            use_tls=email_cfg.get("use_tls", True),
        )
