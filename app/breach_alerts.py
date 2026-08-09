"""Breach alert monitoring for Email Validator API (P5.19).

Customers register an email address (plus optional webhook URL) for ongoing
breach monitoring. The background checker re-checks the address against
Have I Been Pwned; when a NEW breach appears (a breach that was not seen on
the previous run), the checker POSTs a webhook payload to the registered URL.

Storage: alert registrations are persisted to a single JSON file on disk
(`data/breach_alerts.json`). Same simple pattern as sanctions monitors.py:
no database, no queue. Documented as NOT production-grade.

Delivery: best-effort. 10s timeout, one retry. Delivery status recorded in
each alert's `history` array.

Endpoints (added to app/main.py):
  POST /alerts/breach        - register a new breach alert
  GET  /alerts/breach/{id}   - get alert status + history
  DELETE /alerts/breach/{id} - cancel an alert
  POST /alerts/breach/run    - run the check cycle (cron-callable)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any

import certifi
import httpx

logger = logging.getLogger("email-validator.breach_alerts")

CACHE_DIR = os.environ.get("EMAIL_VALIDATOR_CACHE_DIR", "data")
ALERTS_PATH = os.path.join(CACHE_DIR, "breach_alerts.json")
WEBHOOK_TIMEOUT = 10.0
HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"


def _load_alerts() -> dict[str, dict[str, Any]]:
    if not os.path.exists(ALERTS_PATH):
        return {}
    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_alerts(alerts: dict[str, dict[str, Any]]) -> None:
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(ALERTS_PATH, "w", encoding="utf-8") as f:
            json.dump(alerts, f, ensure_ascii=False, indent=2)
    except OSError as e:
        logger.warning("breach alerts save failed: %s", e)


def _get_hibp_key() -> str:
    """Load the HIBP API key from env or .env file."""
    key = os.environ.get("HIBP_API_KEY", "")
    if not key:
        for env_path in [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
            "F:/agent-runner/.env",
        ]:
            if not os.path.exists(env_path):
                continue
            try:
                with open(env_path, "r", encoding="utf-8-sig") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("HIBP_API_KEY="):
                            key = line.split("=", 1)[1].strip().strip('"').strip("'")
                            break
            except OSError:
                continue
            if key:
                break
    return key


def _breach_signature(breaches: list[dict[str, Any]]) -> str:
    """Stable fingerprint of the breach set. Detects new breaches."""
    names = sorted(b.get("Name", "") for b in breaches if isinstance(b, dict))
    return hashlib.sha256("|".join(names).encode()).hexdigest()[:16]


def _check_breaches(email: str) -> list[dict[str, Any]]:
    """Query HIBP for breaches affecting the email. Returns [] on error."""
    key = _get_hibp_key()
    if not key:
        return []
    url = HIBP_API_URL.format(email=email)
    headers = {
        "hibp-api-key": key,
        "User-Agent": "EmailValidatorAPI-BreachAlerts",
    }
    try:
        with httpx.Client(
            timeout=10.0, verify=certifi.where(), follow_redirects=True,
            headers=headers,
        ) as c:
            r = c.get(url)
    except (httpx.TimeoutException, httpx.RequestError):
        return []
    if r.status_code == 404:
        return []  # no breaches
    if r.status_code != 200:
        return []
    try:
        data = r.json()
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def _deliver_webhook(url: str, payload: dict[str, Any], secret: str | None = None) -> dict[str, Any]:
    """POST the alert payload to the webhook. Returns delivery status dict."""
    body = json.dumps(payload, ensure_ascii=False).encode()
    headers = {"Content-Type": "application/json"}
    if secret:
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Webhook-Signature"] = sig
    try:
        with httpx.Client(timeout=WEBHOOK_TIMEOUT, verify=certifi.where()) as c:
            r = c.post(url, content=body, headers=headers)
        if 200 <= r.status_code < 300:
            return {"delivered": True, "status": r.status_code}
        # Retry once.
        r2 = c.post(url, content=body, headers=headers)
        if 200 <= r2.status_code < 300:
            return {"delivered": True, "status": r2.status_code, "retried": True}
        return {"delivered": False, "status": r2.status_code, "retried": True}
    except (httpx.TimeoutException, httpx.RequestError) as e:
        return {"delivered": False, "error": str(e)}


def register_alert(email: str, webhook_url: str | None = None, webhook_secret: str | None = None) -> dict[str, Any]:
    """Register a new breach alert subscription. Returns the alert dict."""
    alerts = _load_alerts()
    alert_id = "ba_" + secrets.token_hex(4)
    alerts[alert_id] = {
        "alert_id": alert_id,
        "email": email.lower().strip(),
        "webhook_url": webhook_url,
        "webhook_secret": webhook_secret,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_check": None,
        "last_breach_signature": None,
        "last_breach_count": 0,
        "history": [],
    }
    _save_alerts(alerts)
    return alerts[alert_id]


def get_alert(alert_id: str) -> dict[str, Any] | None:
    return _load_alerts().get(alert_id)


def delete_alert(alert_id: str) -> bool:
    alerts = _load_alerts()
    if alert_id not in alerts:
        return False
    del alerts[alert_id]
    _save_alerts(alerts)
    return True


def run_check_cycle() -> dict[str, Any]:
    """Check all registered alerts for new breaches. Returns summary.

    Cron-callable: POST /alerts/breach/run. For each alert, query HIBP and
    compare the breach signature to the last run. If different, fire webhook.
    """
    alerts = _load_alerts()
    checked = 0
    new_breaches = 0
    delivered = 0
    for alert_id, alert in alerts.items():
        email = alert.get("email")
        if not email:
            continue
        checked += 1
        breaches = _check_breaches(email)
        sig = _breach_signature(breaches)
        last_sig = alert.get("last_breach_signature")
        now = datetime.now(timezone.utc).isoformat()
        alert["last_check"] = now
        alert["last_breach_count"] = len(breaches)

        event = {"at": now, "breaches": len(breaches), "signature": sig}
        if last_sig is None:
            # First check: record baseline, no alert.
            event["event"] = "baseline"
        elif sig != last_sig:
            # New breach detected!
            event["event"] = "new_breach"
            new_breaches += 1
            # Fire webhook if configured.
            webhook_url = alert.get("webhook_url")
            if webhook_url:
                payload = {
                    "event": "new_breach",
                    "email": email,
                    "alert_id": alert_id,
                    "breach_count": len(breaches),
                    "breaches": [b.get("Name") for b in breaches if isinstance(b, dict)],
                    "checked_at": now,
                }
                delivery = _deliver_webhook(webhook_url, payload, alert.get("webhook_secret"))
                event["delivery"] = delivery
                if delivery.get("delivered"):
                    delivered += 1
        else:
            event["event"] = "no_change"

        alert["last_breach_signature"] = sig
        # Keep history bounded (last 50 entries).
        alert["history"] = (alert.get("history") or [])[-49:] + [event]

    _save_alerts(alerts)
    return {
        "checked": checked,
        "new_breaches": new_breaches,
        "webhooks_delivered": delivered,
        "ran_at": datetime.now(timezone.utc).isoformat(),
    }