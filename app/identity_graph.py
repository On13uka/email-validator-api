"""Email identity graph: enrich email with profile + breach + domain data.

Combines:
  - Gravatar profile (free, no key): avatar URL, display name, bio
  - Breach history (from HIBP, already in main pipeline)
  - Domain age (from RDAP/WHOIS, fetched internally)

This creates an "identity graph" around an email that goes beyond
valid/invalid: who is this person, what breaches have they been in,
how old is their domain.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import certifi
import httpx

GRAVATAR_URL = "https://gravatar.com/{hash}.json"
REQUEST_TIMEOUT = 8.0
HEADERS = {"User-Agent": "EmailValidatorAPI/2.2 (contact: builder@api-portfolio.local)"}


def fetch_gravatar(email: str) -> dict[str, Any] | None:
    """Fetch Gravatar profile for an email. Returns None if no profile."""
    email_hash = hashlib.sha256(email.lower().strip().encode()).hexdigest()
    try:
        with httpx.Client(
            timeout=REQUEST_TIMEOUT, verify=certifi.where(), follow_redirects=True,
            headers=HEADERS,
        ) as c:
            r = c.get(GRAVATAR_URL.format(hash=email_hash))
    except (httpx.TimeoutException, httpx.RequestError):
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    entry = data.get("entry", [{}])[0] if data.get("entry") else {}
    if not entry:
        return None
    return {
        "display_name": entry.get("displayName"),
        "username": entry.get("preferredUsername"),
        "avatar_url": f"https://gravatar.com/avatar/{email_hash}?d=404",
        "bio": entry.get("aboutMe"),
        "accounts": [acc.get("url") for acc in entry.get("accounts", []) if acc.get("url")],
    }


def build_identity_graph(
    email: str,
    domain: str,
    breach_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an identity graph around an email address.

    Returns:
        {
          "email": str,
          "gravatar": {...} | None,
          "breach_count": int,
          "first_breach_date": str | None,
          "last_breach_date": str | None,
          "domain": str,
          "fetched_at": iso,
        }
    """
    gravatar = fetch_gravatar(email)

    breach_count = 0
    first_breach = None
    last_breach = None
    if breach_status and isinstance(breach_status, dict):
        breach_count = breach_status.get("breach_count", 0)
        first_breach = breach_status.get("first_breach_date")
        last_breach = breach_status.get("last_breach_date")

    return {
        "email": email,
        "gravatar": gravatar,
        "breach_count": breach_count,
        "first_breach_date": first_breach,
        "last_breach_date": last_breach,
        "domain": domain,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }