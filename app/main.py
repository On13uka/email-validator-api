"""Email Validator API - syntax + MX + SMTP + disposable + catch-all + role + breach
+ syntax suggestion + free-email/provider identification + greylisting detection.

Checks email validity in stages:
1. Syntax validation (RFC 5322 compliant)
2. MX record lookup (does the domain accept mail?)
3. SMTP verification (does the mailbox exist?) - optional, with timeout
4. Disposable email domain detection (temp-mail providers)
5. Catch-all (accept-all) domain detection (SMTP accepts any mailbox)
6. Role-based account detection (admin@, info@, support@, ...)
7. Email breach status via Have I Been Pwned (CC BY 4.0, attribution required)
8. Syntax suggestion ("did you mean...") via Levenshtein on a popular-domain list
9. Free-email-provider flag + backend provider identification via MX
10. Greylisting detection (SMTP 451 -> retry once after 5s)

Free, no API key required for the core pipeline. The breach feature needs a
HIBP_API_KEY (https://haveibeenpwned.com/API/Key, from $4.39/mo Core tier) and
degrades gracefully (breach_status=null + error field) when the key is missing.
Disposable domain list: https://github.com/disposable-email-domains/disposable-email-domains (CC0).
Breach data: Have I Been Pwned (https://haveibeenpwned.com) - CC BY 4.0.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import random
import re
import smtplib
import socket
import string
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dns.resolver
from fastapi import Body, FastAPI, Query, Request
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from . import breach_alerts
from . import circuit_breaker
from . import headers
from . import identity_graph
from . import idempotency


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Warm the disposable cache in a background thread so the first request
    # is not penalized by the ~100k-domain download.
    threading.Thread(target=_warm_disposable_cache_worker, daemon=True).start()
    yield


app = FastAPI(
    title="Email Validator API",
    description=(
        "Email validation: syntax, MX lookup, SMTP mailbox verify, "
        "disposable domain detection, catch-all detection, role-based account detection, "
        "email breach status via Have I Been Pwned, syntax suggestion (did you mean...), "
        "free-email-provider flag with backend provider identification, "
        "and greylisting detection."
    ),
    version="2.2.0",
    lifespan=_lifespan,
)

# v1.4: Idempotency key middleware for POST endpoints.
app.middleware("http")(idempotency.idempotency_middleware)
app.middleware("http")(headers.headers_middleware)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SMTP_TIMEOUT = 10
CATCH_ALL_TIMEOUT = 10
DISPOSABLE_LIST_URL = (
    "https://raw.githubusercontent.com/disposable/"
    "disposable-email-domains/master/domains.json"
)
DISPOSABLE_REFRESH_DAYS = 7

# HIBP breach integration (https://haveibeenpwned.com/API/v3)
# Key is loaded from HIBP_API_KEY env var (set in .env or your platform's env).
# When missing, the breach feature degrades gracefully: breach_status=null +
# breach_status_error explaining the key is not configured. The endpoint never
# crashes on a missing/invalid key.
HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_TIMEOUT = 10  # seconds; never block the whole request on HIBP
HIBP_CACHE_TTL_DAYS = 7  # breach data doesn't change minute-to-minute
HIBP_ATTRIBUTION_URL = "https://haveibeenpwned.com"

# Greylisting (RFC 7504 / common MTA behavior): when the SMTP RCPT TO returns
# a 451 "temporary failure", the sender is expected to retry after a short
# window. We retry ONCE after GREYLIST_WAIT_SECONDS and, if it still returns
# 451, mark is_greylisted=true. The extra wait is added on top of the normal
# SMTP timeout, so a request that already took 10s can take up to 15s total.
# We never retry more than once (be polite to the receiving MTA).
GREYLIST_WAIT_SECONDS = 5
GREYLIST_SMTP_CODE = 451  # Requested action aborted: local error in processing

# Suggestion (did you mean...) config. We use difflib.get_close_matches against
# a curated list of popular email domains. Max edit distance is implicit in
# difflib's cutoff (0.8 similarity ~ Levenshtein distance 1-2 for short
# domains); we restrict the candidate cutoff so only very-close matches win.
SUGGESTION_CUTOFF = 0.8  # difflib similarity ratio threshold
SUGGESTION_N = 1         # return the single best match

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DISPOSABLE_FILE = DATA_DIR / "disposable-domains.json"
ROLE_FILE = DATA_DIR / "role-accounts.json"
BREACH_CACHE_DIR = DATA_DIR / "breach-cache"
POPULAR_DOMAINS_FILE = DATA_DIR / "popular-email-domains.json"
FREE_EMAIL_DOMAINS_FILE = DATA_DIR / "free-email-domains.json"


def _load_env_file() -> dict[str, str]:
    """Load F:/agent-runner/.env (or repo-local .env) into a dict.

    Strips the UTF-8 BOM if present (the project .env is known to carry one).
    Returns {} if no .env file is found. Does not override existing env vars.
    """
    candidates = [
        BASE_DIR / ".env",
        Path("F:/agent-runner/.env"),
        Path(os.environ.get("AGENT_RUNNER_ENV", "")) if os.environ.get("AGENT_RUNNER_ENV") else None,
    ]
    env: dict[str, str] = {}
    for path in candidates:
        if path is None:
            continue
        try:
            if not path.exists():
                continue
            raw = path.read_text(encoding="utf-8-sig")  # utf-8-sig strips BOM
        except Exception:
            continue
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                env[key] = value
        if env:
            break
    return env


def _get_hibp_api_key() -> str | None:
    """Resolve the HIBP API key from os.environ first, then the .env file."""
    key = os.environ.get("HIBP_API_KEY")
    if key:
        return key.strip() or None
    env = _load_env_file()
    key = env.get("HIBP_API_KEY")
    if key:
        return key.strip() or None
    return None

# RFC 5322 simplified regex
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

# ---------------------------------------------------------------------------
# Lazy-loaded datasets (sets for O(1) lookup; loaded once at startup)
# ---------------------------------------------------------------------------
_disposable_lock = threading.Lock()
_disposable_set: set[str] | None = None
_disposable_loaded_at: float | None = None  # mtime of cache file
_role_set: set[str] | None = None


def _load_role_accounts() -> set[str]:
    """Load the static role-account local-part list into a set (lowercased)."""
    global _role_set
    if _role_set is not None:
        return _role_set
    try:
        with open(ROLE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        _role_set = {str(x).strip().lower() for x in data if str(x).strip()}
    except Exception:
        # Degrade to a minimal built-in set if the file is missing/corrupt.
        _role_set = {
            "admin", "info", "support", "sales", "contact", "noreply", "no-reply",
            "postmaster", "webmaster", "abuse", "billing", "help", "helpdesk",
            "marketing", "office", "orders", "root", "security", "service",
            "spam", "team", "test", "hr", "jobs", "careers", "legal", "finance",
            "accounting", "ops", "operations", "devnull", "mail", "email",
            "feedback", "inquiries", "press", "media", "partners", "partnerships",
            "business", "corporate", "manager", "owner", "contact-us",
            "donotreply", "notifications", "notification", "alerts", "updates",
            "newsletter", "subscribe", "unsubscribe", "hostmaster", "usenet",
            "uucp", "ftp", "www", "noc", "postoffice", "mailer-daemon",
            "mailerdaemon", "administrator",
        }
    return _role_set


# ---------------------------------------------------------------------------
# Email breach status via Have I Been Pwned (https://haveibeenpwned.com)
# License: CC BY 4.0 - commercial use allowed WITH visible attribution + link.
# We surface attribution in the response (_links.breach_data) and in the README
# + landing page (required by the license).
# ---------------------------------------------------------------------------
_breach_cache_lock = threading.Lock()


def _breach_cache_path(email: str) -> Path:
    """Return the on-disk cache path for a given email (SHA-1 keyed)."""
    digest = hashlib.sha1(email.strip().lower().encode("utf-8")).hexdigest()
    return BREACH_CACHE_DIR / f"{digest}.json"


def _read_breach_cache(email: str) -> dict[str, Any] | None:
    """Return a cached breach payload if fresh, else None.

    Cache file shape: {"fetched_at": iso, "payload": {...}}.
    TTL = HIBP_CACHE_TTL_DAYS. Missing/corrupt files are treated as a miss.
    """
    path = _breach_cache_path(email)
    try:
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        fetched_at = data.get("fetched_at")
        payload = data.get("payload")
        if not fetched_at or payload is None:
            return None
        ts = datetime.fromisoformat(fetched_at)
        age_days = (datetime.now(timezone.utc) - ts).total_seconds() / 86400.0
        if age_days > HIBP_CACHE_TTL_DAYS:
            return None
        return payload
    except Exception:
        return None


def _write_breach_cache(email: str, payload: dict[str, Any]) -> None:
    """Persist a breach payload to disk (best-effort, never raises)."""
    try:
        BREACH_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = _breach_cache_path(email)
        tmp = path.with_suffix(".json.tmp")
        record = {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "version": "2.2.0",
            "payload": payload,
        }
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(record, fh, ensure_ascii=True)
        os.replace(tmp, path)
    except Exception:
        # Cache write failure must never break the request.
        pass


def _normalize_hibp_breach(raw: dict[str, Any]) -> dict[str, Any]:
    """Project a raw HIBP breach object down to the fields we expose."""
    return {
        "name": raw.get("Name") or raw.get("name"),
        "date": raw.get("BreachDate") or raw.get("date"),
        "data_classes": raw.get("DataClasses") or raw.get("data_classes") or [],
    }


def _summarize_breaches(breaches: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the breach_status payload from a list of HIBP breach objects."""
    dates = [b.get("BreachDate") or b.get("date") for b in breaches if (b.get("BreachDate") or b.get("date"))]
    dates_sorted = sorted(dates)
    return {
        "breached": True,
        "breach_count": len(breaches),
        "breaches": [_normalize_hibp_breach(b) for b in breaches],
        "first_breach_date": dates_sorted[0] if dates_sorted else None,
        "last_breach_date": dates_sorted[-1] if dates_sorted else None,
    }


_hibp_breaker = circuit_breaker.CircuitBreaker(name="hibp", failure_threshold=3, cooldown_seconds=300)


def _fetch_hibp_breach(email: str) -> dict[str, Any]:
    """Call HIBP breachedaccount/{email} and return a breach_status payload.

    Returns a dict shaped as the breach_status field (breached/breaches/...)
    OR a degraded payload {"error": ..., "retry_after": ...} when the call
    could not produce a clean result. The caller wraps this into the final
    breach_status response shape.

    Uses a circuit breaker: after 3 consecutive failures, enters fallback
    mode for 5 minutes, returning "unavailable" instead of timing out.
    """
    if _hibp_breaker.is_open():
        return {"error": "HIBP temporarily unavailable (circuit breaker open)"}

    import urllib.request
    import urllib.error
    import urllib.parse

    api_key = _get_hibp_api_key()
    if not api_key:
        return {"error": "HIBP_API_KEY not configured"}

    url = f"{HIBP_API_BASE}/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
    req = urllib.request.Request(
        url,
        headers={
            "hibp-api-key": api_key,
            "User-Agent": "Email-Validator-API",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=HIBP_TIMEOUT) as resp:  # nosec - hardcoded official HIBP URL
            raw = resp.read().decode("utf-8")
        breaches = json.loads(raw) if raw else []
        if not isinstance(breaches, list):
            breaches = []
        _hibp_breaker.record_success()
        return _summarize_breaches(breaches)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Not breached - this is a clean "no breaches" result.
            _hibp_breaker.record_success()
            return {
                "breached": False,
                "breach_count": 0,
                "breaches": [],
                "first_breach_date": None,
                "last_breach_date": None,
            }
        if e.code in (401, 403):
            _hibp_breaker.record_failure()
            return {"error": "HIBP_API_KEY invalid or unauthorized"}
        if e.code == 429:
            retry_after = e.headers.get("Retry-After") if e.headers else None
            out: dict[str, Any] = {"error": "HIBP rate limited"}
            if retry_after:
                out["retry_after"] = retry_after
            return out
        return {"error": f"HIBP HTTP {e.code}"}
    except (urllib.error.URLError, TimeoutError, socket.timeout):
        _hibp_breaker.record_failure()
        return {"error": "HIBP request timed out"}
    except (json.JSONDecodeError, ValueError):
        return {"error": "HIBP response parse error"}
    except Exception:
        return {"error": "HIBP request failed"}


def get_breach_status(email: str) -> dict[str, Any] | None:
    """Return the breach_status block for email, or null on hard failure.

    Disk cache is checked first (7-day TTL). On a cache miss we call HIBP,
    cache the result on success (200/404), and return the payload. The
    caller is responsible for the is_trusted_identity composite signal.
    """
    addr = email.strip().lower()
    if not addr:
        return None

    with _breach_cache_lock:
        cached = _read_breach_cache(addr)
    if cached is not None:
        return cached

    fetched = _fetch_hibp_breach(addr)
    # Cache only clean results (breached or not-breached). Errors are NOT
    # cached so the next request can retry immediately.
    if "error" not in fetched:
        with _breach_cache_lock:
            _write_breach_cache(addr, fetched)
        return fetched

    # Degraded: surface the error to the caller but keep breach_status=null.
    return {"error": fetched["error"], "retry_after": fetched.get("retry_after")}


def _compute_is_trusted_identity(
    smtp_verified: bool | None,
    is_disposable: bool,
    breach_status: dict[str, Any] | None,
) -> bool | None:
    """Composite 'is this a real person who has not been compromised' signal.

    Returns True only when ALL of:
      - smtp_verified is True (mailbox accepted mail)
      - is_disposable is False (not a throwaway domain)
      - breach_status.breached is False (not found in any known breach)
    Returns False when any of those is definitively False.
    Returns None when we cannot decide (breach_status is null/errored OR
    smtp_verified is None) - callers should treat None as 'unknown'.
    """
    if smtp_verified is not True:
        return False if smtp_verified is False else None
    if is_disposable:
        return False
    if breach_status is None:
        return None
    if "error" in breach_status:
        return None
    breached = breach_status.get("breached")
    if breached is None:
        return None
    return not breached


def _refresh_disposable_list(force: bool = False) -> tuple[set[str], str]:
    """Return the disposable-domain set, refreshing from the network if stale.

    Refresh policy: refresh if cache file is older than DISPOSABLE_REFRESH_DAYS
    days, or if the file is missing. Network failures degrade to the cached
    file (or an empty set if no cache exists).
    Returns (domains_set, source) where source is one of:
      "cache", "cache-stale-fallback", "refreshed", "empty".
    """
    global _disposable_set, _disposable_loaded_at
    with _disposable_lock:
        now = time.time()
        need_refresh = force
        if not DISPOSABLE_FILE.exists():
            need_refresh = True
        elif _disposable_loaded_at is None:
            need_refresh = True
        else:
            cache_age_days = (now - _disposable_loaded_at) / 86400.0
            if cache_age_days >= DISPOSABLE_REFRESH_DAYS:
                need_refresh = True

        if not need_refresh and _disposable_set is not None:
            return _disposable_set, "cache"

        if need_refresh:
            refreshed = _download_disposable_list()
            if refreshed is not None:
                _disposable_set = refreshed
                try:
                    mtime = DISPOSABLE_FILE.stat().st_mtime
                    _disposable_loaded_at = mtime
                except Exception:
                    _disposable_loaded_at = now
                return _disposable_set, "refreshed"
            # Network failed; fall back to whatever cache we have.
            if DISPOSABLE_FILE.exists():
                cached = _read_disposable_cache()
                if cached is not None:
                    _disposable_set = cached
                    try:
                        _disposable_loaded_at = DISPOSABLE_FILE.stat().st_mtime
                    except Exception:
                        _disposable_loaded_at = now
                    return _disposable_set, "cache-stale-fallback"
            # No cache, no network - degrade to empty set.
            _disposable_set = set()
            _disposable_loaded_at = now
            return _disposable_set, "empty"

        # File exists and fresh enough but not loaded yet (first call path).
        cached = _read_disposable_cache()
        if cached is not None:
            _disposable_set = cached
            try:
                _disposable_loaded_at = DISPOSABLE_FILE.stat().st_mtime
            except Exception:
                _disposable_loaded_at = now
            return _disposable_set, "cache"
        _disposable_set = set()
        _disposable_loaded_at = now
        return _disposable_set, "empty"


def _read_disposable_cache() -> set[str] | None:
    try:
        with open(DISPOSABLE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return {str(d).strip().lower() for d in data if str(d).strip()}
        return None
    except Exception:
        return None


def _download_disposable_list() -> set[str] | None:
    """Download the disposable list and write it to DISPOSABLE_FILE.

    Uses urllib from the stdlib to avoid adding `requests` for this single
    JSON fetch. Returns the set on success, None on failure.
    """
    import urllib.request
    import urllib.error

    try:
        req = urllib.request.Request(
            DISPOSABLE_LIST_URL,
            headers={"User-Agent": "email-validator-api/2.0 (https://github.com/On13uka/email-validator-api)"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec - public URL, hardcoded
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        if not isinstance(data, list):
            return None
        domains = sorted({str(d).strip().lower() for d in data if str(d).strip()})
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = DISPOSABLE_FILE.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(domains, fh, ensure_ascii=True)
        os.replace(tmp, DISPOSABLE_FILE)
        return set(domains)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError, ValueError):
        return None
    except Exception:
        return None


def _ensure_disposable_loaded() -> set[str]:
    """Synchronous accessor used by the validate endpoint."""
    domains, _ = _refresh_disposable_list()
    return domains


# ---------------------------------------------------------------------------
# Popular domains + free-email domains (static JSON assets, loaded once).
# Used by the syntax-suggestion feature (Levenshtein via difflib) and by the
# is_free_email flag. Both files ship in data/ and are pure ASCII.
# ---------------------------------------------------------------------------
_popular_domains_lock = threading.Lock()
_popular_domains: list[str] | None = None
_free_email_domains: set[str] | None = None


def _load_popular_domains() -> list[str]:
    """Load the curated popular-domain list (lowercased, deduped, order-preserving).

    Returns a list (NOT a set) because difflib.get_close_matches needs an
    iterable of candidates. Degrades to a small built-in set if the file is
    missing/corrupt.
    """
    global _popular_domains
    with _popular_domains_lock:
        if _popular_domains is not None:
            return _popular_domains
        try:
            with open(POPULAR_DOMAINS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            seen: set[str] = set()
            ordered: list[str] = []
            for d in data:
                d = str(d).strip().lower()
                if d and d not in seen:
                    seen.add(d)
                    ordered.append(d)
            _popular_domains = ordered or _FALLBACK_POPULAR_DOMAINS
        except Exception:
            _popular_domains = _FALLBACK_POPULAR_DOMAINS
        return _popular_domains


def _load_free_email_domains() -> set[str]:
    """Load the free-email-domain set (lowercased) for the is_free_email flag."""
    global _free_email_domains
    with _popular_domains_lock:
        if _free_email_domains is not None:
            return _free_email_domains
        try:
            with open(FREE_EMAIL_DOMAINS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            _free_email_domains = {str(d).strip().lower() for d in data if str(d).strip()}
        except Exception:
            _free_email_domains = set(_FALLBACK_FREE_EMAIL_DOMAINS)
        return _free_email_domains


# Minimal built-in fallbacks used only if the JSON files are missing/corrupt.
_FALLBACK_POPULAR_DOMAINS: list[str] = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "proton.me", "protonmail.com", "mail.ru", "yandex.ru",
    "zoho.com", "gmx.com", "web.de", "live.com", "msn.com", "me.com",
    "mac.com", "tutanota.com", "tuta.io", "fastmail.com",
]
_FALLBACK_FREE_EMAIL_DOMAINS: list[str] = list(_FALLBACK_POPULAR_DOMAINS)


def _is_free_email_domain(domain: str) -> bool:
    """True when the domain is in the free-email set (gmail/yahoo/outlook/...)."""
    free = _load_free_email_domains()
    return domain.strip().lower() in free


# ---------------------------------------------------------------------------
# MX-based provider identification
# ---------------------------------------------------------------------------
# Map provider-id -> list of suffix patterns matched against MX exchange hosts.
# Order matters: we walk the patterns in declared order and return the first
# match. Patterns are lowercased suffix matches (host.endswith(pattern)).
_PROVIDER_MX_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    ("googleworkspace", (
        "l.google.com",
        ".google.com",
        "googlemail.com",
    )),
    ("microsoft365", (
        ".mail.protection.outlook.com",
        ".outlook.com",
        ".office365.com",
    )),
    ("protonmail", (
        ".protonmail.ch",
        ".proton.me",
        "mail.protonmail.ch",
    )),
    ("zoho", (
        ".zoho.com",
        "mx.zoho.com",
    )),
    ("yandex", (
        ".yandex.ru",
        ".yandex.net",
    )),
    ("mailru", (
        ".mail.ru",
        "emx.mail.ru",
    )),
    ("amazon_ses", (
        ".amazonses.com",
        "feedback-smtp.amazonses.com",
    )),
    ("sendgrid", (
        ".sendgrid.net",
    )),
]


def _identify_email_provider(mx: dict[str, Any] | None) -> str | None:
    """Classify the backend mail provider from MX records.

    Returns one of: googleworkspace, microsoft365, protonmail, zoho, yandex,
    mailru, amazon_ses, sendgrid, other (MX present but unrecognized), or
    None (no MX records).
    """
    if not mx:
        return None
    if not mx.get("has_mx"):
        # A-record fallback means the domain hosts its own mail; we can't
        # classify the provider from an A record.
        return None if mx.get("fallback_a") else None
    records = mx.get("records") or []
    exchanges = [str(r.get("exchange", "")).rstrip(".").lower() for r in records]
    if not exchanges:
        return None
    for provider, patterns in _PROVIDER_MX_PATTERNS:
        for host in exchanges:
            for pat in patterns:
                if host == pat or host.endswith(pat):
                    return provider
    # MX present but no pattern matched.
    return "other"


# ---------------------------------------------------------------------------
# Syntax suggestion via Levenshtein (difflib.get_close_matches)
# ---------------------------------------------------------------------------
def _suggest_correction(email: str, syntax: dict[str, Any]) -> str | None:
    """Return a suggested corrected email when the domain looks like a typo
    of a popular provider. Used on the syntax-INVALID path where the regex
    rejected the address but we can still split on '@' and try to correct.

    Returns the full corrected email (e.g. "alice@gmail.com") or None.
    """
    if syntax.get("valid"):
        return None
    raw = email.strip().lower()
    if "@" not in raw:
        return None
    local, _, domain = raw.rpartition("@")
    if not local or not domain:
        return None
    if " " in domain or "/" in domain:
        return None
    return _suggest_correction_for_domain(local, domain)


def _suggest_correction_for_domain(local: str, domain: str) -> str | None:
    """Given a local part and a domain, return a corrected email if the
    domain is within Levenshtein distance ~2 of a popular provider.

    Skips the lookup when the domain IS already a popular/free domain (no
    point suggesting gmail.com for gmail.com). Uses difflib's similarity
    ratio with a 0.8 cutoff (corresponds to distance 1-2 for short domains).
    """
    domain = domain.strip().lower()
    if not domain:
        return None
    popular = _load_popular_domains()
    if domain in popular:
        return None
    # Also skip when the domain is already a known free-email domain (overlap
    # with popular but the free set is slightly different).
    if _is_free_email_domain(domain):
        return None
    matches = difflib.get_close_matches(
        domain,
        popular,
        n=SUGGESTION_N,
        cutoff=SUGGESTION_CUTOFF,
    )
    if not matches:
        return None
    suggested_domain = matches[0]
    if suggested_domain == domain:
        return None
    return f"{local.strip().lower()}@{suggested_domain}"


# ---------------------------------------------------------------------------
# Greylisting-aware SMTP RCPT. Wraps _smtp_rcpt with one 451 retry.
# ---------------------------------------------------------------------------
def _smtp_rcpt_with_greylisting(
    email: str,
    mx_host: str,
    timeout: int = SMTP_TIMEOUT,
) -> tuple[dict[str, Any], bool, str | None]:
    """Run _smtp_rcpt and, on a 451 temporary failure, retry once after
    GREYLIST_WAIT_SECONDS.

    Returns (smtp_result, is_greylisted, greylisting_note).
      - smtp_result: the final _smtp_rcpt dict (last attempt).
      - is_greylisted: True only when BOTH attempts returned 451.
        False when the retry succeeded (250/251) or when no 451 happened.
        None when SMTP did not run (caller should treat as "not checked").
      - greylisting_note: a plain-English explanation string when
        is_greylisted is True, else None.

    We never retry more than once. The 5s wait is the standard short
    greylisting window; combined with the SMTP timeout this means a worst
    case of ~timeout + 5s + ~timeout for the SMTP stage (e.g. 25s).
    """
    first = _smtp_rcpt(email, mx_host, timeout=timeout)
    code = first.get("smtp_code")
    if code != GREYLIST_SMTP_CODE:
        # No temporary failure -> no greylisting concern.
        return first, False, None
    # 451 received -> wait once, retry once.
    time.sleep(GREYLIST_WAIT_SECONDS)
    second = _smtp_rcpt(email, mx_host, timeout=timeout)
    second_code = second.get("smtp_code")
    if second_code == GREYLIST_SMTP_CODE:
        # Still 451 after a polite retry -> greylisted.
        note = (
            "This domain uses greylisting - temporary rejection of incoming "
            "mail. The mailbox may still be valid; retry later."
        )
        return second, True, note
    # Retry succeeded (or returned a different code) -> not greylisted.
    return second, False, None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class APIError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        self.status_code = status_code
        self.code = code
        self.message = message


def _validate_syntax(email: str) -> dict[str, Any]:
    email = email.strip().lower()
    if not email or len(email) > 254:
        return {"valid": False, "reason": "empty or too long"}
    if not _EMAIL_RE.match(email):
        return {"valid": False, "reason": "syntax error"}
    local, _, domain = email.partition("@")
    if len(local) > 64:
        return {"valid": False, "reason": "local part too long"}
    return {"valid": True, "local": local, "domain": domain}


def _normalize_email(local: str, domain: str) -> tuple[str, bool]:
    """Normalize an email address by stripping plus-addressing and Gmail dots.

    Returns (normalized_email, is_plus_addressed).

    Rules:
    - Strip plus-addressing: "john+spam@gmail.com" -> "john@gmail.com"
    - For Gmail only: remove dots in local part: "j.o.h.n@gmail.com" -> "john@gmail.com"
      (Gmail ignores dots; other providers do not)
    - Detect plus-addressing: set is_plus_addressed=True if "+" present

    This enables user dedup across signups (the same person using
    john+newsletter@gmail.com and john+promo@gmail.com is the same Gmail
    mailbox).
    """
    is_plus_addressed = "+" in local
    # Strip plus-addressing
    if is_plus_addressed:
        local = local.split("+", 1)[0]
    # Gmail dot normalization (Gmail ignores dots in the local part)
    if domain in ("gmail.com", "googlemail.com"):
        local = local.replace(".", "")
    normalized = f"{local}@{domain}"
    return normalized, is_plus_addressed


def _lookup_mx(domain: str) -> dict[str, Any]:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=10)
        records = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in answers])
        return {
            "has_mx": True,
            "records": [{"priority": p, "exchange": e} for p, e in records],
            "best": records[0][1] if records else None,
        }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        # Try A record fallback (RFC 5321: if no MX, use A)
        try:
            dns.resolver.resolve(domain, "A", lifetime=10)
            return {"has_mx": False, "records": [], "best": domain, "fallback_a": True}
        except Exception:
            return {"has_mx": False, "records": [], "best": None}
    except Exception as e:
        return {"has_mx": False, "records": [], "best": None, "error": str(e)}


def _smtp_rcpt(email: str, mx_host: str, timeout: int = SMTP_TIMEOUT) -> dict[str, Any]:
    """Connect to mx_host and run MAIL FROM + RCPT TO for email.

    Returns dict with keys: smtp_code, accepts (bool|None), message.
    """
    try:
        with smtplib.SMTP(timeout=timeout) as srv:
            srv.connect(mx_host, 25)
            srv.ehlo("api-portfolio.local")
            srv.mail("verify@api-portfolio.local")
            code, msg = srv.rcpt(email)
            result = {
                "smtp_code": code,
                "accepts": code in (250, 251),
                "message": msg.decode("utf-8", errors="replace") if isinstance(msg, bytes) else str(msg),
            }
            try:
                srv.quit()
            except Exception:
                pass
            return result
    except socket.timeout:
        return {"smtp_code": None, "accepts": None, "message": "SMTP timeout"}
    except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError) as e:
        return {"smtp_code": None, "accepts": None, "message": f"SMTP error: {e}"}
    except Exception as e:
        return {"smtp_code": None, "accepts": None, "message": f"SMTP error: {e}"}


def _random_local_part(length: int = 22) -> str:
    """Generate a random local part unlikely to be a real mailbox."""
    # Leading letters avoid accidental syntax issues; mix in digits.
    alphabet = string.ascii_lowercase
    head = "".join(random.choice(alphabet) for _ in range(length - 6))
    tail = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return "zzztestnotreal" + head + tail


_CATCH_ALL_CACHE: dict[str, dict[str, Any]] = {}
_CATCH_ALL_CACHE_TTL = 24 * 60 * 60  # 24 hours


def _detect_catch_all(domain: str, mx_host: str) -> dict[str, Any]:
    """Probe whether mx_host accepts a random fake mailbox for `domain`.

    Adds one extra SMTP call. Results are cached per-domain for 24 hours
    so repeat checks on the same domain are instant. On timeout/error
    degrades to is_catch_all=null rather than blocking the whole request.
    """
    import time
    d = domain.strip().lower()
    now = time.time()
    cached = _CATCH_ALL_CACHE.get(d)
    if cached and now - cached.get("_cached_at", 0) < _CATCH_ALL_CACHE_TTL:
        result = dict(cached)
        result.pop("_cached_at", None)
        result["catch_all_cached"] = True
        return result

    fake_local = _random_local_part()
    fake_addr = f"{fake_local}@{domain}"
    probe = _smtp_rcpt(fake_addr, mx_host, timeout=CATCH_ALL_TIMEOUT)
    accepts = probe.get("accepts")
    if accepts is None:
        return {"is_catch_all": None, "probe": probe, "probe_address": fake_addr}
    if accepts:
        result = {"is_catch_all": True, "probe": probe, "probe_address": fake_addr}
    else:
        result = {"is_catch_all": False, "probe": probe, "probe_address": fake_addr}
    # Cache the result
    cached_entry = dict(result)
    cached_entry["_cached_at"] = now
    _CATCH_ALL_CACHE[d] = cached_entry
    return result


def _is_role_account(local_part: str) -> tuple[bool, str | None]:
    """Return (is_role, role_type) for a local part. role_type is the matched
    canonical role name (the local part itself), or None."""
    roles = _load_role_accounts()
    lp = local_part.strip().lower()
    if lp in roles:
        return True, lp
    return False, None


_KNOWN_DISPOSABLE_MX = {
    "mailinator.com", "guerrillamail.com", "guerrillamailblock.com",
    "sharklasers.com", "spam4.me", "dispostable.com", "tempmail.net",
    "throwam.com", "getnada.com", "mailnesia.com", "temp-mail.org",
    "fakeinbox.com", "10minutemail.com", "yopmail.com", "mohmal.com",
    "tempinbox.com", "maildrop.cc", "discard.email", "mailcatch.com",
}

_DISPOSABLE_MX_CACHE: dict[str, bool] = {}


def _is_disposable_domain(domain: str) -> bool:
    """Check if domain is disposable. Uses static list + real-time MX check."""
    domains = _ensure_disposable_loaded()
    d = domain.strip().lower()
    if d in domains:
        _DISPOSABLE_MX_CACHE[d] = True
        return True
    # Real-time MX-based check: if MX points to a known disposable provider
    if d in _DISPOSABLE_MX_CACHE:
        return _DISPOSABLE_MX_CACHE[d]
    try:
        import dns.resolver
        answers = dns.resolver.resolve(d, "MX", lifetime=3)
        for r in answers:
            mx = str(r.exchange).rstrip(".").lower()
            for disposable_mx in _KNOWN_DISPOSABLE_MX:
                if mx == disposable_mx or mx.endswith("." + disposable_mx):
                    _DISPOSABLE_MX_CACHE[d] = True
                    return True
    except Exception:
        pass
    _DISPOSABLE_MX_CACHE[d] = False
    return False


def _compute_score(
    syntax_valid: bool,
    mx_found: bool | None,
    smtp_verified: bool | None,
    is_disposable: bool,
    is_catch_all: bool | None,
    is_role: bool,
) -> int:
    """0-100 deliverability score combining all signals.

    Formula (documented in README):
      - Start from 0.
      - Syntax valid:   +35  (hard floor; invalid syntax = 0)
      - MX found:        +30
      - SMTP verified:   +25  (only if smtp check ran)
      - Not disposable: +10  (disposable = 0 bonus)
      - Not role:        +0   (role accounts get no bonus but no penalty either;
                               they are valid but not personal)
      - Catch-all:       mailbox verification is unreliable; we cap the SMTP bonus
                         to +10 instead of +25 when is_catch_all is True, and
                         we treat smtp_verified as weak signal.
    Final score is clamped to 0-100.
    """
    if not syntax_valid:
        return 0
    score = 0
    score += 35  # syntax
    if mx_found:
        score += 30
    # SMTP bonus depends on whether the check ran and catch-all status.
    if smtp_verified is True:
        if is_catch_all is True:
            score += 10  # catch-all: weak signal
        else:
            score += 25
    elif smtp_verified is False:
        score += 0  # mailbox rejected
    # smtp_verified is None (not run): no bonus.
    if not is_disposable:
        score += 10
    # Role accounts: no bonus, no penalty.
    return max(0, min(100, score))


def _normalize(email: str) -> str:
    email = email.strip()
    if not email:
        raise APIError(422, "invalid_email", "Email parameter is required")
    return email


def _compose_invalid_explanation(
    *,
    valid: bool,
    stage: str,
    syntax: dict[str, Any] | None = None,
    mx_found: bool | None = None,
    smtp_verified: bool | None = None,
    is_disposable: bool = False,
    is_catch_all: bool | None = None,
    is_greylisted: bool | None = None,
    breach_status: dict[str, Any] | None = None,
    breach_error: str | None = None,
) -> str | None:
    """Plain-English explanation of why an email is invalid (P3.1).

    Returns None when the email is valid. Composed from the same signals
    that drive the score so the explanation always matches the verdict.
    """
    if valid:
        return None

    reasons: list[str] = []

    if stage == "syntax":
        reason = "syntax error"
        if syntax and syntax.get("reason"):
            reason = syntax["reason"]
        reasons.append(f"syntax invalid ({reason})")
    elif stage == "mx":
        reasons.append("MX lookup failed (domain does not accept mail)")
    elif stage in ("smtp", "mx") and smtp_verified is False:
        if is_greylisted:
            reasons.append("mailbox greylisted (temporary rejection)")
        else:
            reasons.append("SMTP mailbox rejected")

    if is_disposable:
        reasons.append("disposable domain")
    if is_catch_all is True:
        reasons.append("catch-all domain (accepts any mailbox)")

    if breach_status and isinstance(breach_status, dict):
        count = breach_status.get("breach_count")
        if isinstance(count, int) and count > 0:
            reasons.append(f"{count} breach{'es' if count != 1 else ''}")
    elif breach_error:
        reasons.append(f"breach lookup failed ({breach_error})")

    if not reasons:
        return "Invalid email."
    return "Invalid: " + " + ".join(reasons)


# ---------------------------------------------------------------------------
# Startup: warm the disposable cache in a background thread so the first
# request is not penalized by the ~100k-domain download.
# ---------------------------------------------------------------------------
def _warm_disposable_cache_worker() -> None:
    try:
        _refresh_disposable_list()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
@app.exception_handler(APIError)
async def api_error_handler(request: Request, exc: APIError):
    import uuid as _uuid
    request_id = request.headers.get("x-request-id") or str(_uuid.uuid4())
    retry_after = 60 if exc.status_code == 429 else None
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
                "retry_after": retry_after,
                "docs_url": "https://github.com/On13uka/email-validator-api#readme",
                "request_id": request_id,
            }
        },
        headers={"X-Request-Id": request_id},
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
async def root():
    return {
        "name": "Email Validator API",
        "version": "2.2.0",
        "endpoints": {
            "validate": "/validate?email=user@example.com&smtp=true&catch_all=true&breach=true",
            "health": "/health",
        },
        "features": [
            "syntax", "mx", "smtp", "disposable", "catch_all", "role",
            "breach_status (Have I Been Pwned, CC BY 4.0)",
            "syntax_suggestion (Levenshtein, did-you-mean)",
            "is_free_email (free-provider flag)",
            "email_provider (MX-based: googleworkspace/microsoft365/protonmail/...)",
            "is_greylisted (SMTP 451 retry detection)",
        ],
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


def _build_breach_block(addr: str, want_breach: bool) -> tuple[dict[str, Any] | None, str | None, dict[str, Any]]:
    """Compute the breach_status block + error + _links for a response.

    Returns (breach_status, breach_status_error, _links).
    - breach_status is None when want_breach is False or HIBP failed/missing key.
    - breach_status_error is set only when want_breach is True but we could not
      produce a clean breach_status (missing key, invalid key, rate limit,
      timeout, etc.).
    - _links always includes the HIBP attribution link when breach data is
      surfaced (CC BY 4.0 requirement).
    """
    links: dict[str, Any] = {}
    if not want_breach:
        return None, None, links
    raw = get_breach_status(addr)
    if raw is None:
        # Should not happen (get_breach_status always returns a dict), but guard.
        return None, "breach lookup unavailable", links
    if "error" in raw:
        # Degraded: keep breach_status null, surface the error.
        links["breach_data"] = HIBP_ATTRIBUTION_URL
        return None, raw["error"], links
    # Clean result - include attribution link (CC BY 4.0 requirement).
    links["breach_data"] = HIBP_ATTRIBUTION_URL
    return raw, None, links


@app.get("/validate")
async def validate(
    email: str = Query(..., description="Email to validate"),
    smtp: bool = Query(False, description="Perform SMTP mailbox verification (slower)"),
    catch_all: bool = Query(
        True,
        description=(
            "Probe whether the domain is catch-all (accepts any mailbox). "
            "Adds one extra SMTP call when smtp=true. Ignored when smtp=false."
        ),
    ),
    breach: bool = Query(
        True,
        description=(
            "Look up email breach status via Have I Been Pwned (CC BY 4.0). "
            "Adds one cached HTTP call to HIBP (10s timeout, 7-day disk cache). "
            "Degrades to breach_status=null + breach_status_error when "
            "HIBP_API_KEY is missing or the call fails. Set breach=false to "
            "skip and only run bounce validation."
        ),
    ),
):
    addr = _normalize(email)

    # Stage 1: syntax
    syntax = _validate_syntax(addr)
    if not syntax["valid"]:
        # Syntax suggestion: only attempt when syntax is invalid AND the
        # domain looks like a typo of a popular provider.
        suggestion = _suggest_correction(addr, syntax)
        is_free_email = False
        if syntax.get("domain"):
            is_free_email = _is_free_email_domain(syntax["domain"])
        breach_status, breach_error, links = _build_breach_block(addr, breach)
        return {
            "email": addr,
            "valid": False,
            "stage": "syntax",
            "syntax_valid": False,
            "mx_found": None,
            "smtp_verified": None,
            "is_disposable": False,
            "is_catch_all": None,
            "is_role": False,
            "role_type": None,
            "score": 0,
            "suggestion": suggestion,
            "is_free_email": is_free_email,
            "email_provider": None,
            "is_greylisted": None,
            "greylisting_note": None,
            "normalized_email": None,
            "is_plus_addressed": None,
            "breach_status": breach_status,
            "breach_status_error": breach_error,
            "is_trusted_identity": None,
            "syntax": syntax,
            "mx": None,
            "smtp": None,
            "_links": links,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "version": "2.2.0",
        }

    local = syntax["local"]
    domain = syntax["domain"]

    # v1.4: normalize email (strip plus-addressing, Gmail dots) for dedup.
    normalized_email, is_plus_addressed = _normalize_email(local, domain)

    # Disposable + role detection are cheap; always run them.
    is_disposable = _is_disposable_domain(domain)
    is_role, role_type = _is_role_account(local)
    # Free-email flag is cheap (set lookup); always run it.
    is_free_email = _is_free_email_domain(domain)

    # Syntax suggestion: attempt when the domain is NOT already a popular
    # domain (no point suggesting gmail.com for gmail.com) and looks like a
    # typo of one. We attempt this on valid-syntax emails whose domain is
    # not in the popular list, since e.g. alice@gmial.com IS syntactically
    # valid but has no MX (gmial.com is unregistered). The suggestion gives
    # the caller a "did you mean" hint.
    suggestion = None
    if not is_free_email:
        suggestion = _suggest_correction_for_domain(local, domain)

    # Stage 2: MX lookup
    mx = _lookup_mx(domain)
    mx_found = bool(mx["has_mx"] or mx.get("fallback_a"))
    # Provider identification from MX records (None when no MX / A fallback).
    email_provider = _identify_email_provider(mx)
    if not mx_found:
        score = _compute_score(
            syntax_valid=True,
            mx_found=False,
            smtp_verified=None,
            is_disposable=is_disposable,
            is_catch_all=None,
            is_role=is_role,
        )
        breach_status, breach_error, links = _build_breach_block(addr, breach)
        return {
            "email": addr,
            "valid": False,
            "stage": "mx",
            "syntax_valid": True,
            "mx_found": False,
            "smtp_verified": None,
            "is_disposable": is_disposable,
            "is_catch_all": None,
            "is_role": is_role,
            "role_type": role_type,
            "score": score,
            "suggestion": suggestion,
            "is_free_email": is_free_email,
            "email_provider": email_provider,
            "is_greylisted": None,
            "greylisting_note": None,
            "breach_status": breach_status,
            "breach_status_error": breach_error,
            "is_trusted_identity": _compute_is_trusted_identity(None, is_disposable, breach_status),
            "syntax": syntax,
            "mx": mx,
            "smtp": None,
            "_links": links,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "version": "2.2.0",
        }

    # Stage 3: SMTP verify (optional) with greylisting retry
    smtp_result = None
    smtp_verified: bool | None = None
    is_catch_all: bool | None = None
    catch_all_probe = None
    is_greylisted: bool | None = None
    greylisting_note: str | None = None
    if smtp and mx.get("best"):
        smtp_result, is_greylisted, greylisting_note = _smtp_rcpt_with_greylisting(
            addr, mx["best"]
        )
        smtp_verified = smtp_result.get("accepts")
        # Catch-all probe only when SMTP check is enabled and the mailbox
        # was accepted (if the real mailbox was rejected, the domain clearly
        # is not accepting everything; skip the extra call). Also skip the
        # probe when greylisting is active - the probe would just hit 451 too.
        if catch_all and smtp_verified and not is_greylisted:
            catch_all_probe = _detect_catch_all(domain, mx["best"])
            is_catch_all = catch_all_probe.get("is_catch_all")
        elif catch_all and smtp_verified is False:
            # Mailbox rejected -> not catch-all (the probe would only confirm).
            is_catch_all = False

    valid = syntax["valid"] and mx_found
    if smtp_verified is False and not is_greylisted:
        # Mailbox definitively rejected (not a 451 greylisting case).
        valid = False
    # If catch-all detected, the real SMTP "accepts" is unreliable; we keep
    # valid=True (the address is syntactically valid and the domain accepts
    # mail) but expose is_catch_all so the caller can decide.
    # If greylisted, the 451 is a temporary failure, NOT a definitive
    # rejection - we keep valid=True (domain accepts mail) and surface
    # is_greylisted so the caller can decide to retry later.

    score = _compute_score(
        syntax_valid=True,
        mx_found=mx_found,
        smtp_verified=smtp_verified,
        is_disposable=is_disposable,
        is_catch_all=is_catch_all,
        is_role=is_role,
    )

    # Syntax suggestion already computed above (before MX lookup). Valid
    # emails with a popular-domain typo keep their suggestion; valid emails
    # on a real domain have suggestion=None.
    # Stage 4: breach status (optional, additive). Run after the core
    # pipeline so a slow/timing-out HIBP call never blocks bounce validation.
    breach_status, breach_error, links = _build_breach_block(addr, breach)
    is_trusted_identity = _compute_is_trusted_identity(
        smtp_verified, is_disposable, breach_status
    )

    return {
        "email": addr,
        "valid": valid,
        "stage": "smtp" if smtp_result else "mx",
        "syntax_valid": True,
        "mx_found": mx_found,
        "smtp_verified": smtp_verified,
        "is_disposable": is_disposable,
        "is_catch_all": is_catch_all,
        "is_role": is_role,
        "role_type": role_type,
        "score": score,
        "deliverability": {
            "score": score,
            "factors": {
                "syntax_valid": True,
                "mx_found": mx_found,
                "smtp_verified": smtp_verified,
                "is_disposable": is_disposable,
                "is_catch_all": is_catch_all,
                "is_greylisted": is_greylisted,
                "breach_count": breach_status.get("breach_count", 0) if breach_status else 0,
            },
        },
        "suggestion": suggestion,
        "is_free_email": is_free_email,
        "email_provider": email_provider,
        "is_greylisted": is_greylisted,
        "greylisting_note": greylisting_note,
        "normalized_email": normalized_email,
        "is_plus_addressed": is_plus_addressed,
        "breach_status": breach_status,
        "breach_status_error": breach_error,
        "is_trusted_identity": is_trusted_identity,
        "invalid_explanation": _compose_invalid_explanation(
            valid=valid,
            stage="smtp" if smtp_result else "mx",
            syntax=syntax,
            mx_found=mx_found,
            smtp_verified=smtp_verified,
            is_disposable=is_disposable,
            is_catch_all=is_catch_all,
            is_greylisted=is_greylisted,
            breach_status=breach_status,
            breach_error=breach_error,
        ) if not valid else None,
        "syntax": syntax,
        "mx": mx,
        "smtp": smtp_result,
        "catch_all_probe": catch_all_probe,
        "_links": links,
        "identity_graph": identity_graph.build_identity_graph(addr, domain, breach_status) if valid else None,
        "provenance": {
            "syntax": {"source": "internal", "confidence": 1.0},
            "mx": {"source": "DNS resolver", "confidence": 0.95},
            "smtp_verified": {"source": "SMTP probe", "confidence": 0.90},
            "breach_status": {"source": "Have I Been Pwned", "confidence": 0.95},
        },
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


# --------------------------------------------------------------------------- #
# v2.3: Breach alert monitoring (P5.19)
# --------------------------------------------------------------------------- #

@app.post("/alerts/breach")
async def register_breach_alert(payload: dict[str, Any] = Body(...)):
    """Register an email for breach monitoring. When a new breach appears,
    the API POSTs a webhook payload to the registered URL.

    Body: {"email": "user@example.com", "webhook_url": "https://...", "webhook_secret": "..."}
    """
    email = (payload.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return JSONResponse(status_code=422, content={"error": {"code": "invalid_email", "message": "a valid email is required"}})
    webhook_url = payload.get("webhook_url")
    webhook_secret = payload.get("webhook_secret")
    alert = breach_alerts.register_alert(email, webhook_url, webhook_secret)
    return alert


@app.get("/alerts/breach/{alert_id}")
async def get_breach_alert(alert_id: str):
    """Get the status and history of a breach alert subscription."""
    alert = breach_alerts.get_alert(alert_id)
    if not alert:
        return JSONResponse(status_code=404, content={"error": {"code": "not_found", "message": "alert not found"}})
    return alert


@app.delete("/alerts/breach/{alert_id}")
async def delete_breach_alert(alert_id: str):
    """Cancel a breach alert subscription."""
    if breach_alerts.delete_alert(alert_id):
        return {"deleted": True, "alert_id": alert_id}
    return JSONResponse(status_code=404, content={"error": {"code": "not_found", "message": "alert not found"}})


@app.post("/alerts/breach/run")
async def run_breach_alerts():
    """Run the breach alert check cycle. Cron-callable.

    For each registered alert, queries HIBP and fires a webhook if a new
    breach appeared since the last check.
    """
    return breach_alerts.run_check_cycle()