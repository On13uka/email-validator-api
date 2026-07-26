"""Email Validator API - syntax + MX + SMTP + disposable + catch-all + role detection.

Checks email validity in stages:
1. Syntax validation (RFC 5322 compliant)
2. MX record lookup (does the domain accept mail?)
3. SMTP verification (does the mailbox exist?) - optional, with timeout
4. Disposable email domain detection (temp-mail providers)
5. Catch-all (accept-all) domain detection (SMTP accepts any mailbox)
6. Role-based account detection (admin@, info@, support@, ...)

Free, no API key required. Uses dnspython for DNS, direct SMTP for mailbox check.
Disposable domain list: https://github.com/disposable-email-domains/disposable-email-domains (CC0).
"""
from __future__ import annotations

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
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager


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
        "disposable domain detection, catch-all detection, role-based account detection."
    ),
    version="2.0.0",
    lifespan=_lifespan,
)

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

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DISPOSABLE_FILE = DATA_DIR / "disposable-domains.json"
ROLE_FILE = DATA_DIR / "role-accounts.json"

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


def _detect_catch_all(domain: str, mx_host: str) -> dict[str, Any]:
    """Probe whether mx_host accepts a random fake mailbox for `domain`.

    Adds one extra SMTP call. On timeout/error degrades to is_catch_all=null
    rather than blocking the whole request.
    """
    fake_local = _random_local_part()
    fake_addr = f"{fake_local}@{domain}"
    probe = _smtp_rcpt(fake_addr, mx_host, timeout=CATCH_ALL_TIMEOUT)
    accepts = probe.get("accepts")
    if accepts is None:
        # Timeout / connection error - cannot determine.
        return {"is_catch_all": None, "probe": probe, "probe_address": fake_addr}
    if accepts:
        # SMTP accepted a guaranteed-fake mailbox -> catch-all / accept-all.
        return {"is_catch_all": True, "probe": probe, "probe_address": fake_addr}
    return {"is_catch_all": False, "probe": probe, "probe_address": fake_addr}


def _is_role_account(local_part: str) -> tuple[bool, str | None]:
    """Return (is_role, role_type) for a local part. role_type is the matched
    canonical role name (the local part itself), or None."""
    roles = _load_role_accounts()
    lp = local_part.strip().lower()
    if lp in roles:
        return True, lp
    return False, None


def _is_disposable_domain(domain: str) -> bool:
    domains = _ensure_disposable_loaded()
    return domain.strip().lower() in domains


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
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
async def root():
    return {
        "name": "Email Validator API",
        "version": "2.0.0",
        "endpoints": {
            "validate": "/validate?email=user@example.com&smtp=true&catch_all=true",
            "health": "/health",
        },
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


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
):
    addr = _normalize(email)

    # Stage 1: syntax
    syntax = _validate_syntax(addr)
    if not syntax["valid"]:
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
            "suggestion": None,
            "syntax": syntax,
            "mx": None,
            "smtp": None,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }

    local = syntax["local"]
    domain = syntax["domain"]

    # Disposable + role detection are cheap; always run them.
    is_disposable = _is_disposable_domain(domain)
    is_role, role_type = _is_role_account(local)

    # Stage 2: MX lookup
    mx = _lookup_mx(domain)
    mx_found = bool(mx["has_mx"] or mx.get("fallback_a"))
    if not mx_found:
        score = _compute_score(
            syntax_valid=True,
            mx_found=False,
            smtp_verified=None,
            is_disposable=is_disposable,
            is_catch_all=None,
            is_role=is_role,
        )
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
            "suggestion": None,
            "syntax": syntax,
            "mx": mx,
            "smtp": None,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }

    # Stage 3: SMTP verify (optional)
    smtp_result = None
    smtp_verified: bool | None = None
    is_catch_all: bool | None = None
    catch_all_probe = None
    if smtp and mx.get("best"):
        smtp_result = _smtp_rcpt(addr, mx["best"])
        smtp_verified = smtp_result.get("accepts")
        # Catch-all probe only when SMTP check is enabled and the mailbox
        # was accepted (if the real mailbox was rejected, the domain clearly
        # is not accepting everything; skip the extra call).
        if catch_all and smtp_verified:
            catch_all_probe = _detect_catch_all(domain, mx["best"])
            is_catch_all = catch_all_probe.get("is_catch_all")
        elif catch_all and smtp_verified is False:
            # Mailbox rejected -> not catch-all (the probe would only confirm).
            is_catch_all = False

    valid = syntax["valid"] and mx_found
    if smtp_verified is False:
        valid = False
    # If catch-all detected, the real SMTP "accepts" is unreliable; we keep
    # valid=True (the address is syntactically valid and the domain accepts
    # mail) but expose is_catch_all so the caller can decide.

    score = _compute_score(
        syntax_valid=True,
        mx_found=mx_found,
        smtp_verified=smtp_verified,
        is_disposable=is_disposable,
        is_catch_all=is_catch_all,
        is_role=is_role,
    )

    suggestion = None
    # Disposable domains are valid emails but low-quality for marketing.
    # We surface a suggestion flag via the score; no typo correction yet.

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
        "suggestion": suggestion,
        "syntax": syntax,
        "mx": mx,
        "smtp": smtp_result,
        "catch_all_probe": catch_all_probe,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }