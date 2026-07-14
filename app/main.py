"""Email Validator API - syntax + MX + SMTP verification.

Checks email validity in 3 stages:
1. Syntax validation (RFC 5322 compliant)
2. MX record lookup (does the domain accept mail?)
3. SMTP verification (does the mailbox exist?) - optional, with timeout

Free, no API key required. Uses dnspython for DNS, direct SMTP for mailbox check.
"""
from __future__ import annotations

import re
import smtplib
import socket
import dns.resolver
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Email Validator API",
    description="3-stage email validation: syntax, MX lookup, SMTP mailbox verification.",
    version="1.0.0",
)

# RFC 5322 simplified regex
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)
SMTP_TIMEOUT = 10


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


def _smtp_verify(email: str, mx_host: str) -> dict[str, Any]:
    try:
        with smtplib.SMTP(timeout=SMTP_TIMEOUT) as srv:
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


def _normalize(email: str) -> str:
    email = email.strip()
    if not email:
        raise APIError(422, "invalid_email", "Email parameter is required")
    return email


@app.exception_handler(APIError)
async def api_error_handler(request: Request, exc: APIError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


@app.get("/")
async def root():
    return {
        "name": "Email Validator API",
        "version": "1.0.0",
        "endpoints": {
            "validate": "/validate?email=user@example.com&smtp=true",
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
):
    addr = _normalize(email)

    # Stage 1: syntax
    syntax = _validate_syntax(addr)
    if not syntax["valid"]:
        return {
            "email": addr,
            "valid": False,
            "stage": "syntax",
            "syntax": syntax,
            "mx": None,
            "smtp": None,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }

    domain = syntax["domain"]

    # Stage 2: MX lookup
    mx = _lookup_mx(domain)
    if not mx["has_mx"] and not mx.get("fallback_a"):
        return {
            "email": addr,
            "valid": False,
            "stage": "mx",
            "syntax": syntax,
            "mx": mx,
            "smtp": None,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }

    # Stage 3: SMTP verify (optional)
    smtp_result = None
    if smtp and mx.get("best"):
        smtp_result = _smtp_verify(addr, mx["best"])

    valid = syntax["valid"] and (mx["has_mx"] or mx.get("fallback_a"))
    if smtp_result and not smtp_result.get("accepts"):
        valid = False

    return {
        "email": addr,
        "valid": valid,
        "stage": "smtp" if smtp_result else ("mx" if mx else "syntax"),
        "syntax": syntax,
        "mx": mx,
        "smtp": smtp_result,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }