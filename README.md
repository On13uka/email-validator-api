[![RapidAPI](https://img.shields.io/badge/RapidAPI-Live-brightgreen)](https://rapidapi.com/On13uka/api/email-validator112)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.13-blue)](https://python.org)

# Email Validator API

Multi-stage email validation: syntax check, MX record lookup, optional SMTP
mailbox verification, **disposable email detection**, **catch-all (accept-all)
detection**, and **role-based account detection**. Returns a 0-100
deliverability score combining every signal.

Matches the feature set of hunter.io, mailboxvalidator.com, and debounce.io.

## Endpoints

### GET /validate

```
GET /validate?email=user@example.com&smtp=true&catch_all=true
```

**Parameters**

| Param       | Type   | Default | Description |
|-------------|--------|---------|-------------|
| `email`     | string | required | Email to validate |
| `smtp`      | bool   | `false` | Perform SMTP mailbox verification (slower, ~10s) |
| `catch_all` | bool   | `true`  | Probe whether the domain is catch-all (accepts any mailbox). Adds one extra SMTP call when `smtp=true`. Ignored when `smtp=false`. On RapidAPI this defaults to `true`. |

**Example**

```bash
curl "https://your-app.onrender.com/validate?email=test@gmail.com&smtp=true&catch_all=true"
```

**Response**

```json
{
  "email": "alice@example.com",
  "valid": true,
  "stage": "smtp",
  "syntax_valid": true,
  "mx_found": true,
  "smtp_verified": true,
  "is_disposable": false,
  "is_catch_all": false,
  "is_role": false,
  "role_type": null,
  "score": 100,
  "suggestion": null,
  "syntax": {"valid": true, "local": "alice", "domain": "example.com"},
  "mx": {
    "has_mx": true,
    "records": [{"priority": 10, "exchange": "mail.example.com"}],
    "best": "mail.example.com"
  },
  "smtp": {"smtp_code": 250, "accepts": true, "message": "ok"},
  "catch_all_probe": {
    "is_catch_all": false,
    "probe_address": "zzztestnotrealabc123@example.com",
    "probe": {"smtp_code": 550, "accepts": false, "message": "no such mailbox"}
  },
  "fetched_at": "2026-07-26T14:00:00+00:00"
}
```

### Field reference

| Field | Type | Meaning |
|-------|------|---------|
| `email` | string | Normalized email address (lowercased) |
| `valid` | bool | Overall validity: syntax OK and (MX found) and (SMTP not rejected) |
| `stage` | string | Last stage reached: `syntax`, `mx`, or `smtp` |
| `syntax_valid` | bool | RFC 5322 syntax valid |
| `mx_found` | bool | Domain has MX records (or A-record fallback) |
| `smtp_verified` | bool / null | Mailbox accepted by SMTP. `null` when `smtp=false` |
| `is_disposable` | bool | Domain is a known temporary/disposable email provider |
| `is_catch_all` | bool / null | Domain accepts ANY mailbox (SMTP verification is unreliable). `null` when SMTP not run or probe timed out |
| `is_role` | bool | Local part is a role account (`admin@`, `info@`, `support@`, ...) |
| `role_type` | string / null | The matched role name (e.g. `admin`, `info`), or `null` |
| `score` | int (0-100) | Deliverability score combining all signals (see formula below) |
| `suggestion` | string / null | Reserved for future typo correction. Currently always `null` |
| `syntax` / `mx` / `smtp` / `catch_all_probe` | object | Raw per-stage payloads for advanced users |

> Old fields (`valid`, `stage`, `syntax`, `mx`, `smtp`, `fetched_at`) are kept
> for backward compatibility — this release is additive only.

### Deliverability score formula

The `score` field is a 0-100 deliverability score combining every signal:

| Signal | Bonus | Notes |
|--------|-------|-------|
| Syntax valid | +35 | Hard floor; invalid syntax = score 0 |
| MX found | +30 | Domain can receive mail |
| SMTP verified | +25 | Mailbox accepts mail (only when `smtp=true`) |
| SMTP verified + catch-all | +10 | Catch-all makes SMTP unreliable; bonus capped |
| Not disposable | +10 | Disposable domains get 0 bonus |
| Role account | +0 | Role accounts are valid but not personal — no bonus, no penalty |

Final score is clamped to 0-100. Examples:

- `alice@example.com` with SMTP verified, not disposable, not role, not catch-all → **100**
- `admin@example.com` with SMTP=false → **75** (35 + 30 + 10)
- `anything@mailinator.com` (disposable) → **65** (35 + 30, no disposable bonus)
- `realuser@catchall.example.com` with SMTP verified + catch-all=true → **85** (35 + 30 + 10 + 10)

## Detection features

### Disposable email detection

Maintains a list of ~75,000 disposable/temporary email domains
(mailinator.com, guerrillamail.com, 10minutemail.com, temp-mail.org, ...).
The list is sourced from the public-domain
[disposable-email-domains](https://github.com/disposable/disposable-email-domains)
project (CC0 / public domain) and cached locally at
`data/disposable-domains.json`. The cache is refreshed weekly in the
background. Domain lookup uses a `set` (O(1)) loaded once at startup — not a
list scan — so it stays fast even at ~100k entries.

> Data source attribution: [disposable/disposable-email-domains](https://github.com/disposable/disposable-email-domains) — CC0 1.0 Universal (Public Domain).

### Catch-all (accept-all) detection

A catch-all domain is one where the SMTP server accepts ANY mailbox — even a
guaranteed-fake one. After the existing MX + SMTP check, if SMTP verification is
enabled (`smtp=true`) and the real mailbox was accepted, the API issues one
extra SMTP `RCPT TO` for a random fake mailbox
(`zzztestnotreal<random>@<domain>`). If that fake mailbox is also accepted,
`is_catch_all=true` — meaning mailbox verification is unreliable for this
domain.

- The extra call uses a 10s timeout.
- If the probe times out or errors, `is_catch_all=null` (we do not block the
  whole request on a slow SMTP).
- When `smtp=false`, `is_catch_all=null` (cannot determine without SMTP).
- When the real mailbox was rejected, `is_catch_all=false` (no probe needed).

### Role-based account detection

Detects role accounts: `admin@`, `info@`, `support@`, `sales@`, `contact@`,
`noreply@`, `postmaster@`, `webmaster@`, `abuse@`, `billing@`, and ~50 more.
The list is stored statically in `data/role-accounts.json` and loaded into a
`set` at startup. If the local part matches, `is_role=true` and `role_type`
returns the matched name. Role accounts are valid but not personal — a
lead-quality signal for marketing users.

### GET /health

Returns `{"status": "ok"}`.

## Stages

| Stage | What it checks | Fails on |
|-------|---------------|----------|
| syntax | RFC 5322 format | Bad format, too long |
| mx | DNS MX records for domain | Domain can't receive mail |
| smtp | SMTP RCPT TO command | Mailbox doesn't exist (optional) |
| disposable | Domain in disposable list | Temporary email provider |
| catch_all | SMTP accepts random fake mailbox | Mailbox verification unreliable |
| role | Local part in role-accounts set | Not a personal mailbox |

## Local development

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# or: source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8125
```

The first startup will background-download the disposable domain list
(~1-2 MB) and cache it at `data/disposable-domains.json`. Subsequent starts
load from cache and refresh weekly.

## Tests

```bash
pip install -r requirements.txt
pytest tests/ -q
```

Tests are hermetic — DNS and SMTP are mocked, no network calls.

## Available on RapidAPI

**Live API:** https://rapidapi.com/On13uka/api/email-validator112

Subscribe and get an instant API key. Free tier: 100 requests/month.

## Other APIs in the Portfolio

- [Domain WHOIS](https://github.com/On13uka/domain-whois-api)
- [Company Info](https://github.com/On13uka/company-info-api)
- [Email Validator](https://github.com/On13uka/email-validator-api)
- [IP Geolocation](https://github.com/Onizuka/ip-geolocation-api)
- [Sanctions Screener](https://github.com/On13uka/sanctions-screener-api)

All APIs available on RapidAPI: https://rapidapi.com/user/On13uka