[![RapidAPI](https://img.shields.io/badge/RapidAPI-Live-brightgreen)](https://rapidapi.com/On13uka/api/email-validator112)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.13-blue)](https://python.org)

# Email Validator API

Multi-stage email validation: syntax check, MX record lookup, optional SMTP
mailbox verification, **disposable email detection**, **catch-all (accept-all)
detection**, **role-based account detection**, **email breach status via
Have I Been Pwned**, **syntax suggestion ("did you mean...")**, **free-email
provider flag + backend provider identification via MX**, and **greylisting
detection**. Returns a 0-100 deliverability score and a composite
`is_trusted_identity` signal combining all of the above.

> **Only free email validator with breach status.** Every other validator
> answers "will this email bounce?". This one also answers "**is this identity
> trustworthy?**" — a question fraud teams, KYC flows, and free-trial gating
> care about *more* than bounce rate. No competitor in the 12-vendor scan
> offers breach status.

Matches and exceeds the feature set of hunter.io, mailboxvalidator.com, and
debounce.io on the core pipeline, plus a category-creating breach layer.

## Endpoints

### GET /validate

```
GET /validate?email=user@example.com&smtp=true&catch_all=true&breach=true
```

**Parameters**

| Param       | Type   | Default | Description |
|-------------|--------|---------|-------------|
| `email`     | string | required | Email to validate |
| `smtp`      | bool   | `false` | Perform SMTP mailbox verification (slower, ~10s) |
| `catch_all` | bool   | `true`  | Probe whether the domain is catch-all (accepts any mailbox). Adds one extra SMTP call when `smtp=true`. Ignored when `smtp=false`. On RapidAPI this defaults to `true`. |
| `breach`    | bool   | `true`  | Look up email breach status via Have I Been Pwned (CC BY 4.0). One cached HTTP call to HIBP (10s timeout, 7-day disk cache). Degrades to `breach_status=null` + `breach_status_error` when `HIBP_API_KEY` is missing or the call fails. Set `breach=false` to skip and only run bounce validation. On RapidAPI this defaults to `true`. |

**Example**

```bash
curl "https://your-app.onrender.com/validate?email=test@gmail.com&smtp=true&catch_all=true&breach=true"
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
  "is_free_email": false,
  "email_provider": "other",
  "is_greylisted": false,
  "greylisting_note": null,
  "breach_status": {
    "breached": true,
    "breach_count": 2,
    "breaches": [
      {"name": "LinkedIn", "date": "2016-05-21", "data_classes": ["Emails", "Passwords"]},
      {"name": "Adobe", "date": "2013-10-04", "data_classes": ["Emails", "Password hints"]}
    ],
    "first_breach_date": "2013-10-04",
    "last_breach_date": "2016-05-21"
  },
  "breach_status_error": null,
  "is_trusted_identity": false,
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
  "_links": {"breach_data": "https://haveibeenpwned.com"},
  "fetched_at": "2026-07-26T14:00:00+00:00"
}
```

**Response with a typo (did-you-mean suggestion):**

```json
{
  "email": "alice@gmial.com",
  "valid": false,
  "stage": "mx",
  "syntax_valid": true,
  "mx_found": false,
  "suggestion": "alice@gmail.com",
  "is_free_email": false,
  "email_provider": null,
  ...
}
```

**Response with a free-email provider and MX-based identification:**

```json
{
  "email": "john.doe@gmail.com",
  "valid": true,
  "is_free_email": true,
  "email_provider": "googleworkspace",
  ...
}
```

**Response when the SMTP server greylists:**

```json
{
  "email": "user@example.com",
  "valid": true,
  "smtp_verified": false,
  "is_greylisted": true,
  "greylisting_note": "This domain uses greylisting - temporary rejection of incoming mail. The mailbox may still be valid; retry later.",
  ...
}
```

### Field reference

| Field | Type | Meaning |
|-------|------|---------|
| `email` | string | Normalized email address (lowercased) |
| `valid` | bool | Overall validity: syntax OK and (MX found) and (SMTP not rejected, except greylisted 451s which are inconclusive) |
| `stage` | string | Last stage reached: `syntax`, `mx`, or `smtp` |
| `syntax_valid` | bool | RFC 5322 syntax valid |
| `mx_found` | bool | Domain has MX records (or A-record fallback) |
| `smtp_verified` | bool / null | Mailbox accepted by SMTP. `null` when `smtp=false` |
| `is_disposable` | bool | Domain is a known temporary/disposable email provider |
| `is_catch_all` | bool / null | Domain accepts ANY mailbox (SMTP verification is unreliable). `null` when SMTP not run or probe timed out |
| `is_role` | bool | Local part is a role account (`admin@`, `info@`, `support@`, ...) |
| `role_type` | string / null | The matched role name (e.g. `admin`, `info`), or `null` |
| `score` | int (0-100) | Deliverability score combining all signals (see formula below) |
| `suggestion` | string / null | Did-you-mean correction. When the domain looks like a typo of a popular provider (Levenshtein distance <=2 against ~500 popular domains), returns the corrected email (e.g. `alice@gmial.com` -> `alice@gmail.com`). `null` when no close match or the domain is already a popular domain. |
| `is_free_email` | bool | `true` when the domain is a known free-email provider (gmail.com, yahoo.com, outlook.com, hotmail.com, icloud.com, proton.me, mail.ru, yandex.ru, zoho.com, gmx.com, ... ~100 domains). Useful for B2B-vs-B2C lead segmentation. |
| `email_provider` | string / null | Backend mail provider identified from MX records. One of: `googleworkspace` (`*.google.com`), `microsoft365` (`*.mail.protection.outlook.com`), `protonmail` (`*.protonmail.ch` / `*.proton.me`), `zoho` (`*.zoho.com`), `yandex` (`*.yandex.ru` / `*.yandex.net`), `mailru` (`*.mail.ru`), `amazon_ses` (`*.amazonses.com`), `sendgrid` (`*.sendgrid.net`), `other` (MX present but unrecognized), `null` (no MX). Useful for fraud detection (e.g. protonmail = privacy-conscious). |
| `is_greylisted` | bool / null | `true` when the SMTP server returned a 451 temporary failure on BOTH the initial RCPT TO and a retry after a 5-second wait (the standard short greylisting window). `false` when no 451 occurred, or when a 451 was followed by a successful retry. `null` when SMTP was not run (`smtp=false`). |
| `greylisting_note` | string / null | Plain-English explanation when `is_greylisted=true`: "This domain uses greylisting - temporary rejection of incoming mail. The mailbox may still be valid; retry later." `null` otherwise. |
| `breach_status` | object / null | Email breach status from Have I Been Pwned. `null` when `breach=false` or when the HIBP lookup failed/missing key (see `breach_status_error`) |
| `breach_status_error` | string / null | Set when `breach=true` but `breach_status` is null. Values: `HIBP_API_KEY not configured`, `HIBP_API_KEY invalid or unauthorized`, `HIBP rate limited`, `HIBP request timed out`, etc. |
| `is_trusted_identity` | bool / null | Composite "is this a real person who hasn't been compromised" signal. `true` only when `smtp_verified=true` AND `is_disposable=false` AND `breach_status.breached=false`. `false` when any is definitively false. `null` when unknown (breach lookup failed or SMTP not run). |
| `syntax` / `mx` / `smtp` / `catch_all_probe` | object | Raw per-stage payloads for advanced users |
| `_links` | object | Hypermedia links. Includes `breach_data: "https://haveibeenpwned.com"` whenever breach data is surfaced (CC BY 4.0 attribution requirement) |

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

### Email breach status (Have I Been Pwned)

> **Killer differentiator:** no other email validator in the market offers
> breach status. This reframes the API from "will this email bounce?" to
> "**is this identity trustworthy?**" — a question fraud teams, KYC flows,
> affiliate-screening, and free-trial gating care about *more* than bounce rate.

When `breach=true` (default on RapidAPI), the API makes one extra HTTP call to
the [Have I Been Pwned](https://haveibeenpwned.com) breach API
(`GET /api/v3/breachedaccount/{email}?truncateResponse=false`) and returns a
`breach_status` block:

```json
"breach_status": {
  "breached": true,
  "breach_count": 2,
  "breaches": [
    {"name": "LinkedIn", "date": "2016-05-21", "data_classes": ["Emails", "Passwords"]},
    {"name": "Adobe", "date": "2013-10-04", "data_classes": ["Emails", "Password hints"]}
  ],
  "first_breach_date": "2013-10-04",
  "last_breach_date": "2016-05-21"
}
```

- A HIBP `404` response means **not breached** → `breached: false, breach_count: 0`.
- Results are cached to disk at `data/breach-cache/{sha1(email)}.json` with a
  **7-day TTL** (breach data doesn't change minute-to-minute, but new breaches
  happen). Cache hits make zero HTTP calls.
- HIBP call timeout is 10s and **never blocks the core validation** — if HIBP
  times out or errors, `breach_status=null` and `breach_status_error` explains
  why. The rest of the response (syntax/MX/SMTP/disposable/catch-all/role/score)
  is unaffected.
- Errors are NOT cached, so the next request retries immediately.

#### `is_trusted_identity` — the composite signal

A single boolean fraud/KYC teams can gate on:

```
is_trusted_identity = smtp_verified == true
                   AND is_disposable == false
                   AND breach_status.breached == false
```

- `true` → real mailbox that accepts mail, on a non-throwaway domain, and not
  found in any known breach. A "real person who hasn't been compromised".
- `false` → at least one of those is definitively false (mailbox rejected,
  disposable domain, or breached).
- `null` → unknown (SMTP not run, or breach lookup failed/missing key). Treat
  `null` as "needs manual review" rather than a hard no.

#### Setting `HIBP_API_KEY` (required for the breach feature)

The HIBP API requires a key (since 2024). Without it, the breach feature
degrades gracefully: `breach_status=null` + `breach_status_error: "HIBP_API_KEY
not configured"`, and the rest of the API works normally.

1. Buy a key at **https://haveibeenpwned.com/API/Key** — Core tier from
   **$4.39/month** (1,000 RPM, 20 domains). This is the only paid external
   dependency; the integration code itself is free.
2. Set it as an environment variable on your hosting platform:

   ```bash
   # local dev: add to .env
   HIBP_API_KEY=your-key-here

   # Render / Vercel / RapidAPI: set in the provider's env-var dashboard
   ```

3. The loader reads `HIBP_API_KEY` from `os.environ` first, then from
   `F:/agent-runner/.env` (BOM-stripped) or a repo-local `.env`. Existing env
   vars are never overridden.

#### License & attribution (CC BY 4.0)

The HIBP **breach API** is licensed under
[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
— **commercial use IS allowed** as long as clear visible attribution + a link
to haveibeenpwned.com is present wherever the data is shown. (Only the Pwned
Passwords API is license-free.)

This API satisfies the attribution requirement in three places:

1. Every response that surfaces breach data includes
   `"_links": {"breach_data": "https://haveibeenpwned.com"}`.
2. This README (you are reading it).
3. The marketing landing page footer.

> **Breach data attribution:** [Have I Been Pwned](https://haveibeenpwned.com) —
> CC BY 4.0. Commercial use permitted with attribution.

### GET /health

Returns `{"status": "ok"}`.

### Syntax suggestion ("did you mean...")

When the domain in an email looks like a typo of a popular provider, the API
returns a `suggestion` field with the corrected email. This uses Levenshtein
distance (via stdlib `difflib.get_close_matches`) against a curated list of
~500 popular email domains stored in `data/popular-email-domains.json`
(gmail.com, yahoo.com, outlook.com, hotmail.com, icloud.com, proton.me,
mail.ru, yandex.ru, zoho.com, gmx.com, ...).

- Only suggests when the domain is NOT already a popular domain (no point
  suggesting `gmail.com` for `gmail.com`).
- Matches within Levenshtein distance ~2 (difflib cutoff 0.8).
- Example: `alice@gmial.com` -> `suggestion: "alice@gmail.com"`.
- Returns `null` when no close match is found.

### Free-email-provider flag + provider identification via MX

Two new fields help with lead segmentation (B2B vs B2C) and fraud detection:

- `is_free_email: true` when the domain is in the free-email set
  (`data/free-email-domains.json`, ~100 domains: gmail/yahoo/outlook/hotmail/
  icloud/proton/mail.ru/yandex/zoho/gmx/...). Marketers use this to filter
  out free-mail users from B2B lead lists.
- `email_provider` identifies the backend mail provider from MX records:
  - `googleworkspace` - MX points to `*.google.com` / `l.google.com`
  - `microsoft365` - MX points to `*.mail.protection.outlook.com`
  - `protonmail` - MX points to `*.protonmail.ch` / `*.proton.me`
  - `zoho` - MX points to `*.zoho.com`
  - `yandex` - MX points to `*.yandex.ru` / `*.yandex.net`
  - `mailru` - MX points to `*.mail.ru`
  - `amazon_ses` - MX points to `*.amazonses.com`
  - `sendgrid` - MX points to `*.sendgrid.net`
  - `other` - MX present but doesn't match a known pattern
  - `null` - no MX records (or A-record fallback only)

Fraud-detection use case: `email_provider: "protonmail"` flags a
privacy-conscious user; `email_provider: "googleworkspace"` on a custom
domain confirms a real business.

### Greylisting detection

Greylisting is a common anti-spam technique where the receiving mail server
returns a **451 "temporary failure"** on the first delivery attempt from an
unknown sender, then accepts the mail on a retry after a short wait. This
makes SMTP mailbox verification unreliable for greylisted domains — the
mailbox may be perfectly valid even though the first RCPT TO returned 451.

When `smtp=true` and the SMTP server returns a 451, the API:

1. Waits **5 seconds** (the standard short greylisting window).
2. Retries the RCPT TO **once** (we never retry more than once — be polite).
3. If the retry still returns 451, sets `is_greylisted: true` and includes a
   `greylisting_note` explaining what greylisting is for non-technical users:
   *"This domain uses greylisting - temporary rejection of incoming mail.
   The mailbox may still be valid; retry later."*
4. If the retry succeeds (250/251), sets `is_greylisted: false` and
   `smtp_verified: true` — the mailbox verified after the retry.

> **Timing note:** the greylisting retry adds up to ~5s + one extra SMTP
> timeout on top of the normal SMTP stage. If the first SMTP call took 10s,
> the total worst case for the SMTP stage is ~25s (10s + 5s wait + 10s
> retry). Set `smtp=false` if you need a hard latency cap.

When `is_greylisted=true`, the API keeps `valid=true` (the 451 is
inconclusive, not a definitive rejection) and surfaces `is_greylisted` so
the caller can decide whether to retry later. The catch-all probe is
skipped when greylisting is active (it would just hit 451 too).

## Stages

| Stage | What it checks | Fails on |
|-------|---------------|----------|
| syntax | RFC 5322 format | Bad format, too long |
| mx | DNS MX records for domain | Domain can't receive mail |
| smtp | SMTP RCPT TO command (+ 451 greylisting retry) | Mailbox doesn't exist (optional) |
| disposable | Domain in disposable list | Temporary email provider |
| catch_all | SMTP accepts random fake mailbox | Mailbox verification unreliable |
| role | Local part in role-accounts set | Not a personal mailbox |
| suggestion | Levenshtein against ~500 popular domains | Typo of a popular provider |
| free_email | Domain in free-email set | Free provider (gmail/yahoo/outlook/...) |
| provider | MX host pattern matching | Backend mail provider identification |
| greylisting | SMTP 451 -> retry once after 5s | Greylisted domain (retry later) |
| breach | HIBP breachedaccount lookup | Email appeared in a known data breach (optional, `breach=true`) |

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

The breach feature is **opt-in via env var**. Without `HIBP_API_KEY` the API
runs normally but returns `breach_status=null` + `breach_status_error`. To
enable it locally:

```bash
# Add to .env (or export in your shell)
HIBP_API_KEY=your-key-from-https://haveibeenpwned.com/API/Key
```

## Tests

```bash
pip install -r requirements.txt
pytest tests/ -q
```

Tests are hermetic — DNS, SMTP, and HIBP HTTP are all mocked, no network calls.
26 tests cover the core pipeline (7), the breach feature (6), and the v2.2.0
table-stakes features (13): syntax suggestion (3), free-email flag (2),
provider identification (4), and greylisting detection (4). The greylisting
retry wait is patched to 0s in tests so the suite stays fast.

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