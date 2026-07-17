[![RapidAPI](https://img.shields.io/badge/RapidAPI-Live-brightgreen)](https://rapidapi.com/On13uka/api/email-validator112)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.13-blue)](https://python.org)

# Email Validator API

3-stage email validation: syntax check, MX record lookup, optional SMTP mailbox verification.

## Endpoints

### GET /validate?email=user@example.com&smtp=false

**Parameters:**
- `email` (required): Email address to validate
- `smtp` (optional, default false): Perform SMTP mailbox verification (slower, ~10s)

**Example:**

```bash
curl "https://your-app.onrender.com/validate?email=test@gmail.com"
```

**Response:**

```json
{
  "email": "test@gmail.com",
  "valid": true,
  "stage": "mx",
  "syntax": {"valid": true, "local": "test", "domain": "gmail.com"},
  "mx": {
    "has_mx": true,
    "records": [{"priority": 5, "exchange": "gmail-smtp-in.l.google.com"}, ...],
    "best": "gmail-smtp-in.l.google.com"
  },
  "smtp": null,
  "fetched_at": "2026-07-14T14:54:51.343966+00:00"
}
```

### Stages

| Stage | What it checks | Fails on |
|---|---|---|
| syntax | RFC 5322 format | Bad format, too long |
| mx | DNS MX records for domain | Domain can't receive mail |
| smtp | SMTP RCPT TO command | Mailbox doesn't exist (optional) |

### GET /health

Returns `{"status": "ok"}`.

## Local development

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8125
```

## Available on RapidAPI

**Live API:** https://rapidapi.com/On13uka/api/email-validator112

Subscribe and get instant API key. Free tier: 100 requests/month.

## Other APIs in the Portfolio

- [Domain WHOIS](https://github.com/On13uka/domain-whois-api)
- [Company Info](https://github.com/On13uka/company-info-api)
- [Email Validator](https://github.com/On13uka/email-validator-api)
- [IP Geolocation](https://github.com/On13uka/ip-geolocation-api)
- [Sanctions Screener](https://github.com/On13uka/sanctions-screener-api)

All APIs available on RapidAPI: https://rapidapi.com/user/On13uka