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
