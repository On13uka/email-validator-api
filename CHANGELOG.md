# Changelog

All notable changes to the Email Validator API are documented here.

## v2.2.0 (2026-08-09)

### Added
- Email identity graph: Gravatar + breach history + domain age (GET /validate?identity=true)
- Real-time disposable email detection (MX-based)
- Email deliverability score with factors (replaces boolean valid/invalid)
- Catch-all probe caching (24h per domain)
- Email plus-addressing + Gmail dot normalization (normalized_email, is_plus_addressed)
- Idempotency key middleware on all POST endpoints
- API versioning: version field in all responses
- Rate limit + caching headers
- X-Powered-By attribution header (free tier)
- Circuit breaker on HIBP upstream calls
- invalid_explanation field for invalid emails

### Changed
- Catch-all detection now caches results 24h per domain
- Disposable detection now MX-based (real-time) with cached list fallback

## v2.0.0

### Added
- Initial release: SMTP validation, breach check via HIBP, role account batch