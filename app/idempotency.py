"""Idempotency key middleware for POST endpoints.

When a client sends an `Idempotency-Key` header on a POST request, the
response is cached for 24 hours. A repeat request with the same key
returns the cached response instead of re-executing the operation.

This prevents double-charges on rate-limited APIs when a client retries
after a timeout: the second request gets the first request's response
instead of consuming another rate-limit slot.

Usage in a FastAPI app:

    from .idempotency import idempotency_middleware

    app.middleware("http")(idempotency_middleware)

The middleware only caches POST requests with the Idempotency-Key header.
GET requests are never cached (they are inherently idempotent).

The cache is in-process (dict + TTL). For multi-instance deployments a
Redis-backed cache would be needed, but for single-instance Render/Railway
deployments this is sufficient.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any

from starlette.requests import Request
from starlette.responses import Response

# In-memory cache: key -> (expires_at, status_code, body, headers)
_cache: dict[str, tuple[float, int, bytes, dict[str, str]]] = {}
_CACHE_TTL = 24 * 60 * 60  # 24 hours
_MAX_ENTRIES = 1000  # cap to prevent unbounded memory growth


def _evict_expired() -> None:
    """Remove expired entries. Called on every cache miss."""
    now = time.time()
    expired = [k for k, (exp, _, _, _) in _cache.items() if exp < now]
    for k in expired:
        del _cache[k]
    # If still over max, evict oldest by expiry time.
    if len(_cache) > _MAX_ENTRIES:
        sorted_keys = sorted(_cache.items(), key=lambda x: x[1][0])
        for k, _ in sorted_keys[: len(_cache) - _MAX_ENTRIES]:
            del _cache[k]


async def idempotency_middleware(request: Request, call_next):
    """FastAPI/Starlette middleware for idempotency key caching.

    Only activates for POST requests with an `Idempotency-Key` header.
    """
    if request.method != "POST":
        return await call_next(request)

    key = request.headers.get("idempency-key") or request.headers.get("Idempotency-Key")
    if not key:
        return await call_next(request)

    # Build a cache key from the idempotency key + the request path.
    # This means the same idempotency key on different endpoints is fine.
    cache_key = hashlib.sha256(f"{request.url.path}:{key}".encode()).hexdigest()

    _evict_expired()

    # Cache hit: return the cached response.
    if cache_key in _cache:
        expires_at, status_code, body, headers = _cache[cache_key]
        if time.time() < expires_at:
            return Response(
                content=body,
                status_code=status_code,
                headers=headers,
                media_type=headers.get("content-type"),
            )

    # Cache miss: execute the request, then cache the response.
    response = await call_next(request)

    # Only cache successful responses (2xx) and client errors (4xx).
    # 5xx errors should not be cached (the client should retry).
    if 200 <= response.status_code < 500:
        # Read the response body so we can cache it.
        body_bytes = b""
        async for chunk in response.body_iterator:
            body_bytes += chunk

        # Store in cache.
        headers = dict(response.headers)
        _cache[cache_key] = (
            time.time() + _CACHE_TTL,
            response.status_code,
            body_bytes,
            headers,
        )

        # Return a new response with the same body.
        return Response(
            content=body_bytes,
            status_code=response.status_code,
            headers=headers,
            media_type=headers.get("content-type"),
        )

    return response


def clear_cache() -> None:
    """Test helper: clear the idempotency cache."""
    _cache.clear()