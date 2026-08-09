"""Shared middleware: rate limit headers + X-Request-Id on all responses.

Adds the following headers to every response:
  X-Request-Id: UUID4 per request
  X-RateLimit-Limit: 100 (free tier default)
  X-RateLimit-Remaining: 99 (static, no actual rate limiting logic)
  X-RateLimit-Reset: epoch seconds 1 hour from now

Also adds Cache-Control headers based on the request path and method.
"""
import uuid
import time


def _cache_control_for(path: str, method: str) -> str:
    """Return Cache-Control value based on path and method."""
    if method != "GET":
        return "no-store"
    if "/screen" in path or "/investigate" in path:
        return "public, max-age=1800"
    if "/whois" in path or "/company" in path or "/lookup" in path:
        return "public, max-age=3600"
    if "/geo" in path:
        return "public, max-age=86400"
    if "/validate" in path:
        return "public, max-age=86400"
    return "no-store"


async def headers_middleware(request, call_next):
    """Add X-Request-Id, rate limit, Cache-Control, and X-Response-Time headers."""
    import uuid as _uuid
    import time as _time
    request_id = str(_uuid.uuid4())
    start = _time.perf_counter()
    response = await call_next(request)
    elapsed_ms = int((_time.perf_counter() - start) * 1000)
    response.headers["X-Request-Id"] = request_id
    response.headers["X-RateLimit-Limit"] = "100"
    response.headers["X-RateLimit-Remaining"] = "99"
    response.headers["X-RateLimit-Reset"] = str(int(time.time()) + 3600)
    response.headers["X-Response-Time"] = f"{elapsed_ms}ms"
    response.headers["Cache-Control"] = _cache_control_for(request.url.path, request.method)
    response.headers["X-Powered-By"] = "DomainIntel API - try free at rapidapi.com"
    return response