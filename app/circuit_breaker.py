"""Simple circuit breaker for upstream API calls.

Tracks consecutive failures per upstream. After N consecutive failures
in a time window, enters "open" state for a cooldown period, during which
calls to the upstream are skipped and a fallback value is returned.

Usage:
    cb = CircuitBreaker(name="hibp", failure_threshold=3, cooldown_seconds=300)
    if cb.is_open():
        return fallback_value
    try:
        result = call_upstream()
        cb.record_success()
        return result
    except Exception:
        cb.record_failure()
        return fallback_value
"""
from __future__ import annotations

import time


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 3, cooldown_seconds: int = 300):
        self.name = name
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._consecutive_failures = 0
        self._opened_at: float | None = None

    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        if time.time() - self._opened_at > self.cooldown_seconds:
            self._opened_at = None
            self._consecutive_failures = 0
            return False
        return True

    def record_success(self) -> None:
        self._consecutive_failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.failure_threshold:
            self._opened_at = time.time()

    @property
    def state(self) -> str:
        if self.is_open():
            return "open"
        return "closed"

    def status(self) -> dict:
        return {
            "name": self.name,
            "state": self.state,
            "consecutive_failures": self._consecutive_failures,
            "failure_threshold": self.failure_threshold,
            "cooldown_seconds": self.cooldown_seconds,
        }