"""Thread-safe in-memory quotas."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock


@dataclass(frozen=True)
class QuotaLimits:
    requests: int = 100
    bytes: int = 10 * 1024**3


@dataclass
class _Usage:
    day: str
    requests: int = 0
    bytes: int = 0


class QuotaExceeded(RuntimeError):
    """Raised when a user exceeds a configured quota."""


class QuotaStore:
    def __init__(self, limits: QuotaLimits | None = None) -> None:
        self.limits = limits or QuotaLimits()
        self._lock = Lock()
        self._usage: dict[str, _Usage] = {}

    def _current(self, user_id: str) -> _Usage:
        day = datetime.now(timezone.utc).date().isoformat()
        usage = self._usage.get(user_id)
        if usage is None or usage.day != day:
            usage = _Usage(day)
            self._usage[user_id] = usage
        return usage

    def consume(self, user_id: str, estimated_bytes: int = 0) -> None:
        if estimated_bytes < 0:
            raise ValueError("estimated_bytes cannot be negative")
        with self._lock:
            usage = self._current(user_id)
            if usage.requests + 1 > self.limits.requests or usage.bytes + estimated_bytes > self.limits.bytes:
                raise QuotaExceeded(f"quota exceeded for user {user_id}")
            usage.requests += 1
            usage.bytes += estimated_bytes

    def snapshot(self, user_id: str) -> dict[str, int | str]:
        with self._lock:
            usage = self._current(user_id)
            return {
                "user_id": user_id, "requests_used": usage.requests, "requests_limit": self.limits.requests,
                "bytes_used": usage.bytes, "bytes_limit": self.limits.bytes,
                "remaining_requests": max(0, self.limits.requests - usage.requests),
                "remaining_bytes": max(0, self.limits.bytes - usage.bytes),
            }
