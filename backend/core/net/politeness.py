"""Per-origin politeness controls.

Authorised testing still has to behave: no hammering a customer's site. Every
browser-driven request goes through ``OriginRateLimiter`` so the agent cannot turn
a crawl into a load test, and the per-origin lock keeps one origin serialised.
"""
import asyncio
import time
from typing import Dict

DEFAULT_MIN_INTERVAL = 1.0


class OriginRateLimiter:
    """Serialise requests per origin and keep a minimum gap between them."""

    def __init__(self, min_interval: float = DEFAULT_MIN_INTERVAL):
        self.min_interval = max(0.0, float(min_interval))
        self._locks: Dict[str, asyncio.Lock] = {}
        self._last: Dict[str, float] = {}

    def _lock(self, origin: str) -> asyncio.Lock:
        lock = self._locks.get(origin)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[origin] = lock
        return lock

    async def wait(self, origin: str) -> float:
        """Block until this origin may be hit again; returns the waited seconds."""
        origin = (origin or "").strip().lower()
        async with self._lock(origin):
            now = time.monotonic()
            last = self._last.get(origin, 0.0)
            waited = 0.0
            remaining = self.min_interval - (now - last)
            if remaining > 0:
                waited = remaining
                await asyncio.sleep(remaining)
            self._last[origin] = time.monotonic()
            return waited


def get_limiter() -> OriginRateLimiter:
    """Process-wide limiter configured from settings."""
    global _limiter
    if _limiter is None:
        from config import settings

        _limiter = OriginRateLimiter(
            getattr(settings, "AGENT_MIN_REQUEST_INTERVAL_SECONDS", DEFAULT_MIN_INTERVAL)
        )
    return _limiter


_limiter: OriginRateLimiter | None = None
