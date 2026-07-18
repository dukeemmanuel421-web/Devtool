"""API-key auth + simple in-memory rate limiting for the AgentGuard service.

Opt-in and dependency-free. Enabled only when AGENTGUARD_API_KEYS is set (a
comma-separated list of allowed keys). When unset, the API is open (good for the
public playground / local dev). This keeps the demo frictionless while making the
hosted developer API real.

For multi-instance production, swap the in-memory limiter for Redis; the interface
is intentionally small.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque


def _allowed_keys() -> set[str]:
    raw = os.environ.get("AGENTGUARD_API_KEYS", "")
    return {k.strip() for k in raw.split(",") if k.strip()}


class RateLimiter:
    """Fixed-window-ish sliding limiter: max N requests per window seconds per key."""

    def __init__(self, limit: int | None = None, window_s: int | None = None):
        self.limit = limit if limit is not None else int(os.environ.get("AGENTGUARD_RATE_LIMIT", "60"))
        self.window_s = window_s if window_s is not None else int(os.environ.get("AGENTGUARD_RATE_WINDOW_S", "60"))
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> bool:
        now = time.time()
        dq = self._hits[key]
        while dq and dq[0] <= now - self.window_s:
            dq.popleft()
        if len(dq) >= self.limit:
            return False
        dq.append(now)
        return True


def extract_key(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return authorization.strip() or None
