from __future__ import annotations
from functools import wraps
from agentguard.guard import Guard
from agentguard.model import TrustLevel


def guard_context(source: TrustLevel = TrustLevel.UNTRUSTED, guard: Guard | None = None):
    guard = guard or Guard()
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            text = fn(*args, **kwargs)
            result = guard.scan(str(text), source=source)
            if result.blocked:
                raise ValueError(f"AgentGuard blocked context: {result.findings}")
            return result.sanitized_text or text
        return wrapper
    return deco


def guard_tool(guard: Guard | None = None, trusted_context: list[str] | None = None):
    guard = guard or Guard()
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            decision = guard.check_action({"name": fn.__name__, "args": {"args": args, "kwargs": kwargs}}, trusted_context=trusted_context or [])
            if not decision.allowed:
                raise ValueError(decision.reason)
            return fn(*args, **kwargs)
        return wrapper
    return deco
