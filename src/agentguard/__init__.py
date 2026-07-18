from .guard import Guard
from .model import ActionDecision, Finding, ScanResult, TrustLevel

_default_guard = Guard()

def scan(text: str, source: TrustLevel = TrustLevel.UNKNOWN) -> ScanResult:
    return _default_guard.scan(text, source)

def check_action(tool_call: dict, reasoning_trace: list[str] | None = None, trusted_context: list[str] | None = None) -> ActionDecision:
    return _default_guard.check_action(tool_call, reasoning_trace, trusted_context)

__all__ = ["Guard", "TrustLevel", "Finding", "ScanResult", "ActionDecision", "scan", "check_action"]
