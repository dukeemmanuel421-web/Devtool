from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Literal

Severity = Literal["low", "med", "high", "critical"]


class TrustLevel(str, Enum):
    USER_PROMPT = "USER_PROMPT"
    TRUSTED_TOOL = "TRUSTED_TOOL"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    WEB_PAGE = "WEB_PAGE"
    DOCUMENT = "DOCUMENT"
    MCP_OUTPUT = "MCP_OUTPUT"
    UNKNOWN = "UNKNOWN"
    UNTRUSTED = "UNTRUSTED"


@dataclass(frozen=True)
class Finding:
    detector: str
    severity: Severity
    snippet: str
    reason: str
    pattern: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    blocked: bool
    risk: float
    findings: list[Finding] = field(default_factory=list)
    sanitized_text: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"blocked": self.blocked, "risk": self.risk, "findings": [f.to_dict() for f in self.findings], "sanitized_text": self.sanitized_text}


@dataclass
class ActionDecision:
    allowed: bool
    risk: float
    reason: str
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "risk": self.risk, "reason": self.reason, "findings": [f.to_dict() for f in self.findings]}
