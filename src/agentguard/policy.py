from __future__ import annotations

from dataclasses import dataclass, field
from .model import Finding, TrustLevel

SEVERITY_SCORE = {"low": 0.2, "med": 0.45, "high": 0.7, "critical": 0.95}
UNTRUSTED = {TrustLevel.WEB_PAGE, TrustLevel.DOCUMENT, TrustLevel.TOOL_OUTPUT, TrustLevel.MCP_OUTPUT, TrustLevel.UNKNOWN, TrustLevel.UNTRUSTED}


@dataclass
class Policy:
    block_threshold: float = 0.75
    flag_threshold: float = 0.35
    source_trust: dict[TrustLevel, float] = field(default_factory=lambda: {
        TrustLevel.USER_PROMPT: 0.65, TrustLevel.TRUSTED_TOOL: 0.9,
        TrustLevel.TOOL_OUTPUT: 0.35, TrustLevel.WEB_PAGE: 0.15,
        TrustLevel.DOCUMENT: 0.25, TrustLevel.MCP_OUTPUT: 0.2,
        TrustLevel.UNKNOWN: 0.2, TrustLevel.UNTRUSTED: 0.1,
    })

    def risk_for(self, findings: list[Finding], source: TrustLevel) -> float:
        if not findings:
            return 0.0
        max_sev = max(SEVERITY_SCORE[f.severity] for f in findings)
        density = min(0.2, 0.04 * (len(findings) - 1))
        distrust = 1.0 - self.source_trust.get(source, 0.2)
        return round(min(1.0, max_sev + density + (0.08 * distrust)), 3)

    def blocks(self, risk: float, findings: list[Finding]) -> bool:
        return risk >= self.block_threshold or any(f.severity == "critical" for f in findings)

    def is_untrusted(self, source: TrustLevel) -> bool:
        return source in UNTRUSTED
