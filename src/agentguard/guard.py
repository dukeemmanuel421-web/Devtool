from __future__ import annotations

import json, re
from typing import Any
from .detectors.heuristic import HeuristicDetector
from .model import ActionDecision, Finding, ScanResult, TrustLevel
from .policy import Policy

SENSITIVE_TOOLS = re.compile(r"(email|send|post|upload|delete|shell|exec|payment|transfer|credential|secret)", re.I)

class Guard:
    def __init__(self, policy: Policy | None = None, detectors: list[Any] | None = None, enable_llm_judge: bool = False) -> None:
        self.policy = policy or Policy()
        self.detectors = detectors or [HeuristicDetector()]
        if enable_llm_judge:
            from .detectors.llm_judge import LLMJudgeDetector
            self.detectors.append(LLMJudgeDetector())

    def scan(self, text: str, source: TrustLevel = TrustLevel.UNKNOWN, trusted_context: list[str] | None = None) -> ScanResult:
        if not isinstance(source, TrustLevel):
            source = TrustLevel(str(source))
        findings: list[Finding] = []
        for detector in self.detectors:
            findings.extend(detector.scan(text, source, trusted_context))
        risk = self.policy.risk_for(findings, source)
        blocked = self.policy.blocks(risk, findings)
        return ScanResult(blocked=blocked, risk=risk, findings=findings, sanitized_text=self._sanitize(text, findings) if findings else None)

    def check_action(self, tool_call: dict[str, Any], reasoning_trace: list[str] | None = None, trusted_context: list[str] | None = None) -> ActionDecision:
        reasoning_trace = reasoning_trace or []
        trusted_context = trusted_context or []
        blob = json.dumps(tool_call, sort_keys=True) + "\n" + "\n".join(reasoning_trace)
        scan = self.scan(blob, source=TrustLevel.UNKNOWN, trusted_context=trusted_context)
        findings = list(scan.findings)
        tool_name = str(tool_call.get("name", ""))
        trusted_blob = "\n".join(trusted_context).lower()
        trace_blob = "\n".join(reasoning_trace).lower()
        grounded = bool(trusted_blob) and any(term in trusted_blob for term in re.findall(r"[a-zA-Z]{5,}", trace_blob)[:12])
        if SENSITIVE_TOOLS.search(tool_name) and not grounded:
            findings.append(Finding("policy", "critical", json.dumps(tool_call)[:180], "sensitive tool call is not grounded in trusted context", "ungrounded_sensitive_action"))
        risk = self.policy.risk_for(findings, TrustLevel.UNKNOWN)
        allowed = not self.policy.blocks(risk, findings)
        reason = "allowed: action is grounded in trusted context" if allowed else "blocked: action follows from untrusted or suspicious context"
        return ActionDecision(allowed=allowed, risk=risk, reason=reason, findings=findings)

    def _sanitize(self, text: str, findings: list[Finding]) -> str:
        sanitized = text
        for f in findings:
            if f.snippet and len(f.snippet) > 8:
                sanitized = sanitized.replace(f.snippet, "[removed by AgentGuard]")
        return sanitized if sanitized != text else "[content withheld by AgentGuard]"
