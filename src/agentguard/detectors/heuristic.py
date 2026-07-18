from __future__ import annotations

import base64, re, urllib.parse
from dataclasses import dataclass
from . import __name__ as _pkg
from agentguard.model import Finding, TrustLevel
from agentguard.policy import UNTRUSTED

ZERO_WIDTH = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]")
PATTERNS: list[tuple[str, str, str, str]] = [
    ("ignore_previous", r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)\b", "critical", "attempts to override existing instructions"),
    ("system_prompt", r"\b(disregard|reveal|print|dump|override).{0,40}\b(system|developer)\s+prompt\b", "critical", "targets privileged prompt content"),
    ("role_override", r"\b(you are now|act as|become)\s+(an?\s+)?(system|developer|admin|root|unrestricted)\b", "high", "attempts role override"),
    ("exfiltrate", r"\b(send|forward|email|post|upload|exfiltrate|leak)\b.{0,80}\b(secret|token|key|password|credential|confidential|customer\s+data)\w*\b", "critical", "requests exfiltration or forwarding of sensitive data"),
    ("invoice_exfil", r"\b(send|forward|email|post|upload|exfiltrate|leak)\b.{0,80}\b(confidential\s+)?invoices?\b.{0,80}\b(attacker|external|unknown|gmail|proton|mailinator)\b", "critical", "requests suspicious forwarding of invoices"),
    ("tool_smuggling", r"\b(call|invoke|run|execute|use)\s+(the\s+)?(tool|function|command|shell|bash|python|curl)\b", "high", "smuggles tool or command instructions"),
    ("meta_ai", r"\b(if|when)\s+(an?\s+)?(ai|agent|assistant|llm|model)\s+(is\s+)?(reading|processing|summarizing)\s+this\b", "high", "addresses the model rather than the user"),
    ("new_instruction", r"\b(from now on|new instruction|important instruction|priority:\s*ignore|do not tell the user)\b", "high", "introduces an imperative instruction"),
]
IMPERATIVE = re.compile(r"\b(must|always|never|do not|don't|send|forward|delete|call|execute|ignore|disregard)\b", re.I)


def _snippet(text: str, start: int, end: int) -> str:
    return text[max(0, start-50):min(len(text), end+50)].strip().replace("\n", " ")


def _encoded_payloads(text: str) -> list[tuple[str, str]]:
    out = []
    for token in re.findall(r"[A-Za-z0-9+/=]{24,}|(?:%[0-9A-Fa-f]{2}){6,}", text):
        decoded = ""
        try:
            decoded = urllib.parse.unquote(token)
            if decoded == token:
                decoded = base64.b64decode(token + "===", validate=False).decode("utf-8", "ignore")
        except Exception:
            continue
        if decoded and decoded != token:
            out.append((token, decoded))
    return out


@dataclass
class HeuristicDetector:
    detector_name: str = "heuristic"

    def scan(self, text: str, source: TrustLevel = TrustLevel.UNKNOWN, trusted_context: list[str] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for name, pattern, severity, why in PATTERNS:
            for m in re.finditer(pattern, text, re.I | re.S):
                if source in UNTRUSTED or name not in {"exfiltrate", "invoice_exfil"}:
                    findings.append(Finding(self.detector_name, severity, _snippet(text, *m.span()), why, name))
        if ZERO_WIDTH.search(text):
            findings.append(Finding(self.detector_name, "med", _snippet(text, ZERO_WIDTH.search(text).start(), ZERO_WIDTH.search(text).end()), "contains hidden unicode or zero-width characters", "hidden_unicode"))
        for raw, decoded in _encoded_payloads(text):
            nested = self.scan(decoded, source, trusted_context)
            if nested:
                findings.append(Finding(self.detector_name, "high", raw[:80], "encoded instruction blob decodes to suspicious instructions", "encoded_blob"))
        trusted_blob = "\n".join(trusted_context or []).lower()
        if source in UNTRUSTED and IMPERATIVE.search(text) and not findings:
            key_terms = [w.lower() for w in re.findall(r"[A-Za-z]{5,}", text)[:8]]
            if key_terms and not any(term in trusted_blob for term in key_terms):
                findings.append(Finding(self.detector_name, "med", text[:160].strip(), "new imperative from untrusted source lacks trusted support", "untrusted_provenance"))
        return findings
