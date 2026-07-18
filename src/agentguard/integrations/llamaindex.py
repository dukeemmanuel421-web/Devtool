from __future__ import annotations
from agentguard.guard import Guard
from agentguard.model import TrustLevel

class AgentGuardNodePostprocessor:
    def __init__(self, guard: Guard | None = None, source: TrustLevel = TrustLevel.DOCUMENT):
        self.guard = guard or Guard(); self.source = source

    def postprocess_nodes(self, nodes, **kwargs):
        kept = []
        for node in nodes:
            text = getattr(node, "text", None) or getattr(getattr(node, "node", None), "text", "")
            if not self.guard.scan(str(text), self.source).blocked:
                kept.append(node)
        return kept
