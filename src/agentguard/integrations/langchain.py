from __future__ import annotations
from agentguard.guard import Guard
from agentguard.model import TrustLevel

class GuardedTool:
    def __init__(self, tool, guard: Guard | None = None, source: TrustLevel = TrustLevel.TOOL_OUTPUT):
        self.tool = tool; self.guard = guard or Guard(); self.source = source
        self.name = getattr(tool, "name", tool.__class__.__name__)

    def invoke(self, *args, **kwargs):
        output = self.tool.invoke(*args, **kwargs) if hasattr(self.tool, "invoke") else self.tool(*args, **kwargs)
        result = self.guard.scan(str(output), self.source)
        if result.blocked:
            raise ValueError(f"AgentGuard blocked LangChain tool output: {result.to_dict()}")
        return result.sanitized_text or output
