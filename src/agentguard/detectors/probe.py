from __future__ import annotations
from agentguard.model import Finding, TrustLevel

class ActivationProbeDetector:
    """Optional local HF activation probe. Imports heavy deps lazily when instantiated."""
    def __init__(self, model_name: str = "distilbert-base-uncased") -> None:
        import torch  # noqa: F401
        from transformers import pipeline
        self._classifier = pipeline("text-classification", model=model_name)

    def scan(self, text: str, source: TrustLevel = TrustLevel.UNKNOWN, trusted_context: list[str] | None = None) -> list[Finding]:
        result = self._classifier(text[:2048])[0]
        score = float(result.get("score", 0.0))
        label = str(result.get("label", "")).lower()
        if "inject" in label and score > 0.7:
            return [Finding("probe", "high", text[:160], f"activation probe labeled content as injected ({score:.2f})", "activation_probe")]
        return []
