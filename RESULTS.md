# AgentGuard Results

Measured on `examples/labeled_samples.jsonl`, a tiny synthetic corpus intended as a smoke test rather than a benchmark:

- True positives: 4 / 4
- True negatives: 4 / 4
- Precision: 1.00
- Recall: 1.00

## Caveats

This corpus is synthetic and small. The dependency-free heuristic detector is a floor: it catches common, explicit inbound prompt-injection patterns and provenance problems, but attackers can paraphrase, split payloads across documents, or exploit model-specific behavior. The optional activation probe and LLM judge are intended to improve recall, but no detector is complete and AgentGuard should be combined with least-privilege tools, user confirmations, and audit logging.
