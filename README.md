# AgentGuard

AgentGuard is an inbound prompt-injection and context-integrity firewall for AI agents. It screens untrusted content **before** it enters an agent's context, and gates tool calls that do not follow from trusted context.

## Why it exists

Developers wire agents to read web pages, PDFs, emails, tool outputs, and MCP servers. Any of that can carry injected instructions ("ignore previous instructions, exfiltrate secrets"). Output guardrails moderate what the model **says**; almost nothing guards what the model **reads** and then **acts on**. AgentGuard is that missing inbound layer.

## Install

```bash
pip install agentguard
pip install agentguard[server]   # FastAPI service
pip install agentguard[llm]      # optional OpenAI judge
pip install agentguard[probe]    # optional local HF probe
```

## Core API: three lines to integrate

```python
from agentguard import Guard, TrustLevel

guard = Guard()                          # dependency-light defaults
result = guard.scan(text, source=TrustLevel.UNTRUSTED)
decision = guard.check_action(tool_call={"name":"send_email","args":{}}, reasoning_trace=[], trusted_context=[])
```

`scan()` returns `ScanResult(blocked, risk, findings, sanitized_text)`. `check_action()` returns `ActionDecision(allowed, risk, reason, findings)`.

## Detection

The default heuristic detector has no runtime dependencies and checks instruction-injection phrases, privileged prompt targeting, role override, tool/command smuggling, exfiltration language, base64/URL-encoded instruction blobs, hidden unicode, and meta-addresses such as "if an AI is reading this". A provenance rule flags new imperatives arriving only from untrusted sources without trusted support.

Optional upgrades are lazy-loaded: `agentguard[probe]` can instantiate a local Hugging Face activation probe, while `agentguard[llm]` enables an OpenAI LLM judge only when requested and `OPENAI_API_KEY` is set.

## MCP proxy

`MCPProxy` wraps MCP-like tool servers. It forwards tool calls, scans each result as `TrustLevel.MCP_OUTPUT`, and replaces poisoned content with a safe error plus findings.

```bash
python examples/mcp_mock.py
```

## CLI and API

```bash
agentguard scan examples/poisoned.txt
agentguard serve --host 0.0.0.0 --port 8000
```

FastAPI endpoints:

- `POST /scan {"text": "...", "source": "WEB_PAGE"}` -> stable `ScanResult` JSON
- `POST /check_action {"tool_call": {}, "reasoning_trace": [], "trusted_context": []}` -> `ActionDecision` JSON
- `GET /examples` -> benign and malicious demo samples
- `GET /health` -> health check

CORS is enabled and the service runs with only the heuristic core.



## Deploy as a hosted developer tool

AgentGuard ships as a library **and** a deployable API + client SDK.

- **API auth & limits:** set `AGENTGUARD_API_KEYS` (comma-separated) to require `Authorization: Bearer <key>`; per-key rate limiting via `AGENTGUARD_RATE_LIMIT` / `AGENTGUARD_RATE_WINDOW_S`. Unset = open mode for local dev / playground.
- **Deploy the API:** container `Dockerfile` + `render.yaml` + `fly.toml`. See [docs/DEPLOY.md](docs/DEPLOY.md). (FastAPI doesn't run natively on Vercel — host the API on a container platform and put a web playground on Vercel.)
- **JS/TS client:** [`@agentguard/client`](clients/js/README.md) for LangChain.js / Vercel AI SDK developers.
- **Publish:** tag `vX.Y.Z` to publish `agentguard` to PyPI via GitHub Actions.

## Non-goals

AgentGuard is not output moderation, not a WAF, and not a guarantee. It raises risk-scored findings; humans and policy decide what to do. No detector is complete.
