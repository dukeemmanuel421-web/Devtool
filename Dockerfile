# AgentGuard API — dependency-light heuristic core (no torch by default)
FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[server]"

ENV PORT=8000
# Set AGENTGUARD_API_KEYS to enable key auth; leave unset for open mode.
EXPOSE 8000
CMD ["sh", "-c", "uvicorn agentguard.server.app:app --host 0.0.0.0 --port ${PORT}"]
