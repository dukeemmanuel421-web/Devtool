# Deploying the AgentGuard API

The API's default (heuristic) core is pure Python, no ML — it runs in a small container anywhere.

## Why not Vercel directly?
Vercel is Node-first and does not run FastAPI natively. Two supported paths:
1. **Container host (recommended):** deploy this repo's Dockerfile to Render / Railway / Fly.io / AWS
   (ECS/App Runner). Put your web playground on Vercel and point it at the API URL.
2. **Vercel Python functions:** port the heuristic detector into `api/*.py` serverless functions.
   Works because the core has no torch. The optional probe/LLM upgrades cannot be serverless.

## Render (fastest)
- New > Web Service > connect this repo > Render reads `render.yaml`.
- Set `AGENTGUARD_API_KEYS` (comma-separated) in the dashboard to enable auth.
- Health check: `/health`.

## Fly.io
```bash
fly launch --copy-config --now      # uses fly.toml
fly secrets set AGENTGUARD_API_KEYS="ag_live_xxx,ag_live_yyy"
```

## Docker (any host / local)
```bash
docker build -t agentguard-api .
docker run -p 8000:8000 -e AGENTGUARD_API_KEYS="ag_live_xxx" agentguard-api
curl -s localhost:8000/health
```

## Auth & rate limiting
- No `AGENTGUARD_API_KEYS` set -> **open mode** (good for a public playground / local dev).
- Keys set -> callers must send `Authorization: Bearer <key>`; unknown keys get 401.
- Per-key rate limit via `AGENTGUARD_RATE_LIMIT` / `AGENTGUARD_RATE_WINDOW_S` (defaults 60/60s).
  In-memory limiter is per-instance; use Redis for multi-instance production.
