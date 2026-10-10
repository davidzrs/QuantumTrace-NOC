---
name: deploy
description: Deploy QuantumTrace — API to Fly.io (Docker) and web app to Vercel — configure secrets/env/CORS, and troubleshoot failed deploys or health checks.
---

# Deploy

## API → Fly.io
Files: `fly.toml` (repo root), `backend/Dockerfile` (built from the repo root, samples baked in),
no deploy workflow yet (deploys are manual).

One-time setup (by a human with a Fly account):
```sh
fly launch --no-deploy --copy-config --name <app>      # then set `app` in fly.toml
fly secrets set QT_API_KEY=<random> QT_CORS_ORIGINS=https://<project>.vercel.app
fly deploy --remote-only                               # deploy (manual for now)
```
To automate later, add a workflow that runs `flyctl deploy --remote-only` with a
`FLY_API_TOKEN` secret.

- Health check: `GET /api/v1/health`. Machines auto-stop when idle, so the first request
  cold-starts in about 2s. Fine for a demo.
- Storage is in memory, so scans vanish on restart. That's expected.
- Local parity: `make docker-build && docker run -p 8000:8000 quantumtrace-api`.

## Web → Vercel
Use Vercel's Git integration, so no workflow is needed:
1. Import the repo and set **Root Directory** = `frontend/apps/web`. `vercel.json` sets the
   framework, install from the monorepo root, `dist` output and SPA rewrites.
2. Env var `VITE_API_URL=https://<app>.fly.dev`. Only set `VITE_API_KEY` to a throwaway demo key,
   because it ships in the bundle.
3. Preview deploys per PR come free. `fly.toml` already allows `https://.*\.vercel\.app` through
   `QT_CORS_ORIGIN_REGEX`. Tighten it to your project prefix for production.

## Troubleshooting
| Symptom | Check |
| --- | --- |
| Web shows "Scanner unreachable" | `VITE_API_URL` value; CORS (`fly logs` shows OPTIONS 400); API key mismatch → 401 |
| Fly health check failing | `fly logs`; does `uv.lock` match `pyproject.toml` (`uv lock`)? |
| Docker build fails at `uv sync --frozen` | run `cd backend && uv lock` and commit |
| Vercel install fails | `pnpm-lock.yaml` committed? `packageManager` field in root `package.json` |
