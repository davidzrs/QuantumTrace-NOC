---
name: deploy
description: Deploy QuantumTrace — API and web app as two Vercel projects (Docker/Fly.io as the fallback for big uploads) — configure env vars, CORS and Redis storage, and troubleshoot failed deploys or health checks.
---

# Deploy

Two Vercel projects from one repo. In the Vercel import screen, choose **Import single
project** twice: once for `backend` (FastAPI) and once for `frontend/apps/web` (Vite).

## API → Vercel (root directory `backend`)
Files: `backend/app.py` (entrypoint Vercel detects; adds `src/` to the path and imports
`quantumtrace.api.app:app`), `backend/vercel.json` (60 s max duration, tests excluded from the
bundle). Dependencies install from `pyproject.toml` + `uv.lock` on Python 3.12.

1. Import with Root Directory = `backend`. Framework preset: FastAPI.
2. **Storage → Upstash Redis** (Marketplace, free tier), connected to this project. It adds
   `KV_REST_API_URL` and `KV_REST_API_TOKEN`. Without it scans live in one instance's memory and
   `GET /scans/{id}` can 404 when the next request lands on another instance.
3. Env vars: `QT_CORS_ORIGINS=https://<web-project>.vercel.app`. For preview deploys also set
   `QT_CORS_ORIGIN_REGEX=https://<web-project>-.*\.vercel\.app`. Optional `QT_API_KEY`.
4. Check `https://<api-project>.vercel.app/api/v1/health`: expect `"persistent": true` and
   `"max_upload_mb": 4`.

Limits: request bodies over 4.5 MB never reach the function (Vercel answers 413 without CORS
headers), so `max_upload_mb` defaults to 4 when `VERCEL` is set and the web app checks sizes
first. `samples/` is outside the root directory, so `/samples` is empty and the web app is
upload-only.

## Web → Vercel (root directory `frontend/apps/web`)
`vercel.json` sets the framework, install from the monorepo root, `dist` output and SPA rewrites.
1. Import with Root Directory = `frontend/apps/web`.
2. Env var `VITE_API_URL=https://<api-project>.vercel.app`. Only set `VITE_API_KEY` to a
   throwaway demo key, because it ships in the bundle. Redeploy after changing `VITE_*`.

## Fallback: Docker / Fly.io
For uploads over 4 MB, `backend/Dockerfile` (built from the repo root, samples baked in) runs the
API as one process with in-memory storage and a 50 MB cap. `fly.toml` is ready:
`fly launch --no-deploy --copy-config --name <app>`, `fly secrets set QT_CORS_ORIGINS=...`,
`fly deploy --remote-only`. Local parity: `make docker-build && docker run -p 8000:8000 quantumtrace-api`.

## Troubleshooting
| Symptom | Check |
| --- | --- |
| Web shows "Scanner unreachable" | `VITE_API_URL` (redeploy the web after changing it); CORS origins; API key mismatch → 401 |
| Report opens then says not found | Redis not connected to the API project: `/health` shows `"persistent": false` |
| Upload fails with a network error | Body over 4.5 MB; the web check needs `/health` to load first |
| API build fails resolving deps | `cd backend && uv lock` and commit |
| Vercel web install fails | `pnpm-lock.yaml` committed? `packageManager` field in root `package.json` |
