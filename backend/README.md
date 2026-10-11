# QuantumTrace backend

Python package `quantumtrace`: scanning engine (library), REST API (FastAPI) and CLI (Typer).
See the repo root README and `.claude/CLAUDE.md` for architecture and commands.

```sh
uv sync
uv run quantumtrace scan ../samples/cloud-posture --format table
uv run uvicorn quantumtrace.api.app:app --reload
uv run pytest
uv run quantumtrace trace -- python -m pytest   # which crypto the code really runs; next scan reads it
```

"Fix with AI" needs `GEMINI_API_KEY` where the API runs. With `docker compose`, put it in the
repository root's `.env` (git-ignored); on Vercel, set it on the API project.
