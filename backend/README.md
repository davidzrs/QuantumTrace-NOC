# QuantumTrace backend

Python package `quantumtrace`: scanning engine (library), REST API (FastAPI) and CLI (Typer).
See the repo root README and `.claude/CLAUDE.md` for architecture and commands.

```sh
uv sync
uv run quantumtrace scan ../samples/cloud-posture --format table
uv run uvicorn quantumtrace.api.app:app --reload
uv run pytest
```
