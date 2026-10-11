# QuantumTrace backend

Python package `quantumtrace`: scanning engine (library), REST API (FastAPI) and CLI (Typer).
See the repo root README and `.claude/CLAUDE.md` for architecture and commands.

```sh
uv sync
uv run quantumtrace scan ../samples/cloud-posture --format table
uv run quantumtrace report ../samples --out ../outputs   # offline: PDF summary, report.json and CBOM
uv run uvicorn quantumtrace.api.app:app --reload
uv run pytest
uv run quantumtrace trace -- python -m pytest   # which crypto the code really runs; next scan reads it
```

"Fix with AI" needs `GEMINI_API_KEY` where the API runs. With `docker compose`, put it in the
repository root's `.env` (git-ignored); on Vercel, set it on the API project.

`tests/test_edge_cases.py` lists what the scanners still miss or over-flag (aliased imports, JWT,
TLS pinned in code, a shuffle scored like a break) as `xfail(strict=True)` tests. A fix that makes
one pass turns it into a failure on purpose: drop its marker and it becomes a regular test.
