# QuantumTrace

Find the cryptography a quantum computer will break. QuantumTrace scans cloud exports, source
code and network captures. It classifies every primitive as **critical** (Shor), **weakened**
(Grover) or **resilient**, scores the estate, and exports a **CycloneDX 1.6 CBOM** mapped to NIST
FIPS 203/204/205.

Built for the JunctionX Lisbon 2026 "Inspiring Solutions" challenge (brief in the PDF at the
repo root; data in `samples/`).

## Quick start

```sh
docker compose up --build        # web: http://localhost:8080  api: http://localhost:8000/docs
```

Without Docker (needs [uv](https://docs.astral.sh/uv/) and pnpm ≥ 10):

```sh
make install
make dev                         # api :8000 + web :5173
make scan                        # terminal report over all samples
```

CLI:

```sh
cd backend
uv run quantumtrace scan ../samples/cloud-posture                      # table
uv run quantumtrace scan ../samples -f cbom -o quantumtrace.cdx.json   # CycloneDX 1.6
uv run quantumtrace scan ./my-repo --fail-on critical                  # CI gate
```

## Status

| Vector | Status |
| --- | --- |
| Cloud posture (AWS KMS, ACM, ELB TLS policies) | working: 69 findings on `samples/cloud-posture` |
| Source code (Python, Java, Go) | working: 39 findings with file:line evidence, misuse flags (ECB, hard-coded keys, weak RNG, hand-rolled KDF) |
| Network capture (TLS on any port incl. STARTTLS, SSH, cleartext) | working: 473 findings over 135 sessions, hybrid ML-KEM detected |
| Live TLS probing | planned (needed by the browser extension) |

## Architecture

```
backend/   Python 3.12 · FastAPI · Typer — package `quantumtrace`
  core/       models, classifier, scoring, engine (single entry point)
  rules/      algorithms.yaml (the only place tiers live), AWS ELB policies, TLS suite parsing
  scanners/   cloud/ code/ network/ (pluggable Scanner protocol)
  cbom/       CycloneDX 1.6 export
  api/        /api/v1, optional X-API-Key, in-memory store
frontend/  pnpm workspace
  apps/web            React + Vite + Tailwind dashboard (Vercel)
  packages/sdk        typed client generated from the OpenAPI spec
  packages/ui         TierBadge, DebtStrip, design tokens (shared with extensions)
  apps/vscode-extension, apps/browser-extension   planned; contracts in their READMEs
samples/   organiser data (cloud posture JSON, Python/Java/Go repos, network.pcap)
```

Every client (web, CLI, VS Code, browser extension, CI) is a thin adapter over the same engine.
After changing the API, run `make gen-sdk`.

## Deploy

- **API → Fly.io**: `fly.toml` plus `backend/Dockerfile`; deploy manually with `fly deploy`
  (no deploy workflow yet).
- **Web → Vercel**: import the repo with root directory `frontend/apps/web` and set
  `VITE_API_URL`.

Details are in `.claude/skills/deploy/SKILL.md`.

## Contributing

`make lint && make test` before pushing (CI runs the same checks). Commit messages follow conventional commits (`feat`, `fix`,
`detect`, `rules`, …). Project conventions for humans and Claude live in `.claude/CLAUDE.md`.
