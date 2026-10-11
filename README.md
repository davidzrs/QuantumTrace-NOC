# QuantumTrace

Find the cryptography a quantum computer will break. QuantumTrace scans cloud exports, source
code and network captures. It classifies every primitive as **critical** (Shor), **weakened**
(Grover) or **resilient**, scores the estate, and exports a **CycloneDX 1.6 CBOM** mapped to NIST
FIPS 203/204/205

Built for the JunctionX Lisbon 2026 "Inspiring Solutions" challenge (brief in the PDF at the
repo root; data in `samples/`).

**Live:** web app at <https://quantumtrace-three.vercel.app>, API docs at
<https://quantumtrace-api-six.vercel.app/docs>. The web app's home page offers the browser
extension for Chrome and Firefox, already pointed at this API.

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
uv run quantumtrace probe github.com                                   # live TLS handshake
uv run quantumtrace trace --root ./my-repo -- python -m pytest         # what the tests really run
uv run quantumtrace scan ./my-repo                                     # ...then read the trace
```

## Status

| Vector | Status |
| --- | --- |
| Cloud posture (AWS KMS, ACM, ELB TLS policies) | working: 69 findings on `samples/cloud-posture` |
| Source code (Python, Java, Go) | working: 39 findings with file:line evidence, misuse flags (ECB, hard-coded keys, weak RNG, hand-rolled KDF) |
| Cryptography in use (`quantumtrace trace -- <tests>`, VS Code "Run tests with the runtime tracer") | working for Python 3.12+: a tracer records which lines ran and each `hashlib` / `hmac` / `cryptography` call with its real parameters; the scan marks findings `executed` ("ran 14× in test_login") or not run, and finds what source alone cannot (an algorithm named by a variable, a key size from configuration, calls made inside a library). Java and Go: not yet |
| Network capture (TLS on any port incl. STARTTLS, SSH, cleartext) | working: 473 findings over 135 sessions, hybrid ML-KEM detected |
| Live TLS probing (`quantumtrace probe <host>`, `POST /api/v1/probes/tls`) | working: negotiated version, group (hybrid ML-KEM or classical), cipher, TLS 1.2 downgrade path, leaf certificate key |
| Public GitHub repository by URL (`POST /api/v1/scans/github`, web app) | working: pinned to one commit, branch/tag/folder links, each code finding links to its line on GitHub |

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
extensions/
  browser             Chrome/Firefox popup (WXT): is the site in this tab quantum-ready?
  vscode              VS Code extension: highlights code findings in the editor, via the CLI or the API
samples/   organiser data (cloud posture JSON, Python/Java/Go repos, network.pcap)
```

Every client (web, CLI, VS Code, browser extension, CI) is a thin adapter over the same engine.
After changing the API, run `make gen-sdk`.

## Deploy

Both the API and the web app deploy to Vercel as two projects from this repo:

- **API**: root directory `backend`. Add Upstash Redis from the Vercel Marketplace so scans
  persist across serverless instances, and set `QT_CORS_ORIGINS` to the web app's URL.
- **Web**: root directory `frontend/apps/web`. Set `VITE_API_URL` to the API's URL.

On Vercel a request can carry 4 MB, so the web app gzips files before uploading. Source code and
JSON exports usually shrink 5 to 10 times, so a scan fits if it compresses to 4 MB and unpacks
to at most 50 MB. Folders, files and zips can be mixed in one scan. `backend/Dockerfile` (with
`fly.toml`) runs the same API as one long-lived process with higher limits (200 MB uploaded, 500
MB unpacked), set by `QT_MAX_UPLOAD_MB` and `QT_MAX_UNPACKED_MB`. Details are in
`.claude/skills/deploy/SKILL.md`.

## Contributing

`make lint && make test` before pushing (CI runs the same checks). Commit messages follow conventional commits (`feat`, `fix`,
`detect`, `rules`, …). Project conventions for humans and Claude live in `.claude/CLAUDE.md`.
