# QuantumTrace

Find the cryptography a quantum computer will break, before someone records your traffic today
and decrypts it later.

QuantumTrace scans what you already have (cloud exports, source code, network captures, server
configs, certificates, builds, or a live website), rates every algorithm it finds against quantum
attacks and tells you what to replace it with. You get a report to read, a **CycloneDX 1.6 CBOM**
mapped to NIST FIPS 203/204/205, and a PDF summary to hand to whoever signs off the fixes.

Built for the JunctionX Lisbon 2026 "Inspiring Solutions" challenge. The brief is the PDF at the
repo root; the challenge data is in `samples/`.

**Try it now:** [web app](https://quantumtrace-three.vercel.app) ·
[API docs](https://quantumtrace-api-six.vercel.app/docs). The web app's home page also offers the
browser extension (Chrome, Firefox) and the VS Code extension.

## How it rates what it finds

- **Critical**: Shor's algorithm breaks it outright (RSA, ECDSA, ECDH, DH, EdDSA). Move to ML-KEM
  and ML-DSA.
- **Medium**: Grover's algorithm weakens it (AES-128, SHA-1, 3DES, MD5). Use bigger keys and hashes.
- **Safe**: it holds up (AES-256, SHA-384 and up, ML-KEM, ML-DSA, SLH-DSA, hybrids).

Anything a normal computer already breaks (MD5, DES, TLS 1.0, 1024-bit RSA) is flagged as broken
today on top of its tier. Every finding says where it is (file and line, ARN, or network flow) and
how sure the scanner is, and every scan gets a risk score with a grade from A to F.

## What you can scan

| Input | Where |
| --- | --- |
| AWS posture exports (KMS, ACM, ELB policies, as JSON) | web upload, CLI |
| Source code: Python, Java, Go | web upload or GitHub link, CLI, VS Code |
| Network captures (`.pcap`, `.pcapng`): TLS on any port, SSH | web upload, CLI |
| Server configs: `sshd_config`, nginx, Apache | web upload, CLI |
| Certificates and keys: PEM, DER, PKCS#12, CSRs, SSH keys | web upload, CLI |
| Builds: Java `.class` / `.jar`, Go binaries | web upload (Java), CLI |
| A live website | paste a link in the web app, `quantumtrace probe`, browser extension |
| What your tests actually run (Python 3.12+) | `quantumtrace trace`, VS Code |

## Run it in one command

All you need is [Docker](https://docs.docker.com/get-docker/) with Compose v2 (Docker Desktop has
both). From the repo root:

```sh
docker compose up --build
```

Then open the web app at <http://localhost:8080> (API docs at <http://localhost:8000/docs>). The
first build takes a few minutes. Reports live in memory, so they're gone when the API restarts.

## Set it up for development

### What you need

| Tool | Version | What it's for |
| --- | --- | --- |
| [uv](https://docs.astral.sh/uv/) | 0.8 or newer | the backend's Python packages, and Python itself (it downloads 3.12 if you don't have it) |
| [Node.js](https://nodejs.org) | 22 or newer (22 LTS is what CI uses) | the web app and the extensions |
| [pnpm](https://pnpm.io) | 10.33 (pinned in `package.json`) | the JavaScript packages |
| make | any | the shortcuts below; optional, and on Windows you can run the commands by hand |

### Install the tools

**uv.** Pick one, then open a new terminal and check with `uv --version`:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh     # macOS, Linux (same as `make uv`)
brew install uv                                     # macOS with Homebrew
```

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"   # Windows
winget install --id=astral-sh.uv -e                                                  # Windows, winget
```

**Node.js and pnpm.** Install Node.js 22 LTS from [nodejs.org](https://nodejs.org) (or with nvm,
fnm or Volta), then turn on Corepack, which gives you exactly the pnpm version this repo pins:

```sh
corepack enable
```

Node 25 and newer no longer ship Corepack; there, run `npm install -g pnpm@10.33.0` instead.

### Install and run

```sh
make install    # checks the tools above, then installs everything and the git hook
make dev        # API on http://localhost:8000, web app on http://localhost:5173
```

If a tool is missing, `make install` says which one and how to get it. Without make:

```sh
cd backend && uv sync && cd ..
pnpm install
git config core.hooksPath .githooks
```

Then run the API (`cd backend && uv run uvicorn quantumtrace.api.app:app --reload`) and the web app
(`pnpm dev`) in two terminals.

### Optional settings

Both are off until you set them, and everything else works without them.

- **Fix code with AI**: put `GEMINI_API_KEY=...` in a `.env` file at the repo root (git ignores it).
  Free keys come from [Google AI Studio](https://aistudio.google.com/apikey). Docker and `make dev`
  both read it.
- **Accounts** (scan history across computers): put the four `VITE_FIREBASE_*` values in
  `frontend/apps/web/.env.local`. Without them the Account link stays hidden.

`.env.example` and `frontend/apps/web/.env.example` list every other setting.

## Use the command line

The CLI runs the same engine as the web app, fully offline.

```sh
cd backend
uv run quantumtrace scan ../samples/cloud-posture                      # a table in the terminal
uv run quantumtrace scan ../samples -f cbom -o quantumtrace.cdx.json   # CycloneDX 1.6 CBOM
uv run quantumtrace scan ./my-repo --fail-on critical                  # fail a CI job on Shor-breakable crypto
uv run quantumtrace report ../samples --out ../outputs                 # PDF summary, report.json and CBOM in one folder
uv run quantumtrace probe github.com                                   # handshake with a live site
uv run quantumtrace trace --root ./my-repo -- python -m pytest         # record what your tests really run,
uv run quantumtrace scan ./my-repo                                     # ...and the next scan reads it
```

`make scan` scans all the challenge samples, and `make report` writes the offline report folder.

## What it's built with

| Part | Stack |
| --- | --- |
| Engine, API and CLI (`backend/`) | Python 3.12, FastAPI 0.143, Pydantic 2.14, Typer 0.27, scapy 2.8, cryptography 50 |
| Web app (`frontend/apps/web`) | React 19, Vite 7, Tailwind CSS 4, TanStack Query 5, React Router 7, TypeScript 5.9 |
| Browser extension (`extensions/browser`) | WXT 0.21, Chrome (Manifest V3) and Firefox |
| VS Code extension (`extensions/vscode`) | VS Code 1.95+, bundled with esbuild |
| Optional services | Firebase 12 (accounts), Gemini via google-genai (AI fixes), Upstash Redis (stored reports on Vercel) |
| Checks | pytest, ruff, mypy (strict), Vitest, ESLint |

One engine does all the classifying. The web app, CLI, VS Code and browser extensions are thin
clients over it. The web app and extensions talk to the API through a typed client generated from
its OpenAPI spec (`frontend/packages/sdk`), so after changing the API, run `make gen-sdk`.

```
backend/      the engine (scanners, rules, scoring, CBOM export), the API and the CLI
frontend/     web app, typed API client, shared UI pieces (a pnpm workspace)
extensions/   browser and VS Code extensions
samples/      the organisers' challenge data (read-only)
personal-samples/   our own inputs for the file types samples/ doesn't cover
```

## Deploy

The API and the web app are two Vercel projects from this repo: root directory `backend` for the
API (add Upstash Redis from the Vercel Marketplace so reports survive between requests, and set
`QT_CORS_ORIGINS` to the web app's URL), and `frontend/apps/web` for the web app (set
`VITE_API_URL` to the API's URL). Vercel caps requests at 4.5 MB, so the web app compresses
uploads first; for bigger scans run it locally or use `backend/Dockerfile`. More detail in
`.claude/skills/deploy/SKILL.md`.

## Contributing

Run `make lint && make test` before you push; CI runs the same checks on every pull request. The
project's conventions (tiers, evidence, UI direction) are in `.claude/CLAUDE.md`.
