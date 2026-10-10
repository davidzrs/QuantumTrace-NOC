# QuantumTrace

Post-quantum readiness scanner for the **JunctionX Lisbon 2026 "Inspiring Solutions" challenge**
(brief: `Inspiring Solutions - JunctionX Lisbon 2026.pdf`). It discovers cryptography in cloud
exports, source code and network captures. It classifies each primitive by quantum risk,
scores the estate, and exports a **CycloneDX 1.6 CBOM** mapped to NIST FIPS 203/204/205.

Judging weights, which should guide your priorities:
- detection accuracy and Shor vs Grover differentiation: **40%**
- ingestion coverage (PCAP, code, config): **25%**
- standards and traceability (CBOM, FIPS mapping): **20%**
- usability and demo (one-command setup): **15%**

## Architecture: one engine, thin adapters

```
samples/  ──►  scanners/*  ──CryptoAsset──►  core/classifier  ──Finding──►  core/scoring ──► ScanResult
                                    ▲ rules/algorithms.yaml                           │
                                                                    cbom/cyclonedx ◄──┤
             adapters:  api/ (FastAPI)   cli.py (Typer)   ──►  @quantumtrace/sdk  ──►  web, VS Code, browser ext
```

- `core/engine.run_scan()` is the single entry point. The API, the CLI, and any future client call it
  (directly or through the API). **Clients never classify.**
- `rules/algorithms.yaml` is the **only** place tiers, threats, NIST references and replacements
  are defined. Scanners emit raw `CryptoAsset`s with an alias the classifier can resolve.
- The pydantic models in `core/models.py` are the public contract. OpenAPI is generated from them,
  and so is `frontend/packages/sdk/src/schema.d.ts`.

## Layout

| Path | What |
| --- | --- |
| `backend/src/quantumtrace/core/` | models, classifier, scoring, engine |
| `backend/src/quantumtrace/rules/` | `algorithms.yaml`, `aws_elb_policies.yaml`, `tls.py` (cipher-suite decomposition) |
| `backend/src/quantumtrace/scanners/` | `cloud/aws.py` (AWS KMS/ACM/ELB), `code/` (Python/Java/Go rule sets in `*_lang.py`), `network/` (scapy flow reassembly, TLS + SSH parsers) |
| `backend/src/quantumtrace/cbom/` | CycloneDX 1.6 export |
| `backend/src/quantumtrace/api/` | FastAPI app, `/api/v1/*`, optional `X-API-Key`, in-memory store |
| `backend/tests/` | golden tests against `samples/` for every vector |
| `frontend/apps/web/` | React 19 + Vite + Tailwind v4 dashboard (deployed to Vercel) |
| `frontend/packages/sdk/` | generated OpenAPI types + typed client |
| `frontend/packages/ui/` | `TierBadge`, `DebtStrip`, design tokens, shared with extension popups |
| `frontend/apps/{vscode,browser}-extension/` | placeholders with the integration contract |
| `samples/` | organiser data (READMEs in Portuguese). Read-only: never edit to make a test pass |

## Commands

```sh
make install     # uv sync + pnpm install
make dev         # API :8000 + web :5173
make test        # pytest + vitest
make lint        # ruff, ruff format --check, mypy --strict, eslint, tsc
make gen-sdk     # after ANY API/model change: regenerate openapi.json + SDK types
make scan        # CLI scan of all samples
make demo        # docker compose: api :8000, web :8080
cd backend && uv run quantumtrace scan ../samples/cloud-posture -f cbom -o out.cdx.json
```

## Conventions

- **Tests first for detections.** Every detection or rule change needs a golden test asserting
  tier and name against a real file in `samples/`. The pcap tests pin exact session counts
  (e.g. 54 static-RSA, 36 x25519, 7 X25519MLKEM768), so a regression shows up as a count diff.
- **Tier semantics are strict.** `critical` means Shor (RSA, DSA, ECDSA, EdDSA, ECDH, DH).
  `medium` means Grover-weakened (AES-128, 3DES, SHA-1, MD5). `safe` covers AES-256, SHA-384+,
  ML-KEM, ML-DSA, SLH-DSA and hybrids. Classically broken primitives keep their quantum tier and set
  `classically_broken: true`, which scoring weights like critical. A test enforces that no Grover
  rule is critical.
- **Traceability.** Every asset carries `Evidence` (file plus line, ARN plus `json_path`, or
  network flow plus `packet`). The API rewrites paths relative to the scanned root, so never
  return absolute server paths.
- **Say how you know.** Set `CryptoAsset.observation`: `negotiated` (traffic), `configured`,
  `in-code`, `permitted` (policy allows it, not proven used) or `offered`. Set `confidence`:
  `high` when read directly, `medium` when inferred (e.g. a key size taken from elsewhere in
  the file, or a heuristic), `low` when the input is incomplete. Set `variant` to the precise
  form (AES-128-GCM, Ed25519, ECDSA P-256, x25519). One finding per cipher **and mode**: GCM and CBC
  are different exposures.
- **Group repeats, don't duplicate.** Identical assets at the same place (e.g. a browser's
  parallel sessions to one host) become one finding: the first `evidence` plus
  `more_evidence`. Network scanners use `pcap.group_by_server`. The web inventory further
  groups identical findings across places into one row ("28 places, 36 sessions"). The CBOM
  emits every piece of evidence as an occurrence.
- **State blind spots.** When the input can't prove something, yield a `ScanNote`. Examples:
  certificates referenced only by ARN, certificates encrypted in TLS 1.3, cleartext DNS. Notes
  show up as `ScanResult.limitations`, in the UI, and as CBOM metadata.
- **Protocol tiers.** TLS 1.2 is `medium`, because it can't carry hybrid PQC. TLS 1.3 is
  `medium` unless an ML-KEM group is negotiated or enabled: emit the `TLSv1.3-classical` alias
  with a `no-pq-group` flag. TLS 1.3 with a hybrid group is `safe`.
- Python: 3.12, ruff (line 100), mypy strict, pydantic v2. API-facing models extend
  `core.models.Model` so TS types mark defaulted fields as required.
- TypeScript: strict, `noUncheckedIndexedAccess`. Talk to the API only through `@quantumtrace/sdk`.
- API versioning: everything lives under `/api/v1`. Breaking changes need `/api/v2`, because
  extensions ship on their own release cycle.
- CI (`.github/workflows/ci.yml`) has two jobs: backend (ruff, mypy, pytest) and frontend
  (lint, types, tests, build, SDK drift). Run `make lint && make test` before pushing.

## UI direction (keep it, don't drift into template looks)

- **Palette:** colour is reserved for risk. Crimson = Shor, ochre = Grover, teal = resilient.
  Everything else is ink on porcelain (tokens in `packages/ui/src/tokens.css`, with dark mode).
- **Type:** Public Sans for everything. JetBrains Mono **only** for real identifiers (ARNs, OIDs,
  cipher suites, paths), never for labels.
- **Hero:** the report leads with a plain sentence ("25 of 69 assets break under Shor's algorithm")
  and the debt strip, one tick per finding. No gauges, no card grids, no gradient washes, no
  all-caps eyebrows. Tables use hairline rules. Motion happens once: the strip reveal.
- **Copy:** sentence case, active verbs ("Export CBOM", "Scan sample"). Errors say what failed
  and what to do next.

## Sample-data quirks (read before writing scanners)

- `cloud-posture/`: AWS API shapes. `SslPolicy` values resolve through `rules/aws_elb_policies.yaml`.
  ACM certificates inherit exposure from the ELB listeners in `InUseBy`.
- `sample-repos/`: some crypto is **hand-rolled**, for example a manual PBKDF2/HMAC loop in
  `go/auth-gateway`, which `go_lang._hand_rolled_kdf` detects. Others misuse primitives, e.g. ECB
  mode (Java's default for `"AES"`, Go's raw `block.Encrypt` loops), hard-coded keys, or
  `java.util.Random` / Python `random` / Go `math/rand` used for tokens. Key sizes come from
  same-file constants and literals (`SourceFile.symmetric_key_hint`).
- `network-capture/network.pcap`: 2000 packets, 135 TCP sessions with one server each. It
  contains only ClientHello/ServerHello and no certificates. TLS runs on HTTPS, LDAPS (636),
  IMAPS (993), SMTP after STARTTLS (587) and Postgres after SSLRequest (5432). Profiles:
  - 54 sessions on TLS 1.2 `TLS_RSA_WITH_AES_128_CBC_SHA`
  - 36 sessions on TLS 1.3 with x25519
  - 7 sessions on TLS 1.3 with X25519MLKEM768

  SSH (24 sessions) is either legacy (group14-sha1 / ssh-rsa / aes128-cbc) or modern
  (curve25519 / chacha20). There is also plain HTTP and DNS noise. Use scapy (pure Python),
  because the Docker image has no tshark.

## Deploy

- **API → Fly.io.** `fly.toml` sits at the repo root, the image is `backend/Dockerfile` (built from
  the repo root, with samples baked in). There is no deploy workflow yet: deploy manually with
  `fly deploy` (see the `deploy` skill). Set Fly secrets `QT_API_KEY` and `QT_CORS_ORIGINS`.
- **Web → Vercel** via its Git integration. Root directory is `frontend/apps/web` (see
  `vercel.json`). Set the env var `VITE_API_URL=https://<fly-app>.fly.dev`. Anything in `VITE_*` is
  public.
- Storage is in-memory (`store/repository.py`). Fly machines auto-stop, so scans are ephemeral by
  design. Swap the implementation behind `ScanRepository` if persistence is needed.

## Skills

Use the project skills in `.claude/skills/` for the recurring workflows:
- `add-scanner`
- `crypto-classification`
- `cbom-export`
- `api-endpoint`
- `new-client`
- `deploy`
- `demo-prep`
