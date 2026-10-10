---
name: demo-prep
description: Prepare and rehearse the QuantumTrace hackathon demo — run the full stack on the challenge samples, sanity-check scores and CBOM, and walk the pitch against the judging criteria.
---

# Demo prep

## 1. Fresh-machine check (usability is 15%)
```sh
docker compose up --build          # api :8000/docs, web :8080
```
Or run `make install && make dev`. Time it, because judges value a single command.

## 2. Accuracy pass (40%)
```sh
cd backend && uv run quantumtrace scan ../samples
```
- `unknown` count is 0
- spot-check every sample file against expectations in `backend/tests/test_*_scanner.py`
- no `xfail` left for vectors you plan to demo
- pick 3 "aha" findings, for example:
  - the internet-facing ALB on `ELBSecurityPolicy-2016-08` (TLS 1.0 plus static RSA key transport,
    i.e. no forward secrecy, which is the textbook Harvest-Now-Decrypt-Later case)
  - an RSA-1024 + SHA-1 signature in `python/license_token.py`
  - the TLS 1.3 policy that still negotiates classical ECDH (modern ≠ quantum-safe)
  - pcap: 7 HTTPS sessions already on hybrid X25519MLKEM768 vs 36 on classical x25519. Same
    protocol, different quantum posture.
  - Go `auth-gateway`: a home-made PBKDF2 found without any `pbkdf2` import

## 3. Standards pass (20%)
- Export the CBOM from the report page, then run `uv run pytest tests/test_cbom.py` (schema-valid
  1.6).
- Show a finding's FIPS 203/204/205 replacement and its NIST IR 8547 deadline (2030/2035).

## 4. Coverage (25%)
Scan everything at once from the home page, then show the scanners list: cloud, code, network.

## 5. Pitch skeleton (3 minutes)
1. **Problem**: HNDL means today's traffic is tomorrow's plaintext, and teams can't see where
   RSA/ECC lives.
2. **Live**: "Scan everything", then the headline sentence and the debt strip, then "Migrate
   these first", then expand a finding for evidence and replacement, then Export CBOM.
3. **Why it's credible**: one rules file mapped to NIST, golden tests on organiser data,
   CycloneDX 1.6.
4. **Where it goes**: the API is already there. Next come the VS Code extension (diagnostics in
   the editor), the browser extension ("is this site quantum-ready?") and a CI gate
   (`--fail-on critical`).

Have a fallback: a recorded screen capture and a pre-exported `.cdx.json`, in case of Wi-Fi or
Fly cold-start trouble.
