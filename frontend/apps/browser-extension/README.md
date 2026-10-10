# QuantumTrace browser extension (planned, Chrome + Firefox)

Placeholder: not built yet. Use [WXT](https://wxt.dev) to ship one codebase as a Chrome MV3
and a Firefox extension.

## What it should do
- Toolbar popup for the current tab's origin: "Is this site quantum-ready?"
  Shows negotiated TLS version, key exchange group (classical vs X25519MLKEM768) and certificate
  key algorithm, using `TierBadge` / `DebtStrip` from `@quantumtrace/ui`.
- Badge colour = worst tier.

## How it talks to the engine
Browsers don't expose TLS handshake details to extensions (Firefox has
`webRequest.getSecurityInfo`, Chrome does not). So:
1. The extension sends the origin to a future API endpoint, e.g. `POST /api/v1/probes/tls {host, port}`.
2. The backend actively probes the host (live TLS probing vector) and classifies the result via the
   same engine.
3. On Firefox, `getSecurityInfo` can provide data locally as a fast path.

Add the endpoint with `.claude/skills/api-endpoint`, then `make gen-sdk`, then consume it via
`@quantumtrace/sdk`. No classification logic in the extension.
