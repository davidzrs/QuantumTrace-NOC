---
name: new-client
description: Build a new QuantumTrace client surface — VS Code extension, Chrome/Firefox extension (WXT), GitHub Action/CI gate, or another app — on top of the SDK/CLI without duplicating engine logic.
---

# Add a client surface

The existing clients live in `extensions/vscode/` and `extensions/browser/`.

## Non-negotiables
- **No classification in clients.** Tiers, replacements and scores come from the engine via the
  API (`@quantumtrace/sdk`) or the CLI JSON (`quantumtrace scan --format json`).
- Visuals reuse `@quantumtrace/ui` (`TierBadge`, `TierGlyph`, `DebtStrip`, `tokens.css`) so every
  surface uses the same risk colours and shapes.
- API keys come from user settings or secret storage, never hard-coded or bundled.

## Pick a transport
| Surface | Default transport | Why |
| --- | --- | --- |
| VS Code | local CLI (`quantumtrace scan <ws> -f json`) | offline, code never leaves the machine |
| Browser ext | API (`/api/v1/...` probe endpoint) | browsers can't see TLS internals (Firefox partly can) |
| CI / GitHub Action | CLI with `--fail-on critical` | exit code gates the PR, `-f cbom -o` saves an artifact |

## Steps
1. Scaffold inside `frontend/apps/<name>/` with `package.json` name `@quantumtrace/<name>`. The
   pnpm workspace picks it up automatically.
2. Depend on `"@quantumtrace/sdk": "workspace:*"` (and `@quantumtrace/ui` for React UIs).
3. If you need a new endpoint, use the `api-endpoint` skill first, then `make gen-sdk`.
4. Add `lint`, `typecheck`, `test` and `build` scripts. The root `pnpm -r` commands and CI pick
   them up.
5. Browser extension: use WXT (`pnpm dlx wxt@latest init`) for one codebase that builds
   `chrome-mv3` and `firefox-mv2/3`. Add the extension origins to the API CORS settings
   (`QT_CORS_ORIGINS`), e.g. `chrome-extension://<id>`.
6. VS Code: map `critical` to `DiagnosticSeverity.Error`, `medium` to Warning, and `safe` to
   nothing. Use `evidence.line` for ranges.
