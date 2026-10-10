# QuantumTrace for VS Code (planned)

Placeholder: not built yet. The contract below keeps it a thin client.

## What it should do
- Command **QuantumTrace: Scan workspace** → findings shown as editor diagnostics
  (critical = Error, medium = Warning, safe = hidden by default), hover shows the rationale and the
  FIPS 203/204/205 replacement.
- Code action "Show migration guidance" linking to the finding's NIST reference.
- Export CBOM for the workspace.

## How it talks to the engine
Two backends, chosen by a setting:
1. **Local CLI** (default, offline, no upload): spawn `quantumtrace scan <workspace> --format json`
   and parse the `ScanResult` JSON.
2. **Remote API**: `@quantumtrace/sdk` `createClient({ baseUrl, apiKey }).scanFiles(...)`.

Never re-implement classification here: tiers come from `backend/src/quantumtrace/rules/`.
The code scanner must emit `Evidence.line` for diagnostics to land on the right line.

## Getting started (when we build it)
`npx --package yo --package generator-code -- yo code` inside this folder, TypeScript, then add
`"@quantumtrace/sdk": "workspace:*"`. See `.claude/skills/new-client/SKILL.md`.
