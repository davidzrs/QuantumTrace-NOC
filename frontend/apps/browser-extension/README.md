# QuantumTrace browser extension (Chrome + Firefox)

A toolbar popup that answers "is the site in this tab quantum-ready?". Built with
[WXT](https://wxt.dev): one codebase, a Chrome MV3 build and a Firefox build.

The popup shows:
- whether the connection uses **post-quantum key exchange** (X25519MLKEM768) or a classical group
- a one-line verdict and the debt strip, then findings in three groups: what this connection
  negotiated, what the server **still accepts over TLS 1.2** (the downgrade path), and the leaf
  **certificate** key and signature
- what the check can't see (intermediate CAs, other clients' negotiations)
- **Open full report** (the web app's `/scans/:id`) and **Export CBOM** (CycloneDX 1.6)

The toolbar badge shows the count in the worst tier, coloured by tier, or `PQ` when everything
is resilient. Results are cached per host for 10 minutes; "Check again" re-probes.

## How it works

Browsers don't show TLS handshake details to extensions, so the popup sends the tab's
**host and port only** to `POST /api/v1/probes/tls` through `@quantumtrace/sdk`. The API
handshakes with the site (`backend/src/quantumtrace/scanners/network/probe.py`) and classifies
the result with the same engine as every other vector. The extension never classifies.

The deployed API refuses private, loopback and link-local addresses and probes only ports
that speak TLS directly (443, 8443, 465, 993, ...). For intranet hosts run the API locally
with `QT_PROBE_PRIVATE=true`, or use `quantumtrace probe <host>`.

Permissions: `activeTab` (read the tab's URL only when you open the popup), `storage`
(settings and the result cache), and host access to the API. `http://localhost:8000` is
granted at install; the settings page asks for any other API address you enter.

## Run it

```sh
make dev                                   # API on :8000, web app on :5173
pnpm -F @quantumtrace/browser-extension dev        # opens Chrome with the extension loaded
pnpm -F @quantumtrace/browser-extension build      # .output/chrome-mv3 → chrome://extensions → Load unpacked
pnpm -F @quantumtrace/browser-extension build:firefox
pnpm -F @quantumtrace/browser-extension zip        # store-ready zip
```

The dev server opens Chrome with the extension loaded. To use another Chromium browser (Brave,
Arc, Edge), create a gitignored `web-ext.config.ts` next to `wxt.config.ts`:

```ts
import { defineWebExtConfig } from "wxt";
export default defineWebExtConfig({
  binaries: { chrome: "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" },
  chromiumArgs: ["--user-data-dir=./.wxt/browser-data"], // keep pins and settings between runs
});
```

Point it at a deployed API from the extension's settings page (API address, optional API key,
web app address for full reports).
