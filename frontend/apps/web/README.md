# QuantumTrace web app

React + Vite dashboard: upload files, or paste a GitHub repository or a website link, read the
report, and export it as a CBOM, the raw JSON or a PDF summary. Optional accounts keep a scan
history across computers. It talks to the API only through `@quantumtrace/sdk`

```sh
pnpm -F @quantumtrace/web dev     # http://localhost:5173, API from VITE_API_URL (default :8000)
pnpm -F @quantumtrace/web build   # dist/, plus the browser extension zips in public/extension
```

The build also packages `extensions/browser` and `extensions/vscode` for the download buttons, so
a change to either extension only reaches the site after this project redeploys.

Deployed on Vercel with this folder as the project's root directory and `VITE_API_URL` set to the
API project's URL. Vercel only rebuilds this project when something under this folder (or a
workspace package it uses) changes, so a commit that touches nothing here doesn't redeploy it.

On the Hobby plan Vercel only deploys commits by members of the Vercel team. When a teammate's
merge is blocked, the project owner can push any small commit under this folder, or click
Redeploy on the blocked deployment.
