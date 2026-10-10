# QuantumTrace web app

React + Vite dashboard: upload files or paste a GitHub repository link, read the report, export
the CBOM. It talks to the API only through `@quantumtrace/sdk`.

```sh
pnpm -F @quantumtrace/web dev     # http://localhost:5173, API from VITE_API_URL (default :8000)
pnpm -F @quantumtrace/web build   # dist/, plus the browser extension zips in public/extension
```

Deployed on Vercel with this folder as the project's root directory and `VITE_API_URL` set to the
API project's URL. Vercel only rebuilds this project when something under this folder (or a
workspace package it uses) changes, so a commit that touches nothing here doesn't redeploy it.
