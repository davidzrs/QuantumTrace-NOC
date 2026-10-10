---
name: api-endpoint
description: Add or change a QuantumTrace REST API endpoint (FastAPI, /api/v1) and propagate it to the generated TypeScript SDK and its consumers. Use for any change to api/ routes or core/models.py response shapes.
---

# Add an API endpoint

1. **Model first.** Request and response models extend `quantumtrace.core.models.Model`, not
   plain `BaseModel`, so defaulted fields stay required in the generated TS types. Reuse domain
   models (`ScanResult`, `Finding`) instead of near-duplicates.
2. **Route** in `backend/src/quantumtrace/api/v1/routes.py` (split into modules once it grows):
   - use `router` (API-key protected) unless the route must be public like `/health`
   - set a stable `operation_id` (camelCase); SDK method names follow it
   - add a typed return annotation, which becomes the OpenAPI response schema
   - inject the repo and settings via `Repo` / `SettingsDep`
   - never return absolute server paths (see `_relativise`) or raw exception text
   - for uploads, go through `api/uploads.materialise` (size limits, zip-slip safe)
3. **Test** in `backend/tests/test_api.py` with `make_client(samples, api_key=...)`. Cover
   success, 404/400 and the 401 path when it's protected.
4. **Regenerate the SDK**: `make gen-sdk`. This writes `frontend/packages/sdk/openapi.json` and
   `src/schema.d.ts`. Add a convenience method in `frontend/packages/sdk/src/index.ts`. CI's
   frontend CI job fails if you forget.
5. **Consumers**: update the web app (`frontend/apps/web/src`) and note the change for the
   extensions.
6. **Compatibility**: additive changes are fine in v1. Renames or removals need `/api/v2` because
   extensions update on their own schedule.

```sh
cd backend && uv run pytest tests/test_api.py -q && cd .. && make gen-sdk && pnpm typecheck
```
