# QuantumTrace task runner: bridges uv (backend) and pnpm (frontend).
.PHONY: install dev api web test lint format gen-sdk scan demo docker-build

install:            ## Install backend + frontend dependencies
	cd backend && uv sync
	pnpm install

api:                ## Run the API with reload on :8000
	cd backend && uv run uvicorn quantumtrace.api.app:app --reload --port 8000

web:                ## Run the web app on :5173
	pnpm -F @quantumtrace/web run dev

dev:                ## Run API and web together
	$(MAKE) -j2 api web

test:               ## All tests
	cd backend && uv run pytest
	pnpm test

lint:               ## Lint + format check + typecheck everything
	cd backend && uv run ruff check . && uv run ruff format --check . && uv run mypy src tests
	pnpm lint && pnpm typecheck

format:             ## Auto-format backend
	cd backend && uv run ruff format . && uv run ruff check --fix .

gen-sdk:            ## Regenerate OpenAPI spec + TypeScript SDK types after API changes
	cd backend && uv run quantumtrace openapi -o ../frontend/packages/sdk/openapi.json
	pnpm gen-sdk

scan:               ## Scan all challenge samples in the terminal
	cd backend && uv run quantumtrace scan ../samples

demo:               ## Full stack in Docker (api :8000, web :8080)
	docker compose up --build

docker-build:       ## Build the API image only
	docker build -f backend/Dockerfile -t quantumtrace-api .
