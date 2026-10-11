# QuantumTrace task runner: bridges uv (backend) and pnpm (frontend).
.PHONY: install tools uv dev api web test lint format gen-sdk scan report demo docker-build

install: tools      ## Install backend + frontend dependencies and the git hooks
	cd backend && uv sync
	pnpm install
	git config core.hooksPath .githooks

tools:              ## Check for uv, Node.js 22+ and pnpm, and say how to get any that is missing
	@command -v uv >/dev/null 2>&1 || { echo "uv is missing: run make uv (macOS, Linux), or see Install the tools in README.md"; exit 1; }
	@command -v node >/dev/null 2>&1 || { echo "Node.js is missing: install 22 or newer from https://nodejs.org"; exit 1; }
	@node -e "process.exit(+process.versions.node.split('.')[0] < 22 ? 1 : 0)" || { echo "Node.js $$(node --version) is too old: install 22 or newer"; exit 1; }
	@command -v pnpm >/dev/null 2>&1 || { echo "pnpm is missing: run corepack enable (Node 22-24) or npm install -g pnpm@10.33.0"; exit 1; }
	@echo "Found $$(uv --version), node $$(node --version), pnpm $$(pnpm --version)"

uv:                 ## Install uv with Astral's official installer (macOS, Linux; Windows: see README.md)
	curl -LsSf https://astral.sh/uv/install.sh | sh

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

IN ?= samples
report:             ## Offline report folder in outputs/ (PDF, JSON, CBOM): make report IN=samples
	cd backend && uv run quantumtrace report ../$(IN) --out ../outputs

demo:               ## Full stack in Docker (api :8000, web :8080)
	docker compose up --build

docker-build:       ## Build the API image only
	docker build -f backend/Dockerfile -t quantumtrace-api .
