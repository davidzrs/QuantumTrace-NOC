"""FastAPI application factory. Thin adapter over quantumtrace.core."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from quantumtrace import __version__
from quantumtrace.api.settings import Settings, get_settings
from quantumtrace.api.v1.routes import public, router
from quantumtrace.store.repository import (
    InMemoryScanRepository,
    RedisScanRepository,
    ScanRepository,
)

API_PREFIX = "/api/v1"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title="QuantumTrace API",
        version=__version__,
        description="Discover, classify and report quantum-vulnerable cryptography (CBOM).",
    )
    app.state.repository = make_repository(settings)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_origin_regex=settings.cors_origin_regex,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key"],
    )
    app.include_router(public, prefix=API_PREFIX)
    app.include_router(router, prefix=API_PREFIX)
    return app


def make_repository(settings: Settings) -> ScanRepository:
    if settings.redis_url and settings.redis_token:
        return RedisScanRepository(settings.redis_url, settings.redis_token)
    return InMemoryScanRepository()


app = create_app()
