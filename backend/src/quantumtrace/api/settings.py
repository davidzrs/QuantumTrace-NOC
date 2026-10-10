from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_REPO_SAMPLES = Path(__file__).resolve().parents[4] / "samples"
# Vercel rejects request bodies over 4.5 MB before they reach the function.
_ON_VERCEL = bool(os.environ.get("VERCEL"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="QT_", env_file=".env", extra="ignore", populate_by_name=True
    )

    api_key: str | None = None  # when set, every /api/v1 route except /health needs X-API-Key
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    cors_origin_regex: str | None = None  # e.g. https://quantumtrace-.*\.vercel\.app
    samples_dir: Path = _REPO_SAMPLES
    max_upload_mb: int = 4 if _ON_VERCEL else 50
    # Let /probes/tls reach private and loopback addresses and any port. Only for a local API:
    # on a shared deployment it lets callers probe the server's own network (SSRF).
    probe_private: bool = False
    # Upstash Redis REST credentials. The Vercel Marketplace integration sets KV_REST_API_*;
    # without them scans live in process memory.
    redis_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("QT_REDIS_URL", "KV_REST_API_URL", "UPSTASH_REDIS_REST_URL"),
    )
    redis_token: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "QT_REDIS_TOKEN", "KV_REST_API_TOKEN", "UPSTASH_REDIS_REST_TOKEN"
        ),
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
