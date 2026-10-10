from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_REPO_ROOT = Path(__file__).resolve().parents[4]
_REPO_SAMPLES = _REPO_ROOT / "samples"
_ON_VERCEL = bool(os.environ.get("VERCEL"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="QT_",
        # The repo-root .env, wherever the API is started from; a .env in the cwd overrides it.
        env_file=(_REPO_ROOT / ".env", ".env"),
        extra="ignore",
        populate_by_name=True,
    )

    api_key: str | None = None  # when set, every /api/v1 route except /health needs X-API-Key
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    cors_origin_regex: str | None = None  # e.g. https://quantumtrace-.*\.vercel\.app
    samples_dir: Path = _REPO_SAMPLES
    # Bytes on the wire per scan. Vercel rejects request bodies over 4.5 MB before they reach
    # the function, which is why the web app gzips files before uploading.
    max_upload_mb: int = 4 if _ON_VERCEL else 200
    # Bytes after .zip and .gz uploads are unpacked (also the zip-bomb guard). On Vercel this
    # keeps a scan inside the function's 60 s limit and its /tmp space.
    max_unpacked_mb: int = 50 if _ON_VERCEL else 500
    # Size of a GitHub repository's zip that /scans/github downloads. The server fetches it, so
    # Vercel's request limit doesn't apply; the cap keeps the download inside the 60 s limit.
    # Only the files a scanner reads are unpacked, and those count against max_unpacked_mb.
    max_repo_mb: int = 150 if _ON_VERCEL else 1000
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

    # "Fix me" on code findings sends the snippet to Gemini. Off unless a key is set; a free
    # key comes from aistudio.google.com.
    gemini_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("QT_GEMINI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"),
    )
    # Fastest reliable free-tier option in our benchmark: ~1 s per fix, 24/24 checks. Flash
    # (gemini-flash-latest) writes slightly better fixes but takes 5-30 s, is capped at 20 free
    # requests a day, and timed out often.
    ai_model: str = "gemini-3.5-flash-lite"
    # Gemini 3 thinking level: minimal (Flash-Lite only), low, medium, high. Empty = model default.
    ai_thinking: str | None = "low"

    @property
    def ai_fix(self) -> bool:
        return bool(self.gemini_api_key)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
