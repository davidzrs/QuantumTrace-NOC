"""Vercel entrypoint: Vercel looks for a FastAPI `app` in app.py at the project root.

Locally and in Docker, run `uvicorn quantumtrace.api.app:app` instead.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from quantumtrace.api.app import app

__all__ = ["app"]
