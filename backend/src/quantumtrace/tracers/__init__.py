"""Runtime tracers: small programs that run inside the user's own interpreter while their tests
or a debug session run, and write what cryptography was really called to a trace file.

A tracer only records. The trace is read by `scanners/runtime`, so the tier of what ran is
decided by the same rules as everything else.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

PYTHON_TRACER = Path(__file__).parent / "python"
TRACE_FILE = Path(".quantumtrace") / "trace.jsonl"


def python_environment(root: Path, out: Path, base: Mapping[str, str]) -> dict[str, str]:
    """`base` plus what makes every Python process started with it trace into `out`."""
    env = dict(base)
    earlier = base.get("PYTHONPATH")
    env["PYTHONPATH"] = os.pathsep.join([str(PYTHON_TRACER), *([earlier] if earlier else [])])
    env["QT_TRACE_FILE"] = str(out)
    env["QT_TRACE_ROOT"] = str(root)
    env["QT_TRACE_RUN"] = uuid4().hex[:12]
    return env
