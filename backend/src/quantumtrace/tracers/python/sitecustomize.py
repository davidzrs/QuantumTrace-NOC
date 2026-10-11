"""Starts the QuantumTrace tracer in every Python process that has this folder on PYTHONPATH.

Python imports one `sitecustomize` at start-up. This one starts the tracer, then runs the
`sitecustomize` it shadows, if the environment had its own.
"""

import os
import sys


def _start():
    try:
        import quantumtrace_tracer

        quantumtrace_tracer.start()
    except Exception:  # the traced program matters more than the trace
        pass


def _run_shadowed():
    from importlib.machinery import PathFinder
    from importlib.util import module_from_spec

    here = os.path.normcase(os.path.dirname(os.path.abspath(__file__)))
    for entry in sys.path:
        if os.path.normcase(os.path.abspath(entry or os.curdir)) == here:
            continue
        spec = PathFinder.find_spec("sitecustomize", [entry])
        if spec is not None and spec.loader is not None:
            spec.loader.exec_module(module_from_spec(spec))
            return


_start()
try:
    _run_shadowed()
except Exception:
    pass
