"""Command-line adapter: `quantumtrace scan <paths>`, `quantumtrace probe <host>` and
`quantumtrace trace -- <command>`, with `--format table|json|cbom`, and `quantumtrace report
<paths>` for an offline report folder."""

from __future__ import annotations

import json
import os
import re
import subprocess
from enum import StrEnum
from itertools import count
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from quantumtrace.cbom.cyclonedx import to_cyclonedx
from quantumtrace.core.engine import iter_files, run_probe, run_scan
from quantumtrace.core.models import Evidence, RiskTier, ScanResult
from quantumtrace.report import headline, render_summary
from quantumtrace.scanners.network.probe import ProbeError
from quantumtrace.tracers import TRACE_FILE, python_environment

app = typer.Typer(help="QuantumTrace: post-quantum readiness scanner", no_args_is_help=True)
console = Console()

TIER_STYLE = {
    RiskTier.CRITICAL: "bold red",
    RiskTier.MEDIUM: "yellow",
    RiskTier.SAFE: "green",
    RiskTier.UNKNOWN: "dim",
}


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
    CBOM = "cbom"


@app.callback()
def main() -> None:
    """QuantumTrace CLI."""


@app.command()
def scan(
    paths: Annotated[list[Path], typer.Argument(exists=True, help="Files or directories")],
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.TABLE,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    fail_on: Annotated[
        RiskTier | None, typer.Option(help="Exit 1 if any finding has this tier (for CI)")
    ] = None,
) -> None:
    """Scan files/directories and report quantum-vulnerable cryptography."""
    _report(run_scan(paths), fmt, output, fail_on)


REPORT_FILES = ("summary.pdf", "report.json", "cbom.cdx.json")


@app.command()
def report(
    paths: Annotated[list[Path], typer.Argument(exists=True, help="Files or directories")],
    out: Annotated[
        Path, typer.Option("--out", "-o", help="Folder that keeps one subfolder per run")
    ] = Path("outputs"),
    fail_on: Annotated[
        RiskTier | None, typer.Option(help="Exit 1 if any finding has this tier (for CI)")
    ] = None,
) -> None:
    """Scan offline and write summary.pdf, report.json and cbom.cdx.json to a new folder in
    `outputs/`, named after the time and what was scanned."""
    # Earlier runs inside a scanned folder are reports, not inputs.
    runs = out.resolve()
    files = [f for f in iter_files(paths) if not f.resolve().is_relative_to(runs)]
    result = run_scan(files, display_targets=[str(p) for p in paths])

    folder = _run_folder(out, result, paths)
    summary, report_json, cbom = (folder / name for name in REPORT_FILES)
    report_json.write_text(json.dumps(result.model_dump(mode="json"), indent=2), encoding="utf-8")
    cbom.write_text(json.dumps(to_cyclonedx(result), indent=2), encoding="utf-8")
    summary.write_bytes(render_summary(result, report_name=report_json.name, cbom_name=cbom.name))

    s = result.score
    console.print(f"{headline(result)} Quantum risk score {s.value:.1f} of 10 (grade {s.grade}).")
    for err in result.errors:
        console.print(f"[red]error[/] {err}")
    console.print(f"Wrote {', '.join(REPORT_FILES)} to [bold]{folder}[/]", style="green")
    if fail_on and any(f.classification.tier == fail_on for f in result.findings):
        raise typer.Exit(code=1)


def _run_folder(out: Path, result: ScanResult, paths: list[Path]) -> Path:
    """A new folder per run: `2026-10-11_143052_samples`, local time then the first target,
    with `-2`, `-3` added when two runs land in the same second."""
    when = result.created_at.astimezone().strftime("%Y-%m-%d_%H%M%S")
    name = re.sub(r"[^a-z0-9._-]+", "-", paths[0].resolve().name.lower()).strip("-.")[:40]
    name = name or "scan"
    if len(paths) > 1:
        name += f"-and-{len(paths) - 1}-more"
    for n in count(1):
        folder = out / (f"{when}_{name}" if n == 1 else f"{when}_{name}-{n}")
        try:
            folder.mkdir(parents=True)
        except FileExistsError:
            continue
        return folder
    raise AssertionError("unreachable")


@app.command()
def probe(
    host: Annotated[str, typer.Argument(help="Host name, e.g. example.com")],
    port: Annotated[int, typer.Option("--port", "-p")] = 443,
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.TABLE,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    fail_on: Annotated[
        RiskTier | None, typer.Option(help="Exit 1 if any finding has this tier (for CI)")
    ] = None,
) -> None:
    """Handshake with a live TLS host and report what it negotiates and permits."""
    try:
        result = run_probe(host, port, allow_private=True)  # local CLI: the user's own network
    except ProbeError as exc:
        console.print(f"[red]error[/] {exc}")
        raise typer.Exit(code=2) from exc
    _report(result, fmt, output, fail_on)


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def trace(
    ctx: typer.Context,
    root: Annotated[
        Path, typer.Option(exists=True, file_okay=False, help="The project folder")
    ] = Path("."),
) -> None:
    """Run a command with the runtime tracer, to see which cryptography the code really
    executes: `quantumtrace trace -- python -m pytest`. The next `scan` of the folder reads
    the trace."""
    if not ctx.args:
        console.print(
            "[red]error[/] Give the command to run: quantumtrace trace -- python -m pytest"
        )
        raise typer.Exit(code=2)
    root = root.resolve()
    out = root / TRACE_FILE
    out.unlink(missing_ok=True)  # a trace is one run: an old one would describe other code
    try:
        # the user's own command, run as typed
        done = subprocess.run(ctx.args, env=python_environment(root, out, os.environ), check=False)  # noqa: S603
    except OSError as exc:
        console.print(f"[red]error[/] Could not run {ctx.args[0]}: {exc}")
        raise typer.Exit(code=2) from exc
    if out.exists():
        console.print(f"Trace written to {out}. Read it with: quantumtrace scan {root}")
    else:
        console.print(
            "[yellow]No trace was written.[/] The tracer follows Python programs: check that "
            "the command starts Python 3.12 or newer."
        )
    raise typer.Exit(code=done.returncode)


def _report(
    result: ScanResult, fmt: OutputFormat, output: Path | None, fail_on: RiskTier | None
) -> None:
    if fmt is OutputFormat.TABLE:
        table = Table(title=f"QuantumTrace: {len(result.findings)} findings")
        traced = any(e.execution for f in result.findings for e in f.asset.all_evidence)
        columns = ["Tier", "Algorithm", "Observed", "Usage", "Exposure", "Location"]
        for col in [*columns, *(["Ran"] if traced else [])]:
            table.add_column(col)
        order = list(RiskTier)
        for f in sorted(result.findings, key=lambda f: order.index(f.classification.tier)):
            c = f.classification
            table.add_row(
                f"[{TIER_STYLE[c.tier]}]{c.tier.value}[/]",
                c.name,
                f.asset.observed,
                f.asset.usage or "",
                f.asset.exposure.value,
                f.asset.evidence.location,
                *([_ran(f.asset.all_evidence)] if traced else []),
            )
        console.print(table)
        s = result.score
        console.print(
            f"Quantum Risk Score: [bold]{s.value:.1f}[/] of 10 (grade {s.grade}). "
            f"critical={s.counts.critical} medium={s.counts.medium} "
            f"safe={s.counts.safe} unknown={s.counts.unknown}"
        )
        for err in result.errors:
            console.print(f"[red]error[/] {err}")
    else:
        payload = (
            to_cyclonedx(result) if fmt is OutputFormat.CBOM else result.model_dump(mode="json")
        )
        text = json.dumps(payload, indent=2)
        if output:
            output.write_text(text)
            console.print(f"Wrote {output}", style="green")
        else:
            print(text)

    if fail_on and any(f.classification.tier == fail_on for f in result.findings):
        raise typer.Exit(code=1)


def _ran(places: list[Evidence]) -> str:
    """What a runtime trace saw of a finding: `14 calls`, `yes`, `no`, or nothing to say."""
    seen = [e.execution for e in places if e.execution is not None]
    if not seen:
        return ""
    if not any(x.ran for x in seen):
        return "[dim]no[/]"
    calls = sum(x.calls or 0 for x in seen)
    return f"{calls} call{'' if calls == 1 else 's'}" if calls else "yes"


@app.command("openapi")
def openapi(output: Annotated[Path, typer.Option("--output", "-o")]) -> None:
    """Write the OpenAPI spec (used to generate the TypeScript SDK)."""
    from quantumtrace.api.app import create_app

    output.write_text(json.dumps(create_app().openapi(), indent=2) + "\n")


if __name__ == "__main__":
    app()
