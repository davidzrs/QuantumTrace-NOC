"""Command-line adapter: `quantumtrace scan <paths> --format table|json|cbom`."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from quantumtrace.cbom.cyclonedx import to_cyclonedx
from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import RiskTier

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
    result = run_scan(paths)

    if fmt is OutputFormat.TABLE:
        table = Table(title=f"QuantumTrace: {len(result.findings)} findings")
        for col in ("Tier", "Algorithm", "Observed", "Usage", "Exposure", "Location"):
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
            )
        console.print(table)
        s = result.score
        console.print(
            f"Quantum Risk Score: [bold]{s.value}[/] (grade {s.grade}). "
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


@app.command("openapi")
def openapi(output: Annotated[Path, typer.Option("--output", "-o")]) -> None:
    """Write the OpenAPI spec (used to generate the TypeScript SDK)."""
    from quantumtrace.api.app import create_app

    output.write_text(json.dumps(create_app().openapi(), indent=2) + "\n")


if __name__ == "__main__":
    app()
