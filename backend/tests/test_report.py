"""`quantumtrace report`: one folder per offline run with the PDF summary, report.json and the CBOM."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from quantumtrace.cli import app
from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import (
    Classification,
    CryptoAsset,
    Evidence,
    Finding,
    Observation,
    Primitive,
    QuantumThreat,
    RiskTier,
    ScanNote,
    ScanResult,
    SourceType,
)
from quantumtrace.core.scoring import score
from quantumtrace.report.pdf import pdf_text
from quantumtrace.report.summary import render_summary

runner = CliRunner()
RUN_NAME = re.compile(r"\d{4}-\d{2}-\d{2}_\d{6}_cloud-posture(-2)?")


def report(*args: str) -> int:
    result = runner.invoke(app, ["report", *args])
    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    return result.exit_code


def load(run: Path) -> ScanResult:
    return ScanResult.model_validate_json((run / "report.json").read_text(encoding="utf-8"))


def test_each_run_gets_its_own_folder_with_the_three_files(samples: Path, tmp_path: Path) -> None:
    target, out = samples / "cloud-posture", tmp_path / "outputs"
    assert report(str(target), "--out", str(out)) == 0
    assert report(str(target), "--out", str(out)) == 0

    runs = sorted(out.iterdir())
    assert len(runs) == 2  # two runs in the same second still get two folders
    for run in runs:
        assert RUN_NAME.fullmatch(run.name), run.name
        assert sorted(p.name for p in run.iterdir()) == [
            "cbom.cdx.json",
            "report.json",
            "summary.pdf",
        ]
    assert len(load(runs[0]).findings) == len(run_scan([target]).findings)
    cbom = json.loads((runs[0] / "cbom.cdx.json").read_text(encoding="utf-8"))
    assert (cbom["bomFormat"], cbom["specVersion"]) == ("CycloneDX", "1.6")
    pdf = (runs[0] / "summary.pdf").read_bytes()
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.rstrip().endswith(b"%%EOF")


def test_earlier_runs_inside_the_scanned_folder_are_not_inputs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "outputs" / "old-run").mkdir(parents=True)
    (repo / "app.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (repo / "outputs" / "old-run" / "copy.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")

    assert report(str(repo), "--out", str(repo / "outputs")) == 0
    [run] = [p for p in (repo / "outputs").iterdir() if p.name != "old-run"]
    result = load(run)
    assert [f.classification.name for f in result.findings] == ["MD5"]
    assert result.targets == [str(repo)]


def test_fail_on_still_writes_the_report(samples: Path, tmp_path: Path) -> None:
    out = tmp_path / "outputs"
    assert report(str(samples / "cloud-posture"), "--out", str(out), "--fail-on", "critical") == 1
    [run] = out.iterdir()
    assert (run / "summary.pdf").is_file()


# ---------------------------------------------------------------- the PDF summary


def finding(
    n: int, tier: RiskTier, source: SourceType = SourceType.CODE, broken: bool = False
) -> Finding:
    return Finding(
        id=f"f{n}",
        asset=CryptoAsset(
            observed=f"ALG{n}",
            algorithm=f"ALG{n}",
            usage="encryption",
            observation=Observation.IN_CODE,
            evidence=Evidence(source_type=source, location=f"src/file{n}.py", line=n),
        ),
        classification=Classification(
            rule_id=f"rule-{n}",
            name=f"Algorithm {n}",
            primitive=Primitive.BLOCK_CIPHER,
            threat=QuantumThreat.SHOR if tier is RiskTier.CRITICAL else QuantumThreat.GROVER,
            tier=tier,
            classically_broken=broken,
            replacement=None if tier is RiskTier.SAFE else "ML-KEM (FIPS 203)",
            rationale="",
        ),
    )


def scan(findings: list[Finding], notes: list[str] | None = None) -> ScanResult:
    return ScanResult(
        id="0123456789abcdef",
        targets=["samples/"],
        scanners=["source-code"],
        findings=findings,
        score=score(findings),
        limitations=[ScanNote(scanner="source-code", message=m) for m in notes or []],
    )


def pages(pdf: bytes) -> int:
    return len(re.findall(rb"/Type /Page[^s]", pdf))


def test_pdf_text_keeps_what_the_built_in_font_can_print() -> None:
    assert pdf_text("Shor’s – “quoted” · café") == "Shor’s – “quoted” · café"  # noqa: RUF001
    assert pdf_text("10.0.0.5:51000 → 10.0.0.9:443 ≥ 1") == "10.0.0.5:51000 -> 10.0.0.9:443 >= 1"
    assert pdf_text("Dvořák 鍵") == "Dvorák ?"


def test_summary_fits_one_page_most_urgent_fix_first() -> None:
    pdf = render_summary(
        scan([
            finding(1, RiskTier.MEDIUM),
            finding(2, RiskTier.CRITICAL),
            finding(3, RiskTier.CRITICAL, broken=True),
            finding(4, RiskTier.SAFE),
        ])
    )  # fmt: skip
    assert pages(pdf) == 1
    assert b" of 4 cryptographic assets are critical." in pdf
    assert b"Quantum risk score" in pdf
    assert b"What to fix first" in pdf
    order = [pdf.index(f"({tag})".encode()) for tag in ("Fix now", "Before 2030", "Harden")]
    assert order == sorted(order)
    assert b"Recommended: ML-KEM" in pdf
    assert b"report.json  \xb7  cbom.cdx.json" in pdf  # where the detail is, in WinAnsi
    assert b"Page 1 of 1" in pdf


def test_summary_caps_fixes_and_blind_spots() -> None:
    many = [
        finding(i, RiskTier.CRITICAL if i % 3 else RiskTier.MEDIUM,
                SourceType.CODE if i % 2 else SourceType.CLOUD)
        for i in range(60)
    ]  # fmt: skip
    pdf = render_summary(scan(many, [f"Blind spot {i}." for i in range(10)]))
    assert pages(pdf) <= 2
    assert b"By source" in pdf
    assert b"And 52 more issues in report.json." in pdf
    assert b"Blind spot 5." in pdf
    assert b"Blind spot 6." not in pdf
    assert b"And 5 more notes in report.json." in pdf  # 4 left, plus the missing capture


def test_summary_says_so_when_nothing_was_found() -> None:
    pdf = render_summary(scan([]))
    assert b"No cryptography found." in pdf
    assert b"What to fix first" not in pdf


def test_summary_is_a_well_formed_pdf_whatever_the_paths() -> None:
    odd = finding(1, RiskTier.CRITICAL)
    odd.asset.evidence.location = "src/鍵 (copy)\\back.py"
    pdf = render_summary(scan([odd, *(finding(i, RiskTier.MEDIUM) for i in range(2, 40))]))
    assert b"(copy\\)" in pdf  # parentheses escaped inside PDF strings
    # Every cross-reference entry points at the start of its object, so no viewer has to repair it.
    xref = int(re.findall(rb"startxref\n(\d+)", pdf)[-1])
    entries = pdf[xref:].split(b"trailer")[0].splitlines()[3:]
    for number, entry in enumerate(entries, start=1):
        assert pdf[int(entry[:10]) :].startswith(f"{number} 0 obj".encode())
    assert pages(pdf) == 2
