"""Runtime ("in-use") evidence: the Python tracer, the trace scanner and the merge with the
source scan. The golden cases run copies of files from `samples/sample-repos/python` for real,
in a child Python with the tracer on, and scan the folder the way a user would."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from quantumtrace.api.app import create_app
from quantumtrace.api.settings import Settings, get_settings
from quantumtrace.cbom.cyclonedx import to_cyclonedx
from quantumtrace.cli import app as cli
from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import (
    Confidence,
    Evidence,
    Finding,
    Observation,
    RiskTier,
    ScanResult,
)
from quantumtrace.scanners.runtime import python_api
from quantumtrace.tracers import PYTHON_TRACER, TRACE_FILE, python_environment
from tests.conftest import summarise

pytestmark = pytest.mark.skipif(
    not hasattr(sys, "monitoring"), reason="the Python tracer needs Python 3.12+"
)


def traced(root: Path, *command: str, env: dict[str, str] | None = None) -> Path:
    """Run a Python command in `root` with the tracer on, as the CLI and the extension do."""
    out = root / TRACE_FILE
    out.unlink(missing_ok=True)
    environment = python_environment(root, out, {**os.environ, **(env or {})})
    done = subprocess.run(
        [sys.executable, *command], cwd=root, env=environment, capture_output=True, text=True
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return out


def project(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return root


def in_file(result: ScanResult, name: str) -> list[Finding]:
    return [f for f in result.findings if Path(f.asset.evidence.location).name == name]


def one(result: ScanResult, name: str, rule: str, usage: str) -> Finding:
    found = [
        f
        for f in in_file(result, name)
        if f.classification.rule_id == rule and f.asset.usage == usage
    ]
    assert len(found) == 1, [
        (f.classification.rule_id, f.asset.usage) for f in in_file(result, name)
    ]
    return found[0]


def places(finding: Finding) -> dict[int | None, Evidence]:
    return {e.line: e for e in finding.asset.all_evidence}


# --- golden: a real sample file, run for real -------------------------------------------------


@pytest.fixture(scope="module")
def sample_run(tmp_path_factory: pytest.TempPathFactory, samples: Path) -> tuple[Path, ScanResult]:
    root = tmp_path_factory.mktemp("traced-sample")
    shutil.copytree(samples / "sample-repos" / "python", root / "python")
    traced(root, "python/license_token.py")
    return root, run_scan([root])


def test_sample_run_marks_what_executed(sample_run: tuple[Path, ScanResult]) -> None:
    _, result = sample_run
    assert "runtime-trace" in result.scanners
    assert result.errors == []
    assert result.score.counts.unknown == 0

    generated = one(result, "license_token.py", "rsa-1024", "key-generation")
    assert generated.asset.observation is Observation.EXECUTED
    assert generated.classification.tier is RiskTier.CRITICAL
    ran = generated.asset.evidence.execution
    assert ran is not None and ran.ran and ran.calls == 1
    assert ran.parameters == {"api": "rsa.generate", "key_size": "1024"}
    assert ran.run == "python license_token.py"
    # the source scan's own text, snippet and library stay: the trace adds to the finding
    assert generated.asset.library == "pypi:cryptography"
    assert generated.asset.observed.startswith("rsa.generate_private_key(")
    assert "key_size=1024" in (generated.asset.evidence.snippet or "")

    # sign on line 11, verify on line 16: both ran, with the key the program really used
    signature = one(result, "license_token.py", "rsa-1024", "signature")
    assert signature.asset.observation is Observation.EXECUTED
    assert {line: e.execution and e.execution.calls for line, e in places(signature).items()} == {
        11: 1,
        16: 1,
    }
    assert signature.asset.key_size == 1024
    sha1 = one(result, "license_token.py", "sha1", "hash")
    assert sha1.classification.tier is RiskTier.MEDIUM
    assert set(places(sha1)) == {11, 16}


def test_a_key_size_the_source_scan_inferred_is_proven_by_the_run(
    sample_run: tuple[Path, ScanResult], samples: Path
) -> None:
    _, result = sample_run
    static = one(
        run_scan([samples / "sample-repos" / "python"]), "license_token.py", "rsa-1024", "signature"
    )
    assert static.asset.confidence is Confidence.MEDIUM  # taken from the key generation line
    assert static.asset.observation is Observation.IN_CODE
    traced_one = one(result, "license_token.py", "rsa-1024", "signature")
    assert traced_one.asset.confidence is Confidence.HIGH  # read off the key that signed


def test_code_the_run_never_reached_is_marked_not_run(sample_run: tuple[Path, ScanResult]) -> None:
    _, result = sample_run
    md5 = one(result, "legacy_accounts.py", "md5", "hash")
    assert md5.asset.observation is Observation.IN_CODE
    assert md5.asset.evidence.execution is not None
    assert md5.asset.evidence.execution.ran is False
    assert md5.asset.evidence.execution.run == "python license_token.py"
    others = [
        f for f in result.findings if Path(f.asset.evidence.location).name != "license_token.py"
    ]
    assert others and all(
        e.execution is not None and not e.execution.ran
        for f in others
        for e in f.asset.all_evidence
    )


def test_the_trace_changes_no_tier_and_adds_nothing_the_source_scan_had(
    sample_run: tuple[Path, ScanResult], samples: Path
) -> None:
    _, result = sample_run
    static = run_scan([samples / "sample-repos" / "python"])
    assert summarise(result) == summarise(static)

    def lines(scan: ScanResult) -> list[tuple[str, int | None, str, str | None]]:
        return sorted(
            (Path(e.location).name, e.line, f.classification.rule_id, f.asset.usage)
            for f in scan.findings
            for e in f.asset.all_evidence
        )

    assert lines(result) == lines(static)


def test_the_report_states_what_a_trace_cannot_show(sample_run: tuple[Path, ScanResult]) -> None:
    _, result = sample_run
    notes = [n.message for n in result.limitations if n.scanner == "runtime-trace"]
    assert len(notes) == 1
    assert "`python license_token.py`" in notes[0]
    assert "5 cryptographic calls at 5 places" in notes[0]
    assert "does not prove it is unused" in notes[0]


# --- what only a run can see ------------------------------------------------------------------

APP = {
    "app/__init__.py": "",
    "app/tokens.py": """
        import hashlib
        import os

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        ALGORITHM = os.environ.get("TOKEN_HASH", "md5")
        BITS = int(os.environ.get("TOKEN_BITS", "1024"))


        def fingerprint(data: bytes) -> str:
            return hashlib.new(ALGORITHM, data).hexdigest()


        def keypair():
            return rsa.generate_private_key(public_exponent=65537, key_size=BITS)


        def sign(key, message: bytes) -> bytes:
            return key.sign(
                message,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )


        def unseal(key, sealed: bytes) -> bytes:
            return key.decrypt(sealed, padding.PKCS1v15())


        def never_called(data: bytes) -> str:
            return hashlib.sha1(data).hexdigest()
    """,
    "tests/test_tokens.py": """
        from cryptography.hazmat.primitives.asymmetric import padding

        from app import tokens


        def test_login():
            for _ in range(3):
                assert len(tokens.fingerprint(b"user")) == 32


        def test_logout():
            assert tokens.fingerprint(b"bye")


        def test_signing():
            key = tokens.keypair()
            assert tokens.sign(key, b"m")
            sealed = key.public_key().encrypt(b"s", padding.PKCS1v15())
            assert tokens.unseal(key, sealed) == b"s"
    """,
}


@pytest.fixture(scope="module")
def app_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, ScanResult]:
    root = project(tmp_path_factory.mktemp("traced-app"), APP)
    traced(root, "-m", "pytest", "-q", "-p", "no:cacheprovider")
    return root, run_scan([root])


def test_an_algorithm_named_by_a_variable_is_found_with_its_tests(
    app_run: tuple[Path, ScanResult],
) -> None:
    root, result = app_run
    assert one(run_scan([root / "app"]), "tokens.py", "sha1", "hash")  # the only static hash
    md5 = one(result, "tokens.py", "md5", "hash")  # `hashlib.new(ALGORITHM)`: only a run knows
    assert md5.asset.observation is Observation.EXECUTED
    assert md5.asset.observed == "hashlib.new"
    assert md5.asset.library == "python:stdlib"  # named by the tracer: no import to read it from
    place = md5.asset.evidence
    assert place.line == 12
    assert "hashlib.new(ALGORITHM, data)" in (place.snippet or "")
    assert place.execution is not None
    assert place.execution.calls == 4
    assert place.execution.tests == [
        "tests/test_tokens.py::test_login",  # three of the four calls
        "tests/test_tokens.py::test_logout",
    ]
    assert place.execution.test_count == 2
    assert place.execution.run == "python -m pytest -q"


def test_a_key_size_from_configuration_is_the_one_the_run_used(
    app_run: tuple[Path, ScanResult],
) -> None:
    root, result = app_run
    # in source the size is `BITS`, an environment lookup: the code scan can't name it
    static = [
        f for f in in_file(run_scan([root / "app"]), "tokens.py") if f.asset.algorithm == "RSA"
    ]
    assert {f.asset.key_size for f in static} == {None}
    generated = one(result, "tokens.py", "rsa-1024", "key-generation")
    assert generated.asset.key_size == 1024
    assert generated.asset.evidence.line == 16
    assert generated.asset.evidence.execution is not None
    assert generated.asset.evidence.execution.tests == ["tests/test_tokens.py::test_signing"]


def test_a_call_split_over_lines_is_one_finding_where_the_source_scan_put_it(
    app_run: tuple[Path, ScanResult],
) -> None:
    _, result = app_run
    signature = one(result, "tokens.py", "rsa-1024", "signature")
    # the call starts on line 20; the source scan marks the padding on line 22
    assert list(places(signature)) == [22]
    assert signature.asset.observed == "padding.PKCS1v15"
    assert signature.asset.evidence.execution is not None
    assert signature.asset.evidence.execution.parameters["api"] == "rsa.sign"


def test_the_run_tells_decryption_from_signing(app_run: tuple[Path, ScanResult]) -> None:
    root, result = app_run
    # a PKCS1v15 padding object alone reads as a signature in source
    static = run_scan([root / "app"])
    assert [f.asset.usage for f in in_file(static, "tokens.py") if 28 in places(f)] == ["signature"]
    unsealed = one(result, "tokens.py", "rsa-1024", "encryption")
    assert list(places(unsealed)) == [28]
    assert (
        unsealed.classification.hndl is True
    )  # encryption is exposed to harvest-now-decrypt-later
    assert not [f for f in in_file(result, "tokens.py") if 28 in places(f) and f is not unsealed]


def test_a_function_no_test_calls_did_not_run(app_run: tuple[Path, ScanResult]) -> None:
    _, result = app_run
    sha1 = one(result, "tokens.py", "sha1", "hash")
    assert sha1.asset.observation is Observation.IN_CODE
    assert sha1.asset.evidence.execution is not None and not sha1.asset.evidence.execution.ran


def test_nothing_secret_reaches_the_trace(tmp_path: Path) -> None:
    root = project(tmp_path, {
        "vault.py": """
            import hashlib
            import hmac

            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            KEY = b"TOP-SECRET-KEY-0123456789abcdef!"
            hmac.new(KEY, b"PLAINTEXT-MESSAGE", hashlib.sha256).hexdigest()
            AESGCM(KEY).encrypt(b"NONCE-123456", b"PLAINTEXT-MESSAGE", None)
            Cipher(algorithms.AES(KEY[:16]), modes.CBC(b"INIT-VECTOR-0001")).encryptor()
            hashlib.pbkdf2_hmac("sha256", b"PASSWORD-hunter2", b"SALT-SALT", 10)
        """,
    })  # fmt: skip
    text = traced(root, "vault.py").read_text(encoding="utf-8")
    for secret in ("TOP-SECRET", "PLAINTEXT", "NONCE-", "INIT-VECTOR", "hunter2", "SALT-"):
        assert secret not in text
    result = run_scan([root])
    assert {(f.classification.name, f.asset.variant, f.asset.usage) for f in result.findings} == {
        ("HMAC-SHA256", None, "mac"),
        ("AES-256", "AES-256-GCM", "encryption"),
        ("AES-128", "AES-128-CBC", "encryption"),
        ("PBKDF2", "PBKDF2-HMAC-SHA256", "kdf"),
    }
    assert all(f.asset.observation is Observation.EXECUTED for f in result.findings)


def test_the_mode_the_run_used_replaces_the_one_guessed_for_the_whole_file(tmp_path: Path) -> None:
    root = project(tmp_path, {
        "export.py": """
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            KEY_BYTES = 32


            def legacy(key: bytes) -> Cipher:
                return Cipher(algorithms.AES(key), modes.ECB())


            def seal(key: bytes) -> Cipher:
                return Cipher(algorithms.AES(key), modes.GCM(bytes(12)))


            seal(bytes(KEY_BYTES)).encryptor()
        """,
    })  # fmt: skip
    # in source, one ECB anywhere in the file marks every AES in it, and the key size is unknown
    (static,) = run_scan([root]).findings
    assert (static.asset.flags, static.asset.key_size, set(places(static))) == (
        ["ecb-mode"],
        None,
        {7, 11},
    )
    assert static.classification.classically_broken

    traced(root, "export.py")
    result = run_scan([root])
    sealed = next(f for f in result.findings if 11 in places(f))
    assert sealed.asset.observation is Observation.EXECUTED
    assert (sealed.asset.variant, sealed.asset.flags) == ("AES-256-GCM", [])
    assert sealed.classification.tier is RiskTier.SAFE
    assert sealed.classification.classically_broken is False
    legacy = next(f for f in result.findings if 7 in places(f))  # the ECB one: it never ran
    assert legacy.asset.flags == ["ecb-mode"]
    assert legacy.asset.evidence.execution is not None and not legacy.asset.evidence.execution.ran
    assert len(result.findings) == 2


def test_cryptography_reached_through_a_library_points_at_the_project_line(tmp_path: Path) -> None:
    project(tmp_path, {
        "deps/site-packages/webtokens/__init__.py": """
            import hashlib


            def encode(payload: bytes) -> str:
                return hashlib.sha1(payload).hexdigest()
        """,
        "service.py": """
            import webtokens


            def issue() -> str:
                return webtokens.encode(b"claims")


            issue()
        """,
    })  # fmt: skip
    traced(tmp_path, "service.py", env={"PYTHONPATH": str(tmp_path / "deps" / "site-packages")})
    result = run_scan([tmp_path / "service.py", tmp_path / TRACE_FILE])
    (finding,) = result.findings
    assert (finding.classification.rule_id, finding.asset.evidence.line) == ("sha1", 5)
    assert finding.asset.evidence.execution is not None
    assert finding.asset.evidence.execution.parameters == {
        "api": "hashlib.sha1",
        "via": "webtokens",
    }


def test_unittest_runs_name_their_tests(tmp_path: Path) -> None:
    root = project(tmp_path, {
        "test_legacy.py": """
            import hashlib
            import unittest


            class Legacy(unittest.TestCase):
                def test_digest(self):
                    self.assertEqual(len(hashlib.md5(b"x").hexdigest()), 32)
        """,
    })  # fmt: skip
    traced(root, "-m", "unittest", "-q", "test_legacy")
    (finding,) = run_scan([root]).findings
    assert finding.asset.evidence.execution is not None
    assert finding.asset.evidence.execution.tests == ["test_legacy.Legacy.test_digest"]


# --- a trace is only as good as the files are unchanged -----------------------------------------


def test_a_file_edited_after_the_run_loses_its_runtime_evidence(tmp_path: Path) -> None:
    root = project(tmp_path, {
        "a.py": "import hashlib\nhashlib.md5(b'x')\n",
        "b.py": "import hashlib\nhashlib.sha1(b'x')\n",
        "main.py": "import a\nimport b\n",
    })  # fmt: skip
    traced(root, "main.py")
    (root / "a.py").write_text("import hashlib\n\n\nhashlib.md5(b'x')\n", encoding="utf-8")
    result = run_scan([root])
    md5 = one(result, "a.py", "md5", "hash")
    assert md5.asset.evidence.line == 4
    assert md5.asset.observation is Observation.IN_CODE
    assert md5.asset.evidence.execution is None  # no claim either way
    assert one(result, "b.py", "sha1", "hash").asset.observation is Observation.EXECUTED
    stale = [n.message for n in result.limitations if "changed after the traced run" in n.message]
    assert len(stale) == 1 and "a.py" in stale[0] and "Run the tests again" in stale[0]


def handwritten(root: Path, *records: dict[str, Any]) -> Path:
    out = root / TRACE_FILE
    out.parent.mkdir(exist_ok=True)
    run = {"kind": "run", "version": 1, "run": "r", "language": "python", "runtime": "cpython 3.13.0",
           "command": "python -m pytest"}  # fmt: skip
    out.write_text("".join(json.dumps({"run": "r", **r}) + "\n" for r in (run, *records)))
    return out


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_a_trace_cannot_point_outside_its_folder(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    root = project(tmp_path / "repo", {"ok.py": "x = 1\n"})
    handwritten(
        root,
        {"kind": "file", "file": "../outside.py", "sha256": digest(outside)},
        {"kind": "lines", "file": "../outside.py", "test": None, "lines": [1, 2]},
        {"kind": "call", "file": "../outside.py", "line": 2, "end_line": 2, "api": "hashlib.md5",
         "args": {"name": "md5"}, "via": None, "test": None, "count": 1},
    )  # fmt: skip
    result = run_scan([root, outside])
    (md5,) = result.findings  # found in the file itself, with nothing taken from the trace
    assert md5.asset.observation is Observation.IN_CODE
    assert md5.asset.evidence.execution is None


def test_a_trace_only_speaks_about_files_in_the_scan(tmp_path: Path) -> None:
    root = project(tmp_path, {
        "a.py": "import hashlib\nNAME = 'md5'\nhashlib.new(NAME)\n",
        "b.py": "import hashlib\nNAME = 'sha1'\nhashlib.new(NAME)\n",
        "main.py": "import a\nimport b\n",
    })  # fmt: skip
    trace = traced(root, "main.py")
    result = run_scan([root / "a.py", trace])  # what an editor does for one open file
    assert [
        (Path(f.asset.evidence.location).name, f.classification.rule_id) for f in result.findings
    ] == [("a.py", "md5")]


def test_an_old_python_says_so_instead_of_claiming_nothing_ran(tmp_path: Path) -> None:
    root = project(tmp_path, {"a.py": "import hashlib\nhashlib.md5(b'x')\n"})
    (root / TRACE_FILE).parent.mkdir()
    (root / TRACE_FILE).write_text(json.dumps({
        "kind": "run", "version": 1, "run": "r", "language": "python", "runtime": "cpython 3.10.4",
        "command": "python -m pytest", "unsupported": "the tracer needs Python 3.12 or newer",
    }) + "\n")  # fmt: skip
    result = run_scan([root])
    (md5,) = result.findings
    assert md5.asset.evidence.execution is None
    (note,) = [n.message for n in result.limitations if n.scanner == "runtime-trace"]
    assert "needs Python 3.12 or newer" in note and "cpython 3.10.4" in note


def test_other_jsonl_files_and_broken_lines_are_harmless(tmp_path: Path) -> None:
    root = project(tmp_path, {"a.py": "import hashlib\nhashlib.md5(b'x')\n"})
    out = handwritten(
        root,
        {"kind": "file", "file": "a.py", "sha256": digest(root / "a.py")},
        {"kind": "lines", "file": "a.py", "test": None, "lines": [1, 2, "three"]},
        {"kind": "call", "file": "a.py", "line": "two", "api": "hashlib.md5", "count": 1},
        {"kind": "call", "file": "a.py", "line": 2, "api": "hashlib.blake2b", "args": {"name": "blake2b"},
         "count": 2},
    )  # fmt: skip
    with out.open("a") as handle:
        handle.write('{"kind": "call", "file": "a.py", "li')  # the process was killed mid-write
    (out.parent / "notes.jsonl").write_text('{"hello": "world"}\n')
    result = run_scan([root])
    assert result.errors == []
    (md5,) = result.findings
    assert md5.asset.observation is Observation.EXECUTED  # its line ran
    assert md5.asset.evidence.execution is not None and md5.asset.evidence.execution.calls is None
    assert any("no rule covers yet: hashlib.blake2b" in n.message for n in result.limitations)


# --- the tracer stays out of the way ------------------------------------------------------------


def test_the_tracer_is_off_without_a_trace_file(tmp_path: Path) -> None:
    root = project(tmp_path, {"a.py": "import hashlib\nprint(hashlib.md5(b'x').hexdigest())\n"})
    env = {**os.environ, "PYTHONPATH": str(PYTHON_TRACER)}
    env.pop("QT_TRACE_FILE", None)
    done = subprocess.run(
        [sys.executable, "a.py"], cwd=root, env=env, capture_output=True, text=True
    )
    assert done.stdout.strip() == "9dd4e461268c8034f5c8564e155c67a6"
    assert not (root / ".quantumtrace").exists()


def test_a_sitecustomize_of_the_environment_still_runs(tmp_path: Path) -> None:
    root = project(tmp_path, {
        "site/sitecustomize.py": "import os\nos.environ['FROM_SITE'] = 'yes'\n",
        "a.py": "import os, hashlib\nprint(os.environ.get('FROM_SITE'), hashlib.md5(b'x').name)\n",
    })  # fmt: skip
    env = python_environment(
        root, root / TRACE_FILE, {**os.environ, "PYTHONPATH": str(root / "site")}
    )
    done = subprocess.run(
        [sys.executable, "a.py"], cwd=root, env=env, capture_output=True, text=True
    )
    assert done.stdout.split() == ["yes", "md5"]
    assert (root / TRACE_FILE).exists()


def test_a_program_that_fails_keeps_its_own_error_and_its_trace(tmp_path: Path) -> None:
    root = project(tmp_path, {"a.py": "import hashlib\nhashlib.md5(b'x')\nraise SystemExit(3)\n"})
    env = python_environment(root, root / TRACE_FILE, dict(os.environ))
    assert subprocess.run([sys.executable, "a.py"], cwd=root, env=env).returncode == 3
    assert one(run_scan([root]), "a.py", "md5", "hash").asset.observation is Observation.EXECUTED


# --- names: tracer events -> classifier aliases -------------------------------------------------


@pytest.mark.parametrize(
    ("api", "args", "expected"),
    [
        ("hashlib.md5", {"name": "md5"}, ("MD5", "hash", None)),
        ("hashlib.new", {"name": "SHA3_256"}, ("SHA3-256", "hash", None)),
        ("cryptography.hashes.SHA3_256", {"name": "sha3-256"}, ("SHA3-256", "hash", None)),
        ("hmac", {"name": "sha1"}, ("HMAC-SHA1", "mac", None)),
        ("hashlib.pbkdf2_hmac", {"name": "sha256"}, ("PBKDF2", "kdf", None)),
        ("cryptography.rsa.generate", {"bits": 2048}, ("RSA", "key-generation", 2048)),
        ("cryptography.rsa.verify", {"bits": 1024}, ("RSA", "signature", 1024)),
        ("cryptography.rsa.decrypt", {"bits": 4096}, ("RSA", "encryption", 4096)),
        ("cryptography.padding.OAEP", {}, ("RSA", "encryption", None)),
        (
            "cryptography.ec.generate",
            {"bits": 256, "curve": "secp256r1"},
            ("ECDSA", "key-generation", 256),
        ),
        (
            "cryptography.ec.exchange",
            {"bits": 384, "curve": "secp384r1"},
            ("ECDH", "key-agreement", 384),
        ),
        ("cryptography.ed25519.sign", {}, ("Ed25519", "signature", None)),
        ("cryptography.x25519.exchange", {}, ("ECDH", "key-agreement", None)),
        ("cryptography.dsa.sign", {"bits": 1024}, ("DSA", "signature", 1024)),
        ("cryptography.dh.generate", {}, ("DH", "key-agreement", None)),
        (
            "cryptography.cipher",
            {"name": "TripleDES", "bits": 192, "mode": "CBC"},
            ("3DES", "encryption", None),
        ),
        ("cryptography.algorithms.AES256", {"bits": 256}, ("AES", "encryption", 256)),
        (
            "cryptography.aead.ChaCha20Poly1305",
            {"bits": 256},
            ("ChaCha20-Poly1305", "encryption", None),
        ),
        ("cryptography.fernet.Fernet", {}, ("AES", "encryption", 128)),
        ("cryptography.kdf.Scrypt", {}, ("scrypt", "kdf", None)),
    ],
)
def test_traced_calls_resolve_to_rules(
    api: str, args: dict[str, object], expected: tuple[str, str, int | None]
) -> None:
    from quantumtrace.core.classifier import default_classifier

    seen = python_api.describe(api, args)
    assert seen is not None
    assert (seen.algorithm, seen.usage, seen.key_size) == expected
    assert default_classifier().lookup(seen.algorithm, seen.key_size) is not None


@pytest.mark.parametrize(
    "api", ["hashlib.blake2b", "cryptography.hashes.SM3", "zlib.crc32", "cryptography.aead.Nope"]
)
def test_calls_without_a_rule_are_not_guessed(api: str) -> None:
    assert python_api.describe(api, {"name": api.rsplit(".", 1)[1].lower()}) is None


# --- CBOM, API and CLI ---------------------------------------------------------------------------


def test_cbom_occurrences_say_what_ran(sample_run: tuple[Path, ScanResult]) -> None:
    _, result = sample_run
    bom = to_cyclonedx(result)
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom)) is None
    # the CBOM also lists libraries; the occurrences are on the cryptographic assets
    assets = [c for c in bom["components"] if c["type"] == "cryptographic-asset"]
    contexts = [o["additionalContext"] for c in assets for o in c["evidence"]["occurrences"]]
    assert sum(len(c["evidence"]["occurrences"]) for c in assets) == sum(
        len(f.asset.all_evidence) for f in result.findings
    )
    assert (
        "[executed, high confidence, ran 1x, key_size=1024] key-generation "
        "observed=rsa.generate_private_key(public_exponent=65537, key_size=1024)"
    ) in contexts
    assert (
        "[in-code, high confidence, not run in the traced run] hash observed=hashlib.md5"
        in contexts
    )
    rsa = next(c for c in assets if c["bom-ref"].startswith("crypto/rsa-1024"))
    observations = [
        p["value"] for p in rsa["properties"] if p["name"] == "quantumtrace:observation"
    ]
    assert observations == ["executed"]


def test_api_takes_a_trace_with_the_sources_and_leaks_no_server_path(
    sample_run: tuple[Path, ScanResult], samples: Path
) -> None:
    root, _ = sample_run
    settings = Settings(samples_dir=samples)
    api = create_app(settings)
    api.dependency_overrides[get_settings] = lambda: settings
    uploads = [
        ("files", (name, (root / name).read_bytes(), "text/plain"))
        for name in (
            "python/license_token.py",
            "python/legacy_accounts.py",
            ".quantumtrace/trace.jsonl",
        )
    ]
    res = TestClient(api).post("/api/v1/scans", files=uploads)
    assert res.status_code == 200, res.text
    body = res.json()
    by_line = {
        (e["location"], e["line"]): (f["asset"]["observation"], e["execution"])
        for f in body["findings"]
        for e in [f["asset"]["evidence"], *f["asset"]["more_evidence"]]
    }
    observation, execution = by_line[("python/license_token.py", 6)]
    assert observation == "executed"
    assert execution["calls"] == 1 and execution["parameters"]["key_size"] == "1024"
    assert by_line[("python/legacy_accounts.py", 5)] == (
        "in-code",
        {
            "ran": False,
            "calls": None,
            "tests": [],
            "test_count": 0,
            "parameters": {},
            "run": "python license_token.py",
        },
    )
    text = res.text.lower()
    assert "qt-" not in text and str(root).lower().replace("\\", "\\\\") not in text
    assert all(not Path(e["location"]).is_absolute() and e["context"].get("file") == e["location"]
               for f in body["findings"] for e in [f["asset"]["evidence"], *f["asset"]["more_evidence"]])  # fmt: skip


def test_cli_trace_then_scan(tmp_path: Path) -> None:
    root = project(tmp_path, {"a.py": "import hashlib\nNAME = 'md5'\nhashlib.new(NAME, b'x')\n"})
    runner = CliRunner()
    done = runner.invoke(
        cli, ["trace", "--root", str(root), "--", sys.executable, str(root / "a.py")]
    )
    assert done.exit_code == 0, done.output
    assert "Trace written to" in done.output and (root / TRACE_FILE).is_file()
    scanned = runner.invoke(cli, ["scan", str(root), "--format", "json"])
    (finding,) = json.loads(scanned.output)["findings"]
    assert finding["classification"]["rule_id"] == "md5"
    assert finding["asset"]["observation"] == "executed"
    table = runner.invoke(cli, ["scan", str(root)]).output
    assert "Ran" in table and "1 call" in table


def test_cli_trace_passes_on_the_commands_exit_code(tmp_path: Path) -> None:
    done = CliRunner().invoke(
        cli, ["trace", "--root", str(tmp_path), "--", sys.executable, "-c", "raise SystemExit(7)"]
    )
    assert done.exit_code == 7
    assert CliRunner().invoke(cli, ["trace", "--root", str(tmp_path)]).exit_code == 2
