"""Dependency manifests and the libraries code findings are tied to."""

from __future__ import annotations

from pathlib import Path

from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import CryptoLibrary, ScanResult


def _lib(result: ScanResult, lib_id: str) -> CryptoLibrary:
    return next(lib for lib in result.libraries if lib.id == lib_id)


def _provided(result: ScanResult, lib_id: str) -> set[tuple[str, str]]:
    return {
        (f.classification.name, Path(f.asset.evidence.location).name)
        for f in result.findings
        if f.asset.library == lib_id
    }


def test_samples_declare_cryptography_and_go_and_their_calls_point_at_them(samples: Path) -> None:
    result = run_scan([samples / "sample-repos"])

    crypto = _lib(result, "pypi:cryptography@46.0.5")
    assert crypto.purl == "pkg:pypi/cryptography@46.0.5"
    assert [(Path(e.location).name, e.line) for e in crypto.evidence] == [("requirements.txt", 1)]
    go = _lib(result, "go:stdlib@1.24")
    assert [(Path(e.location).name, e.line) for e in go.evidence] == [("go.mod", 3)]

    assert ("RSA-1024", "license_token.py") in _provided(result, crypto.id)
    for f in result.findings:
        observed, kind = f.asset.observed, Path(f.asset.evidence.location).suffix
        if kind == ".py" and observed.startswith(("hashlib", "hmac", "random")):
            assert f.asset.library == "python:stdlib", f
        elif kind == ".java":
            assert f.asset.library == "java:jdk", f
        elif kind == ".go" and observed.startswith("func "):
            assert f.asset.library is None, f  # hand-rolled: no library provides it
        elif kind == ".go":
            assert f.asset.library == go.id, f


def test_manifests_list_crypto_libraries_with_versions_and_purls(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "dependency-manifests"])
    libs = {lib.id: lib for lib in result.libraries}

    assert set(libs) == {
        "pypi:pycrypto@2.6.1",
        "pypi:pyjwt@>=2.8,<3",
        "pypi:cryptography@>=42",
        "pypi:bcrypt@4.2.0",
        "go:stdlib@1.22",
        "golang:github.com/cloudflare/circl@v1.5.0",
        "golang:golang.org/x/crypto@v0.31.0",
        "maven:org.bouncycastle:bcprov-jdk18on@1.78.1",
        "maven:io.jsonwebtoken:jjwt-api@0.12.6",
        "npm:node-forge@^1.3.1",
        "npm:crypto-js@4.2.0",
        "npm:@noble/post-quantum@0.2.1",
    }
    # requests, fastapi, gin, express and junit aren't cryptographic libraries
    assert "Unmaintained since 2013" in (libs["pypi:pycrypto@2.6.1"].note or "")
    assert libs["pypi:pyjwt@>=2.8,<3"].purl == "pkg:pypi/pyjwt"  # a range: no version in the purl
    bc = libs["maven:org.bouncycastle:bcprov-jdk18on@1.78.1"]  # ${bc.version} resolved
    assert bc.purl == "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1"
    assert bc.evidence[0].line == 13
    assert libs["npm:@noble/post-quantum@0.2.1"].purl == "pkg:npm/%40noble/post-quantum@0.2.1"
    assert libs["golang:github.com/cloudflare/circl@v1.5.0"].purl == (
        "pkg:golang/github.com/cloudflare/circl@v1.5.0"
    )
    assert any("transitively" in n.message for n in result.limitations)


def test_code_reaches_the_declared_library_through_its_import_name(
    personal_samples: Path, tmp_path: Path
) -> None:
    """`from Crypto.Cipher import AES` is PyCryptodome or PyCrypto: the declared one wins."""
    manifest = personal_samples / "dependency-manifests" / "python" / "requirements.txt"
    (tmp_path / "requirements.txt").write_bytes(manifest.read_bytes())  # pins pycrypto 2.6.1
    (tmp_path / "vault.py").write_text(
        "from Crypto.Cipher import AES\n\n\n"
        "def seal(key, data):\n"
        "    return AES.new(key, AES.MODE_ECB).encrypt(data)\n"
    )
    result = run_scan([tmp_path])
    assert _provided(result, "pypi:pycrypto@2.6.1") == {("AES (key size unknown)", "vault.py")}


def test_each_finding_goes_to_the_nearest_manifest(tmp_path: Path) -> None:
    for service, version in (("billing", "41.0.0"), ("ledger", "46.0.5")):
        folder = tmp_path / service
        folder.mkdir()
        (folder / "requirements.txt").write_text(f"cryptography=={version}\n")
        (folder / "digest.py").write_text(
            "from cryptography.hazmat.primitives import hashes\n\nhashes.SHA1()\n"
        )
    result = run_scan([tmp_path])
    assert _provided(result, "pypi:cryptography@41.0.0") == {("SHA-1", "digest.py")}
    assert _provided(result, "pypi:cryptography@46.0.5") == {("SHA-1", "digest.py")}
    by_service = {
        Path(f.asset.evidence.location).parent.name: f.asset.library for f in result.findings
    }
    assert by_service == {
        "billing": "pypi:cryptography@41.0.0",
        "ledger": "pypi:cryptography@46.0.5",
    }


def test_a_library_called_but_never_declared_is_still_listed(tmp_path: Path) -> None:
    (tmp_path / "token.py").write_text(
        "from cryptography.hazmat.primitives import hashes\n\nhashes.MD5()\n"
    )
    result = run_scan([tmp_path])
    lib = _lib(result, "pypi:cryptography")
    assert lib.version is None and lib.evidence == []


def test_a_broken_manifest_is_a_note_not_an_error(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project><dependencies>")
    result = run_scan([tmp_path])
    assert result.errors == []
    assert any("pom.xml: couldn't be parsed" in n.message for n in result.limitations)
