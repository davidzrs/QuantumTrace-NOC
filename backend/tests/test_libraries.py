"""Which library each code finding comes from, read from the imports behind its call."""

from __future__ import annotations

from pathlib import Path

from quantumtrace.core.engine import run_scan


def test_code_calls_point_at_the_library_that_provides_them(samples: Path) -> None:
    result = run_scan([samples / "sample-repos"])
    for f in result.findings:
        observed, kind = f.asset.observed, Path(f.asset.evidence.location).suffix
        if kind == ".py" and observed.startswith(("hashlib", "hmac", "random")):
            assert f.asset.library == "python:stdlib", f
        elif kind == ".java":
            assert f.asset.library == "java:jdk", f
        elif kind == ".go" and observed.startswith("func "):
            assert f.asset.library is None, f  # hand-rolled: no library provides it
        elif kind == ".go":
            assert f.asset.library == "go:stdlib", f

    rsa = {
        Path(f.asset.evidence.location).name
        for f in result.findings
        if f.asset.library == "pypi:cryptography" and f.classification.name == "RSA-1024"
    }
    assert "license_token.py" in rsa
    # nothing in the code pins a version, so no library carries one
    assert {lib.name for lib in result.libraries} == {
        "cryptography",
        "Python standard library",
        "Java Cryptography Architecture (JDK)",
        "Go standard library",
    }
    assert all(lib.version is None and lib.evidence == [] for lib in result.libraries)


def test_an_import_family_reaches_its_package(tmp_path: Path) -> None:
    """`from Crypto.Cipher import AES` is PyCryptodome's API."""
    (tmp_path / "vault.py").write_text(
        "from Crypto.Cipher import AES\n\n\n"
        "def seal(key, data):\n"
        "    return AES.new(key, AES.MODE_ECB).encrypt(data)\n"
    )
    result = run_scan([tmp_path])
    (aes,) = result.findings
    assert aes.asset.library == "pypi:pycryptodome"
