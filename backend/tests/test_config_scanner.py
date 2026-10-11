"""Server configuration files: OpenSSH, nginx and Apache (personal-samples/server-configs)."""

from __future__ import annotations

from pathlib import Path

from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import Confidence, Finding, Observation, ScanResult
from tests.conftest import summarise


def _find(result: ScanResult, name: str, usage: str, variant: str | None = None) -> Finding:
    return next(
        f
        for f in result.findings
        if f.classification.name == name
        and f.asset.usage == usage
        and (variant is None or f.asset.variant == variant)
    )


def test_legacy_sshd_config(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "server-configs" / "ssh-legacy"])
    assert result.scanners == ["server-config"] and result.errors == []
    assert summarise(result) == {
        ("critical", "RSA", "ssh-host-key"),
        ("critical", "EdDSA", "ssh-host-key"),
        ("critical", "DH-1024", "ssh-key-exchange"),
        ("critical", "Diffie-Hellman", "ssh-key-exchange"),
        ("critical", "ECDH", "ssh-key-exchange"),
        ("medium", "SHA-1", "ssh-kex-hash"),
        ("medium", "SHA-1", "ssh-signature-digest"),
        ("medium", "AES-128", "ssh-cipher"),
        ("medium", "3DES", "ssh-cipher"),
        ("safe", "ChaCha20-Poly1305", "ssh-cipher"),
        ("medium", "HMAC-SHA1", "ssh-mac"),
        ("safe", "HMAC-SHA256", "ssh-mac"),
        ("critical", "RSA", "ssh-user-key"),
    }
    group1 = _find(result, "DH-1024", "ssh-key-exchange")
    assert group1.classification.classically_broken
    assert group1.asset.observation is Observation.PERMITTED
    assert group1.asset.evidence.line == 5
    assert (group1.asset.evidence.snippet or "").startswith("KexAlgorithms")

    cbc = _find(result, "AES-128", "ssh-cipher")
    assert cbc.asset.variant == "AES-128-CBC" and "cbc-mode" in cbc.asset.flags
    # HostKey names a file: its type comes from the name, its size isn't known
    host = _find(result, "RSA", "ssh-host-key", variant=None)
    assert host.asset.confidence is Confidence.MEDIUM
    assert host.asset.evidence.context["host_key_file"] == "/etc/ssh/ssh_host_rsa_key"
    user = _find(result, "RSA", "ssh-user-key")
    assert user.asset.evidence.context["adds_to_defaults"] == "yes"  # +ssh-rsa
    assert any("umac-64@openssh.com not classified yet" in n.message for n in result.limitations)


def test_post_quantum_sshd_config(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "server-configs" / "ssh-post-quantum"])
    kex = {
        (f.classification.tier.value, f.classification.name)
        for f in result.findings
        if f.asset.usage == "ssh-key-exchange"
    }
    assert kex == {("safe", "X25519MLKEM768"), ("safe", "sntrup761x25519")}
    assert result.limitations == []  # every main directive is set


def test_an_empty_sshd_config_says_the_defaults_apply(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "server-configs" / "ssh-defaults"])
    assert result.findings == []
    (note,) = result.limitations
    assert "doesn't set KexAlgorithms, Ciphers, MACs, HostKeyAlgorithms" in note.message


def test_legacy_nginx_tls(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "server-configs" / "nginx" / "legacy.conf"])
    protocols = {f.classification.name for f in result.findings if f.asset.usage == "tls-protocol"}
    assert protocols == {"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3 (classical key exchange)"}
    assert (
        "no-pq-group"
        in _find(result, "TLS 1.3 (classical key exchange)", "tls-protocol").asset.flags
    )

    transport = _find(result, "RSA", "tls-key-exchange", variant="RSA key transport")
    assert "no-forward-secrecy" in transport.asset.flags
    assert transport.asset.evidence.context["suites"] == "AES128-SHA, DES-CBC3-SHA"
    assert transport.asset.evidence.line == 7
    triple = _find(result, "3DES", "tls-cipher")
    assert triple.asset.variant == "3DES-CBC" and "cbc-mode" in triple.asset.flags
    curves = {f.asset.variant for f in result.findings if f.asset.evidence.line == 8}
    assert curves == {"secp256r1", "secp384r1"}  # prime256v1 is OpenSSL's name for P-256
    assert any("OpenSSL keywords (HIGH)" in n.message for n in result.limitations)


def test_hybrid_ml_kem_nginx_is_post_quantum(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "server-configs" / "nginx" / "nginx.conf"])
    assert summarise(result) == {
        ("safe", "TLS 1.3 (hybrid post-quantum)", "tls-protocol"),
        ("safe", "X25519MLKEM768", "tls-key-exchange"),
        ("critical", "ECDH", "tls-key-exchange"),
    }
    assert "classical-fallback" in _find(result, "ECDH", "tls-key-exchange").asset.flags


def test_apache_protocol_list_subtracts_exclusions(personal_samples: Path) -> None:
    result = run_scan([personal_samples / "server-configs" / "apache"])
    protocols = {f.classification.name for f in result.findings if f.asset.usage == "tls-protocol"}
    assert protocols == {
        "TLS 1.2",
        "TLS 1.3 (classical key exchange)",
    }  # all -SSLv3 -TLSv1 -TLSv1.1
    assert {f.asset.variant for f in result.findings if f.asset.usage == "tls-cipher"} == {
        "AES-256-GCM",
        "ChaCha20-Poly1305",
    }


def test_other_conf_files_are_left_alone(tmp_path: Path) -> None:
    (tmp_path / "logrotate.conf").write_text("weekly\nrotate 4\ncompress\n")
    result = run_scan([tmp_path])
    assert result.findings == [] and result.limitations == [] and result.errors == []
