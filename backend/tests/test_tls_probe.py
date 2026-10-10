"""Live TLS probe against local servers (no internet in CI).

Each server is a Python `ssl` listener with a throwaway certificate, configured to mimic a
real-world profile: PQ-ready TLS 1.3, classical TLS 1.3 only, legacy TLS 1.2 with RSA.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from quantumtrace.core.engine import run_probe
from quantumtrace.core.models import Observation, ScanResult
from quantumtrace.scanners.network import probe, tls
from tests.conftest import summarise


def _cert(tmp: Path, key_type: str) -> tuple[Path, Path]:
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = (
        rsa.generate_private_key(65537, 2048)
        if key_type == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / f"{key_type}.crt", tmp / f"{key_type}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


Configure = Callable[[ssl.SSLContext], None]


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[Callable[[str, Configure], int]]:
    """Start a TLS server with the given key type and context tweaks; returns its port."""
    stop = threading.Event()
    sockets: list[socket.socket] = []

    def start(key_type: str, configure: Configure) -> int:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*_cert(tmp_path, key_type))
        configure(ctx)
        listener = socket.create_server(("127.0.0.1", 0))
        listener.settimeout(0.2)
        sockets.append(listener)

        def serve() -> None:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except (TimeoutError, OSError):
                    continue
                conn.settimeout(2)
                try:
                    with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                        tls_conn.recv(1)
                except (ssl.SSLError, OSError):
                    pass  # the probe hangs up after the ServerHello: expected
                finally:
                    conn.close()

        threading.Thread(target=serve, daemon=True).start()
        return int(listener.getsockname()[1])

    yield start
    stop.set()
    for s in sockets:
        s.close()


def _probe(port: int) -> ScanResult:
    return run_probe("127.0.0.1", port, allow_private=True)


@pytest.mark.skipif(
    ssl.OPENSSL_VERSION_INFO < (3, 5),
    reason=f"{ssl.OPENSSL_VERSION} has no ML-KEM, so the local server can't play a PQ-ready site",
)
def test_pq_ready_server(tls_server: Callable[[str, Configure], int]) -> None:
    port = tls_server("ec", lambda ctx: None)  # OpenSSL 3.5 defaults: X25519MLKEM768 first
    result = _probe(port)
    assert summarise(result) == {
        ("safe", "TLS 1.3 (hybrid post-quantum)", "tls-protocol"),
        ("safe", "X25519MLKEM768", "tls-key-exchange"),
        ("safe", "AES-256", "tls-cipher"),
        # still accepted from TLS 1.2-only clients: a classical downgrade path
        ("medium", "TLS 1.2", "tls-protocol"),
        ("critical", "ECDH", "tls-key-exchange"),
        ("critical", "ECDSA", "tls-authentication"),
        # leaf certificate
        ("critical", "ECDSA", "certificate-key"),
        ("critical", "ECDSA", "certificate-signature"),
        ("safe", "SHA-256", "certificate-signature-digest"),
    }
    by_usage = {(f.asset.usage, f.asset.observation) for f in result.findings}
    assert ("tls-key-exchange", Observation.NEGOTIATED) in by_usage
    assert ("tls-key-exchange", Observation.PERMITTED) in by_usage
    permitted = [f for f in result.findings if f.asset.observation is Observation.PERMITTED]
    assert all("server-permitted" in f.asset.flags for f in permitted)
    cert = next(f for f in result.findings if f.asset.usage == "certificate-key")
    assert cert.asset.variant == "ECDSA P-256"
    assert cert.asset.evidence.context["subject"] == "CN=localhost"
    assert result.score.counts.unknown == 0


def test_tls13_only_server_refuses_downgrade(
    tls_server: Callable[[str, Configure], int],
) -> None:
    def tls13_only(ctx: ssl.SSLContext) -> None:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    result = _probe(tls_server("ec", tls13_only))
    assert not any(f.asset.observation is Observation.PERMITTED for f in result.findings)
    assert any("refuses TLS 1.2" in n.message for n in result.limitations)


def test_legacy_rsa_server(tls_server: Callable[[str, Configure], int]) -> None:
    def legacy(ctx: ssl.SSLContext) -> None:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ECDHE-RSA-AES128-SHA")

    result = _probe(tls_server("rsa", legacy))
    assert summarise(result) == {
        ("medium", "TLS 1.2", "tls-protocol"),
        ("critical", "ECDH", "tls-key-exchange"),
        ("critical", "RSA", "tls-authentication"),
        ("medium", "AES-128", "tls-cipher"),
        ("medium", "HMAC-SHA1", "tls-mac"),
        ("critical", "RSA", "certificate-key"),
        ("critical", "RSA", "certificate-signature"),
        ("safe", "SHA-256", "certificate-signature-digest"),
    }
    cipher = next(f for f in result.findings if f.asset.usage == "tls-cipher")
    assert cipher.asset.variant == "AES-128-CBC"
    assert "cbc-mode" in cipher.asset.flags
    cert = next(f for f in result.findings if f.asset.usage == "certificate-key")
    assert cert.asset.variant == "RSA-2048"


def test_client_hello_offers_hybrid_share() -> None:
    record = probe.client_hello("example.com", tls13=True, pq=True)
    msgs = tls.handshake_messages(record)
    assert [t for t, _ in msgs] == [tls.CLIENT_HELLO]
    hello = tls.parse_hello(msgs[0][1], server=False)
    assert hello is not None
    assert tls.server_name(hello) == "example.com"
    assert tls.client_groups(hello)[0] == probe.X25519MLKEM768
    shares = hello.extensions[tls.EXT_KEY_SHARE]
    first_group, first_len = int.from_bytes(shares[2:4]), int.from_bytes(shares[4:6])
    assert (first_group, first_len) == (probe.X25519MLKEM768, 1184 + 32)


def test_client_hello_tls12_only_has_no_tls13() -> None:
    record = probe.client_hello(None, tls13=False, pq=False)
    hello = tls.parse_hello(tls.handshake_messages(record)[0][1], server=False)
    assert hello is not None
    assert tls.EXT_SUPPORTED_VERSIONS not in hello.extensions
    assert tls.server_name(hello) is None
    assert not set(probe.TLS13_SUITES) & set(hello.suites)


@pytest.mark.parametrize(
    ("host", "port"),
    [
        ("127.0.0.1", 443),
        ("localhost", 443),
        ("10.0.0.8", 443),
        ("169.254.169.254", 443),  # cloud metadata endpoint
        ("[::1]", 443),
        ("example.com", 22),  # not a TLS port
        ("https://example.com/", 443),
    ],
)
def test_refuses_private_hosts_and_odd_ports(host: str, port: int) -> None:
    with pytest.raises(probe.ProbeRefused):
        probe.resolve_public(host, port)


def test_unreachable_host_is_a_probe_error() -> None:
    with socket.create_server(("127.0.0.1", 0)) as s:
        port = s.getsockname()[1]
    with pytest.raises(probe.ProbeError, match="Could not connect"):
        run_probe("127.0.0.1", port, allow_private=True)


def test_classical_tls13_server_declines_pq(tls_server: Callable[[str, Configure], int]) -> None:
    def classical(ctx: ssl.SSLContext) -> None:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_ecdh_curve("X25519")

    result = _probe(tls_server("ec", classical))
    assert ("medium", "TLS 1.3 (classical key exchange)", "tls-protocol") in summarise(result)
    kx = next(f for f in result.findings if f.asset.usage == "tls-key-exchange")
    assert (kx.classification.tier.value, kx.asset.variant) == ("critical", "x25519")
    assert "server-declined-pq" in kx.asset.flags
