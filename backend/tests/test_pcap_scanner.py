"""Golden tests for the network scanner against samples/network-capture/network.pcap."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import Finding, Observation, ScanResult
from quantumtrace.scanners.network import ssh
from quantumtrace.scanners.network.pcap import PcapScanner


@pytest.fixture(scope="module")
def result(samples: Path) -> ScanResult:
    return run_scan([samples / "network-capture"])


def by_usage(result: ScanResult, usage: str) -> list[Finding]:
    return [f for f in result.findings if f.asset.usage == usage]


def test_pcap_is_accepted(samples: Path) -> None:
    assert PcapScanner().accepts(samples / "network-capture/network.pcap")


def test_no_errors_or_unknowns(result: ScanResult) -> None:
    assert result.errors == []
    assert result.scanners == ["network-pcap"]
    assert result.score.counts.unknown == 0


def test_tls_key_exchange_detected(result: ScanResult) -> None:
    kx = Counter(f.classification.name for f in by_usage(result, "tls-key-exchange"))
    # 54 static-RSA TLS 1.2 sessions, 36 classical x25519, 7 hybrid ML-KEM
    assert kx == {"RSA": 54, "ECDH": 36, "X25519MLKEM768": 7}


def test_hybrid_pq_sessions_are_safe(result: ScanResult) -> None:
    pq = [
        f for f in by_usage(result, "tls-key-exchange") if f.classification.name == "X25519MLKEM768"
    ]
    assert {f.classification.tier.value for f in pq} == {"safe"}
    assert all("FIPS 203" in (f.classification.nist_reference or "") for f in pq)


def test_static_rsa_has_no_forward_secrecy(result: ScanResult) -> None:
    rsa = [f for f in by_usage(result, "tls-key-exchange") if f.classification.name == "RSA"]
    assert all("no-forward-secrecy" in f.asset.flags for f in rsa)


def test_non_443_tls_and_ssh_detected(result: ScanResult) -> None:
    ports = {f.asset.evidence.context.get("server_port") for f in result.findings}
    assert {"636", "993", "587", "5432"} <= ports
    assert any(f.asset.usage == "ssh-key-exchange" for f in result.findings)


def test_starttls_and_postgres_sslrequest_flagged(result: ScanResult) -> None:
    smtp = [f for f in result.findings if f.asset.evidence.context.get("server_port") == "587"]
    pg = [f for f in result.findings if f.asset.evidence.context.get("server_port") == "5432"]
    assert smtp and all("starttls" in f.asset.flags for f in smtp)
    assert pg and all("postgres-sslrequest" in f.asset.flags for f in pg)


def test_ssh_legacy_vs_modern(result: ScanResult) -> None:
    kex = Counter((f.asset.observed, f.asset.observation.value)
                  for f in by_usage(result, "ssh-key-exchange"))  # fmt: skip
    assert kex == {
        ("diffie-hellman-group14-sha1", "negotiated"): 14,
        ("curve25519-sha256", "negotiated"): 10,
        ("diffie-hellman-group1-sha1", "permitted"): 14,  # legacy servers still allow it
    }
    cipher = Counter((f.classification.name, f.asset.observation.value)
                     for f in by_usage(result, "ssh-cipher"))  # fmt: skip
    assert cipher == {
        ("AES-128", "negotiated"): 14,
        ("ChaCha20-Poly1305", "negotiated"): 10,
        ("3DES", "permitted"): 14,
    }
    group1 = [f for f in by_usage(result, "ssh-key-exchange")
              if f.asset.observed == "diffie-hellman-group1-sha1"]  # fmt: skip
    assert len(group1) == 14
    assert all(f.asset.key_size == 1024 for f in group1)
    assert {(f.classification.rule_id, f.classification.classically_broken) for f in group1} == {
        ("dh-1024", True)
    }
    group14 = [f for f in by_usage(result, "ssh-key-exchange")
               if f.asset.observed == "diffie-hellman-group14-sha1"]  # fmt: skip
    assert {(f.classification.rule_id, f.classification.classically_broken) for f in group14} == {
        ("dh", False)
    }
    permitted = [f for f in result.findings if f.asset.observation is Observation.PERMITTED]
    assert all("server-permitted" in f.asset.flags for f in permitted)
    assert len(by_usage(result, "ssh-mac")) == 14  # chacha20-poly1305 is AEAD: no MAC finding


def test_plaintext_http_detected(result: ScanResult) -> None:
    plain = [f for f in result.findings if f.classification.name == "No encryption"]
    assert len(plain) == 14
    assert all(f.asset.evidence.context["request"].startswith("GET ") for f in plain)


def test_evidence_is_a_flow(result: ScanResult) -> None:
    f = result.findings[0]
    assert " -> " in f.asset.evidence.location
    assert f.asset.evidence.context["server"] in f.asset.evidence.location


@pytest.mark.parametrize(
    ("name", "alias", "size"),
    [
        ("mlkem768x25519-sha256", "X25519MLKEM768", None),
        ("sntrup761x25519-sha512@openssh.com", "sntrup761x25519", None),
        ("ecdh-sha2-nistp384", "ECDHE", 384),
        ("diffie-hellman-group1-sha1", "DH", 1024),
        ("ssh-ed25519", "Ed25519", None),
        ("aes256-gcm@openssh.com", "AES-256", None),
        ("hmac-sha2-256-etm@openssh.com", "HMAC-SHA256", None),
    ],
)
def test_ssh_alias(name: str, alias: str, size: int | None) -> None:
    assert ssh.alias(name)[:2] == (alias, size)


def test_protocol_tier_depends_on_negotiated_group(result: ScanResult) -> None:
    proto = Counter(
        (f.classification.name, f.classification.tier.value)
        for f in by_usage(result, "tls-protocol")
    )
    assert proto == {
        ("TLS 1.2", "medium"): 54,
        ("TLS 1.3 (classical key exchange)", "medium"): 36,
        ("TLS 1.3 (hybrid post-quantum)", "safe"): 7,
    }


def test_negotiated_with_packet_and_variants(result: ScanResult) -> None:
    for f in result.findings:
        assert f.asset.observation in (Observation.NEGOTIATED, Observation.PERMITTED)
        assert f.asset.confidence.value == "high"
        assert f.asset.evidence.context["packet"].isdigit()
    variants = Counter(f.asset.variant for f in by_usage(result, "tls-cipher"))
    assert variants == {"AES-128-CBC": 54, "AES-128-GCM": 36, "AES-256-GCM": 7}
    assert Counter(f.asset.variant for f in by_usage(result, "ssh-cipher")) == {
        "AES-128-CBC": 14, "ChaCha20-Poly1305": 10, "3DES-CBC": 14,
    }  # fmt: skip


def test_servers_named_from_dns_answers(result: ScanResult) -> None:
    ssh_hosts = {f.asset.evidence.context.get("host") for f in by_usage(result, "ssh-host-key")}
    assert "legacy-ssh09.lab" in ssh_hosts
    plain = [f for f in result.findings if f.classification.name == "No encryption"]
    assert all(f.asset.evidence.context.get("host", "").startswith("intranet") for f in plain)
    assert any("named 138 host(s)" in n.message for n in result.limitations)


def test_capture_blind_spots_are_reported(result: ScanResult) -> None:
    notes = " ".join(n.message for n in result.limitations)
    assert "43 TLS 1.3 session(s)" in notes  # certificates encrypted
    assert "54 TLS 1.2 session(s) have no Certificate" in notes
    assert "277 DNS packet(s)" in notes


def test_midstream_tls_is_reported_not_called_unparsed(tmp_path: Path) -> None:
    from scapy.layers.inet import IP, TCP
    from scapy.utils import wrpcap

    app_data = b"\x17\x03\x03\x00\x10" + b"\x00" * 16  # encrypted record, no handshake
    pkts = [
        IP(src="192.168.1.2", dst="8.8.8.8")
        / TCP(sport=50000, dport=443, flags="PA", seq=1)
        / app_data,
        IP(src="8.8.8.8", dst="192.168.1.2")
        / TCP(sport=443, dport=50000, flags="PA", seq=1)
        / app_data,
        IP(src="192.168.1.2", dst="1.1.1.1")
        / TCP(sport=50001, dport=443, flags="A", seq=1)
        / b"\x00",
    ]
    capture = tmp_path / "midstream.pcap"
    wrpcap(str(capture), pkts)
    result = run_scan([capture])
    notes = " ".join(n.message for n in result.limitations)
    assert "2 TLS connection(s) were already open" in notes
    assert "8.8.8.8:443" in notes and "1.1.1.1:443" in notes
    assert "does not parse" not in notes


def test_repeat_sessions_to_one_server_are_grouped() -> None:
    from quantumtrace.core.models import CryptoAsset, Evidence, SourceType
    from quantumtrace.scanners.network.pcap import group_by_server

    def session(client_port: int, server: str, sni: str, packet: int) -> CryptoAsset:
        ctx = {"server": server, "server_port": "443", "sni": sni, "service": "https",
               "client": "10.0.0.2", "packet": str(packet)}  # fmt: skip
        return CryptoAsset(
            observed="x25519", algorithm="ECDHE", variant="x25519", usage="tls-key-exchange",
            evidence=Evidence(source_type=SourceType.NETWORK,
                              location=f"10.0.0.2:{client_port} -> {server}:443", context=ctx),
        )  # fmt: skip

    grouped = group_by_server([
        session(1, "1.1.1.1", "a.example", 10),
        session(2, "1.1.1.1", "a.example", 20),
        session(3, "1.1.1.1", "b.example", 30),  # same IP, different virtual host: separate
        session(4, "2.2.2.2", "a.example", 40),  # different server: separate
    ])  # fmt: skip
    assert [len(g.all_evidence) for g in grouped] == [2, 1, 1]
    assert grouped[0].evidence.context["sessions"] == "2"
    assert grouped[0].more_evidence[0].context["packet"] == "20"


# ---------------------------------------------------------------- handshakes beyond the sample
def _vec(data: bytes, size: int = 2) -> bytes:
    return len(data).to_bytes(size, "big") + data


def _ext(kind: int, data: bytes) -> bytes:
    return kind.to_bytes(2, "big") + _vec(data)


def _hello(kind: int, random: bytes, suites: list[int], exts: bytes) -> bytes:
    suite_bytes = b"".join(s.to_bytes(2, "big") for s in suites)
    if kind == 1:  # ClientHello: suite list + compression list
        suite_bytes, compression = _vec(suite_bytes), _vec(b"\x00", 1)
    else:  # ServerHello: the chosen suite + compression method
        compression = b"\x00"
    body = b"\x03\x03" + random + b"\x00" + suite_bytes + compression + _vec(exts)
    return bytes([kind]) + _vec(body, 3)


def _record(*messages: bytes) -> bytes:
    return b"\x16\x03\x03" + _vec(b"".join(messages))


def _scan_session(tmp_path: Path, client: bytes, server: bytes) -> ScanResult:
    from scapy.layers.inet import IP, TCP
    from scapy.utils import wrpcap

    c, s = "192.168.1.2", "203.0.113.10"
    wrpcap(str(tmp_path / "session.pcap"), [
        IP(src=c, dst=s) / TCP(sport=50000, dport=443, flags="S", seq=0),
        IP(src=c, dst=s) / TCP(sport=50000, dport=443, flags="PA", seq=1) / client,
        IP(src=s, dst=c) / TCP(sport=443, dport=50000, flags="PA", seq=1) / server,
    ])  # fmt: skip
    return run_scan([tmp_path / "session.pcap"])


X25519MLKEM768 = 0x11EC
TLS13 = _ext(0x002B, _vec(b"\x03\x04\x03\x03", 1))


def test_hello_retry_request_is_skipped_for_the_real_server_hello(tmp_path: Path) -> None:
    # A stateless server answers the first ClientHello with a cookie-only HelloRetryRequest
    # (no key_share), then negotiates X25519MLKEM768 in the real ServerHello.
    from quantumtrace.scanners.network.tls import HRR_RANDOM

    share = X25519MLKEM768.to_bytes(2, "big") + _vec(bytes(1216))
    groups = _ext(0x000A, _vec(X25519MLKEM768.to_bytes(2, "big") + b"\x00\x1d"))
    hello = _hello(1, bytes(32), [0x1301], groups + TLS13 + _ext(0x0033, _vec(share)))
    hrr_exts = _ext(0x002B, b"\x03\x04") + _ext(0x002C, _vec(b"cookie"))
    hrr = _hello(2, HRR_RANDOM, [0x1301], hrr_exts)
    sh_share = _ext(0x0033, X25519MLKEM768.to_bytes(2, "big") + _vec(bytes(1120)))
    sh = _hello(2, bytes(32), [0x1301], _ext(0x002B, b"\x03\x04") + sh_share)
    result = _scan_session(tmp_path, _record(hello), _record(hrr) + _record(sh))
    rules = {f.asset.usage: f.classification.rule_id for f in result.findings}
    assert rules["tls-protocol"] == "tls1.3"
    assert rules["tls-key-exchange"] == "x25519mlkem768"


def test_hello_retry_request_alone_is_not_a_negotiation(tmp_path: Path) -> None:
    # The client sends no key share (valid, RFC 8446 4.2.8) and the server asks for
    # X25519MLKEM768, but the capture ends there: nothing was negotiated.
    from quantumtrace.scanners.network.tls import HRR_RANDOM

    groups = _ext(0x000A, _vec(X25519MLKEM768.to_bytes(2, "big") + b"\x00\x1d"))
    hello = _hello(1, bytes(32), [0x1301], groups + TLS13 + _ext(0x0033, _vec(b"")))
    hrr_exts = _ext(0x002B, b"\x03\x04") + _ext(0x0033, X25519MLKEM768.to_bytes(2, "big"))
    hrr = _hello(2, HRR_RANDOM, [0x1301], hrr_exts)
    result = _scan_session(tmp_path, _record(hello), _record(hrr))
    [offer] = result.findings
    assert offer.asset.observation is Observation.OFFERED
    assert offer.asset.evidence.context["hrr_selected_group"] == "X25519MLKEM768"


def test_dhe_chacha20_suite_reports_its_key_exchange(tmp_path: Path) -> None:
    hello = _hello(1, bytes(32), [0xCCAA, 0x002F], b"")
    sh = _hello(2, bytes(32), [0xCCAA], b"")
    ske = bytes([12]) + _vec(_vec(bytes(256)) + _vec(b"\x02") + _vec(bytes(256)), 3)
    result = _scan_session(tmp_path, _record(hello), _record(sh, ske))
    [kex] = by_usage(result, "tls-key-exchange")
    assert (kex.classification.rule_id, kex.asset.key_size) == ("dh", 2048)
    assert kex.classification.hndl
    [cipher] = by_usage(result, "tls-cipher")
    assert cipher.asset.variant == "ChaCha20-Poly1305"
