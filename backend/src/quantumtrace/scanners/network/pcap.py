"""Network capture scanner for .pcap/.pcapng.

Reassembles TCP flows with scapy and inspects, per session:
  * TLS on any port (incl. after SMTP/IMAP STARTTLS and Postgres SSLRequest): negotiated
    version, cipher suite and key-exchange group (TLS 1.3 key_share or TLS 1.2
    ServerKeyExchange). Hybrid ML-KEM groups are recognised; a server that declines a
    client's PQ offer is flagged.
  * SSH: banners and KEXINIT name-lists -> negotiated kex, host key, cipher and MAC.
  * Cleartext application protocols (HTTP, FTP, Telnet, POP3, IMAP, SMTP without STARTTLS).
Evidence.location is the flow ("client:port -> server:port").
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from quantumtrace.core.models import (
    Confidence,
    CryptoAsset,
    Evidence,
    Exposure,
    Observation,
    ScanNote,
    SourceType,
)
from quantumtrace.rules.tls import CIPHER_SUITES, NAMED_GROUPS, TLS_VERSIONS, decompose
from quantumtrace.scanners.network import ssh, tls
from quantumtrace.scanners.network.flows import CaptureStats, Flow, read_flows

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",  # pcap little-endian (µs)
    b"\xa1\xb2\xc3\xd4",  # pcap big-endian (µs)
    b"\x4d\x3c\xb2\xa1",  # pcap little-endian (ns)
    b"\xa1\xb2\x3c\x4d",  # pcap big-endian (ns)
    b"\x0a\x0d\x0d\x0a",  # pcapng section header block
}
SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 110: "pop3", 143: "imap",
    389: "ldap", 443: "https", 465: "smtps", 587: "smtp-submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 3306: "mysql", 5432: "postgresql", 8080: "http-alt",
    8443: "https-alt",
}  # fmt: skip
CLEARTEXT_PREFIXES = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS ",
                      b"USER ", b"+OK", b"* OK", b"220 ", b"EHLO", b"HELO")  # fmt: skip
POSTGRES_SSL_REQUEST = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"


class PcapScanner:
    name = "network-pcap"
    source_type = SourceType.NETWORK

    def accepts(self, path: Path) -> bool:
        if path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
            return True
        try:
            with path.open("rb") as fh:
                return fh.read(4) in PCAP_MAGIC
        except OSError:
            return False

    def scan(self, paths: Sequence[Path]) -> Iterable[CryptoAsset | ScanNote]:
        for path in paths:
            stats = CaptureStats()
            tally = _Tally()
            flows = list(read_flows(path, stats))  # reads the whole capture: DNS names known
            assets = (a for f in flows for a in _flow_assets(f, path, tally, stats.dns_names))
            yield from group_by_server(assets)
            yield from _notes(self.name, path, stats, tally)


@dataclass
class _Tally:
    tls13: int = 0
    tls12_without_certificate: int = 0
    unparsed: int = 0
    midstream: list[str] = field(default_factory=list)  # server endpoints


def _notes(scanner: str, path: Path, stats: CaptureStats, t: _Tally) -> Iterator[ScanNote]:
    name = path.name
    if t.tls13:
        yield ScanNote(scanner=scanner, message=(
            f"{name}: {t.tls13} TLS 1.3 session(s) encrypt the server certificate and "
            "CertificateVerify, so their authentication algorithm (RSA/ECDSA/ML-DSA) is not "
            "observable passively. Inventory certificates separately (e.g. ACM export)."
        ))  # fmt: skip
    if t.tls12_without_certificate:
        yield ScanNote(scanner=scanner, message=(
            f"{name}: {t.tls12_without_certificate} TLS 1.2 session(s) have no Certificate "
            "message in the capture (truncated or handshake-only), so certificate key sizes "
            "are unknown."
        ))  # fmt: skip
    if stats.dns_packets:
        named = (
            f" Its answers named {len(stats.dns_names)} host(s), used to label servers."
            if stats.dns_names
            else ""
        )
        yield ScanNote(scanner=scanner, message=(
            f"{name}: {stats.dns_packets} DNS packet(s) seen in cleartext. DNS carries no "
            f"cryptography here (no DoT/DoH), so it is not scored.{named}"
        ))  # fmt: skip
    if t.midstream:
        servers = sorted(set(t.midstream))
        shown = ", ".join(servers[:6]) + (
            f" and {len(servers) - 6} more" if len(servers) > 6 else ""
        )
        yield ScanNote(scanner=scanner, message=(
            f"{name}: {len(t.midstream)} TLS connection(s) were already open when the capture "
            f"started ({shown}). Only encrypted records or keep-alives are visible, so their "
            "negotiated algorithms can't be determined. Start capturing before the client "
            "connects to include them."
        ))  # fmt: skip
    if t.unparsed:
        yield ScanNote(scanner=scanner, message=(
            f"{name}: {t.unparsed} TCP session(s) carried data in protocols QuantumTrace does "
            "not parse yet."
        ))  # fmt: skip


# Context keys that differ per session and must not split a group.
_PER_SESSION = {"client", "packet"}


def group_by_server(assets: Iterable[CryptoAsset]) -> list[CryptoAsset]:
    """Merge identical findings from repeat sessions to the same server (IP, port and SNI).

    A browser opens many parallel connections to one host; they negotiate the same
    parameters, so they are one asset seen N times. The first session stays as `evidence`,
    the rest go to `more_evidence`, and `context["sessions"]` holds the count.
    """
    groups: dict[tuple[object, ...], CryptoAsset] = {}
    for a in assets:
        ctx = a.evidence.context
        key = (
            ctx.get("server"), ctx.get("server_port"), ctx.get("sni"), a.usage, a.algorithm,
            a.variant, a.key_size, tuple(a.flags), a.observation, a.exposure,
            tuple(sorted((k, v) for k, v in ctx.items() if k not in _PER_SESSION)),
        )  # fmt: skip
        if (first := groups.get(key)) is None:
            groups[key] = a
        else:
            first.more_evidence.append(a.evidence)
    for a in groups.values():
        a.evidence.context["sessions"] = str(len(a.all_evidence))
    return list(groups.values())


def _flow_assets(
    flow: Flow, path: Path, tally: _Tally, dns_names: dict[str, str] | None = None
) -> Iterator[CryptoAsset]:
    (s_ip, s_port), (c_ip, c_port) = flow.server, flow.client
    cs, ss = flow.client_stream, flow.server_stream
    if not cs and not ss:
        return
    service = SERVICES.get(s_port, f"tcp/{s_port}")
    context = {
        "server": s_ip,
        "server_port": str(s_port),
        "client": c_ip,
        "service": service,
        "file": str(path),
    }
    if (pkt := flow.first_payload_packet.get(flow.server)) is not None:
        context["packet"] = str(pkt)
    if dns_names and (host := dns_names.get(s_ip)):
        context["host"] = host  # name from a DNS answer in the same capture
    evidence = Evidence(
        source_type=SourceType.NETWORK,
        location=f"{c_ip}:{c_port} -> {s_ip}:{s_port}",
        context=context,
    )
    exposure = _exposure(s_ip)

    if ssh.banner(cs) or ssh.banner(ss):
        yield from _ssh_assets(cs, ss, exposure, evidence)
    elif tls.find_tls_start(cs) >= 0:
        yield from _tls_assets(cs, ss, exposure, evidence, tally)
    elif cs.startswith(CLEARTEXT_PREFIXES) or ss.startswith(CLEARTEXT_PREFIXES):
        first_line = (cs or ss).split(b"\r\n", 1)[0][:80].decode(errors="replace")
        ctx = {**evidence.context, "request": first_line}
        yield CryptoAsset(
            observed=f"{service} (cleartext)",
            algorithm="PLAINTEXT",
            usage="transport",
            observation=Observation.NEGOTIATED,
            exposure=exposure,
            evidence=evidence.model_copy(update={"context": ctx}),
        )
    elif _is_tls_midstream(cs, ss):
        tally.midstream.append(f"{s_ip}:{s_port}")
    else:
        tally.unparsed += 1


def _is_tls_midstream(cs: bytes, ss: bytes) -> bool:
    """Encrypted TLS records (content type 20-23, version 3.x) with no handshake in view, or
    only 1-byte TCP keep-alive probes on a connection opened before the capture began."""

    def tls_record(b: bytes) -> bool:
        return len(b) >= 5 and b[0] in (0x14, 0x15, 0x17) and b[1] == 0x03 and b[2] <= 0x04

    return tls_record(cs) or tls_record(ss) or (0 < len(cs) <= 1 and len(ss) <= 1)


def _tls_assets(
    cs: bytes, ss: bytes, exposure: Exposure, evidence: Evidence, tally: _Tally
) -> Iterator[CryptoAsset]:
    client_msgs = tls.handshake_messages(cs)
    server_msgs = tls.handshake_messages(ss)
    ch_body = next((b for t, b in client_msgs if t == tls.CLIENT_HELLO), None)
    sh_body = next((b for t, b in server_msgs if t == tls.SERVER_HELLO), None)
    ch = tls.parse_hello(ch_body, server=False) if ch_body else None
    sh = tls.parse_hello(sh_body, server=True) if sh_body else None
    if ch is None:
        return

    common = []
    preamble = cs[: tls.find_tls_start(cs)]
    if b"STARTTLS" in preamble.upper():
        common.append("starttls")
    if preamble.startswith(POSTGRES_SSL_REQUEST):
        common.append("postgres-sslrequest")
    ctx = dict(evidence.context)
    if sni := tls.server_name(ch):
        ctx["sni"] = sni
    offered_pq = [NAMED_GROUPS[g].name for g in tls.client_groups(ch)
                  if g in NAMED_GROUPS and NAMED_GROUPS[g].post_quantum]  # fmt: skip
    if offered_pq:
        ctx["client_pq_groups"] = ", ".join(offered_pq)

    def asset(observed: str, alias: str, usage: str, flags: Iterable[str] = (),
              variant: str | None = None, key_size: int | None = None,
              extra: dict[str, str] | None = None,
              observation: Observation = Observation.NEGOTIATED) -> CryptoAsset:  # fmt: skip
        return CryptoAsset(
            observed=observed,
            algorithm=alias,
            variant=variant,
            confidence=Confidence.LOW if observation is Observation.OFFERED else Confidence.HIGH,
            key_size=key_size,
            usage=usage,
            observation=observation,
            exposure=exposure,
            flags=sorted({*common, *flags}),
            evidence=evidence.model_copy(update={"context": {**ctx, **(extra or {})}}),
        )

    if sh is None:  # no server response captured: report what the client offered
        ctx["note"] = "ServerHello not captured; showing client offer"
        yield asset("ClientHello", "unknown-tls-session", "tls-protocol",
                    observation=Observation.OFFERED)  # fmt: skip
        return

    version = tls.negotiated_version(sh)
    version_name = TLS_VERSIONS.get(version, f"0x{version:04x}")
    suite_id = sh.suites[0]
    suite = CIPHER_SUITES.get(suite_id, f"0x{suite_id:04X}")
    ctx.update({"tls_version": version_name, "cipher_suite": suite})

    # key exchange: TLS 1.3 -> key_share group; TLS 1.2 -> suite kx (+ SKE curve if present)
    group_id = tls.server_key_share_group(sh)
    ske = next((b for t, b in server_msgs if t == tls.SERVER_KEY_EXCHANGE), None)
    dh_bits = None
    if group_id is None and ske is not None:
        group_id, dh_bits = tls.ske_group(ske)
    group = NAMED_GROUPS.get(group_id) if group_id is not None else None
    pq = group is not None and group.post_quantum

    if version_name == "TLSv1.3":
        tally.tls13 += 1
        alias, flags = ("TLSv1.3", []) if pq else ("TLSv1.3-classical", ["no-pq-group"])
        yield asset(version_name, alias, "tls-protocol", flags)
    else:
        if not any(t == tls.CERTIFICATE for t, _ in server_msgs):
            tally.tls12_without_certificate += 1
        yield asset(version_name, version_name, "tls-protocol")

    if suite not in CIPHER_SUITES.values():
        yield asset(suite, f"TLS suite {suite}", "tls-cipher-suite")
        return
    parts = decompose(suite)

    kx_flags = [f for f in parts.flags if f == "no-forward-secrecy"]
    if group is not None:
        if offered_pq and not pq:
            kx_flags.append("server-declined-pq")
        yield asset(group.name, group.alias, "tls-key-exchange", kx_flags, variant=group.name,
                    key_size=group.key_size, extra={"group": group.name})  # fmt: skip
    elif parts.key_exchange is not None:
        variant = "RSA key transport" if parts.key_exchange == "RSA" else None
        yield asset(suite, parts.key_exchange, "tls-key-exchange", kx_flags, variant=variant,
                    key_size=dh_bits)  # fmt: skip
    elif group_id is not None:
        yield asset(f"group 0x{group_id:04x}", f"TLS group 0x{group_id:04x}",
                    "tls-key-exchange", kx_flags)  # fmt: skip

    # (EC)DHE suites sign the handshake with the certificate key; static RSA reuses it for
    # key transport (already reported above).
    if parts.authentication and parts.key_exchange not in (None, "RSA"):
        yield asset(suite, parts.authentication, "tls-authentication")

    cipher_flags = [f for f in parts.flags if f == "cbc-mode"]
    yield asset(suite, parts.cipher, "tls-cipher", cipher_flags, variant=parts.cipher_label)
    if parts.mac:
        yield asset(suite, parts.mac, "tls-mac")


def _ssh_assets(
    cs: bytes, ss: bytes, exposure: Exposure, evidence: Evidence
) -> Iterator[CryptoAsset]:
    ctx = dict(evidence.context)
    if b := ssh.banner(ss):
        ctx["server_software"] = b
    if b := ssh.banner(cs):
        ctx["client_software"] = b
    c_kex, s_kex = ssh.kexinit(cs), ssh.kexinit(ss)

    def asset(observed: str, alias: str, usage: str, flags: Iterable[str] = (),
              key_size: int | None = None, extra: dict[str, str] | None = None,
              observation: Observation = Observation.NEGOTIATED) -> CryptoAsset:  # fmt: skip
        return CryptoAsset(
            observed=observed,
            algorithm=alias,
            variant=ssh.display_name(observed),
            confidence=Confidence.LOW if observation is Observation.OFFERED else Confidence.HIGH,
            key_size=key_size,
            usage=usage,
            observation=observation,
            exposure=exposure,
            flags=sorted(set(flags)),
            evidence=evidence.model_copy(update={"context": {**ctx, **(extra or {})}}),
        )

    if c_kex is None or s_kex is None:
        software = ctx.get("server_software", "SSH")
        note = {"note": "KEXINIT not captured"}
        yield asset(software, "unknown-ssh-session", "ssh-key-exchange", extra=note,
                    observation=Observation.OFFERED)  # fmt: skip
        return

    weak_offered = "diffie-hellman-group1-sha1" in s_kex["kex"]
    cipher = ssh.negotiate(c_kex["cipher_c2s"], s_kex["cipher_c2s"]) or ""
    for field_name, usage in (("kex", "ssh-key-exchange"), ("host_key", "ssh-host-key"),
                              ("cipher_c2s", "ssh-cipher"), ("mac_c2s", "ssh-mac")):  # fmt: skip
        chosen = ssh.negotiate(c_kex[field_name], s_kex[field_name])
        if chosen is None:
            continue
        if field_name == "mac_c2s" and cipher.startswith(ssh.AEAD_CIPHERS):
            continue  # AEAD cipher: negotiated MAC is unused
        alias, size, flags = ssh.alias(chosen)
        if field_name == "kex" and weak_offered:
            flags.append("server-offers-dh-group1")
        offered = {"offered_by_server": ", ".join(s_kex[field_name])}
        yield asset(chosen, alias, usage, flags, key_size=size, extra=offered)
        if field_name == "kex" and chosen.endswith("-sha1"):
            yield asset(chosen, "SHA-1", "ssh-kex-hash")
        if field_name == "host_key" and chosen == "ssh-rsa":
            yield asset(chosen, "SHA-1", "ssh-signature-digest")
        # weaker algorithms the server still accepts: a downgrade path for other clients
        for weak in s_kex[field_name]:
            if weak != chosen and weak.split("@")[0] in ssh.WEAK_OFFERS[field_name]:
                w_alias, w_size, w_flags = ssh.alias(weak)
                yield asset(weak, w_alias, usage, [*w_flags, "server-permitted"],
                            key_size=w_size, extra=offered,
                            observation=Observation.PERMITTED)  # fmt: skip


def _exposure(ip: str) -> Exposure:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return Exposure.UNKNOWN
    if addr.is_global:
        return Exposure.INTERNET
    rfc1918 = any(addr in ipaddress.ip_network(n) for n in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))  # fmt: skip
    return Exposure.INTERNAL if rfc1918 or addr.is_loopback else Exposure.UNKNOWN
