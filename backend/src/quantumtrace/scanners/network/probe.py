"""Live TLS probe: handshake with one host and report what it negotiates.

Browsers don't let extensions see TLS internals, so the API probes the site itself:

1. A modern ClientHello (TLS 1.3 + 1.2, offering X25519MLKEM768 first). The ServerHello
   shows the version, suite and key-exchange group the server picks for a PQ-capable client.
2. If that was TLS 1.3, a TLS 1.2-only ClientHello. Whatever the server accepts there is
   still `permitted` for older clients: a downgrade path.
3. A normal handshake through `ssl` to read the leaf certificate (encrypted in TLS 1.3, so
   the raw hellos can't see it): its key and signature algorithm.

The hellos are hand-built and only the ServerHello flight is read, so the probe needs no
ML-KEM implementation; the connection is closed before any keys are derived. Assets go
through the same `tls_assets` as the pcap scanner, so both vectors classify identically.

The API runs this on behalf of callers, so `resolve_public` refuses private, loopback and
link-local addresses (SSRF) and only a short list of TLS ports is allowed.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import struct
from collections.abc import Iterator
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from quantumtrace.core.models import (
    CryptoAsset,
    Evidence,
    Exposure,
    Observation,
    ScanNote,
    SourceType,
)
from quantumtrace.scanners.network import tls
from quantumtrace.scanners.network.pcap import SERVICES, Tally, exposure_of, tls_assets

SCANNER = "tls-probe"
TIMEOUT_S = 6.0
MAX_RESPONSE = 64 * 1024
# Ports that speak TLS from the first byte. STARTTLS ports (25, 587, 143, 5432) need a
# protocol dialogue first and are not probed.
ALLOWED_PORTS = frozenset({443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 8443})

X25519MLKEM768, X25519, SECP256R1, SECP384R1 = 0x11EC, 0x001D, 0x0017, 0x0018
TLS13_SUITES = (0x1301, 0x1302, 0x1303)
TLS12_SUITES = (
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,  # ECDHE AEAD
    0xC009, 0xC013, 0xC00A, 0xC014,  # ECDHE CBC
    0x009E, 0x009F,  # DHE AEAD
    0x009C, 0x009D, 0x002F, 0x0035, 0x000A,  # static RSA, 3DES: what old servers fall back to
)  # fmt: skip
SIGNATURE_SCHEMES = (
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807, 0x0808,
    0x0201, 0x0203,
)  # fmt: skip


class ProbeError(Exception):
    """The probe could not run. The message is safe to show to the caller."""


class ProbeRefused(ProbeError):
    """The target is not allowed (private address, unsupported port, bad host name)."""


@dataclass(frozen=True)
class Target:
    host: str  # as given, used for SNI
    port: int
    ip: str  # the vetted address every connection goes to (no DNS rebinding)

    @property
    def sni(self) -> str | None:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return self.host
        return None


def resolve_public(host: str, port: int, *, allow_private: bool = False) -> Target:
    host = host.strip().rstrip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or len(host) > 253 or any(c in host for c in "/@?# "):
        raise ProbeRefused("Enter a host name such as example.com, without a scheme or path.")
    if port not in ALLOWED_PORTS and not allow_private:
        raise ProbeRefused(
            f"Port {port} is not probed. Use a port that speaks TLS directly, such as 443."
        )
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ProbeError(f"{host} does not resolve. Check the host name.") from exc
    addrs = sorted({str(info[4][0]) for info in infos}, key=lambda a: ":" in a)  # IPv4 first
    if not allow_private:
        for a in addrs:
            if not ipaddress.ip_address(a).is_global:
                raise ProbeRefused(
                    f"{host} resolves to a private or reserved address, which the API won't "
                    "probe. Scan internal hosts with a packet capture instead."
                )
    return Target(host, port, addrs[0])


def probe(target: Target) -> Iterator[CryptoAsset | ScanNote]:
    tally = Tally()
    exposure = exposure_of(target.ip)

    modern_hello = client_hello(target.sni, tls13=True, pq=True)
    modern = _exchange(target, modern_hello)
    if modern is None:  # some stacks reject an unfamiliar key share: retry without ML-KEM
        modern_hello = client_hello(target.sni, tls13=True, pq=False)
        modern = _exchange(target, modern_hello)
    if modern is None:
        raise ProbeError(
            f"{target.host}:{target.port} answered, but refused every TLS 1.2 and 1.3 handshake "
            "the probe offered."
        )

    negotiated = list(
        tls_assets(modern_hello, modern, exposure, _evidence(target, "modern"), tally)
    )
    yield from negotiated

    if tally.tls13:
        legacy_hello = client_hello(target.sni, tls13=False, pq=False)
        legacy = _exchange(target, legacy_hello)
        if legacy is None:
            yield ScanNote(
                scanner=SCANNER,
                message=f"{target.host} refuses TLS 1.2, so older clients can't downgrade it.",
            )
        else:
            seen = {(a.usage, a.algorithm, a.variant) for a in negotiated}
            ev = _evidence(target, "tls12-only")
            for a in tls_assets(legacy_hello, legacy, exposure, ev, Tally()):
                if (a.usage, a.algorithm, a.variant) in seen:
                    continue
                yield a.model_copy(
                    update={
                        "observation": Observation.PERMITTED,
                        "flags": sorted({*a.flags, "server-permitted"}),
                    }
                )

    yield from _certificate(target, exposure)
    yield ScanNote(
        scanner=SCANNER,
        message=(
            f"{target.host}: probed from the QuantumTrace API with a client that offers "
            "X25519MLKEM768. Other clients may negotiate differently, and a CDN or load balancer "
            "in front of the site answers for it."
        ),
    )


# ---------------------------------------------------------------- ClientHello


def client_hello(sni: str | None, *, tls13: bool, pq: bool) -> bytes:
    """A complete TLS record holding a ClientHello."""
    groups = ([X25519MLKEM768] if pq else []) + [X25519, SECP256R1, SECP384R1]
    exts = [
        _ext(0x0017, b""),  # extended_master_secret
        _ext(0xFF01, b"\x00"),  # renegotiation_info
        _ext(10, _vec16(b"".join(struct.pack(">H", g) for g in groups))),
        _ext(11, b"\x01\x00"),  # ec_point_formats: uncompressed
        _ext(13, _vec16(b"".join(struct.pack(">H", s) for s in SIGNATURE_SCHEMES))),
    ]
    if sni:
        name = sni.encode("idna")
        exts.insert(0, _ext(0, _vec16(b"\x00" + _vec16(name))))
    suites = list(TLS12_SUITES)
    if tls13:
        suites = [*TLS13_SUITES, *suites]
        shares = [(X25519, os.urandom(32))]
        if pq:  # hybrid share: ML-KEM-768 encapsulation key, then the X25519 public key
            shares.insert(0, (X25519MLKEM768, _mlkem768_encapsulation_key() + os.urandom(32)))
        exts += [
            _ext(43, b"\x04\x03\x04\x03\x03"),  # supported_versions: 1.3, 1.2
            _ext(45, b"\x01\x01"),  # psk_key_exchange_modes: psk_dhe_ke
            _ext(51, _vec16(b"".join(struct.pack(">H", g) + _vec16(k) for g, k in shares))),
        ]
    body = (
        b"\x03\x03"  # legacy_version TLS 1.2
        + os.urandom(32)
        + b"\x20" + os.urandom(32)  # session id (middlebox compatibility)
        + _vec16(b"".join(struct.pack(">H", s) for s in suites))
        + b"\x01\x00"  # compression: null
        + _vec16(b"".join(exts))
    )  # fmt: skip
    handshake = bytes([tls.CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def _mlkem768_encapsulation_key() -> bytes:
    """A well-formed ML-KEM-768 encapsulation key (FIPS 203 §7.2: every 12-bit coefficient
    below q). Its secret half is never computed: the probe only reads the ServerHello."""
    q, out = 3329, bytearray()
    coeffs = [int.from_bytes(os.urandom(2), "big") % q for _ in range(3 * 256)]
    for a, b in zip(coeffs[::2], coeffs[1::2], strict=True):
        out += bytes([a & 0xFF, (a >> 8) | ((b & 0x0F) << 4), b >> 4])
    return bytes(out) + os.urandom(32)  # + rho


def _ext(typ: int, data: bytes) -> bytes:
    return struct.pack(">HH", typ, len(data)) + data


def _vec16(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


# ---------------------------------------------------------------- transport


def _connect(target: Target) -> socket.socket:
    try:
        return socket.create_connection((target.ip, target.port), timeout=TIMEOUT_S)
    except OSError as exc:
        raise ProbeError(
            f"Could not connect to {target.host}:{target.port}. Check that the site is up and "
            "reachable from the internet."
        ) from exc


def _exchange(target: Target, hello: bytes) -> bytes | None:
    """Send a ClientHello and read the server's first flight. None if the server refused
    (alert or closed connection) instead of answering with a ServerHello."""
    with _connect(target) as sock:
        buf = b""
        try:
            sock.sendall(hello)
            while len(buf) < MAX_RESPONSE and not _flight_complete(buf):
                chunk = sock.recv(16384)
                if not chunk:
                    break
                buf += chunk
        except (TimeoutError, OSError):
            pass  # use whatever arrived
    msgs = tls.handshake_messages(buf)
    return buf if any(t == tls.SERVER_HELLO for t, _ in msgs) else None


def _flight_complete(buf: bytes) -> bool:
    if buf[:1] == b"\x15":  # alert
        return True
    i, seen_hello = 0, False
    while i + 5 <= len(buf):
        typ, length = buf[i], struct.unpack(">H", buf[i + 3 : i + 5])[0]
        if typ != 0x16:
            return seen_hello or typ == 0x15  # CCS / app data: the plaintext part is over
        if i + 5 + length > len(buf):
            return False
        seen_hello = True
        i += 5 + length
    msgs = tls.handshake_messages(buf)
    for typ, body in msgs:
        if typ == 14:  # ServerHelloDone
            return True
        if typ == tls.SERVER_HELLO:
            hello = tls.parse_hello(body, server=True)
            if hello and tls.negotiated_version(hello) == 0x0304:
                return True  # everything after ServerHello is encrypted
    return False


def _evidence(target: Target, probe_name: str) -> Evidence:
    context = {
        "server": target.ip,
        "server_port": str(target.port),
        "service": SERVICES.get(target.port, f"tcp/{target.port}"),
        "probe": probe_name,
    }
    if target.sni:
        context["sni"] = target.sni
    return Evidence(
        source_type=SourceType.NETWORK,
        location=f"{target.host}:{target.port}",
        context=context,
    )


# ---------------------------------------------------------------- certificate

_CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


def _certificate(target: Target, exposure: Exposure) -> Iterator[CryptoAsset | ScanNote]:
    # Inventory, not validation: expired, self-signed and weak-cipher servers must still answer.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    try:
        with (
            _connect(target) as raw,
            ctx.wrap_socket(raw, server_hostname=target.sni) as conn,
        ):
            der = conn.getpeercert(binary_form=True)
    except (ssl.SSLError, OSError):
        der = None
    if not der:
        yield ScanNote(
            scanner=SCANNER,
            message=f"{target.host}: the certificate could not be read, so its key is unknown.",
        )
        return

    cert = x509.load_der_x509_certificate(der)
    evidence = _evidence(target, "certificate")
    evidence.context.update(
        {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_after": cert.not_valid_after_utc.date().isoformat(),
        }
    )

    def asset(observed: str, alias: str, usage: str, **kw: object) -> CryptoAsset:
        return CryptoAsset.model_validate(
            {
                "observed": observed,
                "algorithm": alias,
                "usage": usage,
                "observation": Observation.CONFIGURED,
                "exposure": exposure,
                "evidence": evidence,
                **kw,
            }
        )

    key_oid = cert.public_key_algorithm_oid
    key_name = getattr(key_oid, "_name", None) or key_oid.dotted_string
    try:
        key = cert.public_key()
    except Exception:  # an algorithm cryptography can't load (e.g. ML-DSA): name it by OID
        key = None
    if isinstance(key, rsa.RSAPublicKey):
        yield asset(key_name, "RSA", "certificate-key", key_size=key.key_size,
                    variant=f"RSA-{key.key_size}")  # fmt: skip
    elif isinstance(key, ec.EllipticCurvePublicKey):
        curve = _CURVES.get(key.curve.name, key.curve.name)
        yield asset(key_name, "ECDSA", "certificate-key", key_size=key.curve.key_size,
                    variant=f"ECDSA {curve}")  # fmt: skip
    elif isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        name = "Ed25519" if isinstance(key, ed25519.Ed25519PublicKey) else "Ed448"
        yield asset(key_name, name, "certificate-key", variant=name)
    else:
        yield asset(key_name, key_name, "certificate-key")

    sig_oid = cert.signature_algorithm_oid
    sig_name = getattr(sig_oid, "_name", None) or sig_oid.dotted_string
    lowered = sig_name.lower()
    family = (
        "RSA" if "rsa" in lowered
        else "ECDSA" if "ecdsa" in lowered
        else "Ed25519" if "ed25519" in lowered
        else "Ed448" if "ed448" in lowered
        else sig_name
    )  # fmt: skip
    yield asset(sig_name, family, "certificate-signature")
    digest = cert.signature_hash_algorithm
    if digest is not None:
        alias = digest.name.upper().replace("SHA", "SHA-", 1)  # sha256 -> SHA-256
        yield asset(sig_name, alias, "certificate-signature-digest")
    yield ScanNote(
        scanner=SCANNER,
        message=(
            f"{target.host}: only the leaf certificate is inspected. The intermediate and root "
            "CA keys that sign it need a post-quantum migration path too."
        ),
    )
