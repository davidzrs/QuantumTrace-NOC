"""TLS cipher-suite decomposition shared by the cloud (ELB) and network (pcap) scanners."""

from __future__ import annotations

from dataclasses import dataclass, field

# Default key-exchange groups offered by classical TLS 1.3 stacks when a policy names none.
CLASSICAL_TLS13_GROUPS = ("X25519", "secp256r1")


@dataclass(frozen=True)
class SuiteParts:
    """Algorithm aliases (resolvable by the classifier) that make up one cipher suite."""

    key_exchange: str | None  # None for TLS 1.3 suites (negotiated separately via groups)
    authentication: str | None  # None for TLS 1.3 suites (decided by the certificate)
    cipher: str  # bare primitive, e.g. AES-128
    mode: str | None  # GCM | CCM | CBC | POLY1305 | None (stream ciphers)
    mac: str | None  # record MAC alias for non-AEAD suites
    flags: tuple[str, ...] = field(default=())

    @property
    def aead(self) -> bool:
        return self.mode in ("GCM", "CCM", "POLY1305")

    @property
    def cipher_label(self) -> str:
        """Primitive plus mode, as people say it: AES-128-GCM, AES-256-CBC, ChaCha20-Poly1305."""
        if self.cipher.startswith("CHACHA20"):
            return "ChaCha20-Poly1305"
        return f"{self.cipher}-{self.mode}" if self.mode else self.cipher


def decompose(suite: str) -> SuiteParts:
    """Split an OpenSSL ('ECDHE-RSA-AES128-GCM-SHA256') or IANA ('TLS_AES_128_GCM_SHA256')
    cipher-suite name into its primitives."""
    name = suite.upper()

    if name.startswith("TLS_") and "_WITH_" not in name:  # TLS 1.3 suite: always AEAD
        body = name.removeprefix("TLS_").rsplit("_", 1)[0]  # AES_128_GCM
        if "CHACHA20" in body:
            return SuiteParts(None, None, "CHACHA20-POLY1305", "POLY1305", None)
        mode = "CCM" if "_CCM" in body else "GCM"
        cipher = body.split(f"_{mode}")[0].replace("_", "-")
        return SuiteParts(None, None, cipher, mode, None)

    if "_WITH_" in name:  # IANA TLS 1.2 style: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        kx_auth, rest = name.removeprefix("TLS_").split("_WITH_", 1)
        kx, _, auth = kx_auth.partition("_")
        cipher_part, _, iana_mac = rest.rpartition("_")
        return _build(kx, auth or kx, cipher_part.replace("_", "-"), iana_mac)

    tokens = name.split("-")
    kx, auth = "RSA", "RSA"  # bare 'AES128-SHA' means static RSA key transport
    if tokens[0] in {"ECDHE", "DHE", "ECDH", "DH"}:
        kx = tokens.pop(0)
        if tokens[0] in {"RSA", "ECDSA", "DSS"}:
            auth = tokens.pop(0)
    mac = tokens.pop() if tokens[-1].startswith(("SHA", "MD5")) else None
    return _build(kx, auth, "-".join(tokens), mac)


_MAC_ALIASES = {
    "SHA": "HMAC-SHA1",
    "MD5": "HMAC-MD5",
    "SHA256": "HMAC-SHA256",
    "SHA384": "HMAC-SHA384",
}


def _build(kx: str, auth: str, cipher: str, mac: str | None) -> SuiteParts:
    flags: list[str] = []
    if kx == "RSA":
        flags.append("no-forward-secrecy")
    if "CHACHA20" in cipher:
        return SuiteParts(kx, _auth(auth), "CHACHA20-POLY1305", "POLY1305", None, tuple(flags))
    mode: str | None = next((m for m in ("GCM", "CCM") if m in cipher), None)
    if cipher in ("DES-CBC3", "3DES-EDE-CBC", "3DES-EDE"):
        cipher, mode = "3DES", "CBC"
    elif cipher.startswith("RC4"):
        cipher, mode = "RC4", None
    elif mode is None:
        mode = "CBC"  # TLS 1.2 non-AEAD block ciphers are CBC
    if mode == "CBC":
        flags.append("cbc-mode")
    cipher = cipher.replace("AES128", "AES-128").replace("AES256", "AES-256")
    for m in ("-CBC", "-GCM", "-CCM"):
        cipher = cipher.replace(m, "")
    aead = mode in ("GCM", "CCM")
    return SuiteParts(
        key_exchange=kx,
        authentication=_auth(auth),
        cipher=cipher,
        mode=mode,
        # AEAD suites use the trailing hash only as the handshake PRF, not as a record MAC.
        mac=None if aead or mac is None else _MAC_ALIASES.get(mac, mac),
        flags=tuple(flags),
    )


def _auth(auth: str) -> str:
    return {"DSS": "DSA", "ECDSA": "ECDSA", "RSA": "RSA"}.get(auth, auth)


# IANA registries (subset): enough for real-world captures; unknown ids fall through to
# "unknown" findings so gaps stay visible instead of silently ignored.
TLS_VERSIONS = {
    0x0300: "SSLv3",
    0x0301: "TLSv1",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}

CIPHER_SUITES = {
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}


@dataclass(frozen=True)
class Group:
    name: str  # IANA name, shown as "observed"
    alias: str  # classifier alias
    key_size: int | None = None
    post_quantum: bool = False


NAMED_GROUPS = {
    0x0017: Group("secp256r1", "ECDHE", 256),
    0x0018: Group("secp384r1", "ECDHE", 384),
    0x0019: Group("secp521r1", "ECDHE", 521),
    0x001D: Group("x25519", "ECDHE", 256),
    0x001E: Group("x448", "ECDHE", 448),
    0x0100: Group("ffdhe2048", "DH", 2048),
    0x0101: Group("ffdhe3072", "DH", 3072),
    0x0102: Group("ffdhe4096", "DH", 4096),
    0x0200: Group("MLKEM512", "ML-KEM", post_quantum=True),
    0x0201: Group("MLKEM768", "ML-KEM", post_quantum=True),
    0x0202: Group("MLKEM1024", "ML-KEM", post_quantum=True),
    0x11EB: Group("SecP256r1MLKEM768", "SecP256r1MLKEM768", post_quantum=True),
    0x11EC: Group("X25519MLKEM768", "X25519MLKEM768", post_quantum=True),
    0x11ED: Group("SecP384r1MLKEM1024", "SecP384r1MLKEM1024", post_quantum=True),
    0x6399: Group("X25519Kyber768Draft00", "X25519Kyber768Draft00", post_quantum=True),
}
