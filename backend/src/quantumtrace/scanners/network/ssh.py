"""SSH banner + KEXINIT parsing and algorithm negotiation (RFC 4253 section 7.1)."""

from __future__ import annotations

import re
import struct

NAME_LISTS = (
    "kex", "host_key", "cipher_c2s", "cipher_s2c", "mac_c2s", "mac_s2c",
    "compression_c2s", "compression_s2c",
)  # fmt: skip
AEAD_CIPHERS = ("chacha20-poly1305", "aes128-gcm", "aes256-gcm")

# Algorithms worth reporting when a server merely *offers* them (downgrade exposure).
WEAK_OFFERS: dict[str, frozenset[str]] = {
    "kex": frozenset({"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1",
                      "diffie-hellman-group14-sha1"}),
    "host_key": frozenset({"ssh-dss", "ssh-rsa"}),
    "cipher_c2s": frozenset({"3des-cbc", "des-cbc", "arcfour", "arcfour128", "arcfour256",
                             "blowfish-cbc", "cast128-cbc"}),
    "mac_c2s": frozenset({"hmac-md5", "hmac-md5-96", "hmac-sha1-96"}),
}  # fmt: skip


def banner(stream: bytes) -> str | None:
    if not stream.startswith(b"SSH-"):
        return None
    return stream.split(b"\r\n", 1)[0].decode(errors="replace")


def kexinit(stream: bytes) -> dict[str, list[str]] | None:
    """Parse the first SSH_MSG_KEXINIT after the banner (unencrypted by definition)."""
    i = stream.find(b"\r\n")
    if i < 0:
        return None
    i += 2
    try:
        if stream[i + 5] != 20:  # SSH_MSG_KEXINIT
            return None
        j = i + 6 + 16  # packet_length(4) padding(1) type(1) cookie(16)
        out: dict[str, list[str]] = {}
        for name in NAME_LISTS:
            length = struct.unpack(">I", stream[j : j + 4])[0]
            out[name] = stream[j + 4 : j + 4 + length].decode(errors="replace").split(",")
            j += 4 + length
        return out
    except (IndexError, struct.error):
        return None


def negotiate(client: list[str], server: list[str]) -> str | None:
    return next((c for c in client if c in server), None)


def alias(name: str) -> tuple[str, int | None, list[str]]:
    """Map an SSH algorithm name to (classifier alias, key size, flags)."""
    n = name.split("@")[0].removesuffix("-cert-v01").removeprefix("sk-")  # sk-: FIDO keys
    flags: list[str] = []
    if n.startswith("mlkem768x25519"):
        return "X25519MLKEM768", None, flags
    if n.startswith("sntrup761x25519"):
        return "sntrup761x25519", None, flags
    if n.startswith(("curve25519", "curve448")):
        return "ECDHE", 256 if "25519" in n else 448, flags
    if m := re.match(r"ecdh-sha2-nistp(\d+)", n):
        return "ECDHE", int(m.group(1)), flags
    if m := re.match(r"diffie-hellman-group(\d+)-", n):
        bits = {1: 1024, 14: 2048, 15: 3072, 16: 4096, 17: 6144, 18: 8192}.get(int(m.group(1)))
        if bits == 1024:
            flags.append("weak-dh-1024")
        return "DH", bits, flags
    if n.startswith("diffie-hellman-group-exchange"):
        return "DH", None, flags
    if n in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
        return "RSA", None, flags
    if n in ("ssh-ed25519", "ssh-ed448", "ed25519"):
        return "Ed25519", None, flags
    if m := re.match(r"ecdsa-sha2-nistp(\d+)", n):
        return "ECDSA", int(m.group(1)), flags
    if n == "ssh-dss":
        return "DSA", None, flags
    if m := re.match(r"aes(\d+)-(cbc|ctr|gcm)", n):
        if m.group(2) == "cbc":
            flags.append("cbc-mode")
        return f"AES-{m.group(1)}", None, flags
    if n == "chacha20-poly1305":
        return "ChaCha20-Poly1305", None, flags
    if n == "3des-cbc":
        return "3DES", None, ["cbc-mode"]
    if n.startswith("arcfour"):
        return "RC4", None, flags
    if n.startswith("blowfish"):
        return "Blowfish", None, flags
    if m := re.match(r"hmac-(sha1|md5|sha2-256|sha2-512)", n):
        return {"sha1": "HMAC-SHA1", "md5": "HmacMD5", "sha2-256": "HMAC-SHA256",
                "sha2-512": "HMAC-SHA512"}[m.group(1)], None, flags  # fmt: skip
    return name, None, flags


def display_name(name: str) -> str:
    """Human/CBOM name: aes128-cbc -> AES-128-CBC, chacha20-poly1305@openssh.com ->
    ChaCha20-Poly1305; key exchange and host-key names stay in SSH spelling."""
    n = name.split("@")[0]
    if m := re.fullmatch(r"aes(\d+)-(cbc|ctr|gcm)", n):
        return f"AES-{m.group(1)}-{m.group(2).upper()}"
    if n == "chacha20-poly1305":
        return "ChaCha20-Poly1305"
    if n == "3des-cbc":
        return "3DES-CBC"
    return n
