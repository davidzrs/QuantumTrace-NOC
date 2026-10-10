"""Parse TLS ClientHello / ServerHello / ServerKeyExchange from reassembled streams."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

HANDSHAKE = 0x16
CLIENT_HELLO, SERVER_HELLO, CERTIFICATE, SERVER_KEY_EXCHANGE = 1, 2, 11, 12
EXT_SERVER_NAME, EXT_GROUPS, EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE = 0, 10, 43, 51


@dataclass
class Hello:
    legacy_version: int
    suites: list[int]
    extensions: dict[int, bytes] = field(default_factory=dict)


def find_tls_start(stream: bytes) -> int:
    """Offset of the first TLS handshake record, skipping any cleartext preamble
    (SMTP/IMAP STARTTLS dialogue, Postgres SSLRequest, ...)."""
    i = stream.find(b"\x16\x03")
    while i != -1:
        if i + 6 <= len(stream) and stream[i + 2] <= 0x04 and stream[i + 5] in (1, 2):
            return i
        i = stream.find(b"\x16\x03", i + 1)
    return -1


def handshake_messages(stream: bytes) -> list[tuple[int, bytes]]:
    start = find_tls_start(stream)
    if start < 0:
        return []
    data = bytearray()
    i = start
    while i + 5 <= len(stream) and stream[i] in (0x14, 0x15, 0x16, 0x17):
        length = struct.unpack(">H", stream[i + 3 : i + 5])[0]
        if stream[i] == HANDSHAKE:
            data += stream[i + 5 : i + 5 + length]
        elif stream[i] == 0x17:  # application data: handshake over (or encrypted in 1.3)
            break
        i += 5 + length
    out, j = [], 0
    while j + 4 <= len(data):
        typ, length = data[j], int.from_bytes(data[j + 1 : j + 4], "big")
        out.append((typ, bytes(data[j + 4 : j + 4 + length])))
        j += 4 + length
    return out


def parse_hello(body: bytes, *, server: bool) -> Hello | None:
    try:
        version = struct.unpack(">H", body[0:2])[0]
        i = 34
        i += 1 + body[i]  # session id
        if server:
            suites = [struct.unpack(">H", body[i : i + 2])[0]]
            i += 3  # suite + compression method
        else:
            n = struct.unpack(">H", body[i : i + 2])[0]
            suites = [struct.unpack(">H", body[i + 2 + k : i + 4 + k])[0] for k in range(0, n, 2)]
            i += 2 + n
            i += 1 + body[i]  # compression methods
        exts: dict[int, bytes] = {}
        if i + 2 <= len(body):
            end = i + 2 + struct.unpack(">H", body[i : i + 2])[0]
            i += 2
            while i + 4 <= end:
                typ, length = struct.unpack(">HH", body[i : i + 4])
                exts[typ] = body[i + 4 : i + 4 + length]
                i += 4 + length
        return Hello(version, suites, exts)
    except (IndexError, struct.error):
        return None


def negotiated_version(server_hello: Hello) -> int:
    sv = server_hello.extensions.get(EXT_SUPPORTED_VERSIONS)
    if sv and len(sv) >= 2:
        return int(struct.unpack(">H", sv[:2])[0])
    return server_hello.legacy_version


def server_key_share_group(server_hello: Hello) -> int | None:
    ks = server_hello.extensions.get(EXT_KEY_SHARE)
    return int(struct.unpack(">H", ks[:2])[0]) if ks and len(ks) >= 2 else None


def client_groups(client_hello: Hello) -> list[int]:
    raw = client_hello.extensions.get(EXT_GROUPS, b"")[2:]
    return [struct.unpack(">H", raw[k : k + 2])[0] for k in range(0, len(raw) - 1, 2)]


def server_name(client_hello: Hello) -> str | None:
    raw = client_hello.extensions.get(EXT_SERVER_NAME)
    if not raw or len(raw) < 5:
        return None
    length = struct.unpack(">H", raw[3:5])[0]
    return raw[5 : 5 + length].decode(errors="replace") or None


def ske_group(body: bytes) -> tuple[int | None, int | None]:
    """ServerKeyExchange (TLS <= 1.2): (named curve id, finite-field DH bits)."""
    if len(body) >= 3 and body[0] == 3:  # ECParameters: named_curve
        return int(struct.unpack(">H", body[1:3])[0]), None
    if len(body) >= 2:  # DHE: p length prefix
        return None, struct.unpack(">H", body[0:2])[0] * 8
    return None, None
