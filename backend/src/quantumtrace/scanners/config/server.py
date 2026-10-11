"""Server configuration files: OpenSSH (sshd_config, ssh_config) and TLS in nginx and Apache.

A configuration says what a server *allows*, not what a client negotiates, so its algorithms are
`permitted`. Names reuse the network scanner's mappings (`ssh.alias`, `tls.decompose`), so a
config line and a captured handshake classify the same way. What a file leaves unset falls back
to the software's defaults, which depend on its version: the scan says so instead of guessing.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from quantumtrace.core.models import (
    Confidence,
    CryptoAsset,
    Evidence,
    Observation,
    ScanNote,
    SourceType,
)
from quantumtrace.rules.tls import NAMED_GROUPS, Group, decompose
from quantumtrace.scanners.network import ssh

SCANNER = "server-config"
MAX_BYTES = 512 * 1024
SSH_NAMES = {"sshd_config", "ssh_config"}
TLS_NAMES = {"nginx.conf", "httpd.conf", "apache2.conf", "ssl.conf"}

# OpenSSH directive -> (usage, ssh name-list it fills)
SSH_DIRECTIVES = {
    "kexalgorithms": ("ssh-key-exchange", "kex"),
    "hostkeyalgorithms": ("ssh-host-key", "host_key"),
    "pubkeyacceptedalgorithms": ("ssh-user-key", "host_key"),
    "pubkeyacceptedkeytypes": ("ssh-user-key", "host_key"),
    "casignaturealgorithms": ("ssh-user-key", "host_key"),
    "ciphers": ("ssh-cipher", "cipher_c2s"),
    "macs": ("ssh-mac", "mac_c2s"),
}
SSH_MAIN = ("kexalgorithms", "ciphers", "macs", "hostkeyalgorithms")
_HOST_KEY_FILE = re.compile(r"ssh_host_(rsa|dsa|ecdsa|ed25519)_key", re.I)
_HOST_KEY_ALIAS = {"rsa": "RSA", "dsa": "DSA", "ecdsa": "ECDSA", "ed25519": "Ed25519"}

TLS_VERSIONS = {
    "sslv3": "SSLv3",
    "tlsv1": "TLSv1",
    "tlsv1.1": "TLSv1.1",
    "tlsv1.2": "TLSv1.2",
    "tlsv1.3": "TLSv1.3",
}
_GROUPS = {g.name.lower(): g for g in NAMED_GROUPS.values()}
_GROUP_ALIASES = {
    "prime256v1": "secp256r1",
    "p-256": "secp256r1",
    "p-384": "secp384r1",
    "p-521": "secp521r1",
}
_SUITE = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)+")


class ServerConfigScanner:
    name = SCANNER
    source_type = SourceType.CODE

    def accepts(self, path: Path) -> bool:
        n = path.name.lower()
        return n in SSH_NAMES or n in TLS_NAMES or n.endswith(".conf")

    def scan(self, paths: Sequence[Path]) -> Iterable[CryptoAsset | ScanNote]:
        for path in paths:
            if path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            n = path.name.lower()
            in_ssh_dir = path.parent.name.lower() in ("sshd_config.d", "ssh_config.d")
            if n in SSH_NAMES or in_ssh_dir:
                yield from _ssh(path, text, main=n in SSH_NAMES)
            elif re.search(r"^\s*ssl_(?:protocols|ciphers|ecdh_curve|conf_command)\b", text, re.M):
                yield from _nginx(path, text)
            elif re.search(r"^\s*SSL(?:Protocol|CipherSuite|OpenSSLConfCmd)\b", text, re.M | re.I):
                yield from _apache(path, text)


def _evidence(path: Path, line: int, statement: str, language: str, **context: str) -> Evidence:
    """The directive's line as the snippet, so the report shows it and "Fix with AI" can rewrite
    it; `language` tells the model what kind of file it is reading."""
    return Evidence(
        source_type=SourceType.CODE,
        location=str(path),
        line=line,
        snippet=statement,
        snippet_start_line=line,
        context={"language": language, "directive": statement.split()[0], **context},
    )


def _asset(
    observed: str,
    alias: str,
    usage: str,
    ev: Evidence,
    *,
    flags: Iterable[str] = (),
    key_size: int | None = None,
    variant: str | None = None,
    observation: Observation = Observation.PERMITTED,
    confidence: Confidence = Confidence.HIGH,
) -> CryptoAsset:
    return CryptoAsset(
        observed=observed,
        algorithm=alias,
        usage=usage,
        key_size=key_size,
        variant=variant,
        observation=observation,
        confidence=confidence,
        flags=sorted(set(flags)),
        evidence=ev,
    )


# ---------------------------------------------------------------- OpenSSH


def _ssh(path: Path, text: str, *, main: bool) -> Iterator[CryptoAsset | ScanNote]:
    seen: set[str] = set()
    unmapped: list[str] = []
    match: str | None = None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = re.split(r"[\s=]+", line, maxsplit=1)
        keyword, value = parts[0].lower(), parts[1].strip() if len(parts) > 1 else ""
        if keyword == "match":
            match = value
            continue
        extra = {"match": match} if match else {}
        if keyword == "hostkey" and (m := _HOST_KEY_FILE.search(value)):
            # the key type is in the file name; its size is in the file
            ev = _evidence(path, i, line, "OpenSSH config", host_key_file=value, **extra)
            yield _asset(
                value,
                _HOST_KEY_ALIAS[m.group(1).lower()],
                "ssh-host-key",
                ev,
                observation=Observation.CONFIGURED,
                confidence=Confidence.MEDIUM,
            )
            continue
        if keyword not in SSH_DIRECTIVES or not value:
            continue
        usage, _ = SSH_DIRECTIVES[keyword]
        seen.add(keyword)
        mode = value[0] if value[0] in "+-^" else ""
        if mode == "-":  # removes from the defaults: what remains depends on the version
            continue
        if mode:
            extra["adds_to_defaults"] = "yes"
        ev = _evidence(path, i, line, "OpenSSH config", **extra)
        for name in value.lstrip("+^").split(","):
            name = name.strip()
            alias, size, flags = ssh.alias(name)
            if alias == name:  # no mapping (umac-64, gss-*): stated, not guessed
                unmapped.append(name)
                continue
            yield _asset(
                name, alias, usage, ev, flags=flags, key_size=size, variant=ssh.display_name(name)
            )
            if usage == "ssh-key-exchange" and name.endswith("-sha1"):
                yield _asset(name, "SHA-1", "ssh-kex-hash", ev)
            if usage in ("ssh-host-key", "ssh-user-key") and name.split("@")[0] in (
                "ssh-rsa",
                "ssh-rsa-cert-v01",
            ):
                yield _asset(name, "SHA-1", "ssh-signature-digest", ev)
    if main and (missing := [k for k in SSH_MAIN if k not in seen]):
        names = ", ".join(_SSH_NAME[k] for k in missing)
        yield ScanNote(
            scanner=SCANNER,
            message=(
                f"{path.name}: doesn't set {names}, so OpenSSH's built-in defaults apply, and they "
                "depend on the installed version. Capture a handshake to see what it negotiates."
            ),
        )
    if unmapped:
        yield ScanNote(
            scanner=SCANNER,
            message=(f"{path.name}: {', '.join(sorted(set(unmapped)))} not classified yet."),
        )


_SSH_NAME = {
    "kexalgorithms": "KexAlgorithms",
    "ciphers": "Ciphers",
    "macs": "MACs",
    "hostkeyalgorithms": "HostKeyAlgorithms",
}


# ---------------------------------------------------------------- TLS (nginx, Apache)


@dataclass
class _Tls:
    """What one file allows, each part with the line that says it."""

    protocols: list[tuple[str, Evidence]] = field(default_factory=list)
    suites: list[tuple[str, Evidence]] = field(default_factory=list)
    groups: list[tuple[str, Evidence]] = field(default_factory=list)
    keywords: set[str] = field(default_factory=set)
    unmapped: set[str] = field(default_factory=set)


def _statements(text: str) -> Iterator[tuple[int, str]]:
    """(line, statement) with comments removed; an nginx statement ends at its semicolon."""
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip().rstrip(";").strip()
        if line:
            yield i, line


def _cipher_list(value: str, ev: Evidence, tls: _Tls) -> None:
    """An OpenSSL cipher string: named suites are read; keywords (HIGH, !aNULL, ECDHE+AESGCM)
    only the server's OpenSSL can expand, so they are noted rather than guessed."""
    for token in re.split(r"[:,\s]+", value.strip("'\"")):
        if not token or token.startswith(("!", "-", "+", "@")):
            continue
        if _SUITE.fullmatch(token) and not token.startswith(("TLSV", "SSLV")):
            tls.suites.append((token, ev))
        elif token.upper().startswith("TLS_"):  # TLS 1.3 suite named in the same list
            tls.suites.append((token.upper(), ev))
        else:
            tls.keywords.add(token)


def _group_list(value: str, ev: Evidence, tls: _Tls) -> None:
    for token in re.split(r"[:,\s]+", value.strip("'\"")):
        if token and token.lower() != "auto":
            tls.groups.append((token, ev))


def _nginx(path: Path, text: str) -> Iterator[CryptoAsset | ScanNote]:
    tls = _Tls()
    for i, line in _statements(text):
        directive, _, value = line.partition(" ")
        ev = _evidence(path, i, line, "nginx config")
        if directive == "ssl_protocols":
            tls.protocols.extend((p, ev) for p in value.split())
        elif directive == "ssl_ciphers":
            _cipher_list(value, ev, tls)
        elif directive == "ssl_ecdh_curve":
            _group_list(value, ev, tls)
        elif directive == "ssl_conf_command" and value.split()[0] in ("Groups", "Curves"):
            _group_list(value.split(None, 1)[1] if " " in value else "", ev, tls)
    yield from _tls_assets(path, tls)
    if not tls.protocols:
        yield ScanNote(
            scanner=SCANNER,
            message=(
                f"{path.name}: ssl_protocols isn't set, so nginx's default applies: TLSv1.2 and "
                "TLSv1.3 from 1.23.4, and TLSv1 and TLSv1.1 as well in older versions."
            ),
        )


def _apache(path: Path, text: str) -> Iterator[CryptoAsset | ScanNote]:
    tls = _Tls()
    for i, line in _statements(text):
        directive, _, value = line.partition(" ")
        d = directive.lower()
        ev = _evidence(path, i, line, "Apache httpd config")
        if d == "sslprotocol":
            versions: list[str] = []
            for token in value.split():
                t = token.lower()
                if t in ("all", "+all"):  # mod_ssl 2.4: every TLS version, SSLv3 excluded
                    versions = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
                elif t.startswith("-"):
                    versions = [v for v in versions if v.lower() != t[1:]]
                elif (v := TLS_VERSIONS.get(t.lstrip("+"))) and v not in versions:
                    versions.append(v)
            tls.protocols.extend((v, ev) for v in versions)
        elif d == "sslciphersuite":
            # an optional first argument names the protocol (SSLCipherSuite TLSv1.3 TLS_AES_…)
            _cipher_list(
                value.split(None, 1)[-1] if value.lower().startswith(("tlsv1.3", "ssl")) else value,
                ev,
                tls,
            )
        elif d == "sslopensslconfcmd" and value.split()[0].lower() in ("groups", "curves"):
            _group_list(value.split(None, 1)[1] if " " in value else "", ev, tls)
    yield from _tls_assets(path, tls)


def _tls_assets(path: Path, tls: _Tls) -> Iterator[CryptoAsset | ScanNote]:
    pq = any((g := _group(name)) is not None and g.post_quantum for name, _ in tls.groups)
    for proto, ev in tls.protocols:
        version = TLS_VERSIONS.get(proto.lower().lstrip("+"))
        if version is None:
            tls.unmapped.add(proto)
            continue
        alias, flags = version, []
        if version == "TLSv1.3" and not pq:
            alias, flags = "TLSv1.3-classical", ["no-pq-group"]
        yield _asset(proto, alias, "tls-protocol", ev, flags=flags)

    for name, ev in tls.groups:
        group = _group(name)
        if group is None:
            tls.unmapped.add(name)
            continue
        flags = [] if group.post_quantum or not pq else ["classical-fallback"]
        yield _asset(
            name,
            group.alias,
            "tls-key-exchange",
            ev,
            key_size=group.key_size,
            variant=group.name,
            flags=flags,
        )

    # One finding per algorithm and use, listing the suites that allow it (as for ELB policies).
    found: dict[tuple[str, str], tuple[list[str], set[str], Evidence, str | None]] = {}

    def add(
        alias: str,
        usage: str,
        suite: str,
        ev: Evidence,
        flags: Iterable[str] = (),
        variant: str | None = None,
    ) -> None:
        suites, fl, _, _ = found.setdefault((alias, usage), ([], set(), ev, variant))
        suites.append(suite)
        fl.update(flags)

    for suite, ev in tls.suites:
        try:
            parts = decompose(suite)
        except (ValueError, IndexError):
            tls.unmapped.add(suite)
            continue
        if parts.key_exchange is not None:
            add(
                parts.key_exchange,
                "tls-key-exchange",
                suite,
                ev,
                [f for f in parts.flags if f == "no-forward-secrecy"],
                "RSA key transport" if parts.key_exchange == "RSA" else None,
            )
            if parts.authentication and parts.key_exchange != "RSA":
                add(parts.authentication, "tls-authentication", suite, ev)
        add(
            parts.cipher_label,
            "tls-cipher",
            suite,
            ev,
            [f for f in parts.flags if f == "cbc-mode"],
            parts.cipher_label,
        )
        if parts.mac:
            add(parts.mac, "tls-mac", suite, ev)
    for (alias, usage), (suites, suite_flags, ev, variant) in found.items():
        ctx_ev = ev.model_copy(update={"context": {**ev.context, "suites": ", ".join(suites)}})
        yield _asset(suites[0], alias, usage, ctx_ev, flags=suite_flags, variant=variant)

    if tls.keywords:
        yield ScanNote(
            scanner=SCANNER,
            message=(
                f"{path.name}: the cipher list uses OpenSSL keywords "
                f"({', '.join(sorted(tls.keywords))}) that only the server's OpenSSL can expand. "
                "Named suites are listed; probe the live host to see every suite it accepts."
            ),
        )
    if tls.unmapped:
        yield ScanNote(
            scanner=SCANNER,
            message=(f"{path.name}: {', '.join(sorted(tls.unmapped))} not classified yet."),
        )


def _group(name: str) -> Group | None:
    key = name.lower()
    return _GROUPS.get(_GROUP_ALIASES.get(key, key))
