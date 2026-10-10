from __future__ import annotations

import pytest

from quantumtrace.rules.tls import decompose


@pytest.mark.parametrize(
    ("suite", "kx", "auth", "label", "mac", "flags"),
    [
        ("ECDHE-RSA-AES128-GCM-SHA256", "ECDHE", "RSA", "AES-128-GCM", None, ()),
        ("ECDHE-ECDSA-AES256-SHA", "ECDHE", "ECDSA", "AES-256-CBC", "HMAC-SHA1", ("cbc-mode",)),
        ("ECDHE-RSA-AES128-SHA256", "ECDHE", "RSA", "AES-128-CBC", "HMAC-SHA256", ("cbc-mode",)),
        ("AES128-SHA", "RSA", "RSA", "AES-128-CBC", "HMAC-SHA1", ("no-forward-secrecy", "cbc-mode")),
        ("AES256-GCM-SHA384", "RSA", "RSA", "AES-256-GCM", None, ("no-forward-secrecy",)),
        ("DES-CBC3-SHA", "RSA", "RSA", "3DES-CBC", "HMAC-SHA1", ("no-forward-secrecy", "cbc-mode")),
        ("TLS_AES_256_GCM_SHA384", None, None, "AES-256-GCM", None, ()),
        ("TLS_AES_128_CCM_SHA256", None, None, "AES-128-CCM", None, ()),
        ("TLS_CHACHA20_POLY1305_SHA256", None, None, "ChaCha20-Poly1305", None, ()),
        ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", "AES-128-GCM", None, ()),
        ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "RSA", "ChaCha20-Poly1305", None, ()),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES-CBC", "HMAC-SHA1",
         ("no-forward-secrecy", "cbc-mode")),
        ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "RSA", "AES-256-CBC", "HMAC-SHA1",
         ("no-forward-secrecy", "cbc-mode")),
    ],
)  # fmt: skip
def test_decompose(
    suite: str, kx: str | None, auth: str | None, label: str, mac: str | None,
    flags: tuple[str, ...],
) -> None:  # fmt: skip
    p = decompose(suite)
    assert (p.key_exchange, p.authentication, p.cipher_label, p.mac, p.flags) == (
        kx, auth, label, mac, flags,
    )  # fmt: skip


def test_tls13_suites_are_never_cbc() -> None:
    for s in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"):
        assert decompose(s).aead and "cbc-mode" not in decompose(s).flags
