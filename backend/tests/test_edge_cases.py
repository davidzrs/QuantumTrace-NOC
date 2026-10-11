"""Edge cases beyond the organisers' samples: what the scanners should flag, and what they shouldn't.

The plain tests guard behaviour that is easy to break (comments, strings, constants, safe choices).
The `xfail(strict=True)` ones are known gaps, each with the reason: once a fix makes one pass,
pytest reports it as XPASS and fails, so the marker comes off and it becomes a normal test.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import ScanResult


def scan(tmp_path: Path, files: dict[str, str]) -> ScanResult:
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source).lstrip())
    return run_scan([tmp_path])


def found(result: ScanResult) -> set[tuple[str, str]]:
    """(tier, algorithm name) pairs."""
    return {(f.classification.tier.value, f.classification.name) for f in result.findings}


# ---------------------------------------------------------------- what must not be flagged


def test_crypto_only_named_in_comments_strings_and_docstrings_is_not_flagged(
    tmp_path: Path,
) -> None:
    result = scan(
        tmp_path,
        {
            "notes.py": '''
                """We used hashlib.md5() for ids and RSA.generate(1024) for keys. Both are gone."""
                # hashlib.sha1(b"legacy") was removed in v2
                MESSAGE = "hashlib.md5() is deprecated, use hashlib.sha384()"

                def explain() -> str:
                    return "rsa.generate_private_key(public_exponent=65537, key_size=1024)"
            ''',
            "Notes.java": """
                class Notes {
                    // Cipher.getInstance("DES") was the old way
                    /* MessageDigest.getInstance("MD5") too */
                    static final String HELP = "Never call MessageDigest.getInstance(\\"MD5\\")";
                }
            """,
        },
    )
    assert result.findings == []


def test_commented_out_server_config_is_ignored(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "sshd_config": """
                #KexAlgorithms diffie-hellman-group1-sha1
                #Ciphers 3des-cbc
                KexAlgorithms mlkem768x25519-sha256
            """,
            "nginx/site.conf": """
                server {
                    # ssl_protocols SSLv3 TLSv1;
                    ssl_protocols TLSv1.3;
                }
            """,
        },
    )
    commented_out = {"diffie-hellman-group1-sha1", "3des-cbc", "SSLv3", "TLSv1"}
    assert not {f.asset.observed for f in result.findings} & commented_out
    assert ("safe", "X25519MLKEM768") in found(result)


@pytest.mark.xfail(
    strict=True,
    reason="Gap: any `random`/`math/rand` call is classically broken, and scoring ignores its low "
    "confidence, so a shuffle or retry jitter alone weighs as much as a critical finding.",
)
def test_rng_for_games_and_jitter_does_not_drag_the_score_down(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "game.py": """
                import random

                def shuffle_deck(deck: list[str]) -> list[str]:
                    random.shuffle(deck)
                    return deck

                def retry_delay_ms() -> int:
                    return random.randint(50, 150)
            """,
            "backoff.go": """
                package backoff

                import (
                    "math/rand"
                    "time"
                )

                func Jitter(base time.Duration) time.Duration {
                    return base + time.Duration(rand.Intn(100))*time.Millisecond
                }
            """,
        },
    )
    assert result.score.grade == "A", result.score


# ---------------------------------------------------------------- what must be found


def test_key_size_held_in_a_constant_across_a_multiline_call(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "keys.py": """
                from cryptography.hazmat.primitives.asymmetric import rsa

                KEY_BITS = 1024

                def make_key():
                    return rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=KEY_BITS,
                    )
            """,
        },
    )
    [key] = result.findings
    assert (key.classification.tier.value, key.asset.key_size) == ("critical", 1024)


def test_java_algorithm_held_in_a_constant(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "Vault.java": """
                import java.security.MessageDigest;
                import javax.crypto.Cipher;

                class Vault {
                    private static final String TRANSFORM = "DES/ECB/PKCS5Padding";
                    private static final String DIGEST = "SHA-1";

                    Cipher cipher() throws Exception { return Cipher.getInstance(TRANSFORM); }
                    MessageDigest digest() throws Exception {
                        return MessageDigest.getInstance(DIGEST);
                    }
                }
            """,
        },
    )
    by_name = {f.classification.name: f for f in result.findings}
    assert set(by_name) == {"DES", "SHA-1"}
    assert "ecb-mode" in by_name["DES"].asset.flags


def test_strong_and_post_quantum_choices_stay_safe(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "Safe.java": """
                import java.security.MessageDigest;
                import javax.crypto.Cipher;
                import javax.crypto.KeyGenerator;

                class Safe {
                    byte[] digest(byte[] in) throws Exception {
                        return MessageDigest.getInstance("SHA-384").digest(in);
                    }
                    Cipher cipher() throws Exception {
                        KeyGenerator kg = KeyGenerator.getInstance("AES");
                        kg.init(256);
                        return Cipher.getInstance("AES/GCM/NoPadding");
                    }
                }
            """,
            "sshd_config": """
                KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com
                Ciphers aes256-gcm@openssh.com
            """,
        },
    )
    assert result.findings
    assert {tier for tier, _ in found(result)} == {"safe"}, found(result)


@pytest.mark.xfail(
    strict=True,
    reason="Gap: Python rules match `hashlib.md5(` literally, so `import hashlib as hl` and "
    "`from hashlib import sha1` hide the call.",
)
def test_python_hash_through_an_alias_or_a_from_import(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "ids.py": """
                import hashlib as hl
                from hashlib import sha1

                def fingerprint(data: bytes) -> str:
                    return hl.md5(data).hexdigest()

                def legacy_id(data: bytes) -> str:
                    return sha1(data).hexdigest()
            """,
        },
    )
    assert {("medium", "MD5"), ("medium", "SHA-1")} <= found(result)


@pytest.mark.xfail(
    strict=True,
    reason="Gap: Go rules match the package's own name (`md5.Sum`), so a renamed import "
    '(`m "crypto/md5"`) hides the call.',
)
def test_go_hash_through_a_renamed_import(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "sum.go": """
                package sum

                import m "crypto/md5"

                func Sum(b []byte) [16]byte { return m.Sum(b) }
            """,
        },
    )
    assert ("medium", "MD5") in found(result)


@pytest.mark.xfail(
    strict=True,
    reason="Gap: no rule for JWT libraries, so PyJWT signing with RS256 (RSA, Shor) goes unseen.",
)
def test_jwt_signed_with_rs256(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "auth.py": """
                import jwt

                def issue(private_key: str) -> str:
                    return jwt.encode({"sub": "42"}, private_key, algorithm="RS256")
            """,
        },
    )
    assert ("critical", "RSA") in found(result)


@pytest.mark.xfail(
    strict=True,
    reason="Gap: no rule for Python's `ssl` module or Go's `tls.Config`, so code that pins "
    "TLS 1.0 or a 3DES suite goes unseen (server configs are covered, code isn't).",
)
def test_tls_settings_pinned_in_code(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "client.py": """
                import ssl

                def legacy_context() -> ssl.SSLContext:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                    ctx.set_ciphers("DES-CBC3-SHA")
                    return ctx
            """,
            "server.go": """
                package server

                import "crypto/tls"

                func Config() *tls.Config {
                    return &tls.Config{MinVersion: tls.VersionTLS10}
                }
            """,
        },
    )
    tls10 = [f for f in result.findings if f.classification.name == "TLS 1.0"]
    assert {Path(f.asset.evidence.location).name for f in tls10} == {"client.py", "server.go"}
    assert ("medium", "3DES") in found(result)
