"""Golden tests for the source-code scanner against samples/sample-repos."""

from __future__ import annotations

from pathlib import Path

import pytest

from quantumtrace.core.classifier import load_misuse
from quantumtrace.core.engine import run_scan
from quantumtrace.core.models import Confidence, Finding, Observation, ScanResult
from quantumtrace.scanners.code.common import is_secret_name
from tests.conftest import summarise

REPOS = "sample-repos"


@pytest.fixture(scope="module")
def result(samples: Path) -> ScanResult:
    return run_scan([samples / REPOS])


def in_file(result: ScanResult, name: str) -> list[Finding]:
    # the CLI reports native paths, so compare with forward slashes on every platform
    return [f for f in result.findings if Path(f.asset.evidence.location).as_posix().endswith(name)]


def tiers(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.classification.tier.value, f.classification.name) for f in findings}


def test_whole_repo_has_no_unknowns_or_errors(result: ScanResult) -> None:
    assert result.errors == []
    assert result.scanners == ["source-code"]  # requirements.txt and go.mod are left alone
    assert result.score.counts.unknown == 0


def test_findings_carry_line_numbers_and_snippets(result: ScanResult) -> None:
    assert result.findings
    for f in result.findings:
        assert f.asset.evidence.line, f
        ev = f.asset.evidence
        assert ev.snippet and ev.snippet_start_line and ev.line
        hit = ev.snippet.split("\n")[ev.line - ev.snippet_start_line]
        assert hit.strip() in Path(ev.location).read_text().split("\n")[ev.line - 1]
        assert f.asset.observation is Observation.IN_CODE


# --- Python ------------------------------------------------------------------------------
def test_python_rsa1024_and_sha1(samples: Path) -> None:
    result = run_scan([samples / REPOS / "python/license_token.py"])
    names = {name for _, name, _ in summarise(result)}
    assert {"RSA-1024", "SHA-1"} <= names
    [keygen] = [f for f in result.findings if f.asset.usage == "key-generation"]
    assert keygen.asset.evidence.line == 6


def test_python_ecb_mode_hardcoded_key_and_weak_rng(result: ScanResult) -> None:
    findings = in_file(result, "python/report_export.py")
    [aes] = [f for f in findings if f.classification.name == "AES-128"]
    assert {"ecb-mode", "hardcoded-key"} <= set(aes.asset.flags)
    assert aes.asset.variant == "AES-128-ECB"
    assert ("medium", "Non-cryptographic RNG") in tiers(findings)


def test_python_aesgcm_with_32_byte_key_is_safe(result: ScanResult) -> None:
    assert ("safe", "AES-256") in tiers(in_file(result, "python/secure_transfer.py"))


def test_python_hashlib_and_hmac(result: ScanResult) -> None:
    assert ("medium", "MD5") in tiers(in_file(result, "python/legacy_accounts.py"))
    assert tiers(in_file(result, "python/artifact_manifest.py")) == {
        ("safe", "SHA-384"),
        ("safe", "HMAC-SHA256"),
    }


def test_python_ed25519_is_shor_vulnerable(result: ScanResult) -> None:
    assert ("critical", "EdDSA") in tiers(in_file(result, "python/webhook_signature.py"))


@pytest.mark.parametrize(
    "name",
    ["python/webhook_signature.py", "java/DeviceAttestation.java", "go/agent-enrollment/main.go"],
)
def test_ed25519_generate_and_sign_are_reported_alike_in_every_language(
    result: ScanResult, name: str
) -> None:
    eddsa = [f for f in in_file(result, name) if f.classification.name == "EdDSA"]
    assert sorted(f.asset.usage or "" for f in eddsa) == ["key-generation", "signature"]


def test_python_ed25519_sign_is_a_method_call_on_the_key(result: ScanResult) -> None:
    by_usage = {f.asset.usage: f for f in in_file(result, "python/webhook_signature.py")}
    assert by_usage["key-generation"].asset.evidence.line == 5  # Ed25519PrivateKey.generate()
    assert by_usage["signature"].asset.evidence.line == 10  # private_key.sign(payload)
    assert by_usage["signature"].asset.confidence is Confidence.MEDIUM  # key type inferred


def test_python_sign_with_padding_is_not_read_as_ed25519(tmp_path: Path) -> None:
    code = """from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding

def sign_both(rsa_key, data):
    edkey = ed25519.Ed25519PrivateKey.generate()
    return rsa_key.sign(data, padding.PSS(padding.MGF1(hashes.SHA256()), 32), hashes.SHA256())
"""
    names = {
        (f.classification.name, f.asset.usage) for f in scan_source(tmp_path, "s.py", code).findings
    }
    assert ("EdDSA", "signature") not in names
    assert ("EdDSA", "key-generation") in names


# --- Java --------------------------------------------------------------------------------
def test_java_sha1_with_rsa(samples: Path) -> None:
    result = run_scan([samples / REPOS / "java/ReceiptSigner.java"])
    assert {("critical", "RSA-1024"), ("medium", "SHA-1")} <= {
        (t, n) for t, n, _ in summarise(result)
    }


def test_java_md5(samples: Path) -> None:
    result = run_scan([samples / REPOS / "java/CustomerDirectory.java"])
    assert ("medium", "MD5") in {(t, n) for t, n, _ in summarise(result)}


def test_java_constants_resolved(result: ScanResult) -> None:
    # TRANSFORMATION = "AES/ECB/PKCS5Padding" + 16-byte literal key
    [ecb] = [f for f in in_file(result, "java/BatchExporter.java") if f.asset.usage == "encryption"]
    assert ecb.classification.name == "AES-128"
    assert "ecb-mode" in ecb.asset.flags
    # TRANSFORMATION = "AES/GCM/NoPadding" + KEY_BITS = 256
    [gcm] = in_file(result, "java/SessionCipher.java")
    assert (gcm.classification.name, gcm.asset.flags) == ("AES-256", [])


def test_java_pbkdf2(result: ScanResult) -> None:
    assert tiers(in_file(result, "java/IdentityVault.java")) == {("safe", "PBKDF2")}


# --- Go ----------------------------------------------------------------------------------
def test_go_ed25519_is_shor_vulnerable(samples: Path) -> None:
    result = run_scan([samples / REPOS / "go/agent-enrollment/main.go"])
    assert ("critical", "EdDSA") in {(t, n) for t, n, _ in summarise(result)}


def test_go_rsa_1024_signing(result: ScanResult) -> None:
    findings = in_file(result, "go/invoice-service/main.go")
    assert {("critical", "RSA-1024"), ("medium", "SHA-1")} <= tiers(findings)


def test_go_raw_block_encrypt_is_ecb_and_math_rand_is_weak(result: ScanResult) -> None:
    findings = in_file(result, "go/batch-pipeline/main.go")
    [aes] = [f for f in findings if f.asset.usage == "encryption"]
    assert "ecb-mode" in aes.asset.flags
    assert ("medium", "Non-cryptographic RNG") in tiers(findings)


def test_go_hand_rolled_pbkdf2_detected(result: ScanResult) -> None:
    [kdf] = [f for f in in_file(result, "go/auth-gateway/main.go") if f.asset.usage == "kdf"]
    assert kdf.classification.name == "PBKDF2"
    assert "hand-rolled-crypto" in kdf.asset.flags
    assert "deriveKey" in kdf.asset.observed
    # the HMAC calls inside it are its PRF: named in the finding, not reported again
    assert kdf.asset.variant == "PBKDF2-HMAC-SHA256 (hand-rolled)"
    assert not [f for f in in_file(result, "go/auth-gateway/main.go") if f.asset.usage == "mac"]


def test_hand_rolled_pbkdf2_with_sha1_still_reports_the_weak_prf(tmp_path: Path) -> None:
    code = """package auth

import (
	"crypto/hmac"
	"crypto/sha1"
)

func derive(password, salt []byte, iter int) []byte {
	var out []byte
	for block := 1; block <= 1; block++ {
		u := hmac.New(sha1.New, password).Sum(salt)
		t := append([]byte{}, u...)
		for i := 1; i < iter; i++ {
			u = hmac.New(sha1.New, password).Sum(u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out
}
"""
    findings = scan_source(tmp_path, "derive.go", code).findings
    summary = {(f.classification.name, f.asset.usage) for f in findings}
    assert summary == {("PBKDF2", "kdf"), ("SHA-1", "kdf-prf")}
    [kdf] = [f for f in findings if f.asset.usage == "kdf"]
    assert kdf.asset.variant == "PBKDF2-HMAC-SHA1 (hand-rolled)"


def test_go_hmac_hash_not_double_counted(result: ScanResult) -> None:
    findings = in_file(result, "go/config-sync/main.go")
    assert tiers(findings) == {("safe", "SHA-384"), ("safe", "HMAC-SHA256")}


def test_precise_variants_and_confidence(result: ScanResult) -> None:
    def one(name: str, usage: str) -> Finding:
        [f] = [f for f in in_file(result, name) if f.asset.usage == usage]
        return f

    assert one("python/webhook_signature.py", "signature").asset.variant == "Ed25519"
    assert one("python/secure_transfer.py", "encryption").asset.variant == "AES-256-GCM"
    assert one("java/SessionCipher.java", "encryption").asset.variant == "AES-256-GCM"
    assert one("go/telemetry-relay/main.go", "encryption").asset.variant == "AES-256-GCM"
    assert one("java/IdentityVault.java", "kdf").asset.variant == "PBKDF2-HMAC-SHA256"
    assert one("python/member_credentials.py", "kdf").asset.variant == "PBKDF2-HMAC-SHA256"
    # the PRF inside PBKDF2HMAC(algorithm=hashes.SHA256()) is not a standalone hash
    assert not [
        f for f in in_file(result, "python/member_credentials.py") if f.asset.usage == "hash"
    ]
    # Go: key generation and signing are separate uses of Ed25519
    assert {f.asset.usage for f in in_file(result, "go/agent-enrollment/main.go")} == {
        "key-generation", "signature",
    }  # fmt: skip
    # read directly from a literal argument
    assert one("java/ReceiptSigner.java", "key-generation").asset.confidence is Confidence.HIGH
    # key size carried over from KeyPairGenerator.initialize(1024) to the signature call
    assert one("java/ReceiptSigner.java", "signature").asset.confidence is Confidence.MEDIUM
    # KeyGenerator.init(KEY_BITS) pins the AES size; a file-level literal is only a hint
    assert one("java/SessionCipher.java", "encryption").asset.confidence is Confidence.HIGH
    assert one("python/report_export.py", "encryption").asset.confidence is Confidence.MEDIUM
    assert one("go/auth-gateway/main.go", "kdf").asset.confidence is Confidence.MEDIUM


# --- Misuse, grouping, positions -----------------------------------------------------------
@pytest.mark.parametrize(
    ("file", "flag"),
    [
        ("python/report_export.py", "hardcoded-key"),
        ("java/BatchExporter.java", "ecb-mode"),
        ("go/batch-pipeline/main.go", "ecb-mode"),
        ("go/auth-gateway/main.go", "hand-rolled-crypto"),
    ],
)
def test_misuse_makes_finding_classically_broken(result: ScanResult, file: str, flag: str) -> None:
    [f] = [f for f in in_file(result, file) if flag in f.asset.flags]
    assert f.classification.classically_broken
    assert f.classification.tier.value != "critical"  # the quantum tier is unchanged
    assert load_misuse()[flag] in f.classification.rationale


def test_repeat_lines_become_more_evidence_with_snippets(result: ScanResult) -> None:
    [sha1] = [f for f in in_file(result, "go/invoice-service/main.go") if f.asset.usage == "hash"]
    assert [e.line for e in sha1.asset.all_evidence] == [17, 22]
    for ev in sha1.asset.all_evidence:
        assert ev.snippet and "sha1.Sum" in ev.snippet
        assert "also_lines" not in ev.context


def test_evidence_has_columns_of_the_match(result: ScanResult) -> None:
    for f in result.findings:
        for ev in f.asset.all_evidence:
            assert ev.column and ev.line
            if ev.end_column is not None:
                line = Path(ev.location).read_text().split("\n")[ev.line - 1]
                assert line[ev.column - 1 : ev.end_column - 1] == f.asset.observed


def scan_source(tmp_path: Path, name: str, code: str) -> ScanResult:
    path = tmp_path / name
    path.write_text(code)
    return run_scan([path])


def test_gcm_and_cbc_in_one_file_are_two_findings(tmp_path: Path) -> None:
    code = (
        "import javax.crypto.Cipher;\n"
        "class C {\n"
        '  byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes();\n'
        '  Cipher a = Cipher.getInstance("AES/GCM/NoPadding");\n'
        '  Cipher b = Cipher.getInstance("AES/CBC/PKCS5Padding");\n'
        "}\n"
    )
    result = scan_source(tmp_path, "C.java", code)
    assert sorted(f.asset.variant or "" for f in result.findings) == ["AES-256-CBC", "AES-256-GCM"]
    assert {f.asset.evidence.line for f in result.findings} == {4, 5}


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("comments.py", "import hashlib\n# hashlib.md5(x) was the old way\nx = 1  # hashlib.sha1(\n"),
        ("docstring.py", 'import hashlib\n\ndef f():\n    """Replaces hashlib.md5(data)."""\n'),
        ("strings.py", 'import hashlib\nlog("call hashlib.md5() to hash")\n'),
        ("defs.py", "def HKDF(salt):\n    return salt\n\nclass PBKDF2HMAC(object):\n    pass\n"),
        ("attrs.py", "class W:\n    def k(self):\n        return self.rsa.generate_private_key(1)\n"),
        ("Comments.java", "class C {\n  // Cipher.getInstance(\"DES\")\n  /* MessageDigest"
         ".getInstance(\"MD5\") */\n}\n"),
        ("comments.go", 'package main\nimport "crypto/md5"\n// md5.Sum(b) is gone\n'
         "/* md5.New() */\nvar s = `md5.Sum(x)`\n"),
    ],
)  # fmt: skip
def test_comments_strings_and_names_are_not_findings(tmp_path: Path, name: str, code: str) -> None:
    assert scan_source(tmp_path, name, code).findings == []


def test_masking_keeps_real_calls_and_their_lines(tmp_path: Path) -> None:
    code = (
        "import hashlib\n"
        '"""Module docstring mentioning hashlib.sha1(x)."""\n'
        "# hashlib.md5()\n"
        'URL = "http://x#frag"  # trailing comment\n'
        'h = hashlib.new("md5")\n'
        "q = '''\nhashlib.sha1(\n'''\n"
        "d = hashlib.sha256(b'#')\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "e = cryptography.hazmat.primitives.hashes.SHA384()\n"
    )
    result = scan_source(tmp_path, "keep.py", code)
    found = sorted((f.classification.name, f.asset.evidence.line) for f in result.findings)
    assert found == [("MD5", 5), ("SHA-256", 9), ("SHA-384", 11)]


# --- Weak RNG: always reported, confident only next to a secret ----------------------------
@pytest.mark.parametrize(
    "file", ["python/report_export.py", "java/BatchExporter.java", "go/batch-pipeline/main.go"]
)
def test_weak_rng_making_a_session_token_is_high_confidence(result: ScanResult, file: str) -> None:
    [rng] = [f for f in in_file(result, file) if f.asset.usage == "rng"]
    assert rng.asset.confidence is Confidence.HIGH
    assert "secret-context" in rng.asset.flags
    assert is_secret_name(rng.asset.evidence.context["secret_hint"])


@pytest.mark.parametrize(
    ("name", "secret"),
    [
        ("session_token", True), ("apiKey", True), ("nonceBytes", True), ("getIV", True),
        ("AUTH_HEADER", True), ("api_keys", True), ("issueOTP", True),
        ("private", False), ("monkey", False), ("keyboard", False), ("author", False),
        ("cores", False),
    ],
)  # fmt: skip
def test_secret_names_match_whole_words(name: str, secret: bool) -> None:
    assert is_secret_name(name) is secret


@pytest.mark.parametrize(
    ("name", "code", "hint"),
    [
        # no clue anywhere: still a finding, but low confidence
        ("colour.py", "import random\ncores = ['red', 'blue']\ncor = random.choice(cores)\n", None),
        # whole words only: `monkey` has no `key`, `private` has no `iv`
        ("monkey.py", "import random\n\ndef monkey_patch():\n    return random.random()\n", None),
        ("Private.java", "import java.util.Random;\nclass C {\n"
         "  private int x = new Random().nextInt();\n}\n", None),
        # a function defined above doesn't enclose a module-level call
        ("module.py", "import random\n\ndef make_nonce():\n    pass\n\n"
         "cor = random.choice([1, 2])\n", None),
        ("pick.go", 'package main\nimport "math/rand"\nfunc pickColour() int {\n'
         "\treturn rand.Intn(3)\n}\n", None),
        # (a) the call's line
        ("line.py", "import random\napi_key = random.getrandbits(128)\n", "api_key"),
        # (b) the variable the statement assigns, when the call sits on a later line
        ("target.py", "import random\nreset_token = ''.join(\n"
         "    random.choice('abc') for _ in range(32)\n)\n", "reset_token"),
        # (c) the enclosing function or method, through nested blocks
        ("func.py", "import random\n\ndef make_nonce():\n    x = 1\n    return random.random()\n",
         "make_nonce"),
        ("Salt.java", "import java.util.Random;\nclass C {\n  byte[] newSalt() {\n"
         "    if (true) {\n      return new byte[] { (byte) new Random().nextInt() };\n    }\n"
         "    return null;\n  }\n}\n", "newSalt"),
        ("otp.go", 'package main\nimport "math/rand"\nfunc (s *Server) issueOTP() int {\n'
         "\tif true {\n\t\treturn rand.Intn(999999)\n\t}\n\treturn 0\n}\n", "issueOTP"),
    ],
)  # fmt: skip
def test_weak_rng_confidence_follows_secret_clues(
    tmp_path: Path, name: str, code: str, hint: str | None
) -> None:
    [rng] = scan_source(tmp_path, name, code).findings
    assert rng.asset.usage == "rng"
    assert rng.asset.confidence is (Confidence.HIGH if hint else Confidence.LOW)
    assert ("secret-context" in rng.asset.flags) is (hint is not None)
    assert rng.asset.evidence.context.get("secret_hint") == hint


def test_weak_rng_repeats_keep_the_strongest_clue(tmp_path: Path) -> None:
    code = (
        "import random\n"
        "cor = random.choice([1, 2])\n"
        "\n"
        "def session_id():\n"
        "    return random.getrandbits(64)\n"
    )
    [rng] = scan_source(tmp_path, "mixed.py", code).findings
    assert rng.asset.confidence is Confidence.HIGH
    assert "secret-context" in rng.asset.flags
    assert [e.line for e in rng.asset.all_evidence] == [2, 5]
    assert "secret_hint" not in rng.asset.evidence.context
    assert rng.asset.more_evidence[0].context["secret_hint"] == "session_id"


@pytest.mark.parametrize("name", ["KEY_ALIAS", "keyId", "SIGNING_KEY_NAME", "CACHE_KEY_PREFIX"])
def test_a_string_that_names_a_key_is_not_a_hardcoded_key(tmp_path: Path, name: str) -> None:
    # 16 characters, like an AES-128 key, but it's the key's alias in a keystore
    code = f"""
class Vault {{
    private static final String {name} = "card-data-key-01";
    byte[] seal(java.security.Key key, byte[] pan) throws Exception {{
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        return c.doFinal(pan);
    }}
}}
"""
    [aes] = scan_source(tmp_path, "Vault.java", code).findings
    assert "hardcoded-key" not in aes.asset.flags
    assert not aes.classification.classically_broken
    assert aes.asset.key_size is None  # the size isn't in the source


@pytest.mark.parametrize("name", ["EXPORT_KEY", "FILE_ENCRYPTION_KEY", "HEADER_SIGNING_KEY"])
def test_a_key_literal_is_still_a_hardcoded_key(tmp_path: Path, name: str) -> None:
    # a word before "key" says what the key is for; only words after it point at a key
    code = f'{name} = b"0123456789abcdef"\n'
    code += "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
    code += f"def seal(payload, nonce):\n    return AESGCM({name}).encrypt(nonce, payload, None)\n"
    [aes] = scan_source(tmp_path, "export.py", code).findings
    assert "hardcoded-key" in aes.asset.flags and aes.asset.key_size == 128
    assert aes.classification.classically_broken
