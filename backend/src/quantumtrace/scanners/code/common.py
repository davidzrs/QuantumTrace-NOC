"""Shared plumbing for the per-language source scanners: line numbers, dedupe, key-size hints."""

from __future__ import annotations

import bisect
import re
import textwrap
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from quantumtrace.core.classifier import normalise
from quantumtrace.core.models import Confidence, CryptoAsset, Evidence, Observation, SourceType
from quantumtrace.scanners.code.lexer import lex

# KEY_LEN = 32, KEY_BITS = 256, keyLen = 32, KEY_LEN_BITS = 256 (Python / Java / Go constants)
_KEY_CONST = re.compile(
    r"(?i)\b(\w*key\w*?(?:len|size|bits|length)\w*)\s*(?::=|=)\s*(\d[\d_]*)\s*[;\n)]"
)
# EXPORT_KEY = b"...", byte[] KEY = "...".getBytes(...), exportKey = []byte("...")
_KEY_LITERAL = re.compile(
    r"(?i)\b(\w*key\w*)\s*(?::=|=)\s*(?:b|\[\]byte\()?([\"'])([^\"'\n]{1,64})\2"
)
SNIPPET_CONTEXT = 2  # lines shown above and below the hit
SNIPPET_WIDTH = 200
# A rule match preceded by `x.` is an attribute of some object (`self.rsa.generate_private_key`),
# not the library, unless the dotted chain starts at one of these package roots.
PACKAGE_ROOTS = {"cryptography", "Crypto", "Cryptodome", "javax", "java", "golang", "crypto"}
_DEFINITION = re.compile(r"(?:\bdef|\bfunc|\bclass|\binterface|\bstruct)\s+$")
_CONFIDENCE_ORDER = (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)

# A weak RNG is a real risk when its output is a secret. One of these words inside an
# identifier next to the call (session_token, apiKey, nonceBytes) is the clue.
SECRET_WORDS = frozenset({
    "token", "key", "secret", "password", "passwd", "pwd", "nonce", "salt", "otp", "session",
    "iv", "seed", "csrf", "auth",
})  # fmt: skip
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")
# snake_case and camelCase words: session_token -> session, token; getIVBytes -> get, IV, Bytes
_NAME_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_PY_DEF = re.compile(r"\s*(?:async\s+)?def\s+(\w+)")
_GO_FUNC = re.compile(r"\bfunc\s*(?:\([^)]*\)\s*)?(\w+)\s*(?:\[[^\]]*\]\s*)?\(")
_JAVA_METHOD = re.compile(r"(\w+)\s*\([^()]*\)\s*(?:throws\s+[\w.,\s]+)?$")
_JAVA_NOT_METHODS = {"if", "for", "while", "switch", "catch", "synchronized", "try", "return"}


def is_secret_name(identifier: str) -> bool:
    """Whether a whole word of the identifier names a secret: `api_keys` does, `monkey` and
    `private` don't."""
    words = (w.lower() for w in _NAME_WORD.findall(identifier))
    return any(w in SECRET_WORDS or w.removesuffix("s") in SECRET_WORDS for w in words)


def _go_function(header: str) -> str | None:
    """`func (s *Server) issueOTP() int` -> issueOTP; a func literal has no name."""
    m = _GO_FUNC.search(header)
    return m.group(1) if m else None


def _java_method(header: str) -> str | None:
    """`public static byte[] sessionToken()` -> sessionToken; not `if (...)` or `new X() {`."""
    m = _JAVA_METHOD.search(header)
    if m is None or m.group(1) in _JAVA_NOT_METHODS:
        return None
    return None if re.search(r"\bnew\s+[\w.<>]*$", header[: m.start()]) else m.group(1)


@dataclass
class SourceFile:
    """One source file. `text` has comments blanked out (offsets unchanged) and is what rules
    match against; `raw` is the file as written, used for snippets."""

    path: Path
    language: str
    text: str
    raw: str = field(init=False)
    _strings: list[tuple[int, int]] = field(init=False)
    _assets: dict[tuple[str, int | None, str, str | None], CryptoAsset] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        lexed = lex(self.text, self.language)
        self.raw, self.text, self._strings = self.text, lexed.text, lexed.strings

    @classmethod
    def load(cls, path: Path, language: str) -> SourceFile:
        return cls(path, language, path.read_text(errors="replace"))

    def line_of(self, pos: int) -> int:
        return self.text.count("\n", 0, pos) + 1

    def column_of(self, pos: int) -> int:
        return pos - self.text.rfind("\n", 0, pos)

    def ignored(self, pos: int) -> bool:
        """A match that isn't a library call: inside a string literal, the name of a definition
        (`def HKDF(`), or an attribute of an object (`self.rsa.generate_private_key`)."""
        k = bisect.bisect_right(self._strings, (pos, len(self.text))) - 1
        if k >= 0 and self._strings[k][0] <= pos < self._strings[k][1]:
            return True
        line_start = self.text.rfind("\n", 0, pos) + 1
        if _DEFINITION.search(self.text, line_start, pos):
            return True
        if pos == 0 or self.text[pos - 1] != ".":
            return False
        chain = re.search(r"([A-Za-z_][\w.]*)\.$", self.text[line_start:pos])
        return chain is None or chain.group(1).split(".")[0] not in PACKAGE_ROOTS

    def emit(
        self,
        pos: int,
        observed: str,
        algorithm: str,
        usage: str,
        *,
        key_size: int | None = None,
        flags: tuple[str, ...] | list[str] = (),
        context: dict[str, str] | None = None,
        variant: str | None = None,
        confidence: Confidence = Confidence.HIGH,
    ) -> None:
        """Record an asset. Repeats of the same (algorithm, size, usage, variant) in a file become
        one asset: the first place is `evidence`, later lines go to `more_evidence`."""
        if self.ignored(pos):
            return
        line = self.line_of(pos)
        variant = variant or variant_name(algorithm, key_size, flags, context)
        key = (normalise(algorithm), key_size, usage, variant)
        evidence = self._evidence(pos, observed, context)
        if (existing := self._assets.get(key)) is not None:
            if all(e.line != line for e in existing.all_evidence):
                existing.more_evidence.append(evidence)
            existing.flags = sorted({*existing.flags, *flags})
            existing.confidence = max(existing.confidence, confidence, key=_CONFIDENCE_ORDER.index)
            return
        self._assets[key] = CryptoAsset(
            observed=observed,
            algorithm=algorithm,
            variant=variant,
            key_size=key_size,
            usage=usage,
            observation=Observation.IN_CODE,
            confidence=confidence,
            flags=sorted(set(flags)),
            evidence=evidence,
        )

    def emit_weak_rng(self, pos: int, observed: str) -> None:
        """A non-cryptographic RNG call. Always reported, but high confidence only when a
        secret-looking name sits next to it; otherwise it may just pick a colour."""
        hint = self.secret_hint(pos)
        self.emit(pos, observed, "non-csprng", "rng",
                  flags=["secret-context"] if hint else [],
                  context={"secret_hint": hint} if hint else None,
                  confidence=Confidence.HIGH if hint else Confidence.LOW)  # fmt: skip

    def secret_hint(self, pos: int) -> str | None:
        """The first identifier that marks the value made at `pos` as a secret, looking at the
        call's line, then the variable its statement assigns, then the enclosing function."""
        line = self.line_of(pos)
        starts = self._line_starts
        line_end = starts[line] - 1 if line < len(starts) else len(self._code)
        names = _IDENTIFIER.findall(self._code, starts[line - 1], line_end)
        names += self._assigned_names(self._statement_start(line), pos)
        if (function := self._enclosing_function(pos)) is not None:
            names.append(function)
        return next((n for n in names if is_secret_name(n)), None)

    @cached_property
    def _code(self) -> str:
        """`text` with string literals blanked too (newlines kept): only code is left."""
        out = list(self.text)
        for start, end in self._strings:
            out[start:end] = [c if c == "\n" else " " for c in out[start:end]]
        return "".join(out)

    @cached_property
    def _line_starts(self) -> list[int]:
        return [0, *(m.end() for m in re.finditer("\n", self._code))]

    @cached_property
    def _line_depths(self) -> list[int]:
        """How many brackets are still open at the start of each line. Braces only count in
        Python (dicts, sets); in Java and Go they open blocks, which end statements."""
        opening, closing = ("([{", ")]}") if self.language == "python" else ("([", ")]")
        depths, depth = [0], 0
        for c in self._code:
            if c == "\n":
                depths.append(depth)
            elif c in opening:
                depth += 1
            elif c in closing:
                depth = max(0, depth - 1)
        return depths

    def _statement_start(self, line: int) -> int:
        """Offset of the line where the statement holding `line` starts, walking back over
        lines that continue an open bracket (a call split across lines)."""
        while line > 1 and self._line_depths[line - 1] > 0:
            line -= 1
        return self._line_starts[line - 1]

    def _assigned_names(self, start: int, pos: int) -> list[str]:
        """Identifiers left of the statement's assignment (`reset_token = ''.join(`)."""
        code, depth = self._code, 0
        for i in range(start, pos):
            c = code[i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == "=" and depth == 0 and code[i + 1 : i + 2] != "=" and code[i - 1 : i] not in (
                "=", "!", "<", ">",
            ):  # fmt: skip
                return _IDENTIFIER.findall(code, start, i)
        return []

    def _enclosing_function(self, pos: int) -> str | None:
        code = self._code
        if self.language == "python":
            stmt = self._statement_start(self.line_of(pos))
            indent = len(code[stmt:pos]) - len(code[stmt:pos].lstrip(" \t"))
            for above in reversed(code[:stmt].split("\n")):
                if not above.strip():
                    continue
                level = len(above) - len(above.lstrip(" \t"))
                if level < indent:
                    if m := _PY_DEF.match(above):
                        return m.group(1)
                    indent = level
                if indent == 0:
                    return None
            return None
        # Java / Go: walk out through the unclosed braces until one opens a function body
        depth = 0
        for i in range(pos - 1, -1, -1):
            if code[i] == "}":
                depth += 1
            elif code[i] == "{" and depth:
                depth -= 1
            elif code[i] == "{":
                header = code[max(code.rfind(c, 0, i) for c in ";{}") + 1 : i].strip()
                name = _go_function(header) if self.language == "go" else _java_method(header)
                if name is not None:
                    return name
        return None

    def _evidence(self, pos: int, observed: str, context: dict[str, str] | None) -> Evidence:
        line = self.line_of(pos)
        column = self.column_of(pos)
        snippet, snippet_start = self.snippet(line)
        # `observed` is sometimes a resolved constant that isn't on the line: no end column then
        end = column + len(observed) if self.raw.startswith(observed, pos) else None
        return Evidence(
            source_type=SourceType.CODE,
            location=str(self.path),
            line=line,
            column=column,
            end_column=end,
            snippet=snippet,
            snippet_start_line=snippet_start,
            context={"language": self.language, "file": str(self.path), **(context or {})},
        )

    def snippet(self, line: int) -> tuple[str, int]:
        """The hit line with up to SNIPPET_CONTEXT lines either side, blank edges trimmed and
        common indentation removed. Returns the text and the number of its first line."""
        lines = [x.rstrip("\r")[:SNIPPET_WIDTH] for x in self.raw.split("\n")]
        start, end = max(1, line - SNIPPET_CONTEXT), min(len(lines), line + SNIPPET_CONTEXT)
        while start < line and not lines[start - 1].strip():
            start += 1
        while end > line and not lines[end - 1].strip():
            end -= 1
        return textwrap.dedent("\n".join(lines[start - 1 : end])), start

    @property
    def assets(self) -> list[CryptoAsset]:
        return list(self._assets.values())

    def symmetric_key_hint(self) -> tuple[int | None, bool]:
        """Best-effort symmetric key size in bits for this file, and whether it is hard-coded.

        Prefers a key literal (its byte length is the key size) over KEY_LEN/KEY_BITS constants.
        """
        for m in _KEY_LITERAL.finditer(self.text):
            n = len(m.group(3).encode())
            if n in (16, 24, 32):
                return n * 8, True
        for m in _KEY_CONST.finditer(self.text):
            value = int(m.group(2).replace("_", ""))
            bits = value if "bit" in m.group(1).lower() else value * 8
            if bits in (128, 192, 256):
                return bits, False
        return None, False

    def constant(self, name: str) -> str | None:
        """Resolve `NAME = "value"` / `NAME = 123` declared in this file."""
        m = re.search(rf"\b{re.escape(name)}\s*(?::=|=)\s*\"?([\w./\-]+)\"?", self.text)
        return m.group(1) if m else None

    def int_value(self, token: str) -> int | None:
        token = token.strip()
        if token.replace("_", "").isdigit():
            return int(token.replace("_", ""))
        resolved = self.constant(token)
        return (
            int(resolved.replace("_", ""))
            if resolved and resolved.replace("_", "").isdigit()
            else None
        )


CURVE_NAMES = {
    "SECP256R1": "P-256", "P256": "P-256", "PRIME256V1": "P-256", "SECP384R1": "P-384",
    "P384": "P-384", "SECP521R1": "P-521", "P521": "P-521", "SECP256K1": "secp256k1",
    "X25519": "X25519", "X448": "X448",
}  # fmt: skip


def variant_name(
    algorithm: str, key_size: int | None, flags: tuple[str, ...] | list[str],
    context: dict[str, str] | None,
) -> str | None:  # fmt: skip
    """Precise display/CBOM name: Ed25519 (not EdDSA), ECDSA P-256, X25519, AES-128-ECB."""
    if algorithm in ("Ed25519", "Ed448"):
        return algorithm
    curve = (context or {}).get("curve", "").upper()
    if curve and algorithm in ("ECDSA", "ECDH"):
        name = CURVE_NAMES.get(curve, curve)
        return name if name in ("X25519", "X448") else f"{algorithm} {name}"
    if algorithm == "AES" and key_size:
        mode = "ECB" if "ecb-mode" in flags else (context or {}).get("mode", "")
        return f"AES-{key_size}" + (f"-{mode}" if mode else "")
    return None
