"""Suggest a fix for a code finding with Gemini (Google AI Studio, free tier).

The engine stays the source of truth: the prompt carries the classification (tier, threat,
replacement, NIST reference) and the model only rewrites the snippet around the flagged line.
Suggestions are advice, never applied automatically.
"""

from __future__ import annotations

import re
from typing import Any

from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from quantumtrace.core.models import Finding, Model, SourceType

SYSTEM = """\
You fix cryptography in source code so it survives quantum computers and is not misused today.

You get one finding from a scanner: the language, a snippet with the flagged line marked `>>`,
what was detected, and the scanner's classification with its recommended replacement. Rewrite
the snippet so the finding goes away.

Rules:
- Return the same lines as the snippet, rewritten. Keep indentation, names and structure; change
  only what the finding needs. Drop the `>>` marker and the line numbers.
- Pick by what the key does: ML-DSA (FIPS 204) for signing, ML-KEM (FIPS 203) for encryption
  or key exchange. When the snippet only generates a key, use "Other crypto in this file" to tell.
- Prefer the classification's replacement. Shor-exposed primitives (RSA, ECDSA, ECDH, DH, EdDSA)
  move to ML-KEM (FIPS 203) or ML-DSA (FIPS 204), or a hybrid (X25519MLKEM768) where the
  ecosystem lacks pure PQC. Grover-weakened ones move to AES-256-GCM, SHA-384 or stronger.
- Fix misuse in the same lines: ECB becomes an AEAD mode with a random nonce; non-cryptographic
  random generators become the language's CSPRNG; hard-coded keys come from the environment or a
  KMS. Never invent a secret value.
- Use only APIs that exist; when a library isn't imported yet, use it and say so in caveats.
  Go: ML-KEM is crypto/mlkem (Go 1.24+); the standard library has no ML-DSA, so use
  github.com/cloudflare/circl/sign/mldsa/mldsa65 (mldsa65.GenerateKey(rand.Reader)).
  Java: KeyPairGenerator.getInstance("ML-DSA-65") / "ML-KEM-768" on JDK 24+, else Bouncy Castle.
  Python: the cryptography package has no ML-DSA or ML-KEM; use liboqs-python (oqs.Signature,
  oqs.KeyEncapsulation) or pqcrypto.
- If the whole fix lies outside the snippet (e.g. only an import changes), return the snippet
  unchanged and put the change in caveats.
- If a correct fix needs changes outside the snippet (callers, key storage, wire format, stored
  data), keep the snippet change minimal and list what else must change in caveats.
"""


class FixUnavailable(Exception):
    """The model produced no usable fix (refusal, truncated output)."""


class _Draft(BaseModel):
    """What the model returns (structured output)."""

    summary: str = Field(description="One sentence: what the fix changes")
    fixed_snippet: str = Field(description="The snippet's lines, rewritten")
    explanation: str = Field(description="Why the original is exposed and why the fix holds")
    caveats: list[str] = Field(description="What else must change; empty when nothing")


class FixSuggestion(Model):
    """An AI-written fix for one code finding. Review before applying."""

    finding_id: str
    summary: str
    original_snippet: str
    fixed_snippet: str
    changed: bool = Field(
        description="False when these lines stay as they are and the fix is elsewhere (caveats)"
    )
    snippet_start_line: int
    explanation: str
    caveats: list[str] = Field(default_factory=list)
    model: str = Field(description="Model that wrote the fix (may be a fallback model)")


def fixable(finding: Finding) -> bool:
    e = finding.asset.evidence
    return e.source_type == SourceType.CODE and bool(e.snippet)


def same_file(finding: Finding, findings: list[Finding]) -> list[tuple[int, Finding]]:
    """Other crypto the scan found in the finding's file, by line: tells the model what a
    generated key is used for (signing vs key exchange) when the snippet doesn't show it."""
    here = finding.asset.evidence.location
    out = {
        (e.line or 0, f.asset.observed, f.asset.usage): (e.line or 0, f)
        for f in findings
        for e in f.asset.all_evidence
        if e.location == here and f.id != finding.id
    }
    return sorted(out.values(), key=lambda x: x[0])[:12]


def build_prompt(finding: Finding, related: list[tuple[int, Finding]] | None = None) -> str:
    a, c, e = finding.asset, finding.classification, finding.asset.evidence
    first = e.snippet_start_line or e.line or 1
    width = len(str(first + (e.snippet or "").count("\n")))
    lines = [
        f"{'>>' if first + i == e.line else '  '} {str(first + i).rjust(width)} | {text}"
        for i, text in enumerate((e.snippet or "").split("\n"))
    ]
    facts = {
        "Language": e.context.get("language"),
        "File": e.location,
        "Detected": a.observed,
        "Variant": a.variant,
        "Key size": f"{a.key_size} bits" if a.key_size else None,
        "Usage": a.usage,
        "Flags": ", ".join(a.flags) or None,
        "Classification": f"{c.name} ({c.tier.value}, threat: {c.threat.value}"
        + (", broken classically" if c.classically_broken else "")
        + ")",
        "Replace with": c.replacement,
        "Standard": c.nist_reference,
        "Why": c.rationale,
    }
    head = "\n".join(f"{k}: {v}" for k, v in facts.items() if v)
    others = "".join(
        f"\n- line {line}: {f.asset.observed} ({f.classification.name}, usage: {f.asset.usage})"
        for line, f in related or []
    )
    if others:
        head += "\n\nOther crypto in this file (context, not part of the snippet):" + others
    return f"{head}\n\nSnippet:\n```\n" + "\n".join(lines) + "\n```"


def suggest_fix(
    finding: Finding,
    *,
    api_key: str,
    model: str,
    thinking: str | None = None,
    related: list[tuple[int, Finding]] | None = None,
    client: Any = None,
) -> FixSuggestion:
    """Ask Gemini for a fix. Raises FixUnavailable or google.genai.errors.APIError."""
    gemini = client or genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=50_000))
    response = gemini.models.generate_content(
        model=model,
        contents=build_prompt(finding, related),
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM,
            response_mime_type="application/json",
            response_schema=_Draft,
            # Gemini 3 Flash thinks by default; "low" halves the slow cases at no visible cost.
            thinking_config=types.ThinkingConfig(
                thinking_level=types.ThinkingLevel(thinking.upper())
            )
            if thinking
            else None,
        ),
    )
    draft = response.parsed
    if not isinstance(draft, _Draft):
        reason = response.candidates[0].finish_reason if response.candidates else None
        if reason == types.FinishReason.MAX_TOKENS:
            raise FixUnavailable("The model's answer was cut short.")
        raise FixUnavailable("The model returned no usable fix.")
    e = finding.asset.evidence
    fixed = _strip_gutter(draft.fixed_snippet.strip("\n"))
    changed = not _same_code(fixed, e.snippet or "")
    if not changed and not draft.caveats:
        # Smaller models sometimes describe a fix without making it.
        raise FixUnavailable("The model described a fix but didn't change the code.")
    return FixSuggestion(
        finding_id=finding.id,
        summary=draft.summary,
        original_snippet=e.snippet or "",
        fixed_snippet=fixed,
        changed=changed,
        snippet_start_line=e.snippet_start_line or e.line or 1,
        explanation=draft.explanation,
        caveats=draft.caveats,
        model=response.model_version or model,
    )


_GUTTER = re.compile(r"^(?:>>|  )? *\d+ \| ?")


def _strip_gutter(code: str) -> str:
    """Drop the `>> 12 | ` prefixes the prompt shows, when a model copies them into its answer."""
    lines = code.split("\n")
    if all(_GUTTER.match(x) for x in lines if x.strip()):
        return "\n".join(_GUTTER.sub("", x, count=1) for x in lines)
    return code


def _same_code(a: str, b: str) -> bool:
    """Equal ignoring indentation and blank lines (a re-indent is not a fix)."""

    def lines(s: str) -> list[str]:
        return [x.strip() for x in s.splitlines() if x.strip()]

    return lines(a) == lines(b)
