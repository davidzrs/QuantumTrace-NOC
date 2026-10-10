"""Domain models shared by every scanner, adapter (API/CLI) and exporter.

These pydantic models are the public contract: the OpenAPI schema (and therefore the
TypeScript SDK used by the web app and extensions) is generated from them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Model(BaseModel):
    """Base for API-facing models: defaulted fields are still always present in responses,
    so the generated TypeScript types mark them as required."""

    model_config = ConfigDict(json_schema_serialization_defaults_required=True)


class RiskTier(StrEnum):
    CRITICAL = "critical"  # Shor-vulnerable asymmetric crypto (RSA, DSA, ECDSA, ECDH, DH, EdDSA)
    MEDIUM = "medium"  # Grover-weakened symmetric crypto/hashes (AES-128, 3DES, SHA-1, ...)
    SAFE = "safe"  # Quantum-resilient (AES-256, SHA-384+, ML-KEM, ML-DSA, SLH-DSA)
    UNKNOWN = "unknown"  # Detected but not (yet) classifiable


class QuantumThreat(StrEnum):
    SHOR = "shor"
    GROVER = "grover"
    NONE = "none"
    UNKNOWN = "unknown"


class Primitive(StrEnum):
    SIGNATURE = "signature"
    PKE = "pke"
    KEM = "kem"
    KEY_AGREEMENT = "key-agree"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    AE = "ae"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    PROTOCOL = "protocol"
    OTHER = "other"


class SourceType(StrEnum):
    CLOUD = "cloud"
    CODE = "code"
    NETWORK = "network"


class Exposure(StrEnum):
    INTERNET = "internet"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class Observation(StrEnum):
    """How strongly the input proves the primitive is in use."""

    NEGOTIATED = "negotiated"  # seen agreed in live traffic
    CONFIGURED = "configured"  # explicitly set (KMS key spec, listener protocol)
    IN_CODE = "in-code"  # called in source code
    PERMITTED = "permitted"  # allowed by a policy; may or may not be negotiated
    OFFERED = "offered"  # offered by one side only (e.g. ClientHello without reply)


class Confidence(StrEnum):
    """How sure the scanner is about the identification (not about the risk)."""

    HIGH = "high"  # read directly: API call with literal args, config field, handshake bytes
    MEDIUM = "medium"  # inferred: key size from elsewhere in the file, heuristic pattern
    LOW = "low"  # guessed or unresolvable (unknown policy, missing handshake half)


class Evidence(Model):
    """Where an asset was observed. Enough to trace a finding back to its origin."""

    source_type: SourceType
    location: str = Field(description="File path, cloud ARN or network flow (src:port -> dst:port)")
    line: int | None = None
    snippet: str | None = Field(
        default=None, description="Source lines around `line` (code evidence), dedented"
    )
    snippet_start_line: int | None = Field(
        default=None, description="Line number of the snippet's first line"
    )
    context: dict[str, str] = Field(default_factory=dict)


class CryptoAsset(Model):
    """A raw detection emitted by a scanner, before classification."""

    observed: str = Field(description="Value exactly as seen in the source, e.g. 'RSA_2048'")
    algorithm: str = Field(description="Canonical name or alias resolvable by the classifier")
    variant: str | None = Field(
        default=None, description="Precise form, e.g. AES-128-GCM, X25519, P-256 (display/CBOM)"
    )
    key_size: int | None = None
    usage: str | None = Field(default=None, description="e.g. SIGN_VERIFY, tls-key-exchange")
    observation: Observation = Observation.CONFIGURED
    confidence: Confidence = Confidence.HIGH
    exposure: Exposure = Exposure.UNKNOWN
    flags: list[str] = Field(default_factory=list)
    evidence: Evidence
    more_evidence: list[Evidence] = Field(
        default_factory=list,
        description="Further places with the identical asset (e.g. repeat sessions to one server)",
    )

    @property
    def all_evidence(self) -> list[Evidence]:
        return [self.evidence, *self.more_evidence]


class Classification(Model):
    rule_id: str
    name: str
    primitive: Primitive
    threat: QuantumThreat
    tier: RiskTier
    classically_broken: bool = False
    nist_reference: str | None = None
    replacement: str | None = None
    oid: str | None = None
    classical_security_bits: int | None = None
    nist_quantum_level: int | None = Field(
        default=None, ge=0, le=6, description="NIST PQC security category; 0 = broken by Shor"
    )
    rationale: str


class ScanNote(Model):
    """Something a scanner could not see or verify. Shown to users so gaps are explicit."""

    scanner: str
    message: str


class Finding(Model):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    asset: CryptoAsset
    classification: Classification


class TierCounts(Model):
    critical: int = 0
    medium: int = 0
    safe: int = 0
    unknown: int = 0


class RiskScore(Model):
    value: float = Field(ge=0, le=100, description="0 = quantum-ready, 100 = maximum exposure")
    grade: str
    counts: TierCounts


class ScanResult(Model):
    id: str = Field(default_factory=lambda: uuid4().hex)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    targets: list[str]
    scanners: list[str]
    findings: list[Finding]
    score: RiskScore
    limitations: list[ScanNote] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ScanSummary(Model):
    """One row of scan history: enough to list scans without loading their findings."""

    id: str
    created_at: datetime
    targets: list[str]
    findings: int
    score: RiskScore

    @classmethod
    def of(cls, result: ScanResult) -> ScanSummary:
        return cls(
            id=result.id,
            created_at=result.created_at,
            targets=result.targets,
            findings=len(result.findings),
            score=result.score,
        )
