"""Map raw CryptoAssets to risk classifications using rules/algorithms.yaml."""

from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources
from typing import Any

import yaml
from pydantic import Field

from quantumtrace.core.models import (
    Classification,
    CryptoAsset,
    Finding,
    Model,
    Primitive,
    QuantumThreat,
    RiskTier,
)


class Rule(Model):
    id: str
    name: str
    primitive: Primitive
    threat: QuantumThreat
    tier: RiskTier
    classically_broken: bool = False
    oid: str | None = None
    nist_reference: str | None = None
    replacement: str | None = None
    classical_security_bits: int | None = None
    nist_quantum_level: int | None = None
    rationale: str
    aliases: list[str] = Field(default_factory=list)


def normalise(name: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", name.upper())


class Classifier:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules
        self._index: dict[str, Rule] = {}
        for rule in rules:
            for key in {normalise(rule.id), normalise(rule.name), *map(normalise, rule.aliases)}:
                existing = self._index.get(key)
                if existing is not None and existing.id != rule.id:
                    raise ValueError(f"alias {key!r} maps to both {existing.id} and {rule.id}")
                self._index[key] = rule

    def lookup(self, algorithm: str, key_size: int | None = None) -> Rule | None:
        if key_size is not None:
            rule = self._index.get(normalise(f"{algorithm}{key_size}"))
            if rule is not None:
                return rule
        return self._index.get(normalise(algorithm))

    def classify(self, asset: CryptoAsset) -> Finding:
        rule = self.lookup(asset.algorithm, asset.key_size)
        if rule is None:
            classification = Classification(
                rule_id="unknown",
                name=asset.algorithm,
                primitive=Primitive.OTHER,
                threat=QuantumThreat.UNKNOWN,
                tier=RiskTier.UNKNOWN,
                rationale=f"No rule matches {asset.algorithm!r}; add it to rules/algorithms.yaml.",
            )
        else:
            classification = Classification(
                rule_id=rule.id,
                name=rule.name,
                primitive=rule.primitive,
                threat=rule.threat,
                tier=rule.tier,
                classically_broken=rule.classically_broken,
                nist_reference=rule.nist_reference,
                replacement=rule.replacement,
                oid=rule.oid,
                classical_security_bits=rule.classical_security_bits
                or classical_bits(rule.id, asset.key_size),
                nist_quantum_level=rule.nist_quantum_level,
                rationale=rule.rationale,
            )
        return Finding(asset=asset, classification=classification)


# NIST SP 800-57 Part 1 Table 2 (comparable strengths)
_FFC_IFC_BITS = ((15360, 256), (7680, 192), (3072, 128), (2048, 112), (1024, 80))


def classical_bits(rule_id: str, key_size: int | None) -> int | None:
    """Classical security strength for size-dependent asymmetric primitives."""
    if not key_size:
        return None
    if rule_id in ("rsa", "rsa-1024", "dh", "dsa"):
        return next((bits for size, bits in _FFC_IFC_BITS if key_size >= size), None)
    if rule_id in ("ecdsa", "ecdh", "eddsa"):
        return key_size // 2
    return None


def load_rules(data: dict[str, Any] | None = None) -> list[Rule]:
    if data is None:
        text = resources.files("quantumtrace.rules").joinpath("algorithms.yaml").read_text()
        data = yaml.safe_load(text)
    return [Rule.model_validate(r) for r in data["rules"]]


@lru_cache(maxsize=1)
def default_classifier() -> Classifier:
    return Classifier(load_rules())
