"""AWS cloud-posture scanner: KMS key inventory, ACM certificates, ELB listeners.

Accepts JSON exports shaped like the AWS APIs (see samples/cloud-posture). Files are scanned
together so certificates can inherit the exposure (internet-facing / internal) of the load
balancer listeners that use them.
"""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from quantumtrace.core.models import (
    Confidence,
    CryptoAsset,
    Evidence,
    Exposure,
    Observation,
    ScanNote,
    SourceType,
)
from quantumtrace.rules.tls import CLASSICAL_TLS13_GROUPS, decompose

KIND_KEYS = {"Keys": "kms", "Certificates": "acm", "LoadBalancers": "elb"}
PLAINTEXT_PROTOCOLS = {"HTTP", "TCP", "UDP", "TCP_UDP"}
# Certificate key type -> the TLS 1.2 suite authentication it can perform
SUITE_AUTH = {"RSA": "RSA", "EC": "ECDSA"}


@lru_cache(maxsize=1)
def elb_policies() -> dict[str, dict[str, list[str]]]:
    text = resources.files("quantumtrace.rules").joinpath("aws_elb_policies.yaml").read_text()
    policies: dict[str, dict[str, list[str]]] = yaml.safe_load(text)["policies"]
    return policies


def _kind(path: Path) -> tuple[str, dict[str, Any]] | None:
    if path.suffix.lower() != ".json":
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    for key, kind in KIND_KEYS.items():
        if isinstance(data.get(key), list):
            return kind, data
    return None


@dataclass
class _Agg:
    """Primitives shared by many suites in one policy collapse into one finding."""

    suites: list[str] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)
    macs: set[str] = field(default_factory=set)
    variant: str | None = None


class AwsCloudPostureScanner:
    name = "aws-cloud-posture"
    source_type = SourceType.CLOUD

    def accepts(self, path: Path) -> bool:
        return _kind(path) is not None

    def scan(self, paths: Sequence[Path]) -> Iterable[CryptoAsset | ScanNote]:
        docs: dict[str, list[tuple[Path, dict[str, Any]]]] = {"kms": [], "acm": [], "elb": []}
        for p in paths:
            if (k := _kind(p)) is not None:
                docs[k[0]].append((p, k[1]))

        listener_exposure: dict[str, Exposure] = {}
        for _, data in docs["elb"]:
            for lb in data["LoadBalancers"]:
                exposure = _scheme_exposure(lb.get("Scheme"))
                for li in lb.get("Listeners", []):
                    listener_exposure[li.get("ListenerArn", "")] = exposure

        known_certs: set[str] = set()
        cert_keys: dict[str, str] = {}  # certificate ARN -> key type (RSA / EC)
        for path, data in docs["kms"]:
            yield from self._kms(path, data)
        for path, data in docs["acm"]:
            known_certs.update(
                c.get("CertificateArn", "") for c in data["Certificates"] if c.get("KeyAlgorithm")
            )
            cert_keys.update(_certificate_keys(data))
            yield from self._acm(path, data, listener_exposure)
        referenced: set[str] = set()
        for path, data in docs["elb"]:
            yield from self._elb(path, data, referenced, cert_keys)

        if missing := sorted(referenced - known_certs):
            yield ScanNote(
                scanner=self.name,
                message=(
                    f"{len(missing)} listener certificate(s) are referenced only by ARN, so their "
                    "key and signature algorithms are unknown. Include `aws acm "
                    "describe-certificate` output (like acm_certificates.json) to classify them."
                ),
            )
        if docs["elb"]:
            yield ScanNote(
                scanner=self.name,
                message=(
                    "Load balancer findings are what each TLS security policy permits, not what "
                    "clients negotiate. Pair with a packet capture to see actual sessions."
                ),
            )

    # ------------------------------------------------------------------ KMS
    def _kms(self, path: Path, data: dict[str, Any]) -> Iterable[CryptoAsset | ScanNote]:
        unspecified = 0
        for i, key in enumerate(data["Keys"]):
            # CustomerMasterKeySpec is the deprecated name of KeySpec, same value
            field_name = "KeySpec" if key.get("KeySpec") else "CustomerMasterKeySpec"
            spec: str = key.get(field_name, "")
            if not spec:  # `aws kms list-keys` gives only ids: nothing to classify
                unspecified += 1
                continue
            usage: str = key.get("KeyUsage", "")
            algorithm, key_size, curve = _kms_key_spec(spec, usage)
            flags = []
            if key.get("KeyState") not in (None, "Enabled"):
                flags.append(f"key-state:{key['KeyState']}")
            if key.get("KeyRotationStatus") == "DISABLED":
                flags.append("rotation-disabled")
            if key.get("Origin") == "EXTERNAL":
                flags.append("imported-key-material")
            context = {
                "alias": key.get("AliasName", ""),
                "description": key.get("Description", ""),
                "origin": key.get("Origin", ""),
                "file": str(path),
                "json_path": f"$.Keys[{i}].{field_name}",
            }
            if curve:
                context["curve"] = curve
            evidence = Evidence(
                source_type=SourceType.CLOUD, location=key.get("KeyArn", str(path)), context=context
            )
            yield CryptoAsset(
                observed=spec,
                algorithm=algorithm,
                variant=_variant(algorithm, key_size, curve),
                key_size=key_size,
                usage=usage,
                flags=flags,
                evidence=evidence,
            )
            for j, alg in enumerate(key.get("SigningAlgorithms", [])):
                if hash_alg := _hash_from(alg):
                    ctx = {**context, "json_path": f"$.Keys[{i}].SigningAlgorithms[{j}]"}
                    yield CryptoAsset(
                        observed=alg,
                        algorithm=hash_alg,
                        usage="signature-digest",
                        evidence=evidence.model_copy(update={"context": ctx}),
                    )
        if unspecified:
            yield ScanNote(
                scanner=self.name,
                message=(
                    f"{path.name}: {unspecified} KMS key(s) have no KeySpec (`aws kms list-keys` "
                    "lists only ids), so their algorithms are unknown. Include `aws kms "
                    "describe-key` output to classify them."
                ),
            )

    # ------------------------------------------------------------------ ACM
    def _acm(
        self, path: Path, data: dict[str, Any], listener_exposure: dict[str, Exposure]
    ) -> Iterable[CryptoAsset | ScanNote]:
        unspecified = 0
        for i, cert in enumerate(data["Certificates"]):
            key_alg: str = cert.get("KeyAlgorithm", "")
            if not key_alg:  # e.g. DescribeListenerCertificates: only ARN and IsDefault
                unspecified += 1
                continue
            in_use = cert.get("InUseBy", [])
            exposures = {listener_exposure.get(arn, Exposure.UNKNOWN) for arn in in_use}
            exposure = (
                Exposure.INTERNET
                if Exposure.INTERNET in exposures
                else Exposure.INTERNAL
                if Exposure.INTERNAL in exposures
                else Exposure.UNKNOWN
            )
            flags = ["imported-certificate"] if cert.get("Type") == "IMPORTED" else []
            context = {
                "domain": cert.get("DomainName", ""),
                "not_after": cert.get("NotAfter", ""),
                "in_use_by": ", ".join(in_use),
                "file": str(path),
            }
            evidence = Evidence(
                source_type=SourceType.CLOUD,
                location=cert.get("CertificateArn", str(path)),
                context=context,
            )

            def at(field_name: str, ev: Evidence = evidence, idx: int = i) -> Evidence:
                ctx = {**ev.context, "json_path": f"$.Certificates[{idx}].{field_name}"}
                return ev.model_copy(update={"context": ctx})

            algorithm, key_size, curve = _kms_key_spec(key_alg, "SIGN_VERIFY")
            yield CryptoAsset(
                observed=key_alg,
                algorithm=algorithm,
                variant=_variant(algorithm, key_size, curve),
                key_size=key_size,
                usage="certificate-key",
                exposure=exposure,
                flags=flags,
                evidence=at("KeyAlgorithm"),
            )
            sig: str = cert.get("SignatureAlgorithm", "")
            if sig:
                yield CryptoAsset(
                    observed=sig,
                    algorithm=sig,
                    usage="certificate-signature",
                    exposure=exposure,
                    evidence=at("SignatureAlgorithm"),
                )
                if hash_alg := _hash_from(sig):
                    yield CryptoAsset(
                        observed=sig,
                        algorithm=hash_alg,
                        usage="certificate-signature-digest",
                        exposure=exposure,
                        evidence=at("SignatureAlgorithm"),
                    )
        if unspecified:
            yield ScanNote(
                scanner=self.name,
                message=(
                    f"{path.name}: {unspecified} certificate(s) have no KeyAlgorithm (a "
                    "DescribeListenerCertificates export lists only ARNs), so their keys are "
                    "unknown. Include `aws acm describe-certificate` output to classify them."
                ),
            )

    # ------------------------------------------------------------------ ELB
    def _elb(
        self, path: Path, data: dict[str, Any], referenced: set[str], cert_keys: dict[str, str]
    ) -> Iterable[CryptoAsset]:
        for i, lb in enumerate(data["LoadBalancers"]):
            exposure = _scheme_exposure(lb.get("Scheme"))
            for j, li in enumerate(lb.get("Listeners", [])):
                protocol = li.get("Protocol", "")
                certs = [c["CertificateArn"] for c in li.get("Certificates", [])
                         if "CertificateArn" in c]  # fmt: skip
                referenced.update(certs)
                listener_path = f"$.LoadBalancers[{i}].Listeners[{j}]"
                evidence = Evidence(
                    source_type=SourceType.CLOUD,
                    location=li.get("ListenerArn", lb.get("LoadBalancerArn", str(path))),
                    context={
                        "load_balancer": lb.get("LoadBalancerName", ""),
                        "scheme": lb.get("Scheme", ""),
                        "protocol": protocol,
                        "port": str(li.get("Port", "")),
                        "ssl_policy": li.get("SslPolicy", ""),
                        "file": str(path),
                        "json_path": f"{listener_path}.Protocol",
                    },
                )
                if protocol in PLAINTEXT_PROTOCOLS:
                    if not _redirects_to_https(li):
                        yield CryptoAsset(
                            observed=f"{protocol}:{li.get('Port')}",
                            algorithm="PLAINTEXT",
                            usage="transport",
                            observation=Observation.CONFIGURED,
                            exposure=exposure,
                            evidence=evidence,
                        )
                    continue
                ctx = {**evidence.context, "json_path": f"{listener_path}.SslPolicy"}
                # several certificates (SNI) widen the choice; one missing from the export
                # leaves the listener's key types unknown, so every suite stays
                key_types = None
                if certs and all(arn in cert_keys for arn in certs):
                    key_types = sorted({cert_keys[arn] for arn in certs})
                    ctx["certificate_key"] = ", ".join(key_types)
                yield from _tls_policy_assets(
                    li.get("SslPolicy", ""),
                    exposure,
                    evidence.model_copy(update={"context": ctx}),
                    key_types,
                )


def _tls_policy_assets(
    policy_name: str,
    exposure: Exposure,
    evidence: Evidence,
    cert_keys: Collection[str] | None = None,
) -> Iterable[CryptoAsset]:
    policy = elb_policies().get(policy_name)
    if policy is None:
        yield CryptoAsset(
            observed=policy_name,
            algorithm=policy_name or "unknown-ssl-policy",
            usage="tls-policy",
            confidence=Confidence.LOW,
            exposure=exposure,
            flags=["unknown-ssl-policy"],
            evidence=evidence,
        )
        return

    groups = list(policy.get("groups") or [])
    pq_groups = [g for g in groups if "MLKEM" in g.upper() or "KYBER" in g.upper()]

    for proto in policy["protocols"]:
        flags: list[str] = []
        alias = proto
        if proto == "TLSv1.3" and not pq_groups:
            alias, flags = "TLSv1.3-classical", ["no-pq-group"]
        yield CryptoAsset(
            observed=proto,
            algorithm=alias,
            usage="tls-protocol",
            observation=Observation.PERMITTED,
            exposure=exposure,
            flags=flags,
            evidence=evidence,
        )

    seen: dict[tuple[str, str], _Agg] = {}

    def add(alias: str, usage: str, suite: str, flags: Iterable[str] = (),
            variant: str | None = None, mac: str | None = None) -> None:  # fmt: skip
        agg = seen.setdefault((alias, usage), _Agg(variant=variant))
        agg.suites.append(suite)
        agg.flags.update(flags)
        if mac:
            agg.macs.add(mac)

    signable = None if cert_keys is None else {SUITE_AUTH[k] for k in cert_keys}
    has_tls13 = False
    for suite in policy["ciphers"]:
        parts = decompose(suite)
        # A TLS 1.2 suite authenticates with the listener's certificate: ECDHE-ECDSA needs an
        # EC key, ECDHE-RSA and static RSA an RSA key. TLS 1.3 suites work with either.
        if signable is not None and parts.authentication not in (None, *signable):
            continue
        if parts.key_exchange is None:
            has_tls13 = True
        else:
            kx_flags = [f for f in parts.flags if f == "no-forward-secrecy"]
            add(parts.key_exchange, "tls-key-exchange", suite, kx_flags)
            # static RSA uses the certificate key for both; report authentication separately
            # only for (EC)DHE suites, where it is a distinct signature operation
            if parts.authentication and parts.key_exchange != "RSA":
                add(parts.authentication, "tls-authentication", suite)
        # one finding per cipher *and mode*: AES-128-GCM and AES-128-CBC are different exposures
        cipher_key = parts.cipher_label
        add(cipher_key, "tls-cipher", suite, [f for f in parts.flags if f == "cbc-mode"],
            variant=parts.cipher_label, mac=parts.mac)  # fmt: skip
        if parts.mac:
            add(parts.mac, "tls-mac", suite)

    if has_tls13:
        for group in groups or CLASSICAL_TLS13_GROUPS:
            # classical curve names are ambiguous (secp256r1 is also an ECDSA curve)
            alias = group if group in pq_groups else "ECDHE"
            add(alias, "tls-key-exchange", f"group:{group}")
        if not pq_groups:
            seen[("ECDHE", "tls-key-exchange")].flags.add("no-pq-group")
        elif ("ECDHE", "tls-key-exchange") in seen:
            seen[("ECDHE", "tls-key-exchange")].flags.add("classical-fallback")

    for (alias, usage), agg in seen.items():
        ctx = {**evidence.context, "suites": ", ".join(agg.suites)}
        if agg.macs:
            ctx["record_macs"] = ", ".join(sorted(agg.macs))
        yield CryptoAsset(
            observed=agg.suites[0],
            algorithm=alias,
            variant=agg.variant,
            usage=usage,
            observation=Observation.PERMITTED,
            exposure=exposure,
            flags=sorted(agg.flags),
            evidence=evidence.model_copy(update={"context": ctx}),
        )


def _certificate_keys(data: dict[str, Any]) -> dict[str, str]:
    """ARN -> key type (RSA / EC) of each certificate whose KeyAlgorithm is readable."""
    keys: dict[str, str] = {}
    for cert in data["Certificates"]:
        key_alg = cert.get("KeyAlgorithm", "").upper()
        kind = "RSA" if key_alg.startswith("RSA_") else "EC" if key_alg.startswith("EC") else None
        if kind and cert.get("CertificateArn"):
            keys[cert["CertificateArn"]] = kind
    return keys


def _scheme_exposure(scheme: str | None) -> Exposure:
    return {"internet-facing": Exposure.INTERNET, "internal": Exposure.INTERNAL}.get(
        scheme or "", Exposure.UNKNOWN
    )


def _redirects_to_https(listener: dict[str, Any]) -> bool:
    return any(
        a.get("Type") == "redirect" and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
        for a in listener.get("DefaultActions", [])
    )


_CURVE_BITS = {"P256": 256, "P384": 384, "P521": 521, "PRIME256V1": 256, "SECP384R1": 384,
               "SECP521R1": 521, "P256K1": 256}  # fmt: skip


def _kms_key_spec(spec: str, usage: str) -> tuple[str, int | None, str | None]:
    """Translate KMS KeySpec / ACM KeyAlgorithm into (algorithm alias, key size, curve)."""
    s = spec.upper()
    if m := re.fullmatch(r"RSA_(\d+)", s):
        return "RSA", int(m.group(1)), None
    if s == "ECC_NIST_EDWARDS25519":  # KMS Ed25519 signing key, not a Weierstrass curve
        return "Ed25519", None, None
    if s.startswith(("ECC_", "EC_")):
        curve = s.split("_")[-1]
        alg = "ECDH" if usage == "KEY_AGREEMENT" else "ECDSA"
        return alg, _CURVE_BITS.get(curve), curve
    if s.startswith("HMAC_"):
        return s, None, None
    if s.startswith("ML_DSA"):
        return "ML-DSA", None, None
    return spec, None, None  # SYMMETRIC_DEFAULT, SM2, ... resolved via aliases


def _hash_from(alg: str) -> str | None:
    s = alg.upper().replace("-", "_")
    for token in ("SHA_512", "SHA_384", "SHA_256", "SHA512", "SHA384", "SHA256", "SHA1", "MD5"):
        if token in s:
            return token.replace("_", "-") if "_" in token else token
    return None


_CURVE_NAMES = {"P256": "P-256", "PRIME256V1": "P-256", "P384": "P-384", "SECP384R1": "P-384",
                "P521": "P-521", "SECP521R1": "P-521", "P256K1": "secp256k1"}  # fmt: skip


def _variant(algorithm: str, key_size: int | None, curve: str | None) -> str | None:
    if algorithm == "SYMMETRIC_DEFAULT":  # AWS KMS default symmetric key = AES-256-GCM
        return "AES-256-GCM"
    if algorithm == "Ed25519":
        return algorithm
    if curve:
        return f"{algorithm} {_CURVE_NAMES.get(curve, curve)}"
    if algorithm == "RSA" and key_size:
        return f"RSA-{key_size}"
    return None
