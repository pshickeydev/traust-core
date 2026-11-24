"""Cryptographic verification of external build/release provenance envelopes (DSSE / in-toto)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

import pydantic
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from pydantic import Field

from traust_core.v1.errors import ConfigError, UnresolvedTargetError
from traust_core.v1.models.base import Model
from traust_core.v1.models.component_target import (
    UnresolvedTargetReason,
    VerifiedProvenanceClaim,
)

MAX_PROVENANCE_PAYLOAD_BYTES = 65_536


class ProvenanceVerifier(Protocol):
    def verify(self, record: Mapping[str, Any]) -> VerifiedProvenanceClaim: ...


class TrustedProvenanceKey(Model):
    key_id: str = Field(min_length=1)
    public_key_pem: str = Field(min_length=1)
    issuer: str | None = Field(default=None, min_length=1)


class ProvenanceTrustPolicy(Model):
    trusted_keys: tuple[TrustedProvenanceKey, ...] = ()
    allowed_sources: tuple[str, ...] = ()
    allowed_issuers: tuple[str, ...] = ()


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Standard DSSE v1.0 Pre-Authentication Encoding."""
    pt_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(pt_bytes)).encode("ascii")
        + b" "
        + pt_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _verify_signature(public_key: object, signature: bytes, data: bytes) -> bool:
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
            return True
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
            return True
    except (InvalidSignature, ValueError):
        return False
    return False


def _extract_statement_fields(statement: Mapping[str, Any]) -> dict[str, Any]:
    stmt_type = statement.get("_type")
    if isinstance(stmt_type, str) and stmt_type.startswith("https://in-toto.io/Statement/"):
        predicate = statement.get("predicate")
        if not isinstance(predicate, Mapping):
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "in-toto statement predicate must be an object",
            )
        purl = predicate.get("purl")
        subjects = statement.get("subject")
        if not purl and isinstance(subjects, list) and subjects:
            first_subj = subjects[0]
            if isinstance(first_subj, Mapping):
                cand = first_subj.get("uri") or first_subj.get("name")
                if isinstance(cand, str) and cand.startswith("pkg:"):
                    purl = cand
        return {
            "purl": purl,
            "repository": predicate.get("repository"),
            "commit": predicate.get("commit"),
            "source": statement.get("predicateType") or predicate.get("source"),
            "ref": predicate.get("ref"),
            "manifest_version": predicate.get("manifest_version"),
        }
    return {
        "purl": statement.get("purl"),
        "repository": statement.get("repository"),
        "commit": statement.get("commit"),
        "source": statement.get("source"),
        "ref": statement.get("ref"),
        "manifest_version": statement.get("manifest_version"),
    }


class DsseProvenanceVerifier:
    """Verifies DSSE-signed provenance records against a configured trust policy."""

    def __init__(self, policy: ProvenanceTrustPolicy) -> None:
        self._policy = policy
        self._keys: dict[str, tuple[TrustedProvenanceKey, object]] = {}
        for entry in policy.trusted_keys:
            try:
                pub = serialization.load_pem_public_key(entry.public_key_pem.encode("utf-8"))
            except (ValueError, TypeError) as exc:
                raise ConfigError(
                    f"invalid public key PEM for provenance key {entry.key_id!r}"
                ) from exc
            self._keys[entry.key_id] = (entry, pub)

    @classmethod
    def from_file(cls, path: Path) -> DsseProvenanceVerifier:
        try:
            raw = path.read_text(encoding="utf-8")
            policy = ProvenanceTrustPolicy.model_validate_json(raw)
        except (OSError, pydantic.ValidationError) as exc:
            raise ConfigError(f"invalid provenance trust policy at {path}: {exc}") from exc
        return cls(policy)

    def verify(self, record: Mapping[str, Any]) -> VerifiedProvenanceClaim:
        if not self._keys:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "no trusted provenance keys configured in trust policy",
            )
        if not isinstance(record, Mapping):
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "provenance record must be a JSON object",
            )
        payload_type = record.get("payloadType")
        payload_b64 = record.get("payload")
        signatures = record.get("signatures")
        if (
            not isinstance(payload_type, str)
            or not payload_type.strip()
            or not isinstance(payload_b64, str)
            or not payload_b64.strip()
            or not isinstance(signatures, list)
            or not signatures
        ):
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "malformed DSSE provenance envelope",
            )
        try:
            payload_bytes = base64.b64decode(payload_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "provenance payload is not valid base64",
            ) from exc
        if not payload_bytes or len(payload_bytes) > MAX_PROVENANCE_PAYLOAD_BYTES:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "provenance payload is empty or exceeds size limit",
            )

        pae = dsse_pae(payload_type, payload_bytes)
        matched_key: TrustedProvenanceKey | None = None
        for sig_entry in signatures:
            if not isinstance(sig_entry, Mapping):
                continue
            key_id = sig_entry.get("keyid")
            sig_b64 = sig_entry.get("sig")
            if not isinstance(key_id, str) or not isinstance(sig_b64, str):
                continue
            trusted = self._keys.get(key_id)
            if trusted is None:
                continue
            try:
                sig_bytes = base64.b64decode(sig_b64, validate=True)
            except (binascii.Error, ValueError):
                continue
            if _verify_signature(trusted[1], sig_bytes, pae):
                matched_key = trusted[0]
                break

        if matched_key is None:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "no trusted signature verified on provenance envelope",
            )

        try:
            statement = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "provenance payload is not valid UTF-8 JSON",
            ) from exc
        if not isinstance(statement, Mapping):
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "provenance statement must be a JSON object",
            )

        issuer = matched_key.issuer or (
            statement.get("issuer") if isinstance(statement.get("issuer"), str) else None
        )
        if self._policy.allowed_issuers and issuer not in self._policy.allowed_issuers:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                f"untrusted provenance issuer {issuer!r}",
            )

        extracted = _extract_statement_fields(statement)
        source = extracted.get("source")
        if self._policy.allowed_sources and source not in self._policy.allowed_sources:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                f"untrusted provenance source {source!r}",
            )

        digest = f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"
        try:
            return VerifiedProvenanceClaim(
                purl=extracted["purl"],
                repository=extracted["repository"],
                commit=extracted["commit"],
                source=extracted["source"],
                ref=extracted["ref"],
                digest=digest,
                manifest_version=extracted.get("manifest_version"),
            )
        except (KeyError, pydantic.ValidationError) as exc:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                f"incomplete verified provenance claims: {exc}",
            ) from exc
