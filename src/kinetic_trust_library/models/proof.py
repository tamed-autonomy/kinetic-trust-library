"""Backend-neutral immutable Trust Proof values."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from decimal import Decimal
from enum import Enum, StrEnum, auto
from typing import TYPE_CHECKING, TypeAlias
from unicodedata import category, normalize

from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import CryptoConfigurationError, ValidationError

from ._uri import validate_absolute_uri
from ._common import utc_time
from .soul import SoulConstraintType
from .standing import LineagePhase

if TYPE_CHECKING:
    from kinetic_trust_library.protocols import AsyncSignatureVerifier, SignatureVerifier


_MAX_OTHER_STRING_BYTES = 4096
_MAX_KEY_IDENTIFIER_BYTES = 256
_MAX_ABSOLUTE_URI_BYTES = 2048


class ProofAlgorithm(StrEnum):
    ES256 = "ES256"
    ED25519 = "EdDSA"


class KeyPurpose(StrEnum):
    ORACLE_TRUST_PROOF = "oracle-trust-proof"


class ProofRootStatus(StrEnum):
    CURRENT = "current"
    NON_RENEWABLE = "non_renewable"
    NONE = "none"


class SignatureVerificationOutcome(Enum):
    VALID = auto()
    INVALID_SIGNATURE = auto()
    INVALID_PUBLIC_KEY = auto()


@dataclass(frozen=True, slots=True)
class OracleSigningIdentity:
    issuer: str
    key_id: str
    algorithm: ProofAlgorithm
    purpose: KeyPurpose
    public_key: bytes
    signing_not_before: datetime
    signing_not_after: datetime | None
    revoked_at: datetime | None

    def __post_init__(self) -> None:
        _require_uri(self.issuer, name="signing issuer")
        _require_key_identifier(self.key_id, name="signing key ID")
        _require_algorithm(self.algorithm)
        _require_purpose(self.purpose)
        object.__setattr__(
            self,
            "public_key",
            _owned_bytes(self.public_key, name="signing public key"),
        )
        _require_utc(self.signing_not_before, name="signing not-before")
        _require_optional_utc(self.signing_not_after, name="signing not-after")
        _require_optional_utc(self.revoked_at, name="signing revocation time")
        if (
            self.signing_not_after is not None
            and self.signing_not_after <= self.signing_not_before
        ):
            raise ValidationError("signing not-after must follow signing not-before")


@dataclass(frozen=True, slots=True)
class KeyLookup:
    untrusted_issuer: str
    key_id: str
    algorithm: ProofAlgorithm
    purpose: KeyPurpose
    cutoff: datetime

    def __post_init__(self) -> None:
        _require_uri(self.untrusted_issuer, name="untrusted issuer")
        _require_key_identifier(self.key_id, name="verification key ID")
        _require_algorithm(self.algorithm)
        _require_purpose(self.purpose)
        _require_utc(self.cutoff, name="verification cutoff")


@dataclass(frozen=True, slots=True)
class UnknownVerificationKey:
    key_id: str

    def __post_init__(self) -> None:
        _require_key_identifier(self.key_id, name="unknown verification key ID")


@dataclass(frozen=True, slots=True)
class UntrustedVerificationKey:
    key_id: str

    def __post_init__(self) -> None:
        _require_key_identifier(self.key_id, name="untrusted verification key ID")


@dataclass(frozen=True, slots=True)
class TrustedVerificationKey:
    issuer: str
    key_id: str
    algorithm: ProofAlgorithm
    purpose: KeyPurpose
    public_key: bytes
    signing_not_before: datetime
    signing_not_after: datetime | None
    verification_not_after: datetime | None
    revoked_at: datetime | None

    def __post_init__(self) -> None:
        _require_uri(self.issuer, name="trusted key issuer")
        _require_key_identifier(self.key_id, name="trusted verification key ID")
        _require_algorithm(self.algorithm)
        _require_purpose(self.purpose)
        object.__setattr__(
            self,
            "public_key",
            _owned_bytes(self.public_key, name="trusted verification public key"),
        )
        _require_utc(self.signing_not_before, name="key signing not-before")
        _require_optional_utc(self.signing_not_after, name="key signing not-after")
        _require_optional_utc(
            self.verification_not_after,
            name="key verification not-after",
        )
        _require_optional_utc(self.revoked_at, name="key revocation time")
        if (
            self.signing_not_after is not None
            and self.signing_not_after <= self.signing_not_before
        ):
            raise ValidationError("key signing not-after must follow not-before")
        if (
            self.verification_not_after is not None
            and self.verification_not_after <= self.signing_not_before
        ):
            raise ValidationError("key verification not-after must follow not-before")
        if (
            self.signing_not_after is not None
            and self.verification_not_after is not None
            and self.verification_not_after < self.signing_not_after
        ):
            raise ValidationError(
                "key verification not-after must not precede signing not-after"
            )


KeyResolution: TypeAlias = (
    UnknownVerificationKey | UntrustedVerificationKey | TrustedVerificationKey
)


@dataclass(frozen=True, slots=True)
class VerifierBinding:
    algorithm: ProofAlgorithm
    verifier: SignatureVerifier

    def __post_init__(self) -> None:
        if not _is_declared_proof_algorithm(self.algorithm):
            raise CryptoConfigurationError("proof verifier algorithm is invalid")


@dataclass(frozen=True, slots=True)
class AsyncVerifierBinding:
    algorithm: ProofAlgorithm
    verifier: AsyncSignatureVerifier

    def __post_init__(self) -> None:
        if not _is_declared_proof_algorithm(self.algorithm):
            raise CryptoConfigurationError("async proof verifier algorithm is invalid")


@dataclass(frozen=True, slots=True, init=False)
class ProofCrypto:
    bindings: tuple[VerifierBinding, ...]

    def __init__(self, bindings: tuple[VerifierBinding, ...], /) -> None:
        if type(bindings) is not tuple:
            raise CryptoConfigurationError(
                "proof verifier bindings must be an owned tuple"
            )
        if any(type(binding) is not VerifierBinding for binding in bindings):
            raise CryptoConfigurationError("proof verifier binding is invalid")
        if any(
            not hasattr(binding, "algorithm") or not hasattr(binding, "verifier")
            for binding in bindings
        ):
            raise CryptoConfigurationError("proof verifier binding is incomplete")
        algorithms = tuple(binding.algorithm for binding in bindings)
        if any(not _is_declared_proof_algorithm(algorithm) for algorithm in algorithms):
            raise CryptoConfigurationError("proof verifier algorithm is invalid")
        if len(set(algorithms)) != len(algorithms):
            raise CryptoConfigurationError("proof verifier algorithm is duplicated")
        if ProofAlgorithm.ES256 not in algorithms:
            raise CryptoConfigurationError("ES256 verifier binding is required")
        if any(
            algorithm not in (ProofAlgorithm.ES256, ProofAlgorithm.ED25519)
            for algorithm in algorithms
        ):
            raise CryptoConfigurationError("proof verifier algorithm is unsupported")
        object.__setattr__(self, "bindings", bindings)


@dataclass(frozen=True, slots=True, init=False)
class AsyncProofCrypto:
    bindings: tuple[AsyncVerifierBinding, ...]

    def __init__(self, bindings: tuple[AsyncVerifierBinding, ...], /) -> None:
        if type(bindings) is not tuple:
            raise CryptoConfigurationError(
                "async proof verifier bindings must be an owned tuple"
            )
        if any(type(binding) is not AsyncVerifierBinding for binding in bindings):
            raise CryptoConfigurationError("async proof verifier binding is invalid")
        if any(
            not hasattr(binding, "algorithm") or not hasattr(binding, "verifier")
            for binding in bindings
        ):
            raise CryptoConfigurationError("async proof verifier binding is incomplete")
        algorithms = tuple(binding.algorithm for binding in bindings)
        if any(not _is_declared_proof_algorithm(algorithm) for algorithm in algorithms):
            raise CryptoConfigurationError("async proof verifier algorithm is invalid")
        if len(set(algorithms)) != len(algorithms):
            raise CryptoConfigurationError(
                "async proof verifier algorithm is duplicated"
            )
        if ProofAlgorithm.ES256 not in algorithms:
            raise CryptoConfigurationError("ES256 async verifier binding is required")
        if any(
            algorithm not in (ProofAlgorithm.ES256, ProofAlgorithm.ED25519)
            for algorithm in algorithms
        ):
            raise CryptoConfigurationError(
                "async proof verifier algorithm is unsupported"
            )
        object.__setattr__(self, "bindings", bindings)


@dataclass(frozen=True, slots=True)
class ProofIntent:
    proof_id: str
    resource: str
    context_hash: str
    trajectory_id: str
    lifetime_seconds: int

    def __post_init__(self) -> None:
        _require_key_identifier(self.proof_id, name="proof ID")
        _require_uri(self.resource, name="proof resource")
        _require_sha256(self.context_hash, name="proof context hash")
        _require_key_identifier(self.trajectory_id, name="trajectory ID")
        if (
            type(self.lifetime_seconds) is not int
            or not 1 <= self.lifetime_seconds <= 10
        ):
            raise ValidationError(
                "proof lifetime seconds must be an exact integer from one through ten"
            )


def _require_proof_intent(value: object, /) -> ProofIntent:
    if type(value) is not ProofIntent:
        raise ValidationError("proof intent must be an exact ProofIntent")
    _require_key_identifier(value.proof_id, name="proof ID")
    _require_uri(value.resource, name="proof resource")
    _require_sha256(value.context_hash, name="proof context hash")
    _require_key_identifier(value.trajectory_id, name="trajectory ID")
    if type(value.lifetime_seconds) is not int or not 1 <= value.lifetime_seconds <= 10:
        raise ValidationError(
            "proof lifetime seconds must be an exact integer from one through ten"
        )
    return value


@dataclass(frozen=True, slots=True)
class RiskFactorClaims:
    evidence_density: Decimal
    trust_trend: Decimal
    adversarial_pressure: Decimal
    update_resistance: Decimal
    attestation_coverage: Decimal
    moment_criticality: Decimal

    def __post_init__(self) -> None:
        for name in (
            "evidence_density",
            "trust_trend",
            "adversarial_pressure",
            "update_resistance",
            "attestation_coverage",
            "moment_criticality",
        ):
            _require_decimal(getattr(self, name), name=name, minimum=0, maximum=1)


@dataclass(frozen=True, slots=True)
class SoulProofClaims:
    soul: int
    constraint_type: SoulConstraintType | None
    constraint_id: str | None
    constraint_name: str | None
    authority: str | None
    community: str | None
    remediation: str | None

    def __post_init__(self) -> None:
        if type(self.soul) is not int or self.soul not in (0, 1):
            raise ValidationError("soul must be exactly zero or one")
        if (
            self.constraint_type is not None
            and type(self.constraint_type) is not SoulConstraintType
        ):
            raise ValidationError("Soul constraint type is invalid")
        for name in (
            "constraint_id",
            "constraint_name",
            "community",
            "remediation",
        ):
            value = getattr(self, name)
            if value is not None:
                _require_text(value, name=f"Soul {name}")
        if self.authority is not None:
            validate_absolute_uri(self.authority, name="Soul authority")
        details = (
            self.constraint_type,
            self.constraint_id,
            self.constraint_name,
            self.authority,
            self.community,
            self.remediation,
        )
        if self.soul == 0 and any(value is not None for value in details):
            raise ValidationError("clear Soul claims must not carry constraint details")
        if self.soul == 1 and (self.constraint_type is None or self.authority is None):
            raise ValidationError("active Soul claims require type and authority")


@dataclass(frozen=True, slots=True)
class CeilingClaim:
    ceiling: str
    value: Decimal

    def __post_init__(self) -> None:
        _require_text(self.ceiling, name="ceiling")
        _require_decimal(self.value, name="ceiling value", minimum=0, maximum=100)


@dataclass(frozen=True, slots=True)
class RootInstrumentClaim:
    status: ProofRootStatus
    end_time: datetime | None
    exposure_class: str | None
    declared_exposure: Decimal | None
    anchored_capacity: Decimal | None
    terminator: str | None
    chain_length: int | None

    def __post_init__(self) -> None:
        if type(self.status) is not ProofRootStatus:
            raise ValidationError("proof root status is invalid")
        if self.end_time is not None:
            utc_time(self.end_time, name="root instrument end time")
            if self.end_time.microsecond != 0:
                raise ValidationError("root instrument end time must use whole seconds")
        for name in ("exposure_class", "terminator"):
            value = getattr(self, name)
            if value is not None:
                _require_text(value, name=f"root instrument {name}")
        for name in ("declared_exposure", "anchored_capacity"):
            value = getattr(self, name)
            if value is not None:
                _require_decimal(value, name=f"root instrument {name}", minimum=0)
        if self.chain_length is not None and (
            type(self.chain_length) is not int or self.chain_length < 1
        ):
            raise ValidationError(
                "root instrument chain length must be a positive integer"
            )
        details = (
            self.end_time,
            self.exposure_class,
            self.declared_exposure,
            self.anchored_capacity,
            self.terminator,
            self.chain_length,
        )
        if self.status is ProofRootStatus.NONE:
            if any(value is not None for value in details):
                raise ValidationError("a none root instrument must omit details")
        elif self.end_time is None:
            raise ValidationError("an active root instrument requires an end time")


def _require_key_identifier(value: object, *, name: str) -> str:
    if type(value) is not str:
        raise ValidationError(f"{name} must be an exact string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError(f"{name} contains invalid Unicode") from exc
    if not value or len(encoded) > _MAX_KEY_IDENTIFIER_BYTES:
        raise ValidationError(f"{name} must contain 1 through 256 UTF-8 bytes")
    if normalize("NFC", value) != value:
        raise ValidationError(f"{name} must use NFC Unicode")
    if any(character.isspace() for character in value):
        raise ValidationError(f"{name} must not contain Unicode whitespace")
    if any(category(character) in {"Cc", "Cf"} for character in value):
        raise ValidationError(f"{name} must not contain Unicode controls")
    return value


def _require_uri(value: object, *, name: str) -> str:
    validated = validate_absolute_uri(value, name=name)
    if len(validated.encode("utf-8")) > _MAX_ABSOLUTE_URI_BYTES:
        raise ValidationError(f"{name} exceeds 2048 UTF-8 bytes")
    return validated


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[a-f0-9]{64}", value) is None:
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _require_proof_time(value: object, *, name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise ValidationError(f"{name} must be an exact UTC datetime")
    if value.microsecond != 0:
        raise ValidationError(f"{name} must use whole seconds")
    return value


def _require_proof_lifetime(issued_at: datetime, expires_at: datetime) -> None:
    _require_proof_time(issued_at, name="issued at")
    _require_proof_time(expires_at, name="expires at")
    if not timedelta(0) < expires_at - issued_at <= timedelta(seconds=10):
        raise ValidationError("proof lifetime must be positive and at most ten seconds")


def _require_algorithm(value: object) -> ProofAlgorithm:
    if type(value) is not ProofAlgorithm:
        raise ValidationError("proof algorithm is invalid")
    return value


def _is_declared_proof_algorithm(value: object, /) -> bool:
    return type(value) is ProofAlgorithm and (
        value is ProofAlgorithm.ES256 or value is ProofAlgorithm.ED25519
    )


def _require_purpose(value: object) -> KeyPurpose:
    if type(value) is not KeyPurpose:
        raise ValidationError("proof key purpose is invalid")
    return value


def _owned_bytes(value: object, *, name: str) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be exact immutable bytes")
    return bytes(bytearray(value))


def _require_utc(value: object, *, name: str) -> datetime:
    return utc_time(value, name=name)  # type: ignore[arg-type]


def _require_optional_utc(value: object, *, name: str) -> datetime | None:
    if value is None:
        return None
    return _require_utc(value, name=name)


def _require_decimal(
    value: object,
    *,
    name: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise ValidationError(f"{name} must be an exact finite Decimal")
    return as_decimal(value, name=name, minimum=minimum, maximum=maximum)


def _require_text(value: object, *, name: str) -> str:
    if type(value) is not str:
        raise ValidationError(f"{name} must be an exact string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError(f"{name} contains invalid Unicode") from exc
    if len(encoded) > _MAX_OTHER_STRING_BYTES:
        raise ValidationError(f"{name} exceeds its UTF-8 bound")
    if normalize("NFC", value) != value:
        raise ValidationError(f"{name} must use NFC Unicode")
    return value


@dataclass(frozen=True, slots=True, init=False)
class TrustProofClaims:
    issuer: str
    subject: str
    action: str
    resource: str
    context_hash: str
    trajectory_id: str
    decision_id: str
    issued_at: datetime
    expires_at: datetime
    proof_id: str
    base_trust: Decimal
    effective_trust: Decimal
    risk: Decimal
    velocity: Decimal | None
    volatility: Decimal | None
    context: RiskFactorClaims
    soul: SoulProofClaims
    lineage: LineagePhase
    generation: int
    sponsor: str | None
    resilience_hash: str
    zone: str | None
    oracle_quorum: str | None
    peer_share: Decimal
    applicable_ceilings: tuple[CeilingClaim, ...]
    advancement_floor: Decimal
    root_instrument: RootInstrumentClaim

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("TrustProofClaims values are created by KTP proof operations")


@dataclass(frozen=True, slots=True, init=False)
class ProofToken:
    raw: str
    token_digest: str
    proof_id: str
    issued_at: datetime
    expires_at: datetime

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("ProofToken values are created by KTP proof operations")


@dataclass(frozen=True, slots=True, init=False)
class VerifiedTrustProof:
    raw: str
    token_digest: str
    claims: TrustProofClaims
    verification_key: TrustedVerificationKey

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("VerifiedTrustProof values are created by KTP proof operations")


__all__ = [
    "AsyncProofCrypto",
    "AsyncVerifierBinding",
    "CeilingClaim",
    "KeyLookup",
    "KeyPurpose",
    "KeyResolution",
    "OracleSigningIdentity",
    "ProofAlgorithm",
    "ProofCrypto",
    "ProofIntent",
    "ProofRootStatus",
    "ProofToken",
    "RiskFactorClaims",
    "RootInstrumentClaim",
    "SignatureVerificationOutcome",
    "SoulProofClaims",
    "TrustProofClaims",
    "TrustedVerificationKey",
    "UnknownVerificationKey",
    "UntrustedVerificationKey",
    "VerifiedTrustProof",
    "VerifierBinding",
]
