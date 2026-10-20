"""Kinetic Trust Protocol errors."""

from __future__ import annotations

import re as _re
from unicodedata import category as _unicode_category
from unicodedata import normalize as _normalize


__all__ = (
    "KTPError",
    "ValidationError",
    "ProofIssuanceInputError",
    "ConfigurationError",
    "ProofOperationError",
    "CryptoConfigurationError",
    "InvalidProofError",
    "ProofFormatError",
    "UnsupportedProofAlgorithmError",
    "DisabledProofAlgorithmError",
    "UnknownVerificationKeyError",
    "UntrustedVerificationKeyError",
    "RevokedVerificationKeyError",
    "InactiveVerificationKeyError",
    "InvalidSignatureError",
    "ProofLifetimeError",
    "ProofClaimsError",
    "CryptoProviderUnavailableError",
    "CryptoProviderFailureError",
    "CryptoProviderContractError",
    "VerificationKeySourceUnavailableError",
    "VerificationKeySourceFailureError",
    "VerificationKeySourceContractError",
    "SigningProviderUnavailableError",
    "SigningProviderFailureError",
    "SignerContractError",
    "OutcomeUnknownError",
)

_SHA256_DIGEST = _re.compile(r"^sha256:[a-f0-9]{64}$")


class KTPError(Exception):
    """Base exception for Kinetic Trust Protocol failures."""


class ValidationError(KTPError):
    """Raised when an input value is invalid."""


class ProofIssuanceInputError(ValidationError):
    """Raised when KTP-Core authority cannot supply proof issuance claims."""


class ConfigurationError(KTPError):
    """Raised when a library configuration is invalid."""


class ProofOperationError(KTPError):
    """Raised when a proof operation cannot reach an authoritative result."""


class CryptoConfigurationError(ProofOperationError):
    """Raised when proof cryptography is not configured coherently."""


class InvalidProofError(KTPError):
    """Base exception for a presented proof that is not authoritative."""


class ProofFormatError(InvalidProofError):
    """Raised when compact proof framing or encoding is malformed."""


class UnsupportedProofAlgorithmError(InvalidProofError):
    """Raised when a proof names an algorithm outside the closed profile."""


class DisabledProofAlgorithmError(InvalidProofError):
    """Raised when a supported proof algorithm is not enabled."""


class UnknownVerificationKeyError(InvalidProofError):
    """Raised when the verification key is unknown."""


class UntrustedVerificationKeyError(InvalidProofError):
    """Raised when the verification key is not trusted for proof use."""


class RevokedVerificationKeyError(InvalidProofError):
    """Raised when the verification key is revoked at the cutoff."""


class InactiveVerificationKeyError(InvalidProofError):
    """Raised when the verification key is outside its active interval."""


class InvalidSignatureError(InvalidProofError):
    """Raised when a presented proof signature is invalid."""


class ProofLifetimeError(InvalidProofError):
    """Raised when a proof is outside its authoritative lifetime."""


class ProofClaimsError(InvalidProofError):
    """Raised when authenticated proof claims are invalid or incoherent."""


class CryptoProviderUnavailableError(ProofOperationError):
    """Raised when a configured primitive provider is unavailable."""


class CryptoProviderFailureError(ProofOperationError):
    """Raised when a configured primitive provider definitely fails."""


class CryptoProviderContractError(ProofOperationError):
    """Raised when a primitive provider violates its contract."""


class VerificationKeySourceUnavailableError(ProofOperationError):
    """Raised when trusted verification-key facts are unavailable."""


class VerificationKeySourceFailureError(ProofOperationError):
    """Raised when the verification-key source definitely fails."""


class VerificationKeySourceContractError(ProofOperationError):
    """Raised when the verification-key source violates its contract."""


class SigningProviderUnavailableError(ProofOperationError):
    """Raised when a signer definitely did not accept an operation."""


class SigningProviderFailureError(ProofOperationError):
    """Raised when a signer definitely produced no usable signature."""


class SignerContractError(ProofOperationError):
    """Raised when a signer violates its identity or signature contract."""


class OutcomeUnknownError(ProofOperationError):
    """Raised when a dispatched signing operation may have completed."""

    stage = "signing"

    def __init__(
        self,
        *,
        proof_id: str,
        signing_input_digest: str,
        provider_reference: str | None = None,
        operation_id: str | None = None,
    ) -> None:
        self.proof_id = _require_proof_id(proof_id)
        self.signing_input_digest = _require_signing_input_digest(signing_input_digest)
        self.provider_reference = _require_optional_bounded_text(
            provider_reference,
            name="provider reference",
            allow_empty=True,
        )
        self.operation_id = _require_optional_bounded_text(
            operation_id,
            name="operation ID",
            allow_empty=False,
        )
        super().__init__(f"signing outcome is unknown for proof {self.proof_id}")


def _require_proof_id(value: object) -> str:
    if type(value) is not str:
        raise TypeError("proof ID must be an exact string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("proof ID contains invalid Unicode") from exc
    if not value or len(encoded) > 256:
        raise ValueError("proof ID must contain 1 through 256 UTF-8 bytes")
    if _normalize("NFC", value) != value:
        raise ValueError("proof ID must use NFC Unicode")
    if any(character.isspace() for character in value):
        raise ValueError("proof ID must not contain Unicode whitespace")
    if any(_unicode_category(character) in {"Cc", "Cf"} for character in value):
        raise ValueError("proof ID must not contain Unicode controls")
    return value


def _require_signing_input_digest(value: object) -> str:
    if type(value) is not str:
        raise TypeError("signing-input digest must be an exact string")
    if _SHA256_DIGEST.fullmatch(value) is None:
        raise ValueError("signing-input digest must be canonical SHA-256")
    return value


def _require_optional_bounded_text(
    value: object,
    *,
    name: str,
    allow_empty: bool,
) -> str | None:
    if value is None:
        return None
    if type(value) is not str:
        raise TypeError(f"{name} must be an exact string or None")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} contains invalid Unicode") from exc
    if (not allow_empty and not value) or len(encoded) > 256:
        raise ValueError(f"{name} exceeds its bounded string policy")
    return value
