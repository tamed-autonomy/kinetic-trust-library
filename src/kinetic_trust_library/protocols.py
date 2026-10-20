"""Canonical Trust Proof provider protocols and signals."""

from __future__ import annotations

from typing import Protocol

from .models.proof import (
    KeyLookup,
    KeyResolution,
    OracleSigningIdentity,
    SignatureVerificationOutcome,
)


class ProofSigner(Protocol):
    @property
    def identity(self) -> OracleSigningIdentity: ...

    def sign(self, signing_input: bytes, /) -> bytes: ...


class VerificationKeySource(Protocol):
    def resolve(self, lookup: KeyLookup, /) -> KeyResolution: ...


class SignatureVerifier(Protocol):
    def verify(
        self,
        *,
        public_key: bytes,
        signing_input: bytes,
        signature: bytes,
    ) -> SignatureVerificationOutcome: ...


class AsyncProofSigner(Protocol):
    @property
    def identity(self) -> OracleSigningIdentity: ...

    async def sign(self, signing_input: bytes, /) -> bytes: ...


class AsyncVerificationKeySource(Protocol):
    async def resolve(self, lookup: KeyLookup, /) -> KeyResolution: ...


class AsyncSignatureVerifier(Protocol):
    async def verify(
        self,
        *,
        public_key: bytes,
        signing_input: bytes,
        signature: bytes,
    ) -> SignatureVerificationOutcome: ...


class ProviderSignal(Exception):
    """Base signal raised by an injected proof provider."""


class ProviderUnavailable(ProviderSignal):
    """The provider definitely did not accept the operation."""


class ProviderFailure(ProviderSignal):
    """The provider definitely did not produce a usable result."""


class SigningOutcomeUnknown(ProviderSignal):
    """The signer may have completed an externally observable operation."""

    def __init__(self, provider_reference: str | None = None) -> None:
        if provider_reference is not None and type(provider_reference) is not str:
            raise TypeError("provider reference must be an exact string or None")
        if provider_reference is not None:
            try:
                encoded = provider_reference.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("provider reference contains invalid Unicode") from exc
            if len(encoded) > 256:
                raise ValueError("provider reference exceeds 256 UTF-8 bytes")
        super().__init__()
        self.provider_reference = provider_reference


__all__ = [
    "AsyncProofSigner",
    "AsyncSignatureVerifier",
    "AsyncVerificationKeySource",
    "ProofSigner",
    "ProviderFailure",
    "ProviderSignal",
    "ProviderUnavailable",
    "SignatureVerifier",
    "SigningOutcomeUnknown",
    "VerificationKeySource",
]
