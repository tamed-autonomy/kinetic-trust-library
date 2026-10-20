"""KTP Trust Proof operations."""

from __future__ import annotations

from datetime import datetime

from kinetic_trust_library.errors import (
    CryptoConfigurationError,
    CryptoProviderFailureError,
    CryptoProviderUnavailableError,
    SignerContractError,
    SigningProviderFailureError,
    SigningProviderUnavailableError,
    VerificationKeySourceFailureError,
    VerificationKeySourceUnavailableError,
)
from kinetic_trust_library.models.envelope import EvaluationBundle
from kinetic_trust_library.models.proof import (
    AsyncProofCrypto,
    KeyLookup,
    ProofCrypto,
    ProofIntent,
    ProofToken,
    VerifiedTrustProof,
)
from kinetic_trust_library.protocols import (
    AsyncProofSigner,
    AsyncVerificationKeySource,
    ProofSigner,
    ProviderFailure,
    ProviderUnavailable,
    SigningOutcomeUnknown,
    VerificationKeySource,
)

from ._issue import (
    _signing_outcome_unknown,
    accept_signature as _accept_signature,
    bind_signer as _bind_signer,
    complete_self_verification as _complete_self_verification,
    issue_async as _issue_async,
    prepare_issuance as _prepare_issuance,
    prepare_signing as _prepare_signing,
)
from ._verify import (
    _dispose_nested_native_coroutine,
    accept_key_resolution as _accept_key_resolution,
    complete_verification as _complete_verification,
    prepare_verification as _prepare_verification,
    verify_async as _verify_async,
)


class AsyncTrustProofs:
    """Native asynchronous Trust Proof operations."""

    def __init__(self, crypto: AsyncProofCrypto):
        self._crypto = crypto

    async def issue(
        self,
        evaluation: EvaluationBundle,
        *,
        proof: ProofIntent,
        signer: AsyncProofSigner,
    ) -> ProofToken:
        if type(self._crypto) is not AsyncProofCrypto:
            raise CryptoConfigurationError(
                "asynchronous Trust Proof facade requires exact AsyncProofCrypto"
            )
        return await _issue_async(
            evaluation,
            proof=proof,
            signer=signer,
            crypto=self._crypto,
        )

    async def verify(
        self,
        raw: str,
        *,
        cutoff: datetime,
        keys: AsyncVerificationKeySource,
    ) -> VerifiedTrustProof:
        if type(self._crypto) is not AsyncProofCrypto:
            raise CryptoConfigurationError(
                "asynchronous Trust Proof facade requires exact AsyncProofCrypto"
            )
        return await _verify_async(
            raw,
            cutoff=cutoff,
            crypto=self._crypto,
            keys=keys,
        )


class TrustProofs:
    """Synchronous Trust Proof operations."""

    def __init__(self, crypto: ProofCrypto):
        self._crypto = crypto

    def verify(
        self,
        raw: str,
        *,
        cutoff: datetime,
        keys: VerificationKeySource,
    ) -> VerifiedTrustProof:
        if type(self._crypto) is not ProofCrypto:
            raise CryptoConfigurationError(
                "synchronous Trust Proof facade requires exact ProofCrypto"
            )
        prepared = _prepare_verification(raw, cutoff=cutoff, crypto=self._crypto)
        provider_lookup = KeyLookup(
            untrusted_issuer=prepared.lookup.untrusted_issuer,
            key_id=prepared.lookup.key_id,
            algorithm=prepared.lookup.algorithm,
            purpose=prepared.lookup.purpose,
            cutoff=prepared.lookup.cutoff,
        )
        try:
            resolution = keys.resolve(provider_lookup)
        except ProviderUnavailable as exc:
            raise VerificationKeySourceUnavailableError(
                "verification key source is unavailable"
            ) from exc
        except ProviderFailure as exc:
            raise VerificationKeySourceFailureError(
                "verification key source failed"
            ) from exc
        except Exception as exc:
            raise VerificationKeySourceFailureError(
                "verification key source raised an undeclared failure"
            ) from exc
        _dispose_nested_native_coroutine(resolution)
        accepted = _accept_key_resolution(prepared, resolution)
        try:
            outcome = accepted.verifier.verify(
                public_key=accepted.public_key,
                signing_input=accepted.signing_input,
                signature=accepted.signature,
            )
        except ProviderUnavailable as exc:
            raise CryptoProviderUnavailableError(
                "signature verifier is unavailable"
            ) from exc
        except ProviderFailure as exc:
            raise CryptoProviderFailureError("signature verifier failed") from exc
        except Exception as exc:
            raise CryptoProviderFailureError(
                "signature verifier raised an undeclared failure"
            ) from exc
        _dispose_nested_native_coroutine(outcome)
        return _complete_verification(accepted, outcome)

    def issue(
        self,
        evaluation: EvaluationBundle,
        *,
        proof: ProofIntent,
        signer: ProofSigner,
    ) -> ProofToken:
        if type(self._crypto) is not ProofCrypto:
            raise CryptoConfigurationError(
                "synchronous Trust Proof facade requires exact ProofCrypto"
            )
        prepared = _prepare_issuance(
            evaluation,
            proof=proof,
            crypto=self._crypto,
        )
        try:
            identity = signer.identity
        except ProviderUnavailable as exc:
            raise SigningProviderUnavailableError("signer is unavailable") from exc
        except ProviderFailure as exc:
            raise SigningProviderFailureError("signer failed") from exc
        except Exception as exc:
            raise SignerContractError("signer identity access failed") from exc
        _dispose_nested_native_coroutine(identity)
        bound = _bind_signer(prepared, identity)
        signing = _prepare_signing(bound)
        try:
            sign = signer.sign
        except ProviderUnavailable as exc:
            raise SigningProviderUnavailableError("signer is unavailable") from exc
        except ProviderFailure as exc:
            raise SigningProviderFailureError("signer failed") from exc
        except Exception as exc:
            raise SignerContractError("signer method access failed") from exc
        if not callable(sign):
            raise SignerContractError("signer method is not callable")
        try:
            signature = sign(signing.signing_input)
        except ProviderUnavailable as exc:
            raise SigningProviderUnavailableError("signer is unavailable") from exc
        except ProviderFailure as exc:
            raise SigningProviderFailureError("signer failed") from exc
        except SigningOutcomeUnknown as exc:
            raise _signing_outcome_unknown(signing, exc) from exc
        except Exception as exc:
            raise _signing_outcome_unknown(signing, None) from exc
        _dispose_nested_native_coroutine(signature)
        accepted = _accept_signature(signing, signature)
        try:
            outcome = accepted.verifier.verify(
                public_key=accepted.public_key,
                signing_input=accepted.signing_input,
                signature=accepted.signature,
            )
        except ProviderUnavailable as exc:
            raise CryptoProviderUnavailableError(
                "signature verifier is unavailable"
            ) from exc
        except ProviderFailure as exc:
            raise CryptoProviderFailureError("signature verifier failed") from exc
        except Exception as exc:
            raise CryptoProviderFailureError(
                "signature verifier raised an undeclared failure"
            ) from exc
        _dispose_nested_native_coroutine(outcome)
        return _complete_self_verification(accepted, outcome)


__all__ = ["AsyncTrustProofs", "TrustProofs"]
