"""Private Restricted Issuer Profile v1 kernel."""

from __future__ import annotations

from asyncio import CancelledError
from base64 import urlsafe_b64encode
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from decimal import Decimal
from hashlib import sha256
from inspect import isawaitable

from kinetic_trust_library.core.evaluate import require_validated_evaluation_bundle
from kinetic_trust_library.errors import (
    CryptoProviderContractError,
    OutcomeUnknownError,
    ProofFormatError,
    ProofIssuanceInputError,
    SignerContractError,
    SigningProviderFailureError,
    SigningProviderUnavailableError,
    ValidationError,
)
from kinetic_trust_library.models._uri import validate_absolute_uri
from kinetic_trust_library.models.envelope import EvaluationBundle
from kinetic_trust_library.models.proof import (
    AsyncProofCrypto,
    CeilingClaim,
    KeyPurpose,
    OracleSigningIdentity,
    ProofAlgorithm,
    ProofCrypto,
    ProofIntent,
    ProofRootStatus,
    ProofToken,
    RiskFactorClaims,
    RootInstrumentClaim,
    SignatureVerificationOutcome,
    SoulProofClaims,
    TrustProofClaims,
    _require_key_identifier,
    _require_proof_intent,
    _require_proof_lifetime,
    _require_proof_time,
    _require_uri,
)
from kinetic_trust_library.models.soul import SoulAssessmentState
from kinetic_trust_library.models.standing import (
    LineagePhase,
    RootInstrumentDeclaration,
    RootInstrumentStatus,
)
from kinetic_trust_library.protocols import (
    AsyncProofSigner,
    ProviderFailure,
    ProviderUnavailable,
    SigningOutcomeUnknown,
)

from ._algorithms import (
    _PublicKeyShapeError,
    _SignatureShapeError,
    validate_es256_public_key,
    validate_es256_signature,
    validate_ed25519_public_key,
    validate_ed25519_signature,
)
from ._jwt import (
    _canonical_json_bytes,
    _require_compact_token_width,
    _require_decoded_header_width,
    _require_header_segment_width,
    _require_payload_segment_width,
    _require_signature_segment_width,
    _require_signing_input_width,
    canonical_payload_bytes,
)
from ._verify import (
    _dispose_nested_native_coroutine,
    _validated_crypto_bindings,
    _verify_signature,
)


_ROOT_STATUS_PROJECTION = (
    (RootInstrumentStatus.CURRENT, ProofRootStatus.CURRENT),
    (RootInstrumentStatus.NON_RENEWABLE, ProofRootStatus.NON_RENEWABLE),
    (RootInstrumentStatus.EXPIRED, ProofRootStatus.NONE),
    (RootInstrumentStatus.FOR_CAUSE_PENDING, ProofRootStatus.NONE),
    (RootInstrumentStatus.FOR_CAUSE_SUSTAINED, ProofRootStatus.NONE),
    (RootInstrumentStatus.FOR_CAUSE_REJECTED, ProofRootStatus.NONE),
    (RootInstrumentStatus.FOR_CAUSE_UNRESOLVED, ProofRootStatus.NONE),
    (RootInstrumentStatus.MISATTESTATION, ProofRootStatus.NONE),
    (RootInstrumentStatus.NONE, ProofRootStatus.NONE),
)


@dataclass(frozen=True, slots=True)
class _PreparedIssuance:
    proof_id: str
    issued_at: datetime
    expires_at: datetime
    subject: str
    action: str
    resource: str
    context_hash: str
    trajectory_id: str
    decision_id: str
    base_trust: Decimal
    effective_trust: Decimal
    risk: Decimal
    velocity: Decimal | None
    context: RiskFactorClaims
    lineage: LineagePhase
    generation: int
    sponsor: str | None
    resilience_hash: str
    peer_share: Decimal
    applicable_ceilings: tuple[CeilingClaim, ...]
    advancement_floor: Decimal
    root_instrument: RootInstrumentClaim
    bindings: tuple[tuple[ProofAlgorithm, object], ...]


@dataclass(frozen=True, slots=True)
class _BoundIssuance:
    prepared: _PreparedIssuance
    identity: OracleSigningIdentity
    claims: TrustProofClaims
    verifier: object


@dataclass(frozen=True, slots=True)
class _SigningRequest:
    proof_id: str
    issued_at: datetime
    expires_at: datetime
    public_key: bytes
    verifier: object
    algorithm: ProofAlgorithm
    header_segment: str
    payload_segment: str
    signing_input: bytes


@dataclass(frozen=True, slots=True)
class _AcceptedSignature:
    proof_id: str
    issued_at: datetime
    expires_at: datetime
    public_key: bytes
    verifier: object
    signing_input: bytes
    signature: bytes
    raw: str


async def issue_async(
    evaluation: EvaluationBundle,
    *,
    proof: ProofIntent,
    signer: AsyncProofSigner,
    crypto: AsyncProofCrypto,
) -> ProofToken:
    prepared = prepare_issuance(
        evaluation,
        proof=proof,
        crypto=crypto,
    )
    identity = _signer_identity(signer)
    bound = bind_signer(prepared, identity)
    signing = prepare_signing(bound)
    sign = _sign_method(signer)
    signature = await _sign(signing, sign)
    accepted = accept_signature(signing, signature)
    outcome = await _verify_signature(
        accepted.verifier,
        public_key=accepted.public_key,
        signing_input=accepted.signing_input,
        signature=accepted.signature,
    )
    return complete_self_verification(accepted, outcome)


def _signer_identity(signer: AsyncProofSigner, /) -> OracleSigningIdentity:
    try:
        identity = signer.identity
    except ProviderUnavailable as exc:
        raise SigningProviderUnavailableError("signer is unavailable") from exc
    except ProviderFailure as exc:
        raise SigningProviderFailureError("signer failed") from exc
    except Exception as exc:
        raise SignerContractError("signer identity access failed") from exc
    _dispose_nested_native_coroutine(identity)
    return identity


def _sign_method(signer: AsyncProofSigner, /) -> object:
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
    return sign


async def _sign(signing: _SigningRequest, sign: object, /) -> bytes:
    try:
        operation = sign(signing.signing_input)  # type: ignore[operator]
    except ProviderUnavailable as exc:
        raise SigningProviderUnavailableError("signer is unavailable") from exc
    except ProviderFailure as exc:
        raise SigningProviderFailureError("signer failed") from exc
    except SigningOutcomeUnknown as exc:
        raise _signing_outcome_unknown(signing, exc) from exc
    except CancelledError as exc:
        raise _signing_outcome_unknown(signing, None) from exc
    except Exception as exc:
        raise _signing_outcome_unknown(signing, None) from exc
    if not isawaitable(operation):
        raise SignerContractError("async signer returned a non-awaitable result")
    try:
        result = await operation
    except ProviderUnavailable as exc:
        raise SigningProviderUnavailableError("signer is unavailable") from exc
    except ProviderFailure as exc:
        raise SigningProviderFailureError("signer failed") from exc
    except SigningOutcomeUnknown as exc:
        raise _signing_outcome_unknown(signing, exc) from exc
    except CancelledError as exc:
        raise _signing_outcome_unknown(signing, None) from exc
    except Exception as exc:
        raise _signing_outcome_unknown(signing, None) from exc
    _dispose_nested_native_coroutine(result)
    return result


def _signing_outcome_unknown(
    signing: _SigningRequest,
    signal: SigningOutcomeUnknown | None = None,
    /,
) -> OutcomeUnknownError:
    signing_input_digest = "sha256:" + sha256(signing.signing_input).hexdigest()
    try:
        provider_reference = signal.provider_reference if signal is not None else None
        return OutcomeUnknownError(
            proof_id=signing.proof_id,
            signing_input_digest=signing_input_digest,
            provider_reference=provider_reference,
        )
    except Exception:
        # Optional provider diagnostics must not erase known signing correlation.
        return OutcomeUnknownError(
            proof_id=signing.proof_id,
            signing_input_digest=signing_input_digest,
            provider_reference=None,
        )


def prepare_issuance(
    evaluation: EvaluationBundle,
    *,
    proof: ProofIntent,
    crypto: ProofCrypto | AsyncProofCrypto,
) -> _PreparedIssuance:
    try:
        intent = _require_proof_intent(proof)
        bundle = require_validated_evaluation_bundle(evaluation)
        issued_at = _require_proof_time(bundle.cutoff, name="evaluation cutoff")
        requested_expiration = issued_at + timedelta(seconds=intent.lifetime_seconds)
        decision_id = _require_key_identifier(
            bundle.operation_id,
            name="proof decision ID",
        )
        if bundle.soul.state is not SoulAssessmentState.CLEAR:
            raise ValueError("only a clear complete evaluation can issue a proof")
        if any(
            member is None for member in (bundle.standing, bundle.risk, bundle.trust)
        ):
            raise ValueError("proof issuance requires complete evaluation state")
        standing = bundle.standing
        risk = bundle.risk
        trust = bundle.trust
        if standing is None or risk is None or trust is None:
            raise ValueError("proof issuance requires complete evaluation state")
        root = _project_root(standing.root_status, standing.root_instrument)
        expires_at = requested_expiration
        if root.status is not ProofRootStatus.NONE:
            if root.end_time is None:
                raise ValueError("active proof root requires an end time")
            expires_at = min(requested_expiration, root.end_time)
        _require_proof_lifetime(issued_at, expires_at)
        subject = _require_uri(bundle.action.subject, name="proof subject")
        action = bundle.action.digest
        context = RiskFactorClaims(
            evidence_density=risk.context.evidence_density,
            trust_trend=risk.context.trust_trend,
            adversarial_pressure=risk.context.adversarial_pressure,
            update_resistance=risk.context.update_resistance,
            attestation_coverage=risk.context.attestation_coverage,
            moment_criticality=risk.context.moment_criticality,
        )
        ceilings = tuple(
            CeilingClaim(ceiling.name, ceiling.value)
            for ceiling in standing.applicable_ceilings
        )
        sponsor = _project_sponsor(standing.lineage, standing.root_instrument)
        resilience_hash = "sha256:" + standing.por.digest
        prepared = _PreparedIssuance(
            proof_id=intent.proof_id,
            issued_at=issued_at,
            expires_at=expires_at,
            subject=subject,
            action=action,
            resource=intent.resource,
            context_hash=intent.context_hash,
            trajectory_id=intent.trajectory_id,
            decision_id=decision_id,
            base_trust=standing.base_trust,
            effective_trust=trust.effective_trust,
            risk=risk.risk,
            velocity=None if bundle.velocity is None else bundle.velocity.value,
            context=context,
            lineage=standing.lineage,
            generation=standing.generation,
            sponsor=sponsor,
            resilience_hash=resilience_hash,
            peer_share=standing.shares.peer,
            applicable_ceilings=ceilings,
            advancement_floor=standing.advancement_floor,
            root_instrument=root,
            bindings=(),
        )
        _validate_pre_identity_bounds(prepared)
        bindings = _validated_crypto_bindings(crypto)
        return replace(prepared, bindings=bindings)
    except ProofIssuanceInputError:
        raise
    except (
        AttributeError,
        KeyError,
        OverflowError,
        ProofFormatError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise ProofIssuanceInputError(
            "evaluation cannot supply proof issuance claims"
        ) from exc


def bind_signer(
    prepared: _PreparedIssuance,
    identity: OracleSigningIdentity,
    /,
) -> _BoundIssuance:
    try:
        if type(identity) is not OracleSigningIdentity:
            raise TypeError("signer identity must be exact OracleSigningIdentity")
        if (
            identity.algorithm is not ProofAlgorithm.ES256
            and identity.algorithm is not ProofAlgorithm.ED25519
        ):
            raise ValueError("signer algorithm is undeclared")
        if identity.purpose is not KeyPurpose.ORACLE_TRUST_PROOF:
            raise ValueError("signer purpose is not Oracle Trust Proof")
        owned = OracleSigningIdentity(
            issuer=identity.issuer,
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            purpose=identity.purpose,
            public_key=identity.public_key,
            signing_not_before=identity.signing_not_before,
            signing_not_after=identity.signing_not_after,
            revoked_at=identity.revoked_at,
        )
        verifier = next(
            provider
            for algorithm, provider in prepared.bindings
            if algorithm is owned.algorithm
        )
        if prepared.issued_at < owned.signing_not_before or (
            owned.signing_not_after is not None
            and prepared.issued_at >= owned.signing_not_after
        ):
            raise ValueError("signer is outside its signing window")
        if owned.revoked_at is not None and owned.revoked_at <= prepared.issued_at:
            raise ValueError("signer is revoked")
        if owned.algorithm is ProofAlgorithm.ES256:
            validate_es256_public_key(owned.public_key)
        else:
            validate_ed25519_public_key(owned.public_key)
        claims = _issuance_claims(prepared, issuer=owned.issuer)
        return _BoundIssuance(prepared, owned, claims, verifier)
    except StopIteration as exc:
        raise SignerContractError("signer algorithm is not configured") from exc
    except (
        _PublicKeyShapeError,
        AttributeError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise SignerContractError("signer identity violates its contract") from exc


def prepare_signing(bound: _BoundIssuance, /) -> _SigningRequest:
    try:
        header_bytes = _canonical_json_bytes(
            {
                "alg": bound.identity.algorithm.value,
                "kid": bound.identity.key_id,
                "typ": "ktp+jwt",
            }
        )
        _require_decoded_header_width(header_bytes)
        payload_bytes = canonical_payload_bytes(bound.claims)
        header_segment = _segment(header_bytes)
        payload_segment = _segment(payload_bytes)
        _require_header_segment_width(header_segment)
        _require_payload_segment_width(payload_segment)
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        _require_signing_input_width(signing_input)
        _require_compact_token_width(signing_input.decode("ascii") + "." + ("A" * 86))
        return _SigningRequest(
            proof_id=bound.prepared.proof_id,
            issued_at=bound.prepared.issued_at,
            expires_at=bound.prepared.expires_at,
            public_key=bound.identity.public_key,
            verifier=bound.verifier,
            algorithm=bound.identity.algorithm,
            header_segment=header_segment,
            payload_segment=payload_segment,
            signing_input=signing_input,
        )
    except ProofFormatError as exc:
        raise ProofIssuanceInputError(
            "proof exceeds an issuance resource limit"
        ) from exc


def accept_signature(
    signing: _SigningRequest,
    signature: bytes,
    /,
) -> _AcceptedSignature:
    try:
        if signing.algorithm is ProofAlgorithm.ES256:
            validate_es256_signature(signature)
        else:
            validate_ed25519_signature(signature)
        owned_signature = bytes(bytearray(signature))
        signature_segment = _segment(owned_signature)
        _require_signature_segment_width(signature_segment)
        raw = f"{signing.header_segment}.{signing.payload_segment}.{signature_segment}"
        _require_compact_token_width(raw)
        return _AcceptedSignature(
            proof_id=signing.proof_id,
            issued_at=signing.issued_at,
            expires_at=signing.expires_at,
            public_key=signing.public_key,
            verifier=signing.verifier,
            signing_input=signing.signing_input,
            signature=owned_signature,
            raw=raw,
        )
    except (_SignatureShapeError, ProofFormatError, TypeError) as exc:
        raise SignerContractError(
            "signer returned an invalid canonical signature"
        ) from exc


def complete_self_verification(
    accepted: _AcceptedSignature,
    outcome: SignatureVerificationOutcome,
    /,
) -> ProofToken:
    if type(outcome) is not SignatureVerificationOutcome:
        raise CryptoProviderContractError(
            "signature verifier returned an invalid outcome"
        )
    if (
        outcome is SignatureVerificationOutcome.INVALID_SIGNATURE
        or outcome is SignatureVerificationOutcome.INVALID_PUBLIC_KEY
    ):
        raise SignerContractError("self-verification rejected signer output")
    if outcome is not SignatureVerificationOutcome.VALID:
        raise CryptoProviderContractError(
            "signature verifier returned an undeclared outcome"
        )
    token = object.__new__(ProofToken)
    object.__setattr__(token, "raw", accepted.raw)
    object.__setattr__(
        token,
        "token_digest",
        "sha256:" + sha256(accepted.raw.encode("ascii")).hexdigest(),
    )
    object.__setattr__(token, "proof_id", accepted.proof_id)
    object.__setattr__(token, "issued_at", accepted.issued_at)
    object.__setattr__(token, "expires_at", accepted.expires_at)
    return token


def _issuance_claims(
    prepared: _PreparedIssuance,
    *,
    issuer: str,
) -> TrustProofClaims:
    claims = object.__new__(TrustProofClaims)
    values = {
        "issuer": issuer,
        "subject": prepared.subject,
        "action": prepared.action,
        "resource": prepared.resource,
        "context_hash": prepared.context_hash,
        "trajectory_id": prepared.trajectory_id,
        "decision_id": prepared.decision_id,
        "issued_at": prepared.issued_at,
        "expires_at": prepared.expires_at,
        "proof_id": prepared.proof_id,
        "base_trust": prepared.base_trust,
        "effective_trust": prepared.effective_trust,
        "risk": prepared.risk,
        "velocity": prepared.velocity,
        "volatility": None,
        "context": prepared.context,
        "soul": SoulProofClaims(0, None, None, None, None, None, None),
        "lineage": prepared.lineage,
        "generation": prepared.generation,
        "sponsor": prepared.sponsor,
        "resilience_hash": prepared.resilience_hash,
        "zone": None,
        "oracle_quorum": None,
        "peer_share": prepared.peer_share,
        "applicable_ceilings": prepared.applicable_ceilings,
        "advancement_floor": prepared.advancement_floor,
        "root_instrument": prepared.root_instrument,
    }
    for name, value in values.items():
        object.__setattr__(claims, name, value)
    return claims


def _validate_pre_identity_bounds(prepared: _PreparedIssuance, /) -> None:
    claims = _issuance_claims(prepared, issuer="a:b")
    payload_segment = _segment(canonical_payload_bytes(claims))
    _require_payload_segment_width(payload_segment)
    minimum_header = _segment(
        _canonical_json_bytes({"alg": "ES256", "kid": "a", "typ": "ktp+jwt"})
    )
    signing_input = f"{minimum_header}.{payload_segment}".encode("ascii")
    _require_signing_input_width(signing_input)
    _require_compact_token_width(signing_input.decode("ascii") + "." + ("A" * 86))


def _project_root(
    status: RootInstrumentStatus,
    declaration: object,
) -> RootInstrumentClaim:
    if type(status) is not RootInstrumentStatus:
        raise ValueError("KTP-Core root status is outside the closed profile")
    projected = next(
        (
            proof_status
            for core_status, proof_status in _ROOT_STATUS_PROJECTION
            if status is core_status
        ),
        None,
    )
    if projected is None:
        raise ValueError("KTP-Core root status is outside the closed profile")
    if projected is ProofRootStatus.NONE:
        return RootInstrumentClaim(projected, None, None, None, None, None, None)
    if type(declaration) is not RootInstrumentDeclaration:
        raise TypeError("active KTP-Core root declaration is invalid")
    end_time = declaration.issuance.end_time.replace(microsecond=0)
    if declaration.sponsor_standing is not None:
        return RootInstrumentClaim(projected, end_time, None, None, None, None, None)
    return RootInstrumentClaim(
        projected,
        end_time,
        declaration.exposure_class,
        declaration.declared_exposure,
        declaration.anchored_capacity,
        declaration.terminator.identifier,
        len(declaration.chain),
    )


def _project_sponsor(lineage: LineagePhase, declaration: object) -> str | None:
    if lineage is not LineagePhase.SPONSORED:
        return None
    if (
        type(declaration) is not RootInstrumentDeclaration
        or declaration.sponsor_standing is None
    ):
        raise ValueError("sponsored standing has no selected sponsor")
    return validate_absolute_uri(
        declaration.sponsor_standing.agent_id,
        name="proof sponsor",
    )


def _segment(value: bytes, /) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
