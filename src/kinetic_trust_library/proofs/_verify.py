"""Private ordered Trust Proof verification kernel."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
from hashlib import sha256
from inspect import isawaitable
import re
from types import CoroutineType
from unicodedata import category, normalize

from kinetic_trust_library._decimal import KTP_CONTEXT, as_decimal
from kinetic_trust_library.errors import (
    CryptoConfigurationError,
    CryptoProviderContractError,
    CryptoProviderFailureError,
    CryptoProviderUnavailableError,
    InactiveVerificationKeyError,
    InvalidSignatureError,
    ProofClaimsError,
    ProofLifetimeError,
    RevokedVerificationKeyError,
    UnknownVerificationKeyError,
    UntrustedVerificationKeyError,
    ValidationError,
    VerificationKeySourceContractError,
    VerificationKeySourceFailureError,
    VerificationKeySourceUnavailableError,
)
from kinetic_trust_library.models.proof import (
    AsyncProofCrypto,
    AsyncVerifierBinding,
    CeilingClaim,
    KeyLookup,
    KeyPurpose,
    KeyResolution,
    ProofAlgorithm,
    ProofCrypto,
    ProofRootStatus,
    RiskFactorClaims,
    RootInstrumentClaim,
    TrustedVerificationKey,
    SignatureVerificationOutcome,
    SoulProofClaims,
    TrustProofClaims,
    UnknownVerificationKey,
    UntrustedVerificationKey,
    VerifierBinding,
    VerifiedTrustProof,
    _require_key_identifier,
    _require_proof_lifetime,
    _require_sha256,
    _require_uri,
)
from kinetic_trust_library.models.action import _validate_digest
from kinetic_trust_library.models._uri import validate_absolute_uri
from kinetic_trust_library.models.soul import SoulConstraintType
from kinetic_trust_library.models.standing import LineagePhase
from kinetic_trust_library.protocols import (
    AsyncVerificationKeySource,
    ProviderFailure,
    ProviderUnavailable,
)

from ._algorithms import (
    _PublicKeyShapeError,
    _SignatureShapeError,
    validate_es256_public_key,
    validate_es256_signature,
    validate_ed25519_public_key,
    validate_ed25519_signature,
)
from ._jwt import _require_enabled_algorithm, parse_compact, parse_payload


_TOP_CLAIM_MEMBERS = frozenset({"iss", "sub", "iat", "exp", "jti", "ktp"})
_KTP_REQUIRED_MEMBERS = frozenset(
    {
        "action",
        "resource",
        "context_hash",
        "trajectory_id",
        "decision_id",
        "e_base",
        "e_trust",
        "r",
        "context",
        "soul",
        "lineage",
        "generation",
        "resilience_hash",
        "peer_share",
        "applicable_ceilings",
        "advancement_floor",
        "root_instrument",
    }
)
_KTP_OPTIONAL_MEMBERS = frozenset(
    {"de_dt", "sigma", "sponsor", "zone", "oracle_quorum"}
)
_CONTEXT_MEMBERS = frozenset(
    {
        "evidence_density",
        "trust_trend",
        "adversarial_pressure",
        "update_resistance",
        "attestation_coverage",
        "moment_criticality",
    }
)
_SOUL_REQUIRED_MEMBERS = frozenset({"soul"})
_SOUL_OPTIONAL_MEMBERS = frozenset(
    {
        "constraint_type",
        "constraint_id",
        "constraint_name",
        "authority",
        "community",
        "remediation",
    }
)
_CEILING_MEMBERS = frozenset({"ceiling", "value"})
_ROOT_REQUIRED_MEMBERS = frozenset({"status"})
_ROOT_OPTIONAL_MEMBERS = frozenset(
    {
        "end_time",
        "exposure_class",
        "declared_exposure",
        "anchored_capacity",
        "terminator",
        "chain_length",
    }
)
_RESILIENCE_HASH = re.compile(r"^sha256:[a-f0-9]{64}$")
_ORACLE_QUORUM = re.compile(r"^[0-9]+-of-[0-9]+$")
_MAX_GENERATION = (2**63) - 1


@dataclass(frozen=True, slots=True)
class _PreparedVerification:
    raw: str
    cutoff: datetime
    lookup: KeyLookup
    verifier: object
    public_algorithm: ProofAlgorithm
    payload_bytes: bytes
    signing_input: bytes
    signature: bytes


@dataclass(frozen=True, slots=True)
class _AcceptedVerification:
    raw: str
    cutoff: datetime
    lookup: KeyLookup
    verifier: object
    payload_bytes: bytes
    signing_input: bytes
    signature: bytes
    verification_key: TrustedVerificationKey
    public_key: bytes


def _dispose_nested_native_coroutine(result: object, /) -> None:
    if type(result) is CoroutineType:
        for _ in range(2):
            disposal = GeneratorExit()
            try:
                CoroutineType.throw(result, disposal)
            except GeneratorExit as exc:
                if exc is not disposal:
                    raise
                return
            except Exception:
                # Downstream exact-type validation owns the contract classification.
                return


async def verify_async(
    raw: str,
    *,
    cutoff: datetime,
    crypto: AsyncProofCrypto,
    keys: AsyncVerificationKeySource,
) -> VerifiedTrustProof:
    prepared = prepare_verification(raw, cutoff=cutoff, crypto=crypto)
    provider_lookup = KeyLookup(
        untrusted_issuer=prepared.lookup.untrusted_issuer,
        key_id=prepared.lookup.key_id,
        algorithm=prepared.lookup.algorithm,
        purpose=prepared.lookup.purpose,
        cutoff=prepared.lookup.cutoff,
    )
    resolution = await _resolve_key(keys, provider_lookup)
    accepted = accept_key_resolution(prepared, resolution)
    outcome = await _verify_signature(
        accepted.verifier,
        public_key=accepted.public_key,
        signing_input=accepted.signing_input,
        signature=accepted.signature,
    )
    return complete_verification(accepted, outcome)


async def _resolve_key(
    keys: AsyncVerificationKeySource,
    lookup: KeyLookup,
    /,
) -> KeyResolution:
    try:
        resolve = keys.resolve
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
    try:
        operation = resolve(lookup)
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
    if not isawaitable(operation):
        raise VerificationKeySourceContractError(
            "async verification key source returned a non-awaitable result"
        )
    try:
        result = await operation
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
    _dispose_nested_native_coroutine(result)
    return result


async def _verify_signature(
    verifier: object,
    *,
    public_key: bytes,
    signing_input: bytes,
    signature: bytes,
) -> SignatureVerificationOutcome:
    try:
        verify = verifier.verify  # type: ignore[attr-defined]
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
    try:
        operation = verify(
            public_key=public_key,
            signing_input=signing_input,
            signature=signature,
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
    if not isawaitable(operation):
        raise CryptoProviderContractError(
            "async signature verifier returned a non-awaitable result"
        )
    try:
        result = await operation
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
    _dispose_nested_native_coroutine(result)
    return result


def prepare_verification(
    raw: str,
    *,
    cutoff: datetime,
    crypto: ProofCrypto | AsyncProofCrypto,
) -> _PreparedVerification:
    bindings = _validated_crypto_bindings(crypto)
    effective_cutoff = _require_exact_utc_cutoff(cutoff)
    parsed = parse_compact(raw)
    algorithms = tuple(algorithm for algorithm, _ in bindings)
    _require_enabled_algorithm(parsed.algorithm, algorithms)
    verifier = next(
        provider for algorithm, provider in bindings if algorithm is parsed.algorithm
    )
    lookup = KeyLookup(
        untrusted_issuer=parsed.untrusted_issuer,
        key_id=parsed.key_id,
        algorithm=parsed.algorithm,
        purpose=KeyPurpose.ORACLE_TRUST_PROOF,
        cutoff=effective_cutoff,
    )
    return _PreparedVerification(
        raw=parsed.raw,
        cutoff=effective_cutoff,
        lookup=lookup,
        verifier=verifier,
        public_algorithm=parsed.algorithm,
        payload_bytes=parsed.payload_bytes,
        signing_input=parsed.signing_input,
        signature=parsed.signature,
    )


def accept_key_resolution(
    prepared: _PreparedVerification,
    resolution: KeyResolution,
    /,
) -> _AcceptedVerification:
    if type(resolution) is UnknownVerificationKey:
        key_id = _resolution_key_id(resolution)
        if key_id != prepared.lookup.key_id:
            raise VerificationKeySourceContractError(
                "unknown key result does not match the requested key ID"
            )
        raise UnknownVerificationKeyError("verification key is unknown")
    if type(resolution) is UntrustedVerificationKey:
        key_id = _resolution_key_id(resolution)
        if key_id != prepared.lookup.key_id:
            raise VerificationKeySourceContractError(
                "untrusted key result does not match the requested key ID"
            )
        raise UntrustedVerificationKeyError(
            "verification key is not trusted for Trust Proofs"
        )
    if type(resolution) is not TrustedVerificationKey:
        raise VerificationKeySourceContractError(
            "verification key source returned an invalid result"
        )
    key = _own_trusted_key(resolution)
    if (
        key.issuer != prepared.lookup.untrusted_issuer
        or key.key_id != prepared.lookup.key_id
        or key.algorithm is not prepared.lookup.algorithm
        or key.purpose is not prepared.lookup.purpose
    ):
        raise VerificationKeySourceContractError(
            "trusted verification key does not match the requested facts"
        )
    if key.revoked_at is not None and key.revoked_at <= prepared.cutoff:
        raise RevokedVerificationKeyError("verification key is revoked")
    if prepared.cutoff < key.signing_not_before or (
        key.verification_not_after is not None
        and prepared.cutoff >= key.verification_not_after
    ):
        raise InactiveVerificationKeyError(
            "verification key is outside its verification window"
        )
    try:
        if key.algorithm is ProofAlgorithm.ES256:
            validate_es256_public_key(key.public_key)
        else:
            validate_ed25519_public_key(key.public_key)
    except _PublicKeyShapeError as exc:
        raise VerificationKeySourceContractError(
            "trusted verification key has invalid canonical bytes"
        ) from exc
    try:
        if key.algorithm is ProofAlgorithm.ES256:
            validate_es256_signature(prepared.signature)
        else:
            validate_ed25519_signature(prepared.signature)
    except _SignatureShapeError as exc:
        raise InvalidSignatureError(
            "proof signature has an invalid canonical shape"
        ) from exc
    return _AcceptedVerification(
        raw=prepared.raw,
        cutoff=prepared.cutoff,
        lookup=prepared.lookup,
        verifier=prepared.verifier,
        payload_bytes=prepared.payload_bytes,
        signing_input=prepared.signing_input,
        signature=prepared.signature,
        verification_key=key,
        public_key=key.public_key,
    )


def complete_verification(
    accepted: _AcceptedVerification,
    outcome: SignatureVerificationOutcome,
    /,
) -> VerifiedTrustProof:
    if type(outcome) is not SignatureVerificationOutcome:
        raise CryptoProviderContractError(
            "signature verifier returned an invalid outcome"
        )
    if outcome is SignatureVerificationOutcome.INVALID_SIGNATURE:
        raise InvalidSignatureError("proof signature is invalid")
    if outcome is SignatureVerificationOutcome.INVALID_PUBLIC_KEY:
        raise VerificationKeySourceContractError(
            "signature verifier rejected the trusted public key"
        )
    if outcome is not SignatureVerificationOutcome.VALID:
        raise CryptoProviderContractError(
            "signature verifier returned an undeclared outcome"
        )
    claims = _decode_authenticated_claims(accepted)
    result = object.__new__(VerifiedTrustProof)
    object.__setattr__(result, "raw", accepted.raw)
    object.__setattr__(
        result,
        "token_digest",
        "sha256:" + sha256(accepted.raw.encode("ascii")).hexdigest(),
    )
    object.__setattr__(result, "claims", claims)
    object.__setattr__(result, "verification_key", accepted.verification_key)
    return result


def _validate_authenticated_time_and_key(
    accepted: _AcceptedVerification,
    /,
    *,
    issuer: str,
    issued_at: datetime,
    expires_at: datetime,
) -> None:
    key = accepted.verification_key
    if issuer != key.issuer:
        raise ProofClaimsError(
            "authenticated proof issuer does not match the verification key"
        )
    if issued_at < key.signing_not_before or (
        key.signing_not_after is not None and issued_at >= key.signing_not_after
    ):
        raise InactiveVerificationKeyError(
            "verification key was outside its signing window at proof issuance"
        )
    try:
        _require_proof_lifetime(issued_at, expires_at)
    except ValidationError as exc:
        raise ProofLifetimeError("authenticated proof lifetime is invalid") from exc
    if not issued_at <= accepted.cutoff < expires_at:
        raise ProofLifetimeError("authenticated proof lifetime is invalid")


def _decode_authenticated_claims(
    accepted: _AcceptedVerification,
    /,
) -> TrustProofClaims:
    payload = parse_payload(accepted.payload_bytes)
    try:
        _require_claim_members(
            payload,
            required=_TOP_CLAIM_MEMBERS,
            allowed=_TOP_CLAIM_MEMBERS,
            name="proof payload",
        )
        ktp = _claims_object(payload["ktp"], name="ktp")
        _require_claim_members(
            ktp,
            required=_KTP_REQUIRED_MEMBERS,
            allowed=_KTP_REQUIRED_MEMBERS | _KTP_OPTIONAL_MEMBERS,
            name="ktp",
        )
        context_value = _claims_object(ktp["context"], name="context")
        _require_claim_members(
            context_value,
            required=_CONTEXT_MEMBERS,
            allowed=_CONTEXT_MEMBERS,
            name="context",
        )
        context = RiskFactorClaims(
            evidence_density=_claims_decimal(
                context_value["evidence_density"],
                name="evidence_density",
                minimum=0,
                maximum=1,
            ),
            trust_trend=_claims_decimal(
                context_value["trust_trend"],
                name="trust_trend",
                minimum=0,
                maximum=1,
            ),
            adversarial_pressure=_claims_decimal(
                context_value["adversarial_pressure"],
                name="adversarial_pressure",
                minimum=0,
                maximum=1,
            ),
            update_resistance=_claims_decimal(
                context_value["update_resistance"],
                name="update_resistance",
                minimum=0,
                maximum=1,
            ),
            attestation_coverage=_claims_decimal(
                context_value["attestation_coverage"],
                name="attestation_coverage",
                minimum=0,
                maximum=1,
            ),
            moment_criticality=_claims_decimal(
                context_value["moment_criticality"],
                name="moment_criticality",
                minimum=0,
                maximum=1,
            ),
        )
        soul_value = _claims_object(ktp["soul"], name="soul")
        _require_claim_members(
            soul_value,
            required=_SOUL_REQUIRED_MEMBERS,
            allowed=_SOUL_REQUIRED_MEMBERS | _SOUL_OPTIONAL_MEMBERS,
            name="soul",
        )
        constraint_type_value = soul_value.get("constraint_type")
        constraint_type = (
            None
            if constraint_type_value is None
            else SoulConstraintType(
                _claims_string(constraint_type_value, name="constraint_type")
            )
        )
        soul = SoulProofClaims(
            soul=_claims_integer(soul_value["soul"], name="soul"),
            constraint_type=constraint_type,
            constraint_id=_optional_claims_string(
                soul_value.get("constraint_id"), name="constraint_id"
            ),
            constraint_name=_optional_claims_string(
                soul_value.get("constraint_name"), name="constraint_name"
            ),
            authority=_optional_claims_string(
                soul_value.get("authority"), name="authority"
            ),
            community=_optional_claims_string(
                soul_value.get("community"), name="community"
            ),
            remediation=_optional_claims_string(
                soul_value.get("remediation"), name="remediation"
            ),
        )
        ceilings_value = ktp["applicable_ceilings"]
        if type(ceilings_value) is not list:
            raise TypeError("applicable ceilings must be an array")
        for value in ceilings_value:
            _require_claim_members(
                _claims_object(value, name="ceiling"),
                required=_CEILING_MEMBERS,
                allowed=_CEILING_MEMBERS,
                name="ceiling",
            )
        ceilings = tuple(
            CeilingClaim(
                ceiling=_claims_string(
                    _claims_object(value, name="ceiling")["ceiling"],
                    name="ceiling",
                ),
                value=_claims_decimal(
                    _claims_object(value, name="ceiling")["value"],
                    name="ceiling value",
                    minimum=0,
                    maximum=100,
                ),
            )
            for value in ceilings_value
        )
        root_value = _claims_object(ktp["root_instrument"], name="root instrument")
        _require_claim_members(
            root_value,
            required=_ROOT_REQUIRED_MEMBERS,
            allowed=_ROOT_REQUIRED_MEMBERS | _ROOT_OPTIONAL_MEMBERS,
            name="root instrument",
        )
        root_status = ProofRootStatus(
            _claims_string(root_value["status"], name="root status")
        )
        root_end_value = _optional_nonnull_claim(root_value, "end_time")
        root = RootInstrumentClaim(
            status=root_status,
            end_time=(
                None
                if root_end_value is None
                else _claims_numeric_date(root_end_value, name="root end time")
            ),
            exposure_class=_optional_claims_string(
                root_value.get("exposure_class"), name="root exposure class"
            ),
            declared_exposure=_optional_claims_decimal(
                root_value.get("declared_exposure"),
                name="root declared exposure",
                minimum=0,
            ),
            anchored_capacity=_optional_claims_decimal(
                root_value.get("anchored_capacity"),
                name="root anchored capacity",
                minimum=0,
            ),
            terminator=_optional_claims_string(
                root_value.get("terminator"), name="root terminator"
            ),
            chain_length=_optional_claims_integer(
                root_value.get("chain_length"), name="root chain length"
            ),
        )
        issuer = validate_absolute_uri(payload["iss"], name="proof issuer")
        subject = validate_absolute_uri(payload["sub"], name="proof subject")
        proof_id = _claims_identifier(payload["jti"], name="proof ID")
        issued_at = _claims_numeric_date(payload["iat"], name="issued at")
        expires_at = _claims_numeric_date(payload["exp"], name="expires at")
        lineage = LineagePhase(_claims_string(ktp["lineage"], name="lineage"))
        sponsor_value = _optional_nonnull_claim(ktp, "sponsor")
        sponsor = (
            None
            if sponsor_value is None
            else validate_absolute_uri(sponsor_value, name="proof sponsor")
        )
        base_trust = _claims_decimal(
            ktp["e_base"], name="base trust", minimum=0, maximum=100
        )
        effective_trust = _claims_decimal(
            ktp["e_trust"], name="effective trust", minimum=0, maximum=100
        )
        risk = _claims_decimal(ktp["r"], name="risk", minimum=0, maximum=1)
        generation = _claims_generation(ktp["generation"])
        peer_share = _claims_decimal(
            ktp["peer_share"], name="peer share", minimum=0, maximum=100
        )
        velocity = _optional_claims_decimal(
            _optional_nonnull_claim(ktp, "de_dt"), name="trust velocity"
        )
        volatility = _optional_claims_decimal(
            _optional_nonnull_claim(ktp, "sigma"),
            name="trust volatility",
            minimum=0,
        )
        resilience_hash = _claims_resilience_hash(ktp["resilience_hash"])
        zone = _optional_claims_string(
            _optional_nonnull_claim(ktp, "zone"), name="zone"
        )
        oracle_quorum = _optional_claims_quorum(
            _optional_nonnull_claim(ktp, "oracle_quorum")
        )
        advancement_floor = _claims_decimal(
            ktp["advancement_floor"], name="advancement floor", minimum=0
        )
        _validate_authenticated_time_and_key(
            accepted,
            issuer=issuer,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        _validate_core_coherence(
            base_trust=base_trust,
            effective_trust=effective_trust,
            risk=risk,
            lineage=lineage,
            generation=generation,
            sponsor=sponsor,
            sponsor_member="sponsor" in ktp,
            peer_share=peer_share,
            ceilings=ceilings,
            root=root,
        )
        _validate_root_coherence(
            root,
            lineage=lineage,
            expires_at=expires_at,
            cutoff=accepted.cutoff,
        )
        claims = object.__new__(TrustProofClaims)
        values = {
            "issuer": issuer,
            "subject": subject,
            "action": _validate_digest(ktp["action"], name="proof action"),
            "resource": _require_uri(ktp["resource"], name="proof resource"),
            "context_hash": _require_sha256(
                ktp["context_hash"], name="proof context hash"
            ),
            "trajectory_id": _require_key_identifier(
                ktp["trajectory_id"], name="trajectory ID"
            ),
            "decision_id": _require_key_identifier(
                ktp["decision_id"], name="decision ID"
            ),
            "issued_at": issued_at,
            "expires_at": expires_at,
            "proof_id": proof_id,
            "base_trust": base_trust,
            "effective_trust": effective_trust,
            "risk": risk,
            "velocity": velocity,
            "volatility": volatility,
            "context": context,
            "soul": soul,
            "lineage": lineage,
            "generation": generation,
            "sponsor": sponsor,
            "resilience_hash": resilience_hash,
            "zone": zone,
            "oracle_quorum": oracle_quorum,
            "peer_share": peer_share,
            "applicable_ceilings": ceilings,
            "advancement_floor": advancement_floor,
            "root_instrument": root,
        }
        for name, value in values.items():
            object.__setattr__(claims, name, value)
        return claims
    except (KeyError, OverflowError, TypeError, ValueError, ValidationError) as exc:
        raise ProofClaimsError("authenticated proof claims are invalid") from exc


def _validate_core_coherence(
    *,
    base_trust: Decimal,
    effective_trust: Decimal,
    risk: Decimal,
    lineage: LineagePhase,
    generation: int,
    sponsor: str | None,
    sponsor_member: bool,
    peer_share: Decimal,
    ceilings: tuple[CeilingClaim, ...],
    root: RootInstrumentClaim,
) -> None:
    if not _effective_trust_is_exact(base_trust, effective_trust, risk):
        raise ValueError("effective trust does not match base trust and risk")
    if generation <= 2:
        expected_lineage = LineagePhase.SPONSORED
    elif generation <= 6:
        expected_lineage = LineagePhase.INDEPENDENT
    else:
        expected_lineage = LineagePhase.GUARANTOR
    if lineage is not expected_lineage:
        raise ValueError("lineage does not match generation")
    if lineage is LineagePhase.SPONSORED:
        if not sponsor_member or sponsor is None:
            raise ValueError("sponsored lineage requires a sponsor")
    elif sponsor_member:
        raise ValueError("only sponsored lineage may carry a sponsor")
    if peer_share != 0 and not Decimal(10) <= peer_share <= Decimal(20):
        raise ValueError("peer share is outside the declared profile")
    if base_trust > _authenticated_base_upper_bound(
        peer_share=peer_share,
        lineage=lineage,
        root=root,
    ):
        raise ValueError("base trust exceeds authenticated composition capacity")
    ceiling_names = tuple(ceiling.ceiling for ceiling in ceilings)
    if len(frozenset(ceiling_names)) != len(ceiling_names):
        raise ValueError("applicable ceiling names must be unique")
    required = frozenset({"generation", "ial", "trajectory", "adversity"})
    if not required <= frozenset(ceiling_names):
        raise ValueError("required Library ceilings are missing")
    generation_ceiling = (
        Decimal((25, 35, 45, 55, 65, 75, 85)[generation])
        if generation <= 6
        else Decimal(100)
    )
    declared_generation_ceiling = next(
        ceiling.value for ceiling in ceilings if ceiling.ceiling == "generation"
    )
    if declared_generation_ceiling != generation_ceiling:
        raise ValueError("generation ceiling does not match generation")
    if base_trust > min(ceiling.value for ceiling in ceilings):
        raise ValueError("base trust exceeds an applicable ceiling")


def _authenticated_base_upper_bound(
    *,
    peer_share: Decimal,
    lineage: LineagePhase,
    root: RootInstrumentClaim,
) -> Decimal:
    with localcontext(KTP_CONTEXT):
        remaining = Decimal(100) - peer_share
        por_share = Decimal(70) * remaining / Decimal(100)
        root_share = Decimal(30) * remaining / Decimal(100)
        if root.status is ProofRootStatus.NONE:
            root_score = Decimal(0)
        elif lineage is LineagePhase.SPONSORED:
            root_score = Decimal(100)
        else:
            if (
                root.declared_exposure is None
                or root.anchored_capacity is None
                or root.anchored_capacity <= 0
            ):
                raise ValueError("active non-sponsored root arithmetic is incomplete")
            root_score = min(
                Decimal(100),
                Decimal(100) * root.declared_exposure / root.anchored_capacity,
            )
        root_contribution = root_score * root_share / Decimal(100)
        return por_share + root_contribution + peer_share


def _effective_trust_is_exact(
    base_trust: Decimal,
    effective_trust: Decimal,
    risk: Decimal,
    /,
) -> bool:
    with localcontext(KTP_CONTEXT):
        return effective_trust == base_trust * (Decimal(1) - risk)


def _validate_root_coherence(
    root: RootInstrumentClaim,
    /,
    *,
    lineage: LineagePhase,
    expires_at: datetime,
    cutoff: datetime,
) -> None:
    if root.status is ProofRootStatus.NONE:
        return
    if root.end_time is None:
        raise ValueError("active root instrument requires an end time")
    if expires_at > root.end_time or cutoff >= root.end_time:
        raise ProofLifetimeError(
            "authenticated proof outlives its active root instrument"
        )
    details = (
        root.exposure_class,
        root.declared_exposure,
        root.anchored_capacity,
        root.terminator,
        root.chain_length,
    )
    if lineage is LineagePhase.SPONSORED:
        if any(value is not None for value in details):
            raise ValueError(
                "sponsored root instrument must not carry attestation details"
            )
        return
    if any(value is None for value in details):
        raise ValueError("independent and guarantor roots require attestation details")
    if root.anchored_capacity is None or root.anchored_capacity <= 0:
        raise ValueError("root anchored capacity must be positive")
    if root.chain_length is None or root.chain_length > 12:
        raise ValueError("root chain length exceeds the hard protocol bound")


def _claims_object(value: object, /, *, name: str) -> dict[str, object]:
    if type(value) is not dict:
        raise TypeError(f"{name} must be an object")
    return value


def _require_claim_members(
    value: dict[str, object],
    /,
    *,
    required: frozenset[str],
    allowed: frozenset[str],
    name: str,
) -> None:
    members = set(value)
    if not required <= members or not members <= allowed:
        raise TypeError(f"{name} members are invalid")


def _optional_nonnull_claim(
    value: dict[str, object],
    member: str,
    /,
) -> object | None:
    if member not in value:
        return None
    result = value[member]
    if result is None:
        raise TypeError(f"{member} must not be null")
    return result


def _claims_string(value: object, /, *, name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{name} must be a string")
    encoded = value.encode("utf-8")
    if len(encoded) > 4_096:
        raise ValueError(f"{name} exceeds its UTF-8 bound")
    if normalize("NFC", value) != value:
        raise ValueError(f"{name} must use NFC Unicode")
    return value


def _optional_claims_string(value: object, /, *, name: str) -> str | None:
    if value is None:
        return None
    return _claims_string(value, name=name)


def _claims_integer(value: object, /, *, name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    return value


def _optional_claims_integer(value: object, /, *, name: str) -> int | None:
    if value is None:
        return None
    return _claims_integer(value, name=name)


def _claims_generation(value: object, /) -> int:
    generation = _claims_integer(value, name="generation")
    if not 0 <= generation <= _MAX_GENERATION:
        raise ValueError("generation is outside its bounded range")
    return generation


def _claims_resilience_hash(value: object, /) -> str:
    resilience_hash = _claims_string(value, name="resilience hash")
    if _RESILIENCE_HASH.fullmatch(resilience_hash) is None:
        raise ValueError("resilience hash must be canonical SHA-256")
    return resilience_hash


def _optional_claims_quorum(value: object, /) -> str | None:
    if value is None:
        return None
    quorum = _claims_string(value, name="oracle quorum")
    if _ORACLE_QUORUM.fullmatch(quorum) is None:
        raise ValueError("oracle quorum is malformed")
    return quorum


def _claims_decimal(
    value: object,
    /,
    *,
    name: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> Decimal:
    if type(value) is not int and type(value) is not Decimal:
        raise TypeError(f"{name} must be a number")
    return as_decimal(value, name=name, minimum=minimum, maximum=maximum)


def _optional_claims_decimal(
    value: object,
    /,
    *,
    name: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> Decimal | None:
    if value is None:
        return None
    return _claims_decimal(value, name=name, minimum=minimum, maximum=maximum)


def _claims_numeric_date(value: object, /, *, name: str) -> datetime:
    seconds = _claims_integer(value, name=name)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    return epoch + timedelta(seconds=seconds)


def _claims_identifier(value: object, /, *, name: str) -> str:
    result = _claims_string(value, name=name)
    encoded = result.encode("utf-8")
    if not result or len(encoded) > 256:
        raise ValueError(f"{name} is outside its byte bound")
    if normalize("NFC", result) != result:
        raise ValueError(f"{name} must use NFC Unicode")
    if any(character.isspace() for character in result):
        raise ValueError(f"{name} must not contain whitespace")
    if any(category(character) in {"Cc", "Cf"} for character in result):
        raise ValueError(f"{name} must not contain controls")
    return result


def _resolution_key_id(
    resolution: UnknownVerificationKey | UntrustedVerificationKey,
    /,
) -> str:
    try:
        key_id = resolution.key_id
        type(resolution)(key_id)
    except (AttributeError, TypeError, ValidationError) as exc:
        raise VerificationKeySourceContractError(
            "verification key source returned a malformed key status"
        ) from exc
    return key_id


def _own_trusted_key(resolution: TrustedVerificationKey, /) -> TrustedVerificationKey:
    try:
        return TrustedVerificationKey(
            issuer=resolution.issuer,
            key_id=resolution.key_id,
            algorithm=resolution.algorithm,
            purpose=resolution.purpose,
            public_key=resolution.public_key,
            signing_not_before=resolution.signing_not_before,
            signing_not_after=resolution.signing_not_after,
            verification_not_after=resolution.verification_not_after,
            revoked_at=resolution.revoked_at,
        )
    except (AttributeError, TypeError, ValidationError) as exc:
        raise VerificationKeySourceContractError(
            "verification key source returned malformed trusted facts"
        ) from exc


def _validated_crypto_bindings(
    crypto: object,
    /,
) -> tuple[tuple[ProofAlgorithm, object], ...]:
    if type(crypto) is ProofCrypto:
        binding_type = VerifierBinding
        configuration_name = "proof"
    elif type(crypto) is AsyncProofCrypto:
        binding_type = AsyncVerifierBinding
        configuration_name = "async proof"
    else:
        raise CryptoConfigurationError(
            "Trust Proof facade requires an exact proof crypto configuration"
        )
    try:
        bindings = crypto.bindings
    except AttributeError as exc:
        raise CryptoConfigurationError(
            f"{configuration_name} verifier bindings are missing"
        ) from exc
    if type(bindings) is not tuple:
        raise CryptoConfigurationError(
            f"{configuration_name} verifier bindings must be an owned tuple"
        )
    normalized: list[tuple[ProofAlgorithm, object]] = []
    for binding in bindings:
        if type(binding) is not binding_type:
            raise CryptoConfigurationError(
                f"{configuration_name} verifier binding is invalid"
            )
        try:
            algorithm = binding.algorithm
            verifier = binding.verifier
        except AttributeError as exc:
            raise CryptoConfigurationError(
                f"{configuration_name} verifier binding is incomplete"
            ) from exc
        if type(algorithm) is not ProofAlgorithm or (
            algorithm is not ProofAlgorithm.ES256
            and algorithm is not ProofAlgorithm.ED25519
        ):
            raise CryptoConfigurationError(
                f"{configuration_name} verifier algorithm is invalid"
            )
        normalized.append((algorithm, verifier))
    algorithms = tuple(algorithm for algorithm, _ in normalized)
    if ProofAlgorithm.ES256 not in algorithms:
        raise CryptoConfigurationError("ES256 verifier binding is required")
    if len(frozenset(algorithms)) != len(algorithms):
        raise CryptoConfigurationError("proof verifier algorithm is duplicated")
    if any(
        algorithm not in (ProofAlgorithm.ES256, ProofAlgorithm.ED25519)
        for algorithm in algorithms
    ):
        raise CryptoConfigurationError("proof verifier algorithm is unsupported")
    return tuple(normalized)


def _require_exact_utc_cutoff(cutoff: object, /) -> datetime:
    if type(cutoff) is not datetime:
        raise ValidationError("proof verification cutoff must be an exact datetime")
    if cutoff.tzinfo is not timezone.utc:
        raise ValidationError("proof verification cutoff must use exact UTC")
    return cutoff
