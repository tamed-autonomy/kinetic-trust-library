"""Derive lineage standing, External Root, ceilings, and authoritative E_base."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, localcontext

from kinetic_trust_library._canonical import canonical_json_bytes, canonical_sha256
from kinetic_trust_library._decimal import KTP_CONTEXT, as_decimal
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models._common import utc_time, validate_identifier
from kinetic_trust_library.models.profile import (
    DeploymentProfile,
    _ValidatedProfileContext,
    _bind_profile_to_context,
    _profile_from_context,
    _validated_profile_context,
    require_validated_profile as require_validated_profile,
)
from kinetic_trust_library.models.standing import (
    AdjudicationFindingOutcome,
    CeilingDeclaration,
    ExternalTerminatorDeclaration,
    ExternalTerminatorKind,
    LineagePhase,
    NoRootInstrumentDeclaration,
    PeerScoreDeclaration,
    PoRAttestationDeclaration,
    PoRResult,
    RootAdjudicationFinding,
    RootDeclaration,
    RootInstrumentDeclaration,
    RootInstrumentStatus,
    RootIssuanceDeclaration,
    RootWithdrawalClaim,
    ShareAllocation,
    StandingDeclaration,
    StandingSnapshot,
    WithdrawalCause,
)

from .por import calculate_por, require_validated_por_result


MAX_PEER_EVIDENCE_IDS = 2_048
MAX_PEER_PROVENANCE_REFS = 2_048

_MAX_COUNTER = (1 << 63) - 1
_RESERVED_CEILINGS = frozenset(("generation", "ial", "trajectory", "adversity"))
_ZERO_ROOT_STATUSES = frozenset(
    (
        RootInstrumentStatus.EXPIRED,
        RootInstrumentStatus.FOR_CAUSE_PENDING,
        RootInstrumentStatus.FOR_CAUSE_SUSTAINED,
        RootInstrumentStatus.FOR_CAUSE_REJECTED,
        RootInstrumentStatus.FOR_CAUSE_UNRESOLVED,
        RootInstrumentStatus.MISATTESTATION,
        RootInstrumentStatus.NONE,
    )
)


class _SnapshotValidationState:
    """Per-operation identity memo for bounded sponsor snapshot validation."""

    __slots__ = ("active", "completed", "profile_context")

    def __init__(self, profile_context: _ValidatedProfileContext) -> None:
        self.active: dict[int, StandingSnapshot] = {}
        self.completed: dict[int, StandingSnapshot] = {}
        self.profile_context = profile_context


def prepare_standing(
    profile: DeploymentProfile,
    declaration: StandingDeclaration,
    cutoff: datetime,
) -> StandingSnapshot:
    """Validate raw standing facts and calculate full published E_base."""
    return _prepare_standing_with_context(
        _validated_profile_context(profile), declaration, cutoff
    )


def _prepare_standing_with_context(
    context: object,
    declaration: StandingDeclaration,
    cutoff: datetime,
) -> StandingSnapshot:
    effective_profile = _profile_from_context(context)
    effective_cutoff = utc_time(cutoff, name="standing cutoff")
    return _prepare_standing(
        effective_profile,
        declaration,
        effective_cutoff,
        validating_agents=frozenset(),
        validation_state=_SnapshotValidationState(context),
    )


def require_validated_standing_snapshot(
    value: object, *, profile: DeploymentProfile | None = None
) -> StandingSnapshot:
    """Rederive a standing snapshot from every represented declaration."""
    if type(value) is not StandingSnapshot:
        raise ValidationError("value is not a validated standing snapshot")
    try:
        stored_profile = value._profile
        context = _validated_profile_context(
            stored_profile if profile is None else profile
        )
    except Exception as exc:
        raise ValidationError("standing snapshot integrity is invalid") from exc
    return _require_validated_standing_snapshot_with_context(value, context)


def _require_validated_standing_snapshot_with_context(
    value: object,
    context: object,
) -> StandingSnapshot:
    """Private standing rederivation against one already validated profile."""
    if type(value) is not StandingSnapshot:
        raise ValidationError("value is not a validated standing snapshot")
    try:
        effective_profile = _require_profile_binding(value._profile, context)
        return _require_standing_snapshot_with_profile(
            value,
            profile=effective_profile,
            expected_cutoff=None,
            validating_agents=frozenset(),
            validation_state=_SnapshotValidationState(context),
        )
    except Exception as exc:
        raise ValidationError("standing snapshot integrity is invalid") from exc


def _prepare_standing(
    profile: DeploymentProfile,
    declaration: StandingDeclaration,
    cutoff: datetime,
    *,
    validating_agents: frozenset[str],
    validation_state: _SnapshotValidationState,
) -> StandingSnapshot:
    normalized, por, lineage = _validate_standing_declaration(
        declaration,
        profile=profile,
        cutoff=cutoff,
        validating_agents=validating_agents,
        validation_state=validation_state,
    )
    root_score, selected_root, root_status = _select_root(
        normalized.root_instruments, lineage=lineage, cutoff=cutoff
    )
    shares = _shares(profile.peer_share)
    ceilings = _ceilings(normalized, por=por)
    peer_score = Decimal(0) if normalized.peer is None else normalized.peer.score
    with localcontext(KTP_CONTEXT):
        raw_base = (
            por.contribution * (shares.por / Decimal(70))
            + root_score * (shares.root / Decimal(100))
            + peer_score * (shares.peer / Decimal(100))
        )
        base_trust = min(raw_base, *(item.value for item in ceilings))

    snapshot = object.__new__(StandingSnapshot)
    for name, member in (
        ("agent_id", normalized.agent_id),
        ("generation", normalized.generation),
        ("lineage", lineage),
        ("por", por),
        ("root_score", root_score),
        ("root_instrument", selected_root),
        ("root_status", root_status),
        ("peer", normalized.peer),
        ("shares", shares),
        ("applicable_ceilings", ceilings),
        ("advancement_floor", normalized.advancement_floor),
        ("base_trust", base_trust),
        ("_profile", profile),
        ("_declaration", normalized),
        ("_cutoff", cutoff),
    ):
        object.__setattr__(snapshot, name, member)
    object.__setattr__(
        snapshot, "digest", canonical_sha256(_standing_digest_input(snapshot))
    )
    return snapshot


def _require_standing_snapshot_with_profile(
    value: StandingSnapshot,
    *,
    profile: DeploymentProfile,
    expected_cutoff: datetime | None,
    validating_agents: frozenset[str],
    validation_state: _SnapshotValidationState,
) -> StandingSnapshot:
    _require_standing_structure(value, validation_state=validation_state)
    _require_profile_binding(value._profile, validation_state.profile_context)
    if expected_cutoff is not None and value._cutoff != expected_cutoff:
        raise ValidationError("sponsor standing cutoff does not match")
    normalized = _prepare_standing(
        profile,
        value._declaration,
        value._cutoff,
        validating_agents=validating_agents,
        validation_state=validation_state,
    )
    actual = canonical_json_bytes(_standing_public_projection(value))
    expected = canonical_json_bytes(_standing_public_projection(normalized))
    if actual != expected:
        raise ValidationError("standing does not match represented declarations")
    return value


def _require_profile_binding(
    stored: object,
    context: _ValidatedProfileContext,
) -> DeploymentProfile:
    try:
        return _bind_profile_to_context(context, stored)
    except ValidationError as exc:
        raise ValidationError("standing snapshot belongs to another profile") from exc


def _validate_standing_declaration(
    value: object,
    *,
    profile: DeploymentProfile,
    cutoff: datetime,
    validating_agents: frozenset[str],
    validation_state: _SnapshotValidationState,
) -> tuple[StandingDeclaration, PoRResult, LineagePhase]:
    if type(value) is not StandingDeclaration:
        raise ValidationError("standing must use the explicit declaration")
    try:
        value = StandingDeclaration(
            agent_id=value.agent_id,
            generation=value.generation,
            identity_assurance_level=value.identity_assurance_level,
            trajectory_length=value.trajectory_length,
            por_attestations=value.por_attestations,
            root_instruments=value.root_instruments,
            peer=value.peer,
            additional_ceilings=value.additional_ceilings,
            advancement_floor=value.advancement_floor,
        )
    except AttributeError as exc:
        raise ValidationError("standing declaration structure is invalid") from exc
    generation = _bounded_int(
        value.generation, name="generation", minimum=0, maximum=_MAX_COUNTER
    )
    agent_id, lineage = _agent_identifier(value.agent_id, generation=generation)
    if agent_id in validating_agents:
        raise ValidationError("sponsor standing graph must be acyclic")
    current_agents = validating_agents | {agent_id}
    if agent_id == profile.misattestation_adjudicator:
        raise ValidationError("misattestation adjudicator must differ from subject")
    ial = _bounded_int(
        value.identity_assurance_level,
        name="identity assurance level",
        minimum=1,
        maximum=3,
    )
    trajectory = _bounded_int(
        value.trajectory_length,
        name="trajectory length",
        minimum=0,
        maximum=_MAX_COUNTER,
    )
    if type(value.por_attestations) is not tuple:
        raise ValidationError("PoR attestations must be a tuple")
    normalized_por = calculate_por(
        value.por_attestations, agent_id=agent_id, cutoff=cutoff
    )
    attestations = normalized_por._attestations
    if type(value.root_instruments) is not tuple or not value.root_instruments:
        raise ValidationError("root instruments must be a non-empty tuple")
    roots = _validate_roots(
        value.root_instruments,
        profile=profile,
        agent_id=agent_id,
        lineage=lineage,
        cutoff=cutoff,
        validating_agents=current_agents,
        validation_state=validation_state,
    )
    ceilings = _validate_additional_ceilings(value.additional_ceilings)
    applicable_ceilings = (
        *_built_in_ceilings(
            generation=generation,
            identity_assurance_level=ial,
            trajectory_length=trajectory,
            por=normalized_por,
        ),
        *ceilings,
    )
    peer = _validate_peer(
        value.peer,
        peer_share=profile.peer_share,
        agent_id=agent_id,
        por_digest=normalized_por.digest,
        attestations=attestations,
        roots=roots,
        ceilings=applicable_ceilings,
    )
    advancement_floor = as_decimal(
        value.advancement_floor, name="advancement floor", minimum=0
    )
    normalized = StandingDeclaration(
        agent_id=agent_id,
        generation=generation,
        identity_assurance_level=ial,
        trajectory_length=trajectory,
        por_attestations=attestations,
        root_instruments=roots,
        peer=peer,
        additional_ceilings=ceilings,
        advancement_floor=advancement_floor,
    )
    return normalized, normalized_por, lineage


def _validate_roots(
    values: tuple[RootDeclaration, ...],
    *,
    profile: DeploymentProfile,
    agent_id: str,
    lineage: LineagePhase,
    cutoff: datetime,
    validating_agents: frozenset[str],
    validation_state: _SnapshotValidationState,
) -> tuple[RootDeclaration, ...]:
    roots: list[RootDeclaration] = []
    instrument_ids: set[str] = set()
    attestors: set[str] = set()
    explicit_none = False
    for value in values:
        if type(value) is NoRootInstrumentDeclaration:
            try:
                instrument_id = value.instrument_id
            except AttributeError as exc:
                raise ValidationError("no-root instrument structure is invalid") from exc
            root: RootDeclaration = NoRootInstrumentDeclaration(
                _identifier(instrument_id, name="root instrument ID")
            )
            explicit_none = True
        else:
            root = _validate_root(
                value,
                profile=profile,
                agent_id=agent_id,
                lineage=lineage,
                cutoff=cutoff,
                validating_agents=validating_agents,
                validation_state=validation_state,
            )
            if root.attestor in attestors:
                raise ValidationError("concurrent root attestors must be distinct")
            attestors.add(root.attestor)
        if root.instrument_id in instrument_ids:
            raise ValidationError(f"duplicate root instrument ID: {root.instrument_id}")
        instrument_ids.add(root.instrument_id)
        roots.append(root)
    if explicit_none and len(roots) != 1:
        raise ValidationError("explicit no-instrument root cannot be combined")
    return tuple(sorted(roots, key=lambda item: item.instrument_id))


def _validate_root(
    value: object,
    *,
    profile: DeploymentProfile,
    agent_id: str,
    lineage: LineagePhase,
    cutoff: datetime,
    validating_agents: frozenset[str],
    validation_state: _SnapshotValidationState,
) -> RootInstrumentDeclaration:
    if type(value) is not RootInstrumentDeclaration:
        raise ValidationError("root instrument must use the explicit declaration")
    try:
        instrument_id = value.instrument_id
        attestor = value.attestor
        issuance = value.issuance
        sponsor_standing = value.sponsor_standing
        stake_percentage = value.stake_percentage
        exposure_class = value.exposure_class
        declared_exposure = value.declared_exposure
        anchored_capacity = value.anchored_capacity
        chain = value.chain
        terminator = value.terminator
        withdrawal_claim = value.withdrawal_claim
        adjudication_finding = value.adjudication_finding
    except AttributeError as exc:
        raise ValidationError("root instrument structure is invalid") from exc
    instrument_id = _identifier(instrument_id, name="root instrument ID")
    attestor = _identifier(attestor, name="root attestor")
    if attestor in {agent_id, profile.misattestation_adjudicator}:
        raise ValidationError("root attestor must differ from subject and adjudicator")
    issuance = _validate_issuance(issuance, cutoff=cutoff)
    terminator = _validate_terminator(terminator)
    chain = _validate_chain(
        chain,
        terminator=terminator,
        agent_id=agent_id,
        attestor=attestor,
        hop_bound=profile.external_root_hop_bound,
    )
    withdrawal = _validate_withdrawal(
        withdrawal_claim,
        attestor=attestor,
        issuance=issuance,
        cutoff=cutoff,
    )
    finding = _validate_finding(
        adjudication_finding,
        withdrawal=withdrawal,
        profile=profile,
        agent_id=agent_id,
        attestor=attestor,
        issuance=issuance,
        cutoff=cutoff,
    )
    if lineage is LineagePhase.SPONSORED:
        sponsor, stake = _validate_sponsor(
            RootInstrumentDeclaration(
                instrument_id=instrument_id,
                attestor=attestor,
                issuance=issuance,
                sponsor_standing=sponsor_standing,
                stake_percentage=stake_percentage,
                exposure_class=exposure_class,
                declared_exposure=declared_exposure,
                anchored_capacity=anchored_capacity,
                chain=chain,
                terminator=terminator,
                withdrawal_claim=withdrawal,
                adjudication_finding=finding,
            ),
            profile=profile,
            cutoff=cutoff,
            subject_agent_id=agent_id,
            attestor=attestor,
            chain=chain,
            terminator=terminator,
            validating_agents=validating_agents,
            validation_state=validation_state,
        )
        exposure_class = None
        exposure = None
        capacity = None
    else:
        if sponsor_standing is not None or stake_percentage is not None:
            raise ValidationError("independent roots must not use sponsorship fields")
        sponsor = None
        stake = None
        exposure_class = _identifier(exposure_class, name="exposure class")
        exposure = as_decimal(
            declared_exposure, name="declared exposure", minimum=0
        )
        capacity = as_decimal(
            anchored_capacity, name="anchored capacity", minimum=0
        )
        if capacity == 0:
            raise ValidationError("anchored capacity must be positive")
    return RootInstrumentDeclaration(
        instrument_id=instrument_id,
        attestor=attestor,
        issuance=issuance,
        sponsor_standing=sponsor,
        stake_percentage=stake,
        exposure_class=exposure_class,
        declared_exposure=exposure,
        anchored_capacity=capacity,
        chain=chain,
        terminator=terminator,
        withdrawal_claim=withdrawal,
        adjudication_finding=finding,
    )


def _validate_sponsor(
    value: RootInstrumentDeclaration,
    *,
    profile: DeploymentProfile,
    cutoff: datetime,
    subject_agent_id: str,
    attestor: str,
    chain: tuple[str, ...],
    terminator: ExternalTerminatorDeclaration,
    validating_agents: frozenset[str],
    validation_state: _SnapshotValidationState,
) -> tuple[StandingSnapshot, Decimal]:
    if type(value.sponsor_standing) is not StandingSnapshot:
        raise ValidationError("sponsored root requires validated sponsor standing")
    try:
        _require_shallow_guarantor_sponsor(value.sponsor_standing)
        sponsor = _require_standing_snapshot_with_profile(
            value.sponsor_standing,
            profile=profile,
            expected_cutoff=cutoff,
            validating_agents=validating_agents,
            validation_state=validation_state,
        )
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError("sponsor standing integrity is invalid") from exc
    if (
        sponsor.lineage is not LineagePhase.GUARANTOR
        or sponsor.generation < 7
        or sponsor._declaration.identity_assurance_level < 2
    ):
        raise ValidationError("sponsor is not lineage and identity eligible")
    if sponsor.agent_id != attestor:
        raise ValidationError("sponsor standing does not match root attestor")
    subject_sponsor = subject_agent_id.split(":")[2]
    sponsor_parts = sponsor.agent_id.split(":")
    if subject_sponsor != sponsor_parts[4]:
        raise ValidationError("sponsor identifier does not match sponsored Agent")
    if (
        type(sponsor.root_instrument) is not RootInstrumentDeclaration
        or sponsor.root_status
        not in {RootInstrumentStatus.CURRENT, RootInstrumentStatus.NON_RENEWABLE}
        or sponsor.root_score <= 0
    ):
        raise ValidationError("sponsor lacks a current external root")
    expected_chain = (sponsor.root_instrument.attestor, *sponsor.root_instrument.chain)
    if chain != expected_chain or terminator != sponsor.root_instrument.terminator:
        raise ValidationError("sponsorship chain does not bind the sponsor root")
    stake = as_decimal(
        value.stake_percentage, name="stake percentage", minimum=1, maximum=50
    )
    with localcontext(KTP_CONTEXT):
        stake_amount = sponsor.base_trust * stake / Decimal(100)
    ial_limit = Decimal(
        20 if sponsor._declaration.identity_assurance_level == 2 else 50
    )
    if stake_amount > ial_limit:
        raise ValidationError("sponsor stake exceeds its identity assurance limit")
    if any(
        item is not None
        for item in (
            value.exposure_class,
            value.declared_exposure,
            value.anchored_capacity,
        )
    ):
        raise ValidationError("sponsored roots must use sponsorship fields only")
    return sponsor, stake


def _validate_issuance(value: object, *, cutoff: datetime) -> RootIssuanceDeclaration:
    if type(value) is not RootIssuanceDeclaration:
        raise ValidationError("root issuance must use the explicit declaration")
    try:
        issued_at = value.issued_at
        end_time = value.end_time
        verification_ref = value.verification_ref
    except AttributeError as exc:
        raise ValidationError("root issuance structure is invalid") from exc
    issued_at = utc_time(issued_at, name="root issuance time")
    end_time = utc_time(end_time, name="root instrument end time")
    if issued_at > cutoff:
        raise ValidationError("root issuance is after the standing cutoff")
    if end_time <= issued_at:
        raise ValidationError("root expiry must be after issuance")
    return RootIssuanceDeclaration(
        issued_at,
        end_time,
        _identifier(
            verification_ref, name="root issuance verification reference"
        ),
    )


def _validate_terminator(value: object) -> ExternalTerminatorDeclaration:
    if type(value) is not ExternalTerminatorDeclaration:
        raise ValidationError("external terminator must use the typed declaration")
    try:
        kind = value.kind
        identifier = value.identifier
        verification_ref = value.verification_ref
    except AttributeError as exc:
        raise ValidationError("external terminator structure is invalid") from exc
    if type(kind) is not ExternalTerminatorKind:
        raise ValidationError("external terminator kind is invalid")
    identifier = _identifier(identifier, name="external terminator identifier")
    if identifier.startswith("agent:"):
        raise ValidationError("external terminator cannot use the Agent namespace")
    return ExternalTerminatorDeclaration(
        kind,
        identifier,
        _identifier(
            verification_ref,
            name="external terminator verification reference",
        ),
    )


def _validate_chain(
    value: object,
    *,
    terminator: ExternalTerminatorDeclaration,
    agent_id: str,
    attestor: str,
    hop_bound: int,
) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise ValidationError("root accountability chain must be a tuple")
    if not value or len(value) > hop_bound:
        raise ValidationError("root accountability chain exceeds its hop bound")
    chain = tuple(_identifier(item, name="root accountability hop") for item in value)
    if len(frozenset(chain)) != len(chain) or agent_id in chain or attestor in chain:
        raise ValidationError("root accountability chain must be acyclic")
    if chain[-1] != terminator.identifier:
        raise ValidationError("root accountability chain must end at its terminator")
    return chain


def _validate_withdrawal(
    value: object,
    *,
    attestor: str,
    issuance: RootIssuanceDeclaration,
    cutoff: datetime,
) -> RootWithdrawalClaim | None:
    if value is None:
        return None
    if type(value) is not RootWithdrawalClaim:
        raise ValidationError("root withdrawal must use the typed claim")
    try:
        claim_id = value.claim_id
        declared_by = value.declared_by
        cause = value.cause
        claimed_at = value.claimed_at
        evidence_ref = value.evidence_ref
    except AttributeError as exc:
        raise ValidationError("root withdrawal structure is invalid") from exc
    if type(cause) is not WithdrawalCause:
        raise ValidationError("root withdrawal cause is invalid")
    declared_by = _identifier(declared_by, name="withdrawal declarant")
    if declared_by != attestor:
        raise ValidationError("root withdrawal must be declared by its attestor")
    claimed_at = utc_time(claimed_at, name="root withdrawal claim time")
    if not issuance.issued_at <= claimed_at < issuance.end_time:
        raise ValidationError("root withdrawal claim is outside instrument validity")
    if claimed_at > cutoff:
        raise ValidationError("root withdrawal claim is after the standing cutoff")
    return RootWithdrawalClaim(
        _identifier(claim_id, name="root withdrawal claim ID"),
        declared_by,
        cause,
        claimed_at,
        _identifier(evidence_ref, name="root withdrawal evidence reference"),
    )


def _validate_finding(
    value: object,
    *,
    withdrawal: RootWithdrawalClaim | None,
    profile: DeploymentProfile,
    agent_id: str,
    attestor: str,
    issuance: RootIssuanceDeclaration,
    cutoff: datetime,
) -> RootAdjudicationFinding | None:
    if value is None:
        return None
    if type(value) is not RootAdjudicationFinding:
        raise ValidationError("root finding must use the typed declaration")
    try:
        finding_id = value.finding_id
        adjudicator_id = value.adjudicator_id
        outcome = value.outcome
        found_at = value.found_at
        claim_id = value.claim_id
        evidence_ref = value.evidence_ref
    except AttributeError as exc:
        raise ValidationError("root finding structure is invalid") from exc
    if type(outcome) is not AdjudicationFindingOutcome:
        raise ValidationError("root finding outcome is invalid")
    adjudicator = _identifier(adjudicator_id, name="root adjudicator ID")
    if adjudicator != profile.misattestation_adjudicator:
        raise ValidationError("root finding uses an undeclared adjudicator")
    if adjudicator in {agent_id, attestor}:
        raise ValidationError("root adjudicator must differ from subject and attestor")
    found_at = utc_time(found_at, name="root finding time")
    if not issuance.issued_at <= found_at < issuance.end_time:
        raise ValidationError("root finding is outside instrument validity")
    if found_at > cutoff:
        raise ValidationError("root finding is after the standing cutoff")
    claim_id = (
        None
        if claim_id is None
        else _identifier(claim_id, name="root finding claim ID")
    )
    if outcome is AdjudicationFindingOutcome.MISATTESTATION:
        if claim_id is not None:
            raise ValidationError("direct misattestation finding cannot link a claim")
        if withdrawal is not None and (
            withdrawal.cause is not WithdrawalCause.WITHOUT_CAUSE
            or found_at < withdrawal.claimed_at
        ):
            raise ValidationError(
                "direct misattestation finding conflicts with its withdrawal"
            )
    elif (
        withdrawal is None
        or withdrawal.cause is not WithdrawalCause.FOR_CAUSE
        or claim_id != withdrawal.claim_id
        or found_at < withdrawal.claimed_at
    ):
        raise ValidationError("for-cause finding does not match its claim")
    return RootAdjudicationFinding(
        _identifier(finding_id, name="root finding ID"),
        adjudicator,
        outcome,
        found_at,
        claim_id,
        _identifier(evidence_ref, name="root finding evidence reference"),
    )


def _validate_peer(
    value: object,
    *,
    peer_share: Decimal,
    agent_id: str,
    por_digest: str,
    attestations: tuple[PoRAttestationDeclaration, ...],
    roots: tuple[RootDeclaration, ...],
    ceilings: tuple[CeilingDeclaration, ...],
) -> PeerScoreDeclaration | None:
    if peer_share == 0:
        if value is not None:
            raise ValidationError("peer declaration must be absent at zero share")
        return None
    if type(value) is not PeerScoreDeclaration:
        raise ValidationError("peer share requires the typed peer declaration")
    try:
        score = value.score
        source_id = value.source_id
        evidence_ids = value.evidence_ids
        provenance_refs = value.provenance_refs
    except AttributeError as exc:
        raise ValidationError("peer score structure is invalid") from exc
    score = as_decimal(score, name="peer score", minimum=0, maximum=100)
    source_id = _identifier(source_id, name="peer source ID")
    evidence_ids = _bounded_identifier_tuple(
        evidence_ids,
        name="peer evidence IDs",
        maximum=MAX_PEER_EVIDENCE_IDS,
    )
    provenance_refs = _bounded_identifier_tuple(
        provenance_refs,
        name="peer provenance references",
        maximum=MAX_PEER_PROVENANCE_REFS,
    )
    peer_facts = (source_id, *evidence_ids, *provenance_refs)
    if len(frozenset(peer_facts)) != len(peer_facts):
        raise ValidationError("peer evidence and provenance must be unique")
    represented = _represented_base_references(
        agent_id=agent_id,
        por_digest=por_digest,
        attestations=attestations,
        roots=roots,
        ceilings=ceilings,
    )
    if frozenset(peer_facts) & represented:
        raise ValidationError(
            "peer provenance must be independent of represented base facts"
        )
    return PeerScoreDeclaration(score, source_id, evidence_ids, provenance_refs)


def _represented_base_references(
    *,
    agent_id: str,
    por_digest: str,
    attestations: tuple[PoRAttestationDeclaration, ...],
    roots: tuple[RootDeclaration, ...],
    ceilings: tuple[CeilingDeclaration, ...],
) -> frozenset[str]:
    represented = {agent_id, por_digest}
    for value in attestations:
        _add_attestation_references(represented, value)
    seen_sponsors: dict[int, StandingSnapshot] = {}
    for value in roots:
        _add_root_references(represented, value, seen_sponsors=seen_sponsors)
    for value in ceilings:
        _add_ceiling_references(represented, value)
    return frozenset(represented)


def _add_attestation_references(
    represented: set[str], value: PoRAttestationDeclaration
) -> None:
    represented.update(
        (
            value.attestation_id,
            value.agent_id,
            value.transaction_ref,
            value.oracle_id,
            value.verification_ref,
        )
    )


def _add_ceiling_references(represented: set[str], value: CeilingDeclaration) -> None:
    represented.update((value.name, value.provenance_id))


def _add_root_references(
    represented: set[str],
    value: RootDeclaration,
    *,
    seen_sponsors: dict[int, StandingSnapshot],
) -> None:
    represented.add(value.instrument_id)
    if type(value) is NoRootInstrumentDeclaration:
        return
    represented.update(
        (
            value.attestor,
            value.issuance.verification_ref,
            value.terminator.identifier,
            value.terminator.verification_ref,
            *value.chain,
        )
    )
    if value.exposure_class is not None:
        represented.add(value.exposure_class)
    if value.withdrawal_claim is not None:
        represented.update(
            (
                value.withdrawal_claim.claim_id,
                value.withdrawal_claim.declared_by,
                value.withdrawal_claim.evidence_ref,
            )
        )
    if value.adjudication_finding is not None:
        represented.update(
            (
                value.adjudication_finding.finding_id,
                value.adjudication_finding.adjudicator_id,
                value.adjudication_finding.evidence_ref,
            )
        )
        if value.adjudication_finding.claim_id is not None:
            represented.add(value.adjudication_finding.claim_id)
    if value.sponsor_standing is not None:
        _add_sponsor_standing_references(
            represented,
            value.sponsor_standing,
            seen_sponsors=seen_sponsors,
        )


def _add_sponsor_standing_references(
    represented: set[str],
    value: StandingSnapshot,
    *,
    seen_sponsors: dict[int, StandingSnapshot],
) -> None:
    identity = id(value)
    if seen_sponsors.get(identity) is value:
        return
    seen_sponsors[identity] = value
    represented.update(
        (
            value.agent_id,
            value.digest,
            value.por.digest,
            value._profile.digest,
        )
    )
    for ceiling in value.applicable_ceilings:
        _add_ceiling_references(represented, ceiling)
    declaration = value._declaration
    for attestation in declaration.por_attestations:
        _add_attestation_references(represented, attestation)
    for root in declaration.root_instruments:
        _add_root_references(represented, root, seen_sponsors=seen_sponsors)
    if declaration.peer is not None:
        represented.update(
            (
                declaration.peer.source_id,
                *declaration.peer.evidence_ids,
                *declaration.peer.provenance_refs,
            )
        )
    for ceiling in declaration.additional_ceilings:
        _add_ceiling_references(represented, ceiling)


def _bounded_identifier_tuple(
    value: object, *, name: str, maximum: int
) -> tuple[str, ...]:
    if type(value) is not tuple or not value:
        raise ValidationError(f"{name} must be a non-empty tuple")
    if len(value) > maximum:
        raise ValidationError(f"{name} exceeds its library safety maximum")
    normalized = tuple(_identifier(item, name=name) for item in value)
    if len(frozenset(normalized)) != len(normalized):
        raise ValidationError(f"{name} contains duplicates")
    return normalized


def _validate_additional_ceilings(
    value: object,
) -> tuple[CeilingDeclaration, ...]:
    if type(value) is not tuple:
        raise ValidationError("additional ceilings must be a tuple")
    ceilings: list[CeilingDeclaration] = []
    names: set[str] = set()
    for declaration in value:
        if type(declaration) is not CeilingDeclaration:
            raise ValidationError("ceiling must use the explicit declaration")
        try:
            name = declaration.name
            ceiling_value = declaration.value
            provenance_id = declaration.provenance_id
        except AttributeError as exc:
            raise ValidationError("ceiling declaration structure is invalid") from exc
        name = _identifier(name, name="ceiling name")
        if name in _RESERVED_CEILINGS or name in names:
            raise ValidationError(f"duplicate or reserved ceiling: {name}")
        names.add(name)
        ceilings.append(
            CeilingDeclaration(
                name,
                as_decimal(
                    ceiling_value,
                    name=f"{name} ceiling",
                    minimum=0,
                    maximum=100,
                ),
                _identifier(
                    provenance_id, name=f"{name} ceiling provenance"
                ),
            )
        )
    return tuple(sorted(ceilings, key=lambda item: item.name))


def _select_root(
    roots: tuple[RootDeclaration, ...],
    *,
    lineage: LineagePhase,
    cutoff: datetime,
) -> tuple[Decimal, RootDeclaration, RootInstrumentStatus]:
    scored = tuple(
        (
            _root_score(root, lineage=lineage, cutoff=cutoff),
            root,
            _root_status(root, cutoff=cutoff),
        )
        for root in roots
    )
    return max(scored, key=lambda item: item[0])


def _root_status(root: RootDeclaration, *, cutoff: datetime) -> RootInstrumentStatus:
    if type(root) is NoRootInstrumentDeclaration:
        return RootInstrumentStatus.NONE
    finding = root.adjudication_finding
    if finding is not None:
        return RootInstrumentStatus(finding.outcome.value)
    claim = root.withdrawal_claim
    if claim is not None and claim.cause is WithdrawalCause.FOR_CAUSE:
        if cutoff >= root.issuance.end_time:
            return RootInstrumentStatus.FOR_CAUSE_UNRESOLVED
        return RootInstrumentStatus.FOR_CAUSE_PENDING
    if cutoff >= root.issuance.end_time:
        return RootInstrumentStatus.EXPIRED
    if claim is not None:
        return RootInstrumentStatus.NON_RENEWABLE
    return RootInstrumentStatus.CURRENT


def _root_score(
    root: RootDeclaration, *, lineage: LineagePhase, cutoff: datetime
) -> Decimal:
    status = _root_status(root, cutoff=cutoff)
    if status in _ZERO_ROOT_STATUSES:
        return Decimal(0)
    if type(root) is not RootInstrumentDeclaration:
        raise ValidationError("root instrument arithmetic is incomplete")
    with localcontext(KTP_CONTEXT):
        if lineage is LineagePhase.SPONSORED:
            if root.sponsor_standing is None or root.stake_percentage is None:
                raise ValidationError("sponsored root arithmetic is incomplete")
            return (
                (
                    root.sponsor_standing.base_trust
                    * root.stake_percentage
                    / Decimal(100)
                )
                / Decimal(50)
                * Decimal(100)
            )
        if root.declared_exposure is None or root.anchored_capacity is None:
            raise ValidationError("independent root arithmetic is incomplete")
        return min(
            Decimal(100),
            Decimal(100) * root.declared_exposure / root.anchored_capacity,
        )


def _shares(peer_share: Decimal) -> ShareAllocation:
    with localcontext(KTP_CONTEXT):
        remaining = Decimal(100) - peer_share
        return ShareAllocation(
            por=Decimal(70) * remaining / Decimal(100),
            root=Decimal(30) * remaining / Decimal(100),
            peer=peer_share,
        )


def _ceilings(
    value: StandingDeclaration, *, por: PoRResult
) -> tuple[CeilingDeclaration, ...]:
    return (
        *_built_in_ceilings(
            generation=value.generation,
            identity_assurance_level=value.identity_assurance_level,
            trajectory_length=value.trajectory_length,
            por=por,
        ),
        *value.additional_ceilings,
    )


def _built_in_ceilings(
    *,
    generation: int,
    identity_assurance_level: int,
    trajectory_length: int,
    por: PoRResult,
) -> tuple[CeilingDeclaration, ...]:
    generation_ceiling = Decimal(
        (25, 35, 45, 55, 65, 75, 85)[generation] if generation < 7 else 100
    )
    ial_ceiling = Decimal({1: 40, 2: 80, 3: 95}[identity_assurance_level])
    trajectory_ceiling = Decimal(
        50 if trajectory_length < 1_000 else 70 if trajectory_length < 10_000 else 100
    )
    adversity_ceiling = _adversity_ceiling(por)
    return (
        CeilingDeclaration("generation", generation_ceiling, "ktp:identity:generation"),
        CeilingDeclaration("ial", ial_ceiling, "ktp:identity:ial"),
        CeilingDeclaration("trajectory", trajectory_ceiling, "ktp:core:trajectory"),
        CeilingDeclaration("adversity", adversity_ceiling, "ktp:core:adversity"),
    )


def _adversity_ceiling(por: PoRResult) -> Decimal:
    eligible = frozenset(por.eligible_attestation_ids)
    highest = Decimal(0)
    crisis = False
    for value in por._attestations:
        if value.attestation_id not in eligible:
            continue
        highest = max(highest, value.friction)
        crisis = crisis or value.friction_category.value == "crisis"
    if crisis:
        return Decimal(100)
    if highest > Decimal("0.7"):
        return Decimal(90)
    if highest > Decimal("0.5"):
        return Decimal(80)
    return Decimal(60)


def _agent_identifier(value: object, *, generation: int) -> tuple[str, LineagePhase]:
    identifier = _identifier(value, name="Agent identifier")
    parts = identifier.split(":")
    if len(parts) != 5 or parts[0] != "agent":
        raise ValidationError("Agent identifier has an invalid segment shape")
    for position, part in enumerate(parts[1:], start=1):
        _identifier(part, name=f"Agent identifier segment {position}")
        if ":" in part:
            raise ValidationError("Agent identifier segment contains a delimiter")
    lineage = _lineage(generation)
    if parts[1] != lineage.value:
        raise ValidationError("Agent identifier lineage does not match generation")
    if lineage is not LineagePhase.SPONSORED and parts[2] != f"{generation}gen":
        raise ValidationError("Agent identifier generation segment is not exact")
    return identifier, lineage


def _lineage(generation: int) -> LineagePhase:
    if generation <= 2:
        return LineagePhase.SPONSORED
    if generation <= 6:
        return LineagePhase.INDEPENDENT
    return LineagePhase.GUARANTOR


def _standing_digest_input(value: StandingSnapshot) -> dict[str, object]:
    return {
        "profile_digest": value._profile.digest,
        "cutoff": value._cutoff,
        "declaration": _standing_declaration_projection(value._declaration),
        **_standing_public_projection(value, include_digest=False),
    }


def _standing_public_projection(
    value: StandingSnapshot, *, include_digest: bool = True
) -> dict[str, object]:
    projection = {
        "agent_id": value.agent_id,
        "generation": value.generation,
        "lineage": value.lineage,
        "por": value.por,
        "root_score": value.root_score,
        "root_instrument": _root_projection(value.root_instrument),
        "root_status": value.root_status,
        "peer": value.peer,
        "shares": value.shares,
        "applicable_ceilings": value.applicable_ceilings,
        "advancement_floor": value.advancement_floor,
        "base_trust": value.base_trust,
    }
    if include_digest:
        projection["digest"] = value.digest
    return projection


def _standing_declaration_projection(
    value: StandingDeclaration,
) -> dict[str, object]:
    return {
        "agent_id": value.agent_id,
        "generation": value.generation,
        "identity_assurance_level": value.identity_assurance_level,
        "trajectory_length": value.trajectory_length,
        "por_attestations": value.por_attestations,
        "root_instruments": tuple(
            _root_projection(root) for root in value.root_instruments
        ),
        "peer": value.peer,
        "additional_ceilings": value.additional_ceilings,
        "advancement_floor": value.advancement_floor,
    }


def _root_projection(value: RootDeclaration) -> dict[str, object]:
    if type(value) is NoRootInstrumentDeclaration:
        return {"kind": "none", "instrument_id": value.instrument_id}
    return {
        "kind": "instrument",
        "instrument_id": value.instrument_id,
        "attestor": value.attestor,
        "issuance": value.issuance,
        "sponsor_standing": (
            None
            if value.sponsor_standing is None
            else _sponsor_reference_projection(value.sponsor_standing)
        ),
        "stake_percentage": value.stake_percentage,
        "exposure_class": value.exposure_class,
        "declared_exposure": value.declared_exposure,
        "anchored_capacity": value.anchored_capacity,
        "chain": value.chain,
        "terminator": value.terminator,
        "withdrawal_claim": value.withdrawal_claim,
        "adjudication_finding": value.adjudication_finding,
    }


def _sponsor_reference_projection(value: StandingSnapshot) -> dict[str, object]:
    return {
        "agent_id": value.agent_id,
        "generation": value.generation,
        "lineage": value.lineage,
        "base_trust": value.base_trust,
        "digest": value.digest,
        "profile_digest": value._profile.digest,
        "cutoff": value._cutoff,
    }


def _require_standing_structure(
    value: StandingSnapshot,
    *,
    validation_state: _SnapshotValidationState,
) -> None:
    identity = id(value)
    if validation_state.completed.get(identity) is value:
        return
    if validation_state.active.get(identity) is value:
        raise ValidationError("represented sponsor standing graph is cyclic")
    validation_state.active[identity] = value
    try:
        _require_standing_structure_members(
            value,
            validation_state=validation_state,
        )
        validation_state.completed[identity] = value
    finally:
        validation_state.active.pop(identity, None)


def _require_standing_structure_members(
    value: StandingSnapshot,
    *,
    validation_state: _SnapshotValidationState,
) -> None:
    if (
        type(value.agent_id) is not str
        or type(value.generation) is not int
        or type(value.lineage) is not LineagePhase
        or type(value.por) is not PoRResult
        or type(value.root_score) is not Decimal
        or type(value.root_instrument)
        not in {RootInstrumentDeclaration, NoRootInstrumentDeclaration}
        or type(value.root_status) is not RootInstrumentStatus
        or (value.peer is not None and type(value.peer) is not PeerScoreDeclaration)
        or type(value.shares) is not ShareAllocation
        or type(value.applicable_ceilings) is not tuple
        or type(value.advancement_floor) is not Decimal
        or type(value.base_trust) is not Decimal
        or type(value.digest) is not str
        or type(value._profile) is not DeploymentProfile
        or type(value._profile.digest) is not str
        or type(value._declaration) is not StandingDeclaration
        or type(value._cutoff) is not datetime
    ):
        raise ValidationError("standing snapshot structure is invalid")
    utc_time(value._cutoff, name="standing cutoff")
    _agent_identifier(value.agent_id, generation=value.generation)
    require_validated_por_result(value.por)
    _require_root_structure(
        value.root_instrument,
        validation_state=validation_state,
    )
    if value.peer is not None:
        _require_peer_structure(value.peer)
    for number in (
        value.root_score,
        value.shares.por,
        value.shares.root,
        value.shares.peer,
        value.advancement_floor,
        value.base_trust,
    ):
        _exact_decimal(number, name="standing numeric value")
    if any(
        type(item) is not CeilingDeclaration
        or type(item.name) is not str
        or type(item.provenance_id) is not str
        or type(item.value) is not Decimal
        or not item.value.is_finite()
        for item in value.applicable_ceilings
    ):
        raise ValidationError("standing ceiling structure is invalid")
    _require_normalized_declaration_structure(
        value._declaration,
        validation_state=validation_state,
    )


def _require_normalized_declaration_structure(
    value: StandingDeclaration,
    *,
    validation_state: _SnapshotValidationState,
) -> None:
    if (
        type(value.agent_id) is not str
        or type(value.generation) is not int
        or type(value.identity_assurance_level) is not int
        or type(value.trajectory_length) is not int
        or type(value.por_attestations) is not tuple
        or type(value.root_instruments) is not tuple
        or (value.peer is not None and type(value.peer) is not PeerScoreDeclaration)
        or type(value.additional_ceilings) is not tuple
        or type(value.advancement_floor) is not Decimal
    ):
        raise ValidationError("represented standing declaration is malformed")
    for attestation in value.por_attestations:
        _require_normalized_attestation_structure(attestation)
    for root in value.root_instruments:
        _require_root_structure(root, validation_state=validation_state)
    if value.peer is not None:
        _require_peer_structure(value.peer)
    for ceiling in value.additional_ceilings:
        if (
            type(ceiling) is not CeilingDeclaration
            or type(ceiling.name) is not str
            or type(ceiling.value) is not Decimal
            or type(ceiling.provenance_id) is not str
        ):
            raise ValidationError("represented additional ceiling is malformed")


def _require_normalized_attestation_structure(value: object) -> None:
    from kinetic_trust_library.models.standing import FrictionCategory

    if (
        type(value) is not PoRAttestationDeclaration
        or type(value.attestation_id) is not str
        or type(value.agent_id) is not str
        or type(value.transaction_ref) is not str
        or type(value.friction) is not Decimal
        or type(value.friction_category) is not FrictionCategory
        or type(value.action_risk) is not Decimal
        or type(value.outcome) is not str
        or type(value.timestamp) is not datetime
        or type(value.oracle_id) is not str
        or type(value.verification_ref) is not str
    ):
        raise ValidationError("represented PoR attestation is malformed")
    utc_time(value.timestamp, name="represented PoR attestation timestamp")


def _require_shallow_guarantor_sponsor(value: object) -> None:
    """Reject impossible sponsor roles before traversing their snapshot graph."""
    if type(value) is not StandingSnapshot:
        raise ValidationError("represented sponsor standing is malformed")
    if (
        type(value.agent_id) is not str
        or type(value.generation) is not int
        or value.generation < 7
        or type(value.lineage) is not LineagePhase
        or value.lineage is not LineagePhase.GUARANTOR
        or type(value.root_instrument)
        not in {RootInstrumentDeclaration, NoRootInstrumentDeclaration}
        or type(value._declaration) is not StandingDeclaration
    ):
        raise ValidationError("represented sponsor must be a Guarantor")
    _, public_lineage = _agent_identifier(
        value.agent_id,
        generation=value.generation,
    )
    declaration = value._declaration
    if (
        public_lineage is not LineagePhase.GUARANTOR
        or type(declaration.agent_id) is not str
        or type(declaration.generation) is not int
        or declaration.generation < 7
        or type(declaration.root_instruments) is not tuple
        or declaration.agent_id != value.agent_id
        or declaration.generation != value.generation
    ):
        raise ValidationError("represented sponsor must be a Guarantor")
    _, declaration_lineage = _agent_identifier(
        declaration.agent_id,
        generation=declaration.generation,
    )
    if declaration_lineage is not LineagePhase.GUARANTOR:
        raise ValidationError("represented sponsor must be a Guarantor")
    selected_root = value.root_instrument
    if (
        type(selected_root) is RootInstrumentDeclaration
        and selected_root.sponsor_standing is not None
    ):
        raise ValidationError("Guarantor sponsor cannot carry sponsored roots")
    for root in declaration.root_instruments:
        if type(root) not in {
            RootInstrumentDeclaration,
            NoRootInstrumentDeclaration,
        }:
            raise ValidationError("represented sponsor root is malformed")
        if (
            type(root) is RootInstrumentDeclaration
            and root.sponsor_standing is not None
        ):
            raise ValidationError("Guarantor sponsor cannot carry sponsored roots")


def _require_root_structure(
    value: object,
    *,
    validation_state: _SnapshotValidationState,
) -> None:
    if type(value) is NoRootInstrumentDeclaration:
        if type(value.instrument_id) is not str:
            raise ValidationError("represented no-root declaration is malformed")
        return
    if type(value) is not RootInstrumentDeclaration:
        raise ValidationError("represented root declaration is malformed")
    if (
        type(value.instrument_id) is not str
        or type(value.attestor) is not str
        or type(value.issuance) is not RootIssuanceDeclaration
        or (
            value.sponsor_standing is not None
            and type(value.sponsor_standing) is not StandingSnapshot
        )
        or (
            value.stake_percentage is not None
            and type(value.stake_percentage) is not Decimal
        )
        or (value.exposure_class is not None and type(value.exposure_class) is not str)
        or (
            value.declared_exposure is not None
            and type(value.declared_exposure) is not Decimal
        )
        or (
            value.anchored_capacity is not None
            and type(value.anchored_capacity) is not Decimal
        )
        or type(value.chain) is not tuple
        or type(value.terminator) is not ExternalTerminatorDeclaration
        or (
            value.withdrawal_claim is not None
            and type(value.withdrawal_claim) is not RootWithdrawalClaim
        )
        or (
            value.adjudication_finding is not None
            and type(value.adjudication_finding) is not RootAdjudicationFinding
        )
    ):
        raise ValidationError("represented root declaration is malformed")
    if any(type(item) is not str for item in value.chain):
        raise ValidationError("represented root chain is malformed")
    if (
        type(value.issuance.issued_at) is not datetime
        or type(value.issuance.end_time) is not datetime
        or type(value.issuance.verification_ref) is not str
        or type(value.terminator.kind) is not ExternalTerminatorKind
        or type(value.terminator.identifier) is not str
        or type(value.terminator.verification_ref) is not str
    ):
        raise ValidationError("represented root issuance is malformed")
    utc_time(value.issuance.issued_at, name="represented root issuance time")
    utc_time(value.issuance.end_time, name="represented root end time")
    if value.withdrawal_claim is not None and (
        type(value.withdrawal_claim.claim_id) is not str
        or type(value.withdrawal_claim.declared_by) is not str
        or type(value.withdrawal_claim.cause) is not WithdrawalCause
        or type(value.withdrawal_claim.claimed_at) is not datetime
        or type(value.withdrawal_claim.evidence_ref) is not str
    ):
        raise ValidationError("represented root withdrawal is malformed")
    if value.withdrawal_claim is not None:
        utc_time(
            value.withdrawal_claim.claimed_at,
            name="represented root withdrawal time",
        )
    if value.adjudication_finding is not None and (
        type(value.adjudication_finding.finding_id) is not str
        or type(value.adjudication_finding.adjudicator_id) is not str
        or type(value.adjudication_finding.outcome) is not AdjudicationFindingOutcome
        or type(value.adjudication_finding.found_at) is not datetime
        or (
            value.adjudication_finding.claim_id is not None
            and type(value.adjudication_finding.claim_id) is not str
        )
        or type(value.adjudication_finding.evidence_ref) is not str
    ):
        raise ValidationError("represented root finding is malformed")
    if value.adjudication_finding is not None:
        utc_time(
            value.adjudication_finding.found_at,
            name="represented root finding time",
        )
    if value.sponsor_standing is not None:
        _require_shallow_guarantor_sponsor(value.sponsor_standing)
        _require_standing_structure(
            value.sponsor_standing,
            validation_state=validation_state,
        )


def _require_peer_structure(value: PeerScoreDeclaration) -> None:
    if (
        type(value.score) is not Decimal
        or type(value.source_id) is not str
        or type(value.evidence_ids) is not tuple
        or type(value.provenance_refs) is not tuple
        or any(type(item) is not str for item in value.evidence_ids)
        or any(type(item) is not str for item in value.provenance_refs)
    ):
        raise ValidationError("represented peer declaration is malformed")


def _exact_decimal(value: object, *, name: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise ValidationError(f"{name} must be an exact finite Decimal")
    return value


def _bounded_int(value: object, *, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValidationError(f"{name} must be an exact integer in range")
    return value


def _identifier(value: object, *, name: str) -> str:
    if type(value) is not str:
        raise ValidationError(f"{name} must be an exact string")
    return validate_identifier(value, name=name)


__all__ = [
    "MAX_PEER_EVIDENCE_IDS",
    "MAX_PEER_PROVENANCE_REFS",
    "prepare_standing",
    "require_validated_standing_snapshot",
]
