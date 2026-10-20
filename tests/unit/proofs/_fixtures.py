"""Deterministic Trust Proof framing and issuance fixtures."""

from base64 import urlsafe_b64encode
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json

from kinetic_trust_library.models.proof import (
    CeilingClaim,
    KeyPurpose,
    OracleSigningIdentity,
    ProofAlgorithm,
    ProofIntent,
    ProofRootStatus,
    RiskFactorClaims,
    RootInstrumentClaim,
    SoulProofClaims,
    TrustProofClaims,
)
from kinetic_trust_library.core.evaluate import evaluate
from kinetic_trust_library.core.trust import calculate_effective_trust
from kinetic_trust_library.models.action import (
    MomentCriticalityDeclaration,
    ValidatedActionDemand,
)
from kinetic_trust_library.models.envelope import EvaluationBundle, EvaluationRequest
from kinetic_trust_library.models.soul import SoulConstraintType, SoulResponseDeclaration
from kinetic_trust_library.models.standing import (
    AdjudicationFindingOutcome,
    CeilingDeclaration,
    LineagePhase,
    NoRootInstrumentDeclaration,
    RootAdjudicationFinding,
    RootInstrumentStatus,
    RootWithdrawalClaim,
    WithdrawalCause,
)
from tests.unit.core.test_envelope import CURRENT_STRESSES, configured_profile
from tests.unit.core.test_evaluate import request as evaluation_request
from tests.unit.core.test_evidence import CUTOFF
from tests.unit.core.test_risk import evidence_declarations, risk_state, standing
from tests.unit.core.test_standing_contract import (
    SPONSORED_ID,
    declaration as standing_declaration,
    external_root,
    sponsor_snapshot,
    sponsored_declaration,
)
from tests.unit.models.test_profile import complete_action, complete_capability


ISSUED_AT = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
EXPIRES_AT = ISSUED_AT + timedelta(seconds=10)
BINDING = {
    "resource": "urn:resource:document:42",
    "context_hash": "sha256:" + ("b" * 64),
    "issued_at": ISSUED_AT,
    "expires_at": EXPIRES_AT,
    "trajectory_id": "trajectory-1",
    "decision_id": "decision-1",
}


def proof_intent(**overrides: object) -> ProofIntent:
    values: dict[str, object] = {
        "proof_id": "proof-1",
        "resource": "urn:resource:document:42",
        "context_hash": "sha256:" + ("b" * 64),
        "trajectory_id": "trajectory-1",
        "lifetime_seconds": 10,
    }
    values.update(overrides)
    return ProofIntent(**values)  # type: ignore[arg-type]


def _segment(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def compact_token(header: bytes, payload: bytes, signature: bytes) -> str:
    return ".".join((_segment(header), _segment(payload), _segment(signature)))


def es256_signature(*, r: int, s: int) -> bytes:
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def ed25519_signature(*, encoded_r: bytes, s: int) -> bytes:
    return encoded_r + s.to_bytes(32, "little")


def nested_payload(depth: int) -> bytes:
    return b'{"a":' + (b"[" * (depth - 1)) + b"0" + (b"]" * (depth - 1)) + b"}"


def object_member_payload(member_count: int) -> bytes:
    members = {f"k{index:03d}": 0 for index in range(member_count)}
    return json.dumps(members, sort_keys=True, separators=(",", ":")).encode("ascii")


def total_object_member_payload(member_count: int) -> bytes:
    if member_count not in (512, 513):
        raise ValueError("fixture supports only the reviewed total-member boundaries")
    child_counts = (127, 127, 127, 127)
    if member_count == 513:
        child_counts = (128, 127, 127, 127)
    root = {
        f"a{outer}": {f"k{inner:03d}": 0 for inner in range(count)}
        for outer, count in enumerate(child_counts)
    }
    return json.dumps(root, sort_keys=True, separators=(",", ":")).encode("ascii")


def array_item_payload(item_count: int) -> bytes:
    return b'{"a":[' + b",".join(b"0" for _ in range(item_count)) + b"]}"


def total_collection_item_payload(item_count: int) -> bytes:
    if item_count not in (1_024, 1_025):
        raise ValueError("fixture supports only the reviewed total-item boundaries")
    counts = (256, 256, 256, 256)
    if item_count == 1_025:
        counts = (256, 256, 256, 256, 1)
    members = (
        f'"a{index}":['.encode("ascii") + b",".join(b"0" for _ in range(count)) + b"]"
        for index, count in enumerate(counts)
    )
    return b"{" + b",".join(members) + b"}"


def string_payload(field: str, utf8_length: int) -> bytes:
    if field in {"iss", "sub"}:
        value = "urn:" + ("a" * (utf8_length - 4))
    else:
        value = "a" * utf8_length
    return ('{"' + field + '":"' + value + '"}').encode("ascii")


def numeric_lexeme_payload(length: int) -> bytes:
    return b'{"n":' + b"1" + (b"0" * (length - 1)) + b"}"


def payload_of_size(size: int) -> bytes:
    if size not in (45_000, 45_001):
        raise ValueError("fixture supports only the reviewed payload-byte boundaries")
    last_string_length = 3_986 + (size - 45_000)
    values = ((b"a" * 4_096),) * 10 + ((b"a" * last_string_length),)
    payload = b'{"a":[' + b",".join(b'"' + value + b'"' for value in values)
    payload += b'],"iss":"urn:o"}'
    if len(payload) != size:
        raise AssertionError("hand-checked payload fixture has the wrong byte length")
    return payload


def trust_proof_claims(*, full: bool) -> TrustProofClaims:
    issued_at = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
    if full:
        soul = SoulProofClaims(
            soul=1,
            constraint_type=SoulConstraintType.TK_LABEL,
            constraint_id="TK-NC-001",
            constraint_name="TK Non-Commercial",
            authority="https://authority.example",
            community="Example Community",
            remediation="Ask first",
        )
        lineage = LineagePhase.SPONSORED
        sponsor = "urn:agent:sponsor"
        root = RootInstrumentClaim(
            status=ProofRootStatus.CURRENT,
            end_time=issued_at + timedelta(hours=1),
            exposure_class="legal",
            declared_exposure=Decimal("50"),
            anchored_capacity=Decimal("60"),
            terminator="org:root",
            chain_length=2,
        )
    else:
        soul = SoulProofClaims(
            soul=0,
            constraint_type=None,
            constraint_id=None,
            constraint_name=None,
            authority=None,
            community=None,
            remediation=None,
        )
        lineage = LineagePhase.GUARANTOR
        sponsor = None
        root = RootInstrumentClaim(
            status=ProofRootStatus.NONE,
            end_time=None,
            exposure_class=None,
            declared_exposure=None,
            anchored_capacity=None,
            terminator=None,
            chain_length=None,
        )
    values: dict[str, object] = {
        "issuer": "https://oracle.example",
        "subject": "urn:agent:test",
        "action": "c" * 64,
        "resource": BINDING["resource"],
        "context_hash": BINDING["context_hash"],
        "trajectory_id": BINDING["trajectory_id"],
        "decision_id": BINDING["decision_id"],
        "issued_at": issued_at,
        "expires_at": issued_at + timedelta(seconds=10),
        "proof_id": "proof-1",
        "base_trust": Decimal("80"),
        "effective_trust": Decimal("72"),
        "risk": Decimal("0.1"),
        "velocity": Decimal("-0.5") if full else None,
        "volatility": Decimal("0.2") if full else None,
        "context": RiskFactorClaims(
            evidence_density=Decimal("0.1"),
            trust_trend=Decimal("0.2"),
            adversarial_pressure=Decimal("0.3"),
            update_resistance=Decimal("0.4"),
            attestation_coverage=Decimal("0.5"),
            moment_criticality=Decimal("0.6"),
        ),
        "soul": soul,
        "lineage": lineage,
        "generation": 2 if full else 7,
        "sponsor": sponsor,
        "resilience_hash": "sha256:" + ("a" * 64),
        "zone": "zone-blue" if full else None,
        "oracle_quorum": "1-of-1" if full else None,
        "peer_share": Decimal("0"),
        "applicable_ceilings": (
            (CeilingClaim("generation", Decimal("80")),) if full else ()
        ),
        "advancement_floor": Decimal("0"),
        "root_instrument": root,
    }
    claims = object.__new__(TrustProofClaims)
    for name, value in values.items():
        object.__setattr__(claims, name, value)
    return claims


def complete_bundle() -> EvaluationBundle:
    value = evaluate(evaluation_request())
    if type(value) is not EvaluationBundle:
        raise AssertionError("issuance fixture did not produce a complete bundle")
    return value


def complete_bundle_at(cutoff: datetime) -> EvaluationBundle:
    configured = configured_profile()
    action = ValidatedActionDemand.validate(
        complete_action(
            action_id="action:proof:cutoff",
            subject="agent:independent:3gen:acme-line:agent-one",
            demand="1",
            moment_criticality=MomentCriticalityDeclaration(
                value="0.75",
                supplier="action-api",
                unit="stress-0-1",
                observed_at=cutoff,
                provenance_id="moment:proof:cutoff",
            ),
        ),
        profile=configured,
        capability=complete_capability(
            subject="agent:independent:3gen:acme-line:agent-one",
            not_before=cutoff - timedelta(minutes=1),
            not_after=cutoff + timedelta(minutes=1),
        ),
        cutoff=cutoff,
    )
    responses = tuple(
        SoulResponseDeclaration(
            framework_id=framework,
            profile_ref=configured.ref,
            profile_digest=configured.digest,
            action_id=action.action_id,
            action_digest=action.digest,
            query_cutoff=cutoff,
            state="clear",
            observed_at=cutoff,
            provenance_id=f"soul:{framework}",
        )
        for framework in configured.soul_frameworks
    )
    value = evaluate(
        EvaluationRequest(
            operation_id="operation:proof:cutoff",
            profile=configured,
            action=action,
            standing=standing_declaration(),
            observations=evidence_declarations(cutoff, CURRENT_STRESSES),
            soul_responses=responses,
            cutoff=cutoff,
        )
    )
    if type(value) is not EvaluationBundle:
        raise AssertionError("cutoff fixture did not produce a complete bundle")
    return value


def ceiling_bundle(additional_count: int) -> EvaluationBundle:
    ceilings = tuple(
        CeilingDeclaration(
            name=f"proof_ceiling_{index:03d}",
            value="100",
            provenance_id=f"proof_provenance_{index:03d}",
        )
        for index in range(additional_count)
    )
    request = replace(
        evaluation_request(),
        standing=standing_declaration(additional_ceilings=ceilings),
    )
    value = evaluate(request)
    if type(value) is not EvaluationBundle:
        raise AssertionError("ceiling fixture did not produce a complete bundle")
    return value


def velocity_bundle() -> EvaluationBundle:
    configured = configured_profile()
    previous_at = CUTOFF - timedelta(seconds=1)
    action, soul, _evidence, risk = risk_state(
        configured,
        previous_at,
        ("0.1", "0.2", "0.3", "0.4", "0"),
        moment="0.75",
        action_id="action:proof:previous",
    )
    previous = calculate_effective_trust(
        configured,
        standing(configured, previous_at),
        risk,
        soul,
        action,
        previous_at,
    )
    value = evaluate(
        replace(
            evaluation_request(profile=configured),
            previous_trust=previous,
        )
    )
    if type(value) is not EvaluationBundle or value.velocity is None:
        raise AssertionError("velocity fixture did not produce a complete bundle")
    return value


def sponsored_bundle() -> EvaluationBundle:
    configured = configured_profile()
    sponsor = sponsor_snapshot(configured)
    action = ValidatedActionDemand.validate(
        complete_action(
            action_id="action:proof:sponsored",
            subject=SPONSORED_ID,
            demand="1",
            moment_criticality=MomentCriticalityDeclaration(
                value="0.75",
                supplier="action-api",
                unit="stress-0-1",
                observed_at=CUTOFF,
                provenance_id="moment:proof:sponsored",
            ),
        ),
        profile=configured,
        capability=complete_capability(
            subject=SPONSORED_ID,
            not_before=CUTOFF - timedelta(minutes=1),
            not_after=CUTOFF + timedelta(minutes=1),
        ),
        cutoff=CUTOFF,
    )
    responses = tuple(
        SoulResponseDeclaration(
            framework_id=framework,
            profile_ref=configured.ref,
            profile_digest=configured.digest,
            action_id=action.action_id,
            action_digest=action.digest,
            query_cutoff=CUTOFF,
            state="clear",
            observed_at=CUTOFF,
            provenance_id=f"soul:{framework}",
        )
        for framework in configured.soul_frameworks
    )
    value = evaluate(
        EvaluationRequest(
            operation_id="operation:proof:sponsored",
            profile=configured,
            action=action,
            standing=sponsored_declaration(sponsor),
            observations=evidence_declarations(CUTOFF, CURRENT_STRESSES),
            soul_responses=responses,
            cutoff=CUTOFF,
        )
    )
    if type(value) is not EvaluationBundle:
        raise AssertionError("sponsored fixture did not produce a complete bundle")
    return value


def non_clear_bundle(*, veto: bool) -> EvaluationBundle:
    request = evaluation_request(soul_clear=False)
    if veto:
        clear_response = evaluation_request().soul_responses[0]
        response = replace(
            clear_response,
            state="veto",
            constraint_type=SoulConstraintType.TK_LABEL,
            constraint_id="TK-NC-001",
            authority="https://authority.example",
        )
        request = replace(request, soul_responses=(response,))
    value = evaluate(request)
    if type(value) is not EvaluationBundle:
        raise AssertionError("non-clear fixture did not produce an evaluation bundle")
    return value


def root_bundle(
    status: RootInstrumentStatus,
    *,
    end_time: datetime | None = None,
) -> EvaluationBundle:
    root = _root_for_status(status, end_time=end_time)
    request = replace(
        evaluation_request(),
        standing=standing_declaration(root_instruments=(root,)),
    )
    value = evaluate(request)
    if type(value) is not EvaluationBundle:
        raise AssertionError(f"root fixture did not produce a {status.value} bundle")
    if value.standing is None or value.standing.root_status is not status:
        raise AssertionError(
            f"root fixture produced the wrong status for {status.value}"
        )
    return value


def _root_for_status(
    status: RootInstrumentStatus,
    *,
    end_time: datetime | None,
) -> object:
    if status is RootInstrumentStatus.NONE:
        return NoRootInstrumentDeclaration("root:none")
    root = external_root()
    if end_time is not None:
        root = replace(root, issuance=replace(root.issuance, end_time=end_time))
    if status is RootInstrumentStatus.CURRENT:
        return root
    if status is RootInstrumentStatus.EXPIRED:
        return replace(
            root,
            issuance=replace(root.issuance, end_time=CUTOFF),
        )
    cause = (
        WithdrawalCause.WITHOUT_CAUSE
        if status is RootInstrumentStatus.NON_RENEWABLE
        else WithdrawalCause.FOR_CAUSE
    )
    claim = RootWithdrawalClaim(
        claim_id="claim:proof",
        declared_by=root.attestor,
        cause=cause,
        claimed_at=CUTOFF - timedelta(hours=1),
        evidence_ref="claim-evidence:proof",
    )
    if status is RootInstrumentStatus.NON_RENEWABLE:
        return replace(root, withdrawal_claim=claim)
    if status is RootInstrumentStatus.FOR_CAUSE_PENDING:
        return replace(root, withdrawal_claim=claim)
    if status is RootInstrumentStatus.FOR_CAUSE_UNRESOLVED:
        return replace(
            root,
            issuance=replace(root.issuance, end_time=CUTOFF),
            withdrawal_claim=claim,
        )
    outcome = {
        RootInstrumentStatus.FOR_CAUSE_SUSTAINED: (
            AdjudicationFindingOutcome.FOR_CAUSE_SUSTAINED
        ),
        RootInstrumentStatus.FOR_CAUSE_REJECTED: (
            AdjudicationFindingOutcome.FOR_CAUSE_REJECTED
        ),
        RootInstrumentStatus.MISATTESTATION: AdjudicationFindingOutcome.MISATTESTATION,
    }[status]
    finding = RootAdjudicationFinding(
        finding_id="finding:proof",
        adjudicator_id="adjudicator:one",
        outcome=outcome,
        found_at=CUTOFF - timedelta(minutes=30),
        claim_id=(
            None if status is RootInstrumentStatus.MISATTESTATION else claim.claim_id
        ),
        evidence_ref="finding-evidence:proof",
    )
    return replace(
        root,
        withdrawal_claim=(
            None if status is RootInstrumentStatus.MISATTESTATION else claim
        ),
        adjudication_finding=finding,
    )


def oracle_signing_identity() -> OracleSigningIdentity:
    cutoff = complete_bundle().cutoff
    return OracleSigningIdentity(
        issuer="https://oracle.example",
        key_id="oracle-key-1",
        algorithm=ProofAlgorithm.ES256,
        purpose=KeyPurpose.ORACLE_TRUST_PROOF,
        public_key=b"\x04" + (b"\x01" * 64),
        signing_not_before=cutoff - timedelta(minutes=1),
        signing_not_after=cutoff + timedelta(minutes=1),
        revoked_at=None,
    )
