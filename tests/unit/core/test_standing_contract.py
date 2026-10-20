"""Adversarial contract tests for the authoritative Task 2 standing boundary."""

import copy
import sys
import unittest
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta, tzinfo
from decimal import Decimal
from types import MappingProxyType

import kinetic_trust_library.core.standing as standing_module
from kinetic_trust_library.core.por import calculate_por, require_validated_por_result
from kinetic_trust_library.core.standing import (
    prepare_standing,
    require_validated_standing_snapshot,
)
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.standing import (
    AdjudicationFindingOutcome,
    CeilingDeclaration,
    ExternalTerminatorDeclaration,
    ExternalTerminatorKind,
    FrictionCategory,
    NoRootInstrumentDeclaration,
    PeerScoreDeclaration,
    PoRAttestationDeclaration,
    RootAdjudicationFinding,
    RootInstrumentDeclaration,
    RootInstrumentStatus,
    RootIssuanceDeclaration,
    RootWithdrawalClaim,
    StandingDeclaration,
    StandingSnapshot,
    WithdrawalCause,
)
from tests.unit.core.test_evidence_review import (
    profile_with_counted_one_route_feeds,
)
from tests.unit.core.test_por import CUTOFF
from tests.unit.models.test_profile import (
    _ExternalFailureMapping,
    complete_profile_declaration,
)


INDEPENDENT_ID = "agent:independent:3gen:acme-line:agent-one"
GUARANTOR_ID = "agent:guarantor:7gen:anchor:guarantor-one"
SPONSORED_ID = "agent:sponsored:guarantor-one:child:agent-child"


class ObservableZeroOffsetTimezone(tzinfo):
    def __init__(self):
        self.calls = 0

    def utcoffset(self, value):
        self.calls += 1
        return timedelta(0)

    def dst(self, value):
        self.calls += 1
        return timedelta(0)


def profile(**changes):
    from kinetic_trust_library.models.profile import DeploymentProfile

    values = {"peer_share": "0"}
    values.update(changes)
    return DeploymentProfile.validate(complete_profile_declaration(**values))


def por_attestation(index=1, *, agent_id=INDEPENDENT_ID, **changes):
    values = {
        "attestation_id": f"attestation:{index}",
        "agent_id": agent_id,
        "transaction_ref": f"transaction:{index}",
        "friction": "0.6",
        "friction_category": FrictionCategory.HIGH,
        "action_risk": "1",
        "outcome": "success",
        "timestamp": CUTOFF - timedelta(minutes=1),
        "oracle_id": f"oracle:{index}",
        "verification_ref": f"verification:{index}",
    }
    values.update(changes)
    return PoRAttestationDeclaration(**values)


def external_root(index=1, **changes):
    values = {
        "instrument_id": f"root:{index}",
        "attestor": f"entity:attestor-{index}",
        "issuance": RootIssuanceDeclaration(
            issued_at=CUTOFF - timedelta(days=1),
            end_time=CUTOFF + timedelta(days=1),
            verification_ref=f"issuance-verification:{index}",
        ),
        "sponsor_standing": None,
        "stake_percentage": None,
        "exposure_class": "legal-liability",
        "declared_exposure": "100",
        "anchored_capacity": "100",
        "chain": (f"legal:root-{index}",),
        "terminator": ExternalTerminatorDeclaration(
            kind=ExternalTerminatorKind.LEGAL_ENTITY,
            identifier=f"legal:root-{index}",
            verification_ref=f"terminator-verification:{index}",
        ),
        "withdrawal_claim": None,
        "adjudication_finding": None,
    }
    values.update(changes)
    return RootInstrumentDeclaration(**values)


def declaration(*, agent_id=INDEPENDENT_ID, generation=3, **changes):
    values = {
        "agent_id": agent_id,
        "generation": generation,
        "identity_assurance_level": 3,
        "trajectory_length": 10_000,
        "por_attestations": (por_attestation(agent_id=agent_id),),
        "root_instruments": (external_root(),),
        "peer": None,
        "additional_ceilings": (),
        "advancement_floor": "0",
    }
    values.update(changes)
    return StandingDeclaration(**values)


def sponsor_snapshot(configured=None):
    configured = profile() if configured is None else configured
    return prepare_standing(
        configured,
        declaration(agent_id=GUARANTOR_ID, generation=7),
        CUTOFF,
    )


def sponsored_declaration(sponsor, **changes):
    sponsor_root = sponsor.root_instrument
    values = {
        "agent_id": SPONSORED_ID,
        "generation": 0,
        "identity_assurance_level": 1,
        "trajectory_length": 0,
        "por_attestations": (),
        "root_instruments": (
            RootInstrumentDeclaration(
                instrument_id="bond:one",
                attestor=sponsor.agent_id,
                issuance=RootIssuanceDeclaration(
                    issued_at=CUTOFF - timedelta(hours=1),
                    end_time=CUTOFF + timedelta(days=30),
                    verification_ref="bond-verification:one",
                ),
                sponsor_standing=sponsor,
                stake_percentage="25",
                exposure_class=None,
                declared_exposure=None,
                anchored_capacity=None,
                chain=(sponsor_root.attestor, *sponsor_root.chain),
                terminator=sponsor_root.terminator,
                withdrawal_claim=None,
                adjudication_finding=None,
            ),
        ),
        "peer": None,
        "additional_ceilings": (),
        "advancement_floor": "0",
    }
    values.update(changes)
    return StandingDeclaration(**values)


class SponsoredAuthorityTests(unittest.TestCase):
    def test_sponsored_root_derives_from_profile_and_cutoff_bound_sponsor(self):
        configured = profile()
        sponsor = sponsor_snapshot(configured)
        result = prepare_standing(configured, sponsored_declaration(sponsor), CUTOFF)
        self.assertEqual(
            result.root_score,
            Decimal("17.38560627359831218647513951627558"),
        )

        with self.assertRaises(TypeError):
            replace(result.root_instrument, sponsor_e_base="100")

    def test_sponsor_must_be_guarantor_ial_eligible_and_exactly_bound(self):
        configured = profile()
        sponsor = sponsor_snapshot(configured)
        wrong_cutoff = prepare_standing(
            configured,
            declaration(agent_id=GUARANTOR_ID, generation=7),
            CUTOFF - timedelta(microseconds=1),
        )
        independent = prepare_standing(
            configured,
            declaration(),
            CUTOFF,
        )
        for invalid in (wrong_cutoff, independent):
            with self.subTest(invalid=invalid.agent_id):
                root = replace(
                    sponsored_declaration(sponsor).root_instruments[0],
                    sponsor_standing=invalid,
                    attestor=invalid.agent_id,
                )
                with self.assertRaises(ValidationError):
                    prepare_standing(
                        configured,
                        sponsored_declaration(sponsor, root_instruments=(root,)),
                        CUTOFF,
                    )

        low_ial = prepare_standing(
            configured,
            declaration(
                agent_id=GUARANTOR_ID,
                generation=7,
                identity_assurance_level=1,
            ),
            CUTOFF,
        )
        low_ial_root = replace(
            sponsored_declaration(sponsor).root_instruments[0],
            sponsor_standing=low_ial,
            attestor=low_ial.agent_id,
        )
        with self.assertRaisesRegex(ValidationError, "identity eligible"):
            prepare_standing(
                configured,
                sponsored_declaration(sponsor, root_instruments=(low_ial_root,)),
                CUTOFF,
            )

        with self.assertRaisesRegex(ValidationError, "another profile"):
            prepare_standing(
                profile(standing_decay_rate="3"),
                sponsored_declaration(sponsor),
                CUTOFF,
            )

        with self.assertRaisesRegex(ValidationError, "sponsor.*identifier"):
            prepare_standing(
                configured,
                sponsored_declaration(
                    sponsor,
                    agent_id="agent:sponsored:wrong:child:agent-child",
                ),
                CUTOFF,
            )

    def test_malformed_exact_sponsor_snapshot_is_a_controlled_validation_error(self):
        configured = profile()
        sponsor = sponsor_snapshot(configured)
        root = replace(
            sponsored_declaration(sponsor).root_instruments[0],
            sponsor_standing=object.__new__(type(sponsor)),
        )
        with self.assertRaises(ValidationError):
            prepare_standing(
                configured,
                sponsored_declaration(sponsor, root_instruments=(root,)),
                CUTOFF,
            )

    def test_root_and_sponsor_times_require_owned_utc_without_timezone_hooks(self):
        configured = profile()
        custom_timezone = ObservableZeroOffsetTimezone()
        custom_time = datetime(2026, 8, 19, 12, tzinfo=custom_timezone)
        root = external_root(
            issuance=replace(external_root().issuance, issued_at=custom_time)
        )
        with self.assertRaises(ValidationError):
            prepare_standing(
                configured,
                declaration(root_instruments=(root,)),
                CUTOFF,
            )
        self.assertEqual(custom_timezone.calls, 0)

        sponsor = sponsor_snapshot(configured)
        subject = prepare_standing(
            configured,
            sponsored_declaration(sponsor),
            CUTOFF,
        )
        retained_timezone = ObservableZeroOffsetTimezone()
        retained_cutoff = datetime(2026, 8, 20, 12, tzinfo=retained_timezone)
        hostile_sponsor = copy.copy(sponsor)
        object.__setattr__(hostile_sponsor, "_cutoff", retained_cutoff)
        hostile_root = replace(
            subject.root_instrument,
            sponsor_standing=hostile_sponsor,
        )
        forged = copy.copy(subject)
        object.__setattr__(forged, "root_instrument", hostile_root)
        object.__setattr__(
            forged,
            "_declaration",
            replace(subject._declaration, root_instruments=(hostile_root,)),
        )
        with self.assertRaises(ValidationError):
            require_validated_standing_snapshot(forged, profile=configured)
        self.assertEqual(retained_timezone.calls, 0)

    def test_sponsored_identifier_binds_only_the_sponsor_unique_id(self):
        configured = profile()
        sponsor_one = sponsor_snapshot(configured)
        sponsor_two_id = "agent:guarantor:7gen:anchor:guarantor-two"
        sponsor_two = prepare_standing(
            configured,
            declaration(
                agent_id=sponsor_two_id,
                generation=7,
                por_attestations=(por_attestation(agent_id=sponsor_two_id),),
            ),
            CUTOFF,
        )

        one = prepare_standing(
            configured,
            sponsored_declaration(sponsor_one),
            CUTOFF,
        )
        two = prepare_standing(
            configured,
            sponsored_declaration(
                sponsor_two,
                agent_id="agent:sponsored:guarantor-two:child:agent-child",
            ),
            CUTOFF,
        )
        self.assertIs(require_validated_standing_snapshot(one), one)
        self.assertIs(require_validated_standing_snapshot(two), two)
        self.assertNotEqual(one.digest, two.digest)

        for alias_or_mismatch in (
            "agent:sponsored:anchor:child:agent-child",
            "agent:sponsored:guarantor-two:child:agent-child",
        ):
            with self.subTest(agent_id=alias_or_mismatch):
                with self.assertRaisesRegex(ValidationError, "sponsor.*identifier"):
                    prepare_standing(
                        configured,
                        sponsored_declaration(
                            sponsor_one,
                            agent_id=alias_or_mismatch,
                        ),
                        CUTOFF,
                    )


class AdversityCeilingTests(unittest.TestCase):
    def _ceiling(self, attestations):
        result = prepare_standing(
            profile(peer_share="10"),
            declaration(
                por_attestations=attestations,
                peer=PeerScoreDeclaration(
                    "100",
                    "peer:source",
                    ("peer:evidence",),
                    ("peer:provenance",),
                ),
            ),
            CUTOFF,
        )
        return next(
            item.value
            for item in result.applicable_ceilings
            if item.name == "adversity"
        )

    def test_strict_adversity_gates_derive_sixty_eighty_ninety_and_one_hundred(self):
        cases = (
            (
                (por_attestation(friction="0.5"),),
                Decimal("60"),
            ),
            (
                (por_attestation(friction="0.500001"),),
                Decimal("80"),
            ),
            (
                (
                    por_attestation(
                        friction="0.700001",
                        friction_category=FrictionCategory.SEVERE,
                    ),
                ),
                Decimal("90"),
            ),
            (
                (
                    por_attestation(
                        friction="0.9",
                        friction_category=FrictionCategory.CRISIS,
                    ),
                ),
                Decimal("100"),
            ),
        )
        for attestations, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(self._ceiling(attestations), expected)

    def test_many_elevated_attestations_cannot_cross_sixty(self):
        attestations = tuple(
            por_attestation(
                index,
                agent_id=GUARANTOR_ID,
                friction="0.4",
                friction_category=FrictionCategory.ELEVATED,
            )
            for index in range(1, 102)
        )
        result = prepare_standing(
            profile(peer_share="20"),
            declaration(
                agent_id=GUARANTOR_ID,
                generation=7,
                por_attestations=attestations,
                peer=PeerScoreDeclaration(
                    "100",
                    "peer:source",
                    ("peer:evidence",),
                    ("peer:provenance",),
                ),
            ),
            CUTOFF,
        )
        self.assertEqual(result.base_trust, Decimal("60"))


class RootLifecycleTests(unittest.TestCase):
    def test_status_is_derived_and_end_time_is_first_expired_instant(self):
        issuance = replace(external_root().issuance, end_time=CUTOFF)
        result = prepare_standing(
            profile(),
            declaration(root_instruments=(external_root(issuance=issuance),)),
            CUTOFF,
        )
        self.assertIs(result.root_status, RootInstrumentStatus.EXPIRED)
        self.assertEqual(result.root_score, 0)

    def test_withdrawal_and_finding_facts_derive_every_zero_branch(self):
        for_cause = RootWithdrawalClaim(
            claim_id="claim:one",
            declared_by="entity:attestor-1",
            cause=WithdrawalCause.FOR_CAUSE,
            claimed_at=CUTOFF - timedelta(hours=1),
            evidence_ref="claim-evidence:one",
        )
        pending = prepare_standing(
            profile(),
            declaration(root_instruments=(external_root(withdrawal_claim=for_cause),)),
            CUTOFF,
        )
        self.assertIs(pending.root_status, RootInstrumentStatus.FOR_CAUSE_PENDING)
        self.assertEqual(pending.root_score, 0)

        finding = RootAdjudicationFinding(
            finding_id="finding:one",
            adjudicator_id="adjudicator:one",
            outcome=AdjudicationFindingOutcome.FOR_CAUSE_SUSTAINED,
            found_at=CUTOFF - timedelta(minutes=30),
            claim_id="claim:one",
            evidence_ref="finding-evidence:one",
        )
        sustained = prepare_standing(
            profile(),
            declaration(
                root_instruments=(
                    external_root(
                        withdrawal_claim=for_cause,
                        adjudication_finding=finding,
                    ),
                )
            ),
            CUTOFF,
        )
        self.assertIs(sustained.root_status, RootInstrumentStatus.FOR_CAUSE_SUSTAINED)

    def test_impossible_claim_and_finding_order_is_rejected(self):
        claim = RootWithdrawalClaim(
            claim_id="claim:one",
            declared_by="entity:attestor-1",
            cause=WithdrawalCause.FOR_CAUSE,
            claimed_at=CUTOFF - timedelta(hours=1),
            evidence_ref="claim-evidence:one",
        )
        finding = RootAdjudicationFinding(
            finding_id="finding:one",
            adjudicator_id="adjudicator:one",
            outcome=AdjudicationFindingOutcome.FOR_CAUSE_REJECTED,
            found_at=CUTOFF - timedelta(hours=2),
            claim_id="claim:one",
            evidence_ref="finding-evidence:one",
        )
        with self.assertRaisesRegex(ValidationError, "finding"):
            prepare_standing(
                profile(),
                declaration(
                    root_instruments=(
                        external_root(
                            withdrawal_claim=claim,
                            adjudication_finding=finding,
                        ),
                    )
                ),
                CUTOFF,
            )

    def test_direct_misattestation_can_follow_without_cause_before_expiry(self):
        withdrawal = RootWithdrawalClaim(
            claim_id="claim:without-cause",
            declared_by="entity:attestor-1",
            cause=WithdrawalCause.WITHOUT_CAUSE,
            claimed_at=CUTOFF - timedelta(hours=1),
            evidence_ref="claim-evidence:without-cause",
        )
        finding = RootAdjudicationFinding(
            finding_id="finding:direct-misattestation",
            adjudicator_id="adjudicator:one",
            outcome=AdjudicationFindingOutcome.MISATTESTATION,
            found_at=CUTOFF - timedelta(minutes=30),
            claim_id=None,
            evidence_ref="finding-evidence:direct-misattestation",
        )
        result = prepare_standing(
            profile(),
            declaration(
                root_instruments=(
                    external_root(
                        withdrawal_claim=withdrawal,
                        adjudication_finding=finding,
                    ),
                )
            ),
            CUTOFF,
        )

        self.assertIs(result.root_status, RootInstrumentStatus.MISATTESTATION)
        self.assertEqual(result.root_score, 0)
        self.assertEqual(result.root_instrument.withdrawal_claim, withdrawal)
        self.assertEqual(result.root_instrument.adjudication_finding, finding)
        self.assertIs(require_validated_standing_snapshot(result), result)

    def test_direct_misattestation_preserves_order_expiry_and_branch_rules(self):
        without_cause = RootWithdrawalClaim(
            claim_id="claim:without-cause",
            declared_by="entity:attestor-1",
            cause=WithdrawalCause.WITHOUT_CAUSE,
            claimed_at=CUTOFF - timedelta(hours=1),
            evidence_ref="claim-evidence:without-cause",
        )
        for_cause = replace(without_cause, cause=WithdrawalCause.FOR_CAUSE)
        direct = RootAdjudicationFinding(
            finding_id="finding:direct-misattestation",
            adjudicator_id="adjudicator:one",
            outcome=AdjudicationFindingOutcome.MISATTESTATION,
            found_at=CUTOFF - timedelta(minutes=30),
            claim_id=None,
            evidence_ref="finding-evidence:direct-misattestation",
        )
        invalid_roots = (
            external_root(
                withdrawal_claim=without_cause,
                adjudication_finding=replace(
                    direct,
                    found_at=without_cause.claimed_at - timedelta(microseconds=1),
                ),
            ),
            external_root(
                withdrawal_claim=without_cause,
                adjudication_finding=replace(
                    direct,
                    claim_id=without_cause.claim_id,
                ),
            ),
            external_root(
                withdrawal_claim=for_cause,
                adjudication_finding=direct,
            ),
            external_root(
                issuance=replace(external_root().issuance, end_time=CUTOFF),
                withdrawal_claim=without_cause,
                adjudication_finding=replace(direct, found_at=CUTOFF),
            ),
        )
        for root in invalid_roots:
            with self.subTest(root=root):
                with self.assertRaises(ValidationError):
                    prepare_standing(
                        profile(),
                        declaration(root_instruments=(root,)),
                        CUTOFF,
                    )

        rejected = replace(
            direct,
            outcome=AdjudicationFindingOutcome.FOR_CAUSE_REJECTED,
            claim_id=for_cause.claim_id,
        )
        result = prepare_standing(
            profile(),
            declaration(
                root_instruments=(
                    external_root(
                        withdrawal_claim=for_cause,
                        adjudication_finding=rejected,
                    ),
                )
            ),
            CUTOFF,
        )
        self.assertIs(result.root_status, RootInstrumentStatus.FOR_CAUSE_REJECTED)
        self.assertEqual(result.root_score, 0)

    def test_lifecycle_rejects_future_mismatched_and_impossible_facts(self):
        claim = RootWithdrawalClaim(
            claim_id="claim:one",
            declared_by="entity:attestor-1",
            cause=WithdrawalCause.FOR_CAUSE,
            claimed_at=CUTOFF - timedelta(hours=1),
            evidence_ref="claim-evidence:one",
        )
        impossible_roots = (
            external_root(
                issuance=RootIssuanceDeclaration(
                    CUTOFF + timedelta(seconds=1),
                    CUTOFF + timedelta(days=1),
                    "issuance-verification:future",
                )
            ),
            external_root(withdrawal_claim=replace(claim, declared_by="entity:other")),
            external_root(
                withdrawal_claim=replace(
                    claim,
                    claimed_at=CUTOFF + timedelta(seconds=1),
                )
            ),
            external_root(
                adjudication_finding=RootAdjudicationFinding(
                    "finding:no-claim",
                    "adjudicator:one",
                    AdjudicationFindingOutcome.FOR_CAUSE_SUSTAINED,
                    CUTOFF - timedelta(minutes=1),
                    "claim:one",
                    "finding-evidence:no-claim",
                )
            ),
            external_root(
                adjudication_finding=RootAdjudicationFinding(
                    "finding:wrong-adjudicator",
                    "adjudicator:other",
                    AdjudicationFindingOutcome.MISATTESTATION,
                    CUTOFF - timedelta(minutes=1),
                    None,
                    "finding-evidence:wrong-adjudicator",
                )
            ),
            external_root(
                withdrawal_claim=claim,
                adjudication_finding=RootAdjudicationFinding(
                    "finding:misattestation-with-claim",
                    "adjudicator:one",
                    AdjudicationFindingOutcome.MISATTESTATION,
                    CUTOFF - timedelta(minutes=1),
                    None,
                    "finding-evidence:misattestation-with-claim",
                ),
            ),
        )
        for root in impossible_roots:
            with self.subTest(root=root.instrument_id):
                with self.assertRaises(ValidationError):
                    prepare_standing(
                        profile(),
                        declaration(root_instruments=(root,)),
                        CUTOFF,
                    )


class ExternalityAndPeerTests(unittest.TestCase):
    def test_agent_prefixed_external_terminator_is_rejected(self):
        terminator = ExternalTerminatorDeclaration(
            ExternalTerminatorKind.NAMED_HUMAN,
            "agent:guarantor:7gen:false:terminator",
            "terminator-verification:false",
        )
        with self.assertRaisesRegex(ValidationError, "external terminator"):
            prepare_standing(
                profile(),
                declaration(
                    root_instruments=(
                        external_root(
                            chain=(terminator.identifier,), terminator=terminator
                        ),
                    )
                ),
                CUTOFF,
            )

    def test_peer_rejects_every_represented_base_reference(self):
        represented = (
            INDEPENDENT_ID,
            "attestation:1",
            "transaction:1",
            "oracle:1",
            "verification:1",
            "root:1",
            "entity:attestor-1",
            "legal:root-1",
            "issuance-verification:1",
            "terminator-verification:1",
            "legal-liability",
        )
        configured = profile(peer_share="10")
        for overlap in represented:
            with self.subTest(overlap=overlap):
                peer = PeerScoreDeclaration(
                    score="50",
                    source_id=overlap,
                    evidence_ids=("peer-evidence:one",),
                    provenance_refs=("peer-provenance:one",),
                )
                with self.assertRaisesRegex(ValidationError, "independent"):
                    prepare_standing(configured, declaration(peer=peer), CUTOFF)

        ceiling = CeilingDeclaration("zone_mass", "100", "zone:mass:one")
        with self.assertRaisesRegex(ValidationError, "independent"):
            prepare_standing(
                configured,
                declaration(
                    peer=PeerScoreDeclaration(
                        "50",
                        "zone:mass:one",
                        ("peer-evidence:one",),
                        ("peer-provenance:one",),
                    ),
                    additional_ceilings=(ceiling,),
                ),
                CUTOFF,
            )

    def test_peer_rejects_sources_nested_in_sponsor_standing(self):
        configured = profile(peer_share="10")
        sponsor = prepare_standing(
            configured,
            declaration(
                agent_id=GUARANTOR_ID,
                generation=7,
                por_attestations=(por_attestation(agent_id=GUARANTOR_ID),),
                peer=PeerScoreDeclaration(
                    "50",
                    "sponsor-peer:source",
                    ("sponsor-peer:evidence",),
                    ("sponsor-peer:provenance",),
                ),
            ),
            CUTOFF,
        )
        overlapping = PeerScoreDeclaration(
            "50",
            "transaction:1",
            ("subject-peer:evidence",),
            ("subject-peer:provenance",),
        )
        with self.assertRaisesRegex(ValidationError, "independent"):
            prepare_standing(
                configured,
                sponsored_declaration(sponsor, peer=overlapping),
                CUTOFF,
            )

    def test_peer_rejects_subject_digests_and_every_applicable_ceiling_reference(
        self,
    ):
        configured = profile(peer_share="10")
        raw = declaration(
            additional_ceilings=(
                CeilingDeclaration("zone_mass", "100", "zone:mass:subject"),
            )
        )
        por = calculate_por(raw.por_attestations, raw.agent_id, CUTOFF)
        references = (
            por.digest,
            "generation",
            "ktp:identity:generation",
            "ial",
            "ktp:identity:ial",
            "trajectory",
            "ktp:core:trajectory",
            "adversity",
            "ktp:core:adversity",
            "zone_mass",
            "zone:mass:subject",
        )
        for index, reference in enumerate(references):
            with self.subTest(reference=reference):
                peer = PeerScoreDeclaration(
                    "50",
                    f"peer:subject-source:{index}",
                    (f"peer:subject-evidence:{index}",),
                    (reference,),
                )
                with self.assertRaisesRegex(ValidationError, "independent"):
                    prepare_standing(
                        configured,
                        replace(raw, peer=peer),
                        CUTOFF,
                    )

    def test_peer_rejects_complete_canonical_sponsor_reference_graph(self):
        configured = profile(peer_share="10")
        sponsor = prepare_standing(
            configured,
            declaration(
                agent_id=GUARANTOR_ID,
                generation=7,
                por_attestations=(por_attestation(agent_id=GUARANTOR_ID),),
                peer=PeerScoreDeclaration(
                    "50",
                    "sponsor-peer:source",
                    ("sponsor-peer:evidence",),
                    ("sponsor-peer:provenance",),
                ),
                additional_ceilings=(
                    CeilingDeclaration(
                        "sponsor_zone",
                        "100",
                        "zone:mass:sponsor",
                    ),
                ),
            ),
            CUTOFF,
        )
        references = {
            sponsor.agent_id,
            sponsor.digest,
            sponsor.por.digest,
            sponsor._profile.digest,
        }
        for ceiling in sponsor.applicable_ceilings:
            references.update((ceiling.name, ceiling.provenance_id))

        for index, reference in enumerate(sorted(references)):
            with self.subTest(reference=reference):
                peer = PeerScoreDeclaration(
                    "50",
                    f"peer:sponsor-source:{index}",
                    (f"peer:sponsor-evidence:{index}",),
                    (reference,),
                )
                with self.assertRaisesRegex(ValidationError, "independent"):
                    prepare_standing(
                        configured,
                        sponsored_declaration(sponsor, peer=peer),
                        CUTOFF,
                    )


class IdentifierAndStructuralBoundaryTests(unittest.TestCase):
    def test_missing_nested_standing_slots_are_validation_errors(self):
        no_root = NoRootInstrumentDeclaration("root:none")
        root = external_root()
        issuance_root = external_root()
        terminator_root = external_root()
        withdrawal = RootWithdrawalClaim(
            "claim:one", "entity:attestor-1", WithdrawalCause.WITHOUT_CAUSE,
            CUTOFF - timedelta(hours=1), "claim-evidence:one",
        )
        finding = RootAdjudicationFinding(
            "finding:one", "adjudicator:one",
            AdjudicationFindingOutcome.MISATTESTATION,
            CUTOFF - timedelta(minutes=30), None, "finding-evidence:one",
        )
        peer = PeerScoreDeclaration(
            "10", "peer:one", ("peer-evidence:one",), ("peer-provenance:one",)
        )
        ceiling = CeilingDeclaration("custom", "90", "ceiling-provenance:one")
        cases = (
            (no_root, "instrument_id", {"root_instruments": (no_root,)}),
            (root, "anchored_capacity", {"root_instruments": (root,)}),
            (
                issuance_root.issuance, "verification_ref",
                {"root_instruments": (issuance_root,)},
            ),
            (
                terminator_root.terminator, "verification_ref",
                {"root_instruments": (terminator_root,)},
            ),
            (
                withdrawal, "evidence_ref",
                {"root_instruments": (external_root(withdrawal_claim=withdrawal),)},
            ),
            (
                finding, "evidence_ref",
                {"root_instruments": (external_root(adjudication_finding=finding),)},
            ),
            (peer, "provenance_refs", {"peer": peer}),
            (ceiling, "provenance_id", {"additional_ceilings": (ceiling,)}),
        )
        for nested, member, changes in cases:
            configured = profile(peer_share="10" if nested is peer else "0")
            value = declaration(**changes)
            object.__delattr__(nested, member)
            with self.subTest(declaration_type=type(nested).__name__, member=member):
                with self.assertRaises(ValidationError):
                    prepare_standing(configured, value, CUTOFF)

    @staticmethod
    def _forged_sponsor_layer(
        template: StandingSnapshot,
        child: StandingSnapshot,
    ) -> StandingSnapshot:
        root = replace(
            template.root_instrument,
            sponsor_standing=child,
            stake_percentage=Decimal("1"),
            exposure_class=None,
            declared_exposure=None,
            anchored_capacity=None,
        )
        layer = copy.copy(template)
        object.__setattr__(layer, "root_instrument", root)
        object.__setattr__(
            layer,
            "_declaration",
            replace(template._declaration, root_instruments=(root,)),
        )
        return layer

    def test_stored_profile_tree_rejects_armed_nested_field_before_hooks(self):
        class ArmedEqualityString(str):
            calls = 0

            def __eq__(self, _other):
                type(self).calls += 1
                raise RuntimeError("armed retained profile equality")

            __hash__ = str.__hash__

        configured = profile()
        snapshot = prepare_standing(configured, declaration(), CUTOFF)
        hostile_profile = copy.copy(configured)
        object.__setattr__(
            hostile_profile,
            "misattestation_adjudicator",
            ArmedEqualityString(configured.misattestation_adjudicator),
        )
        forged = copy.copy(snapshot)
        object.__setattr__(forged, "_profile", hostile_profile)

        with self.assertRaises(ValidationError):
            require_validated_standing_snapshot(forged, profile=configured)
        self.assertEqual(ArmedEqualityString.calls, 0)
        self.assertEqual(forged, snapshot)
        self.assertEqual(ArmedEqualityString.calls, 0)

    def test_snapshot_equality_ignores_retained_declaration_hooks(self):
        class ArmedEqualityString(str):
            calls = 0

            def __eq__(self, _other):
                type(self).calls += 1
                raise RuntimeError("armed retained declaration equality")

            __hash__ = str.__hash__

        snapshot = prepare_standing(profile(), declaration(), CUTOFF)
        hostile_declaration = copy.copy(snapshot._declaration)
        object.__setattr__(
            hostile_declaration,
            "agent_id",
            ArmedEqualityString(hostile_declaration.agent_id),
        )
        forged = copy.copy(snapshot)
        object.__setattr__(forged, "_declaration", hostile_declaration)

        self.assertEqual(forged, snapshot)
        self.assertEqual(ArmedEqualityString.calls, 0)

    def test_snapshot_equality_ignores_retained_cutoff_hooks(self):
        class ArmedDatetime(datetime):
            calls = 0

            def __eq__(self, _other):
                type(self).calls += 1
                raise RuntimeError("armed retained cutoff equality")

            __hash__ = datetime.__hash__

        snapshot = prepare_standing(profile(), declaration(), CUTOFF)
        hostile_cutoff = ArmedDatetime(
            CUTOFF.year,
            CUTOFF.month,
            CUTOFF.day,
            CUTOFF.hour,
            CUTOFF.minute,
            CUTOFF.second,
            CUTOFF.microsecond,
            tzinfo=CUTOFF.tzinfo,
            fold=CUTOFF.fold,
        )
        forged = copy.copy(snapshot)
        object.__setattr__(forged, "_cutoff", hostile_cutoff)

        self.assertEqual(forged, snapshot)
        self.assertEqual(ArmedDatetime.calls, 0)

    def test_generation_and_agent_identifier_must_have_exact_same_lineage(self):
        invalid = (
            ("agent:one", 3),
            ("agent:sponsored:anchor:child:id", 7),
            ("agent:guarantor:7gen:anchor:id", 0),
            ("agent:independent:03gen:line:id", 3),
            ("agent:independent:4gen:line:id", 3),
        )
        for agent_id, generation in invalid:
            with self.subTest(agent_id=agent_id):
                with self.assertRaisesRegex(ValidationError, "identifier"):
                    prepare_standing(
                        profile(),
                        declaration(
                            agent_id=agent_id,
                            generation=generation,
                            por_attestations=(por_attestation(agent_id=agent_id),),
                        ),
                        CUTOFF,
                    )

    def test_structural_validators_reject_hostile_equality_before_comparison(self):
        class HostileEquality:
            def __eq__(self, _other):
                raise RuntimeError("boom")

        standing = prepare_standing(profile(), declaration(), CUTOFF)
        por = copy.copy(standing.por)
        object.__setattr__(por, "eligible_attestation_ids", (HostileEquality(),))
        with self.assertRaises(ValidationError):
            require_validated_por_result(por)

        forged = copy.copy(standing)
        object.__setattr__(
            forged,
            "root_instrument",
            replace(standing.root_instrument, chain=(HostileEquality(),)),
        )
        with self.assertRaises(ValidationError):
            require_validated_standing_snapshot(forged)

    def test_nested_sponsor_primitives_are_checked_before_canonical_projection(self):
        class HostileString(str):
            touched = False

            def encode(self, *_args, **_kwargs):
                type(self).touched = True
                raise RuntimeError("hostile attribute executed")

        configured = profile()
        sponsor = sponsor_snapshot(configured)
        subject = prepare_standing(
            configured,
            sponsored_declaration(sponsor),
            CUTOFF,
        )
        hostile_sponsor = copy.copy(sponsor)
        object.__setattr__(
            hostile_sponsor,
            "agent_id",
            HostileString(sponsor.agent_id),
        )
        forged = copy.copy(subject)
        object.__setattr__(
            forged,
            "root_instrument",
            replace(subject.root_instrument, sponsor_standing=hostile_sponsor),
        )

        with self.assertRaises(ValidationError):
            require_validated_standing_snapshot(forged)
        self.assertFalse(HostileString.touched)

    def test_sponsor_reference_projection_does_not_walk_untrusted_profile_internals(
        self,
    ):
        class HostileMapping(Mapping):
            touched = False

            def __iter__(self):
                type(self).touched = True
                raise RuntimeError("hostile mapping executed")

            def __len__(self):
                return 1

            def __getitem__(self, _key):
                type(self).touched = True
                raise RuntimeError("hostile mapping executed")

        configured = profile()
        sponsor = sponsor_snapshot(configured)
        subject = prepare_standing(
            configured,
            sponsored_declaration(sponsor),
            CUTOFF,
        )
        hostile_profile = copy.copy(configured)
        object.__setattr__(
            hostile_profile,
            "actions",
            MappingProxyType(HostileMapping()),
        )
        hostile_sponsor = copy.copy(sponsor)
        object.__setattr__(hostile_sponsor, "_profile", hostile_profile)
        object.__setattr__(
            hostile_sponsor,
            "base_trust",
            sponsor.base_trust + Decimal(1),
        )
        forged = copy.copy(subject)
        object.__setattr__(
            forged,
            "root_instrument",
            replace(subject.root_instrument, sponsor_standing=hostile_sponsor),
        )

        with self.assertRaises(ValidationError):
            require_validated_standing_snapshot(forged)
        self.assertFalse(HostileMapping.touched)

    def test_standing_boundary_rejects_unowned_mapping_before_control_hooks(self):
        class ArmedProcessControlMapping(_ExternalFailureMapping):
            calls = 0

            def __iter__(self):
                type(self).calls += 1
                return super().__iter__()

        configured = profile()
        snapshot = prepare_standing(configured, declaration(), CUTOFF)
        hostile_profile = copy.copy(configured)
        object.__setattr__(
            hostile_profile,
            "actions",
            MappingProxyType(
                ArmedProcessControlMapping(iteration_error=KeyboardInterrupt())
            ),
        )

        with self.assertRaises(ValidationError):
            require_validated_standing_snapshot(snapshot, profile=hostile_profile)
        self.assertEqual(ArmedProcessControlMapping.calls, 0)

    def test_structural_sponsor_validation_visits_each_distinct_snapshot_once(self):
        configured = profile()
        sponsor = sponsor_snapshot(configured)
        subject = prepare_standing(
            configured,
            sponsored_declaration(sponsor),
            CUTOFF,
        )
        structure_code = standing_module._require_standing_structure_members.__code__
        calls = 0

        def count_calls(frame, event, _argument):
            nonlocal calls
            if event == "call" and frame.f_code is structure_code:
                calls += 1

        sys.setprofile(count_calls)
        try:
            require_validated_standing_snapshot(subject)
        finally:
            sys.setprofile(None)
        self.assertEqual(calls, 2)

    def test_impossible_sponsor_depth_is_rejected_before_dag_expansion(self):
        configured = profile()
        template = sponsor_snapshot(configured)
        forged = template
        for _ in range(6):
            forged = self._forged_sponsor_layer(template, forged)

        structure_code = standing_module._require_standing_structure_members.__code__
        calls = 0

        def count_calls(frame, event, _argument):
            nonlocal calls
            if event == "call" and frame.f_code is structure_code:
                calls += 1

        sys.setprofile(count_calls)
        try:
            with self.assertRaises(ValidationError):
                require_validated_standing_snapshot(forged)
        finally:
            sys.setprofile(None)
        self.assertLessEqual(calls, 2)

    def test_hostile_sponsor_role_primitive_fails_before_recursion(self):
        class HostileGeneration(int):
            def __eq__(self, _other):
                raise RuntimeError("hostile generation compared")

        configured = profile()
        template = sponsor_snapshot(configured)
        hostile = copy.copy(template)
        object.__setattr__(hostile, "generation", HostileGeneration(7))
        forged = self._forged_sponsor_layer(template, hostile)
        structure_code = standing_module._require_standing_structure_members.__code__
        calls = 0

        def count_calls(frame, event, _argument):
            nonlocal calls
            if event == "call" and frame.f_code is structure_code:
                calls += 1

        sys.setprofile(count_calls)
        try:
            with self.assertRaises(ValidationError):
                require_validated_standing_snapshot(forged)
        finally:
            sys.setprofile(None)
        self.assertEqual(calls, 1)

    def test_structural_sponsor_cycle_is_rejected_with_bounded_work(self):
        configured = profile()
        cyclic = sponsor_snapshot(configured)
        root = replace(
            cyclic.root_instrument,
            sponsor_standing=cyclic,
            stake_percentage=Decimal("1"),
            exposure_class=None,
            declared_exposure=None,
            anchored_capacity=None,
        )
        object.__setattr__(cyclic, "root_instrument", root)
        object.__setattr__(
            cyclic,
            "_declaration",
            replace(cyclic._declaration, root_instruments=(root,)),
        )
        structure_code = standing_module._require_standing_structure_members.__code__
        calls = 0

        def count_calls(frame, event, _argument):
            nonlocal calls
            if event == "call" and frame.f_code is structure_code:
                calls += 1

        sys.setprofile(count_calls)
        try:
            with self.assertRaises(ValidationError):
                require_validated_standing_snapshot(cyclic)
        finally:
            sys.setprofile(None)
        self.assertEqual(calls, 1)

    def test_high_fanout_standing_boundary_validates_effective_profile_once(self):
        configured, _source_mapping = profile_with_counted_one_route_feeds(2_100)
        value = declaration()
        validation_code = standing_module.require_validated_profile.__code__
        calls = 0

        def count_calls(frame, event, _argument):
            nonlocal calls
            if event == "call" and frame.f_code is validation_code:
                calls += 1

        sys.setprofile(count_calls)
        try:
            snapshot = prepare_standing(configured, value, CUTOFF)
        finally:
            sys.setprofile(None)
        self.assertEqual(calls, 1)

        equivalent, _ = profile_with_counted_one_route_feeds(2_100)
        calls = 0
        sys.setprofile(count_calls)
        try:
            require_validated_standing_snapshot(snapshot, profile=equivalent)
        finally:
            sys.setprofile(None)
        self.assertEqual(calls, 1)


class ExplicitAbsenceTests(unittest.TestCase):
    def test_explicit_no_root_is_typed_and_computes_zero(self):
        result = prepare_standing(
            profile(),
            declaration(root_instruments=(NoRootInstrumentDeclaration("root:none"),)),
            CUTOFF,
        )
        self.assertIs(result.root_status, RootInstrumentStatus.NONE)
        self.assertEqual(result.root_score, 0)


if __name__ == "__main__":
    unittest.main()
