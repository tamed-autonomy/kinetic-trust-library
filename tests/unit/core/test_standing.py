"""Standing and E_base tests derived from KTP Core 5.1."""

import copy
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from decimal import Decimal

from kinetic_trust_library.core.standing import (
    MAX_PEER_EVIDENCE_IDS,
    MAX_PEER_PROVENANCE_REFS,
    prepare_standing,
    require_validated_standing_snapshot,
)
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.standing import (
    CeilingDeclaration,
    ExternalTerminatorDeclaration,
    ExternalTerminatorKind,
    LineagePhase,
    NoRootInstrumentDeclaration,
    PeerScoreDeclaration,
    RootInstrumentStatus,
    RootWithdrawalClaim,
    ShareAllocation,
    StandingSnapshot,
    WithdrawalCause,
)
from tests.unit.core.test_por import CUTOFF
from tests.unit.core.test_standing_contract import (
    GUARANTOR_ID,
    declaration,
    external_root,
    por_attestation,
    profile,
    sponsor_snapshot,
    sponsored_declaration,
)


def peer(score="50", **changes):
    values = {
        "score": score,
        "source_id": "peer:source",
        "evidence_ids": ("peer:evidence",),
        "provenance_refs": ("peer:provenance",),
    }
    values.update(changes)
    return PeerScoreDeclaration(**values)


class StandingTests(unittest.TestCase):
    def test_peer_share_reallocates_por_and_root(self):
        snapshot = prepare_standing(
            profile(peer_share="20"), declaration(peer=peer()), CUTOFF
        )
        self.assertEqual(snapshot.shares.por, Decimal("56"))
        self.assertEqual(snapshot.shares.root, Decimal("24"))
        self.assertEqual(snapshot.shares.peer, Decimal("20"))

    def test_base_trust_uses_each_share_as_a_cap_not_a_score_multiplier(self):
        snapshot = prepare_standing(
            profile(peer_share="10"), declaration(peer=peer()), CUTOFF
        )
        self.assertEqual(
            snapshot.shares,
            ShareAllocation(Decimal("63"), Decimal("27"), Decimal("10")),
        )
        self.assertEqual(
            snapshot.base_trust,
            Decimal("36.29409129247696193565525112929604"),
        )

    def test_sponsored_root_formula_and_lineage(self):
        configured = profile()
        sponsor = sponsor_snapshot(configured)
        snapshot = prepare_standing(configured, sponsored_declaration(sponsor), CUTOFF)
        self.assertIs(snapshot.lineage, LineagePhase.SPONSORED)
        self.assertEqual(
            snapshot.root_score,
            Decimal("17.38560627359831218647513951627558"),
        )

    def test_independent_and_guarantor_root_formula(self):
        for agent_id, generation, lineage in (
            (
                "agent:independent:3gen:acme-line:agent-one",
                3,
                LineagePhase.INDEPENDENT,
            ),
            (GUARANTOR_ID, 7, LineagePhase.GUARANTOR),
        ):
            with self.subTest(generation=generation):
                snapshot = prepare_standing(
                    profile(),
                    declaration(
                        agent_id=agent_id,
                        generation=generation,
                        por_attestations=(por_attestation(agent_id=agent_id),),
                    ),
                    CUTOFF,
                )
                self.assertIs(snapshot.lineage, lineage)
                self.assertEqual(snapshot.root_score, Decimal("100"))

    def test_current_root_requires_positive_capacity(self):
        with self.assertRaisesRegex(ValidationError, "anchored capacity"):
            prepare_standing(
                profile(),
                declaration(root_instruments=(external_root(anchored_capacity="0"),)),
                CUTOFF,
            )

    def test_strongest_concurrent_root_counts_once(self):
        weak = external_root(
            instrument_id="root:weak",
            declared_exposure="10",
            anchored_capacity="100",
        )
        strong = external_root(
            2,
            instrument_id="root:strong",
            declared_exposure="90",
            anchored_capacity="100",
        )
        snapshot = prepare_standing(
            profile(), declaration(root_instruments=(weak, strong)), CUTOFF
        )
        self.assertEqual(snapshot.root_score, Decimal("90"))
        self.assertEqual(snapshot.root_instrument.instrument_id, "root:strong")

    def test_expired_for_cause_and_unresolved_roots_compute_zero(self):
        expired_issuance = replace(
            external_root().issuance, end_time=CUTOFF - timedelta(microseconds=1)
        )
        claim = RootWithdrawalClaim(
            "claim:one",
            "entity:attestor-1",
            WithdrawalCause.FOR_CAUSE,
            CUTOFF - timedelta(hours=1),
            "claim:evidence",
        )
        unresolved_issuance = replace(external_root().issuance, end_time=CUTOFF)
        cases = (
            (external_root(issuance=expired_issuance), RootInstrumentStatus.EXPIRED),
            (
                external_root(withdrawal_claim=claim),
                RootInstrumentStatus.FOR_CAUSE_PENDING,
            ),
            (
                external_root(
                    issuance=unresolved_issuance,
                    withdrawal_claim=claim,
                ),
                RootInstrumentStatus.FOR_CAUSE_UNRESOLVED,
            ),
        )
        for root, status in cases:
            with self.subTest(status=status):
                snapshot = prepare_standing(
                    profile(), declaration(root_instruments=(root,)), CUTOFF
                )
                self.assertEqual(snapshot.root_score, 0)
                self.assertIs(snapshot.root_status, status)

    def test_without_cause_is_nonrenewable_before_expiry_and_zero_at_expiry(self):
        claim = RootWithdrawalClaim(
            "claim:notice",
            "entity:attestor-1",
            WithdrawalCause.WITHOUT_CAUSE,
            CUTOFF - timedelta(hours=1),
            "claim:notice-evidence",
        )
        before = prepare_standing(
            profile(),
            declaration(root_instruments=(external_root(withdrawal_claim=claim),)),
            CUTOFF,
        )
        self.assertIs(before.root_status, RootInstrumentStatus.NON_RENEWABLE)
        self.assertEqual(before.root_score, Decimal(100))

        exact_end = replace(external_root().issuance, end_time=CUTOFF)
        expired = prepare_standing(
            profile(),
            declaration(
                root_instruments=(
                    external_root(issuance=exact_end, withdrawal_claim=claim),
                )
            ),
            CUTOFF,
        )
        self.assertIs(expired.root_status, RootInstrumentStatus.EXPIRED)
        self.assertEqual(expired.root_score, 0)

    def test_explicit_no_instrument_computes_zero(self):
        snapshot = prepare_standing(
            profile(),
            declaration(root_instruments=(NoRootInstrumentDeclaration("root:none"),)),
            CUTOFF,
        )
        self.assertEqual(snapshot.root_score, 0)
        self.assertIs(snapshot.root_status, RootInstrumentStatus.NONE)

    def test_root_chain_is_acyclic_bounded_and_terminated(self):
        wrong_terminator = ExternalTerminatorDeclaration(
            ExternalTerminatorKind.LEGAL_ENTITY,
            "legal:root-1",
            "terminator-verification:1",
        )
        cases = (
            external_root(chain=("legal:root-1", "legal:root-1")),
            external_root(chain=("legal:wrong",), terminator=wrong_terminator),
            external_root(
                chain=tuple(f"legal:hop-{index}" for index in range(7)),
                terminator=ExternalTerminatorDeclaration(
                    ExternalTerminatorKind.LEGAL_ENTITY,
                    "legal:hop-6",
                    "terminator-verification:long",
                ),
            ),
        )
        for instrument in cases:
            with self.subTest(instrument=instrument):
                with self.assertRaises(ValidationError):
                    prepare_standing(
                        profile(external_root_hop_bound=6),
                        declaration(root_instruments=(instrument,)),
                        CUTOFF,
                    )

    def test_adjudicator_is_distinct_from_concrete_attestor(self):
        with self.assertRaisesRegex(ValidationError, "adjudicator"):
            prepare_standing(
                profile(misattestation_adjudicator="entity:attestor-1"),
                declaration(),
                CUTOFF,
            )

    def test_peer_is_absent_at_zero_share_and_requires_distinct_provenance(self):
        with self.assertRaisesRegex(ValidationError, "absent"):
            prepare_standing(profile(), declaration(peer=peer()), CUTOFF)
        with self.assertRaisesRegex(ValidationError, "independent"):
            prepare_standing(
                profile(peer_share="10"),
                declaration(peer=peer(source_id="oracle:1")),
                CUTOFF,
            )

    def test_builtin_ceilings_and_additional_minimum_apply(self):
        configured = profile()
        sponsor = sponsor_snapshot(configured)
        cases = (
            (sponsored_declaration(sponsor), "generation", Decimal("25")),
            (declaration(identity_assurance_level=1), "ial", Decimal("40")),
            (declaration(trajectory_length=999), "trajectory", Decimal("50")),
            (
                declaration(por_attestations=(por_attestation(friction="0.5"),)),
                "adversity",
                Decimal("60"),
            ),
            (
                declaration(
                    additional_ceilings=(
                        CeilingDeclaration("zone_mass", "12", "zone:one"),
                    )
                ),
                "zone_mass",
                Decimal("12"),
            ),
        )
        for value, expected_name, expected in cases:
            with self.subTest(expected_name=expected_name):
                snapshot = prepare_standing(configured, value, CUTOFF)
                self.assertLessEqual(snapshot.base_trust, expected)
                self.assertIn(
                    (expected_name, expected),
                    tuple(
                        (ceiling.name, ceiling.value)
                        for ceiling in snapshot.applicable_ceilings
                    ),
                )

    def test_trajectory_ceiling_boundaries(self):
        cases = ((999, "50"), (1000, "70"), (9999, "70"), (10000, "100"))
        for length, ceiling in cases:
            with self.subTest(length=length):
                snapshot = prepare_standing(
                    profile(), declaration(trajectory_length=length), CUTOFF
                )
                value = next(
                    item.value
                    for item in snapshot.applicable_ceilings
                    if item.name == "trajectory"
                )
                self.assertEqual(value, Decimal(ceiling))

    def test_advancement_floor_is_validated_and_preserved_not_added(self):
        baseline = prepare_standing(
            profile(), declaration(advancement_floor="0"), CUTOFF
        )
        preserved = prepare_standing(
            profile(), declaration(advancement_floor="1000"), CUTOFF
        )
        self.assertEqual(preserved.advancement_floor, Decimal("1000"))
        self.assertEqual(preserved.base_trust, baseline.base_trust)
        with self.assertRaisesRegex(ValidationError, "advancement floor"):
            prepare_standing(profile(), declaration(advancement_floor="-1"), CUTOFF)

    def test_standing_decay_is_preserved_by_profile_but_never_applied(self):
        slow = prepare_standing(profile(standing_decay_rate="2"), declaration(), CUTOFF)
        fast = prepare_standing(
            profile(standing_decay_rate="20"), declaration(), CUTOFF
        )
        self.assertEqual(slow.base_trust, fast.base_trust)
        self.assertEqual(slow.por, fast.por)

    def test_declaration_and_result_are_owned_immutable_values(self):
        roots = [external_root()]
        value = declaration(root_instruments=tuple(roots))
        snapshot = prepare_standing(profile(), value, CUTOFF)
        original = copy.copy(snapshot)
        roots.clear()
        self.assertIs(require_validated_standing_snapshot(snapshot), snapshot)
        self.assertEqual(snapshot, original)
        with self.assertRaises(TypeError):
            StandingSnapshot()
        with self.assertRaises(FrozenInstanceError):
            snapshot.base_trust = Decimal(100)

    def test_resealed_inconsistent_snapshot_fails_structural_validation(self):
        snapshot = prepare_standing(profile(), declaration(), CUTOFF)
        forged = object.__new__(StandingSnapshot)
        for name in snapshot.__slots__:
            object.__setattr__(forged, name, getattr(snapshot, name))
        object.__setattr__(
            forged, "shares", ShareAllocation(Decimal(0), Decimal(0), Decimal(100))
        )
        with self.assertRaisesRegex(ValidationError, "integrity"):
            require_validated_standing_snapshot(forged)

    def test_input_primitives_and_cardinalities_are_strict(self):
        cases = (
            declaration(generation=True),
            declaration(identity_assurance_level=4),
            declaration(trajectory_length=-1),
            declaration(root_instruments=()),
            declaration(
                additional_ceilings=(CeilingDeclaration("generation", "10", "x"),)
            ),
        )
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    prepare_standing(profile(), value, CUTOFF)

    def test_configuration_scale_has_no_fixed_library_quota(self):
        roots = tuple(external_root(index) for index in range(1, 66))
        ceilings = tuple(
            CeilingDeclaration(f"zone:{index}", "100", f"provenance:{index}")
            for index in range(65)
        )
        snapshot = prepare_standing(
            profile(),
            declaration(root_instruments=roots, additional_ceilings=ceilings),
            CUTOFF,
        )
        self.assertEqual(len(snapshot._declaration.root_instruments), 65)
        self.assertEqual(len(snapshot.applicable_ceilings), 69)

    def test_peer_provenance_safety_bounds_accept_maximum_and_reject_next(self):
        self.assertEqual(MAX_PEER_EVIDENCE_IDS, 2_048)
        self.assertEqual(MAX_PEER_PROVENANCE_REFS, 2_048)
        evidence = tuple(f"peer:evidence:{index}" for index in range(2_048))
        accepted = peer(evidence_ids=evidence)
        prepare_standing(profile(peer_share="10"), declaration(peer=accepted), CUTOFF)
        with self.assertRaisesRegex(ValidationError, "safety maximum"):
            prepare_standing(
                profile(peer_share="10"),
                declaration(
                    peer=peer(evidence_ids=(*evidence, "peer:evidence:overflow"))
                ),
                CUTOFF,
            )

    def test_additional_ceiling_order_does_not_change_standing(self):
        ceilings = (
            CeilingDeclaration("zone:second", "80", "provenance:second"),
            CeilingDeclaration("zone:first", "70", "provenance:first"),
        )
        forward = prepare_standing(
            profile(), declaration(additional_ceilings=ceilings), CUTOFF
        )
        reverse = prepare_standing(
            profile(),
            declaration(additional_ceilings=tuple(reversed(ceilings))),
            CUTOFF,
        )
        self.assertEqual(forward, reverse)
        self.assertEqual(forward.digest, reverse.digest)


if __name__ == "__main__":
    unittest.main()
