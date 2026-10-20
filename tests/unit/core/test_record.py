"""Decision records preserve evaluation authority and reject malformed values."""

from __future__ import annotations

import copy
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from typing import get_type_hints
import unittest

import kinetic_trust_library.core.record as record_operations
from kinetic_trust_library.core.record import (
    build_decision_record,
    require_validated_decision_record,
)
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.core.evaluate import evaluate
from kinetic_trust_library.models.action import (
    MomentCriticalityDeclaration,
    ValidatedActionDemand,
)
from kinetic_trust_library.models.capacity import CapacityRelation
from kinetic_trust_library.models.envelope import EvaluationBundle, Supervision
from kinetic_trust_library.models.record import DecisionRecord
from kinetic_trust_library.models.risk import MomentCriticalityResult
from kinetic_trust_library.models.soul import SoulAssessmentState
from kinetic_trust_library.models.standing import CeilingDeclaration
from kinetic_trust_library.models.trust import TrustTier
from tests.unit.core.test_envelope import validated_action, uniform_vectors
from tests.unit.core.test_evidence import CUTOFF
from tests.unit.core.test_evaluate import request, soul_responses
from tests.unit.core.test_risk import evidence_declarations
from tests.unit.models.test_profile import complete_action, complete_capability
from tests.unit.proofs._fixtures import (
    complete_bundle,
    complete_bundle_at,
    non_clear_bundle,
)


class DecisionRecordTests(unittest.TestCase):
    def test_rehashed_above_capacity_record_rejects_stable_supervision(self) -> None:
        source = request()
        action = validated_action(source.profile, demand="100")
        evaluation = evaluate(
            replace(
                source,
                action=action,
                soul_responses=soul_responses(source.profile, action),
            )
        )
        self.assertIsInstance(evaluation, EvaluationBundle)
        assert isinstance(evaluation, EvaluationBundle)
        original = build_decision_record(evaluation)
        self.assertIs(original.capacity_relation, CapacityRelation.ABOVE_CAPACITY)
        self.assertIs(original.supervision, Supervision.SILENT_VETO)
        malformed = copy.copy(original)
        object.__setattr__(malformed, "supervision", Supervision.STABLE)
        object.__setattr__(
            malformed,
            "digest",
            record_operations.canonical_sha256(
                record_operations._record_projection(malformed, include_digest=False)
            ),
        )
        with self.assertRaises(ValidationError):
            require_validated_decision_record(malformed)

    def test_rehashed_records_reject_invalid_capacity_bindings(self) -> None:
        original = build_decision_record(complete_bundle())
        self.assertIsNotNone(original.core_capacity_digest)
        self.assertIs(original.capacity_relation, CapacityRelation.BELOW_CAPACITY)
        for digest, relation in (
            (None, None),
            (None, original.capacity_relation),
            (original.core_capacity_digest, None),
            ("not-a-digest", original.capacity_relation),
            ("A" * 64, original.capacity_relation),
            (original.core_capacity_digest, "below_capacity"),
            (original.core_capacity_digest, CapacityRelation.AT_CAPACITY),
            (original.core_capacity_digest, CapacityRelation.ABOVE_CAPACITY),
        ):
            with self.subTest(digest=digest, relation=relation):
                malformed = copy.copy(original)
                object.__setattr__(malformed, "core_capacity_digest", digest)
                object.__setattr__(malformed, "capacity_relation", relation)
                object.__setattr__(
                    malformed,
                    "digest",
                    record_operations.canonical_sha256(
                        record_operations._record_projection(
                            malformed, include_digest=False
                        )
                    ),
                )
                with self.assertRaises(ValidationError):
                    require_validated_decision_record(malformed)

    def test_rehashed_short_path_records_reject_capacity_authority(self) -> None:
        for veto in (True, False):
            original = build_decision_record(non_clear_bundle(veto=veto))
            self.assertIsNone(original.core_capacity_digest)
            self.assertIsNone(original.capacity_relation)
            for digest, relation in (
                ("a" * 64, None),
                (None, CapacityRelation.AT_CAPACITY),
                ("a" * 64, CapacityRelation.AT_CAPACITY),
            ):
                with self.subTest(veto=veto, digest=digest, relation=relation):
                    malformed = copy.copy(original)
                    object.__setattr__(malformed, "core_capacity_digest", digest)
                    object.__setattr__(malformed, "capacity_relation", relation)
                    object.__setattr__(
                        malformed,
                        "digest",
                        record_operations.canonical_sha256(
                            record_operations._record_projection(
                                malformed, include_digest=False
                            )
                        ),
                    )
                    with self.assertRaises(ValidationError):
                        require_validated_decision_record(malformed)

    def test_rehashed_records_reject_contradictory_retained_arithmetic(self) -> None:
        original = build_decision_record(complete_bundle())

        def changed_member(value, path, replacement):
            member, *remaining = path
            child = value[member] if type(value) is tuple else getattr(value, member)
            changed = (
                changed_member(child, remaining, replacement)
                if remaining
                else replacement
            )
            if type(value) is tuple:
                result = list(value)
                result[member] = changed
                return tuple(result)
            result = copy.copy(value)
            object.__setattr__(result, member, changed)
            return result

        # Compensating edits keep downstream equations coherent, so each row
        # catches its named missing check rather than another arithmetic check.
        for relationship, changes in (
            (
                "signal contribution",
                (
                    (("risk_factors", 0, "contribution"), Decimal("0.03")),
                    (("risk_factors", 1, "contribution"), Decimal("0.03")),
                ),
            ),
            (
                "moment contribution",
                (
                    (("risk_factors", 5, "contribution"), Decimal("0.1")),
                    (("risk",), Decimal("0.265")),
                    (("base_trust",), Decimal("0")),
                    (("effective_trust",), Decimal("0")),
                    (("capacity_relation",), CapacityRelation.AT_CAPACITY),
                    (("environmental_capacity",), Decimal("0")),
                    (("margin",), Decimal("0")),
                    (("tier",), TrustTier.HIBERNATION),
                ),
            ),
            (
                "authoritative risk",
                (
                    (("risk",), Decimal("0.3")),
                    (("base_trust",), Decimal("0")),
                    (("effective_trust",), Decimal("0")),
                    (("capacity_relation",), CapacityRelation.AT_CAPACITY),
                    (("environmental_capacity",), Decimal("0")),
                    (("margin",), Decimal("0")),
                    (("tier",), TrustTier.HIBERNATION),
                ),
            ),
            ("effective trust", ((("base_trust",), Decimal("40")),)),
            ("trust tier", ((("tier",), TrustTier.ADMIN),)),
            ("environmental margin", ((("margin",), Decimal("0.5")),)),
            (
                "signal context",
                (
                    (("risk_factors", 0, "domains", 0, "stress"), Decimal("0.2")),
                    (("domain_risks", 0, "risk"), Decimal("0.2975")),
                ),
            ),
            ("domain risk", ((("domain_risks", 0, "risk"), Decimal("0.3")),)),
        ):
            with self.subTest(relationship=relationship):
                malformed = original
                for path, replacement in changes:
                    malformed = changed_member(malformed, path, replacement)
                object.__setattr__(
                    malformed,
                    "digest",
                    record_operations.canonical_sha256(
                        record_operations._record_projection(
                            malformed, include_digest=False
                        )
                    ),
                )
                with self.assertRaises(ValidationError):
                    require_validated_decision_record(malformed)

    def test_complete_record_has_reviewed_v1_literal_digest(self) -> None:
        self.assertEqual(
            build_decision_record(complete_bundle()).digest,
            "c82b3eb2b03946316bc0645671c30f37bb01160d24de9915c76c7406c902f91f",
        )

    def test_soul_veto_record_has_reviewed_v1_literal_digest(self) -> None:
        self.assertEqual(
            build_decision_record(non_clear_bundle(veto=True)).digest,
            "efe97f8929a596c04a03bbdc61756841343ac75a4011cf98affb0f1ba16802d8",
        )

    def test_valid_extreme_margin_uses_closed_canonical_encoding(self) -> None:
        source = request()
        action = validated_action(source.profile, demand="100", moment="0.97")
        evaluation = evaluate(
            replace(
                source,
                action=action,
                standing=replace(
                    source.standing,
                    additional_ceilings=(
                        CeilingDeclaration(
                            name="extreme-envelope-limit",
                            value="1E-6141",
                            provenance_id="ceiling:extreme-envelope-limit",
                        ),
                    ),
                ),
                observations=evidence_declarations(
                    CUTOFF,
                    uniform_vectors(("0.99", "0.99", "1", "0.99", "1")),
                ),
                soul_responses=soul_responses(source.profile, action),
            )
        )
        self.assertIsInstance(evaluation, EvaluationBundle)
        assert isinstance(evaluation, EvaluationBundle)
        self.assertIsNotNone(evaluation.envelope.margin)
        assert evaluation.envelope.margin is not None
        self.assertEqual(evaluation.envelope.margin.adjusted(), 6145)
        record = build_decision_record(evaluation)
        self.assertEqual(record.margin, evaluation.envelope.margin)
        self.assertIs(require_validated_decision_record(record), record)

    def test_past_moment_observation_preserves_valid_evaluation(self) -> None:
        source = request()
        observed_at = CUTOFF - timedelta(seconds=1)
        action = ValidatedActionDemand.validate(
            complete_action(
                subject=source.action.subject,
                moment_criticality=MomentCriticalityDeclaration(
                    value="0.75",
                    supplier="action-api",
                    unit="stress-0-1",
                    observed_at=observed_at,
                    provenance_id="moment:past",
                ),
            ),
            profile=source.profile,
            capability=complete_capability(
                subject=source.action.subject,
                not_before=CUTOFF - timedelta(minutes=1),
                not_after=CUTOFF + timedelta(minutes=1),
            ),
            cutoff=CUTOFF,
        )
        evaluation = evaluate(
            replace(
                source,
                action=action,
                soul_responses=soul_responses(source.profile, action),
            )
        )
        self.assertIsInstance(evaluation, EvaluationBundle)
        assert isinstance(evaluation, EvaluationBundle)
        record = build_decision_record(evaluation)
        self.assertIsNotNone(record.risk_factors)
        assert record.risk_factors is not None
        moment = record.risk_factors[-1]
        self.assertIsInstance(moment, MomentCriticalityResult)
        assert isinstance(moment, MomentCriticalityResult)
        self.assertEqual(moment.supplied_value.observed_at, observed_at)
        self.assertEqual(record.evaluation_digest, evaluation.digest)

    def test_unknown_capacity_preserves_computed_numeric_envelope(self) -> None:
        evaluation = evaluate(replace(request(), observations=()))
        self.assertIsInstance(evaluation, EvaluationBundle)
        assert isinstance(evaluation, EvaluationBundle)
        self.assertFalse(evaluation.envelope.capacity_known)
        record = build_decision_record(evaluation)
        self.assertFalse(record.capacity_known)
        self.assertIsNotNone(evaluation.core_capacity)
        assert evaluation.core_capacity is not None
        self.assertEqual(record.core_capacity_digest, evaluation.core_capacity.digest)
        self.assertIs(record.capacity_relation, evaluation.core_capacity.relation)
        self.assertIsNotNone(record.environmental_capacity)
        self.assertEqual(
            record.environmental_capacity, evaluation.envelope.environmental_capacity
        )
        self.assertEqual(record.margin, evaluation.envelope.margin)

    def test_record_annotations_resolve_at_runtime(self) -> None:
        self.assertIs(get_type_hints(DecisionRecord)["evaluated_at"], type(CUTOFF))

    def test_veto_record_preserves_short_path_without_invented_zeroes(self) -> None:
        evaluation = non_clear_bundle(veto=True)
        record = build_decision_record(evaluation)
        self.assertIs(record.soul_state, SoulAssessmentState.VETO)
        self.assertEqual(record.record_id, evaluation.operation_id)
        self.assertEqual(record.evaluation_digest, evaluation.digest)
        for name in (
            "standing_digest",
            "evidence_digest",
            "risk_digest",
            "trust_digest",
            "velocity_digest",
            "core_capacity_digest",
            "capacity_relation",
            "risk_context",
            "risk_factors",
            "domain_risks",
            "base_trust",
            "risk",
            "effective_trust",
            "tier",
            "velocity",
            "environmental_capacity",
            "margin",
        ):
            self.assertIsNone(getattr(record, name), name)

    def test_undetermined_record_preserves_authoritative_absence(self) -> None:
        record = build_decision_record(non_clear_bundle(veto=False))
        self.assertIs(record.soul_state, SoulAssessmentState.UNDETERMINED)
        self.assertIsNone(record.risk_factors)
        self.assertIsNone(record.environmental_capacity)
        self.assertIsNone(record.core_capacity_digest)
        self.assertIsNone(record.capacity_relation)
        self.assertFalse(record.capacity_known)

    def test_complete_record_projects_authoritative_evaluation_values(self) -> None:
        evaluation = complete_bundle()
        record = build_decision_record(evaluation)
        self.assertEqual(record.record_profile, "ktp-python-decision-record-v1")
        self.assertEqual(record.subject, evaluation.action.subject)
        self.assertEqual(record.action_id, evaluation.action.action_id)
        self.assertEqual(record.action_digest, evaluation.action.digest)
        self.assertEqual(record.soul_digest, evaluation.soul.digest)
        self.assertIsNotNone(evaluation.standing)
        self.assertIsNotNone(evaluation.evidence)
        self.assertIsNotNone(evaluation.risk)
        self.assertIsNotNone(evaluation.trust)
        assert evaluation.standing is not None
        assert evaluation.evidence is not None
        assert evaluation.risk is not None
        assert evaluation.trust is not None
        self.assertIsNotNone(evaluation.core_capacity)
        assert evaluation.core_capacity is not None
        self.assertEqual(record.standing_digest, evaluation.standing.digest)
        self.assertEqual(record.evidence_digest, evaluation.evidence.digest)
        self.assertEqual(record.risk_digest, evaluation.risk.digest)
        self.assertEqual(record.trust_digest, evaluation.trust.digest)
        self.assertEqual(record.core_capacity_digest, evaluation.core_capacity.digest)
        self.assertIs(record.capacity_relation, evaluation.core_capacity.relation)
        self.assertEqual(record.envelope_digest, evaluation.envelope.digest)
        self.assertEqual(record.risk_context, evaluation.risk.context)
        self.assertEqual(record.risk_factors, evaluation.risk.factors)
        self.assertEqual(record.domain_risks, evaluation.risk.domains)
        self.assertEqual(record.base_trust, evaluation.standing.base_trust)
        self.assertEqual(record.effective_trust, evaluation.trust.effective_trust)
        self.assertRegex(record.digest, r"^[a-f0-9]{64}$")
        self.assertIs(require_validated_decision_record(record), record)

    def test_submillisecond_cutoff_floors_record_time_only(self) -> None:
        cutoff = CUTOFF + timedelta(microseconds=987_654)
        evaluation = complete_bundle_at(cutoff)
        record = build_decision_record(evaluation)
        self.assertEqual(record.evaluated_at, cutoff.replace(microsecond=987_000))
        self.assertEqual(record.evaluation_digest, evaluation.digest)
        self.assertEqual(evaluation.cutoff, cutoff)

    def test_factor_projection_uses_explicit_kind_discriminators(self) -> None:
        record = build_decision_record(complete_bundle())
        projection = record_operations._record_projection(record, include_digest=False)
        kinds = tuple(item["kind"] for item in projection["risk_factors"])
        self.assertIn("signal", kinds)
        self.assertIn("moment_criticality", kinds)

    def test_record_digest_is_deterministic_for_the_fixed_evaluation(self) -> None:
        first = build_decision_record(complete_bundle())
        second = build_decision_record(complete_bundle())
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(
            first.digest,
            record_operations.canonical_sha256(
                record_operations._record_projection(first, include_digest=False)
            ),
        )

    def test_revalidation_rejects_top_level_and_nested_tampering(self) -> None:
        original = build_decision_record(complete_bundle())
        top_level = copy.copy(original)
        object.__setattr__(top_level, "record_id", "operation:tampered")
        with self.assertRaises(ValidationError):
            require_validated_decision_record(top_level)

        nested = copy.copy(original)
        self.assertIsNotNone(nested.risk_factors)
        assert nested.risk_factors is not None
        factors = list(nested.risk_factors)
        factor = copy.copy(factors[0])
        object.__setattr__(factor, "contribution", factor.contribution + 1)
        factors[0] = factor
        object.__setattr__(nested, "risk_factors", tuple(factors))
        with self.assertRaises(ValidationError):
            require_validated_decision_record(nested)

    def test_builder_revalidates_evaluation_before_projection(self) -> None:
        evaluation = copy.copy(complete_bundle())
        object.__setattr__(evaluation, "operation_id", "operation:tampered")
        with self.assertRaises(ValidationError):
            build_decision_record(evaluation)

    def test_public_constructor_is_guarded(self) -> None:
        with self.assertRaises(TypeError):
            DecisionRecord()
