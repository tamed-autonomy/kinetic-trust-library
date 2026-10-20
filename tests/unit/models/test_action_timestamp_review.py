"""Regression tests for owned UTC timestamps in represented actions."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo

from kinetic_trust_library.core.risk import calculate_risk
from kinetic_trust_library.core.trust import (
    calculate_effective_trust,
    calculate_velocity,
    require_validated_trust_snapshot,
    require_validated_trust_velocity,
)
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models import action as action_module
from kinetic_trust_library.models.action import (
    MomentCriticalityDeclaration,
    NormativeGateDecision,
    NormativeGateToken,
    ValidatedActionDemand,
    ValidatedCapability,
    require_validated_action,
    require_validated_capability,
)
from kinetic_trust_library.models.profile import (
    DeploymentProfile,
    FactorName,
    NormativeGatePolicy,
)
from tests.unit.core.test_evidence import CUTOFF, profile_declaration
from tests.unit.core.test_risk import (
    evidence,
    soul_clear,
    standing,
    uniform_vectors,
)
from tests.unit.core.test_standing_contract import INDEPENDENT_ID
from tests.unit.models.test_profile import (
    complete_action,
    complete_capability,
    complete_profile_declaration,
)


class _PassiveDateTime(datetime):
    pass


class _ArmedZeroOffsetTimezone(tzinfo):
    armed = False
    calls = 0

    @classmethod
    def reset(cls, *, armed: bool) -> None:
        cls.armed = armed
        cls.calls = 0

    def _observe(self, hook: str) -> None:
        if type(self).armed:
            type(self).calls += 1
            raise AssertionError(f"hostile timezone {hook} executed")

    def utcoffset(self, dt):
        self._observe("UTC-offset")
        return timedelta(0)

    def dst(self, dt):
        self._observe("DST")
        return timedelta(0)

    def tzname(self, dt):
        self._observe("name")
        return "UTC"

    def fromutc(self, dt):
        self._observe("from-UTC")
        return dt


def _custom_utc(value: datetime) -> datetime:
    return datetime(
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond,
        tzinfo=_ArmedZeroOffsetTimezone(),
        fold=value.fold,
    )


def _passive_datetime(value: datetime) -> datetime:
    return _PassiveDateTime(
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond,
        tzinfo=timezone.utc,
        fold=value.fold,
    )


def _gate(observed_at: datetime) -> NormativeGateToken:
    return NormativeGateToken(
        gate_id="schema:review",
        schema_uri="https://schemas.example/gates/review/v1",
        decision=NormativeGateDecision.CLEAR,
        authority="https://policy.example/authority",
        observed_at=observed_at,
        provenance_id="gate-token:review",
    )


def _profile_with_gate() -> DeploymentProfile:
    declaration = profile_declaration()
    return DeploymentProfile.validate(
        replace(
            declaration,
            actions={
                "deploy": replace(
                    declaration.actions["deploy"],
                    normative_gates=(
                        NormativeGatePolicy(
                            gate_id="schema:review",
                            schema_uri="https://schemas.example/gates/review/v1",
                            required=False,
                        ),
                    ),
                )
            },
        )
    )


def _validated_action(
    profile: DeploymentProfile,
    cutoff: datetime,
    *,
    action_id: str,
) -> ValidatedActionDemand:
    return ValidatedActionDemand.validate(
        complete_action(
            action_id=action_id,
            subject=INDEPENDENT_ID,
            moment_criticality=MomentCriticalityDeclaration(
                value="0.75",
                supplier="action-api",
                unit="stress-0-1",
                observed_at=cutoff,
                provenance_id=f"moment:{action_id}",
            ),
            normative_gate_tokens=(_gate(cutoff),),
        ),
        profile=profile,
        capability=complete_capability(
            subject=INDEPENDENT_ID,
            not_before=cutoff - timedelta(minutes=1),
            not_after=cutoff + timedelta(minutes=1),
        ),
        cutoff=cutoff,
    )


def _evaluation_fixture(cutoff: datetime, *, action_id: str):
    profile = _profile_with_gate()
    action = _validated_action(profile, cutoff, action_id=action_id)
    soul = soul_clear(profile, action, cutoff)
    prepared = evidence(
        profile,
        cutoff,
        uniform_vectors(("0.1", "0.2", "0.3", "0.4", "0")),
    )
    risk = calculate_risk(profile, prepared, soul, action, cutoff)
    trust = calculate_effective_trust(
        profile,
        standing(profile, cutoff),
        risk,
        soul,
        action,
        cutoff,
    )
    return profile, action, risk, trust


def _forge_action_time(
    action: ValidatedActionDemand, location: str
) -> ValidatedActionDemand:
    forged = copy.copy(action)
    if location == "action_cutoff":
        object.__setattr__(
            forged, "validation_cutoff", _custom_utc(action.validation_cutoff)
        )
    elif location == "moment":
        object.__setattr__(
            forged,
            "moment_criticality",
            replace(
                action.moment_criticality,
                observed_at=_custom_utc(action.moment_criticality.observed_at),
            ),
        )
    elif location == "gate":
        token = action.normative_gate_tokens[0]
        object.__setattr__(
            forged,
            "normative_gate_tokens",
            (replace(token, observed_at=_custom_utc(token.observed_at)),),
        )
    else:
        capability = copy.copy(action.capability)
        field_name = location.removeprefix("capability_")
        object.__setattr__(
            capability,
            field_name,
            _custom_utc(getattr(capability, field_name)),
        )
        object.__setattr__(forged, "capability", capability)
    return forged


class ActionTimestampConstructionReviewTests(unittest.TestCase):
    def setUp(self):
        self.profile = _profile_with_gate()

    def test_public_capability_construction_rejects_custom_timezone_without_hooks(self):
        cases = (
            ("not_before", _custom_utc(CUTOFF - timedelta(minutes=1))),
            ("not_after", _custom_utc(CUTOFF + timedelta(minutes=1))),
            ("cutoff", _custom_utc(CUTOFF)),
        )
        for field_name, hostile in cases:
            _ArmedZeroOffsetTimezone.reset(armed=True)
            try:
                with (
                    self.subTest(field_name=field_name),
                    self.assertRaises(ValidationError),
                ):
                    if field_name == "cutoff":
                        ValidatedCapability.validate(
                            complete_capability(),
                            profile=self.profile,
                            cutoff=hostile,
                        )
                    else:
                        ValidatedCapability.validate(
                            complete_capability(**{field_name: hostile}),
                            profile=self.profile,
                            cutoff=CUTOFF,
                        )
            finally:
                _ArmedZeroOffsetTimezone.armed = False
            self.assertEqual(_ArmedZeroOffsetTimezone.calls, 0)

    def test_public_action_construction_rejects_every_custom_timezone_without_hooks(
        self,
    ):
        cases = (
            ("action_cutoff", _custom_utc(CUTOFF)),
            ("moment", _custom_utc(CUTOFF)),
            ("gate", _custom_utc(CUTOFF)),
            ("capability_not_before", _custom_utc(CUTOFF - timedelta(minutes=1))),
            ("capability_not_after", _custom_utc(CUTOFF + timedelta(minutes=1))),
        )
        for location, hostile in cases:
            declaration = complete_action()
            capability = complete_capability()
            cutoff = CUTOFF
            if location == "action_cutoff":
                cutoff = hostile
            elif location == "moment":
                declaration = replace(
                    declaration,
                    moment_criticality=replace(
                        declaration.moment_criticality,
                        observed_at=hostile,
                    ),
                )
            elif location == "gate":
                declaration = replace(
                    declaration,
                    normative_gate_tokens=(_gate(hostile),),
                )
            else:
                capability = replace(
                    capability,
                    **{location.removeprefix("capability_"): hostile},
                )

            _ArmedZeroOffsetTimezone.reset(armed=True)
            try:
                with (
                    self.subTest(location=location),
                    self.assertRaises(ValidationError),
                ):
                    ValidatedActionDemand.validate(
                        declaration,
                        profile=self.profile,
                        capability=capability,
                        cutoff=cutoff,
                    )
            finally:
                _ArmedZeroOffsetTimezone.armed = False
            self.assertEqual(_ArmedZeroOffsetTimezone.calls, 0)

    def test_public_construction_rejects_passive_datetime_subclasses(self):
        with self.assertRaises(ValidationError):
            ValidatedCapability.validate(
                complete_capability(not_before=_passive_datetime(CUTOFF)),
                profile=self.profile,
                cutoff=CUTOFF,
            )
        with self.assertRaises(ValidationError):
            ValidatedActionDemand.validate(
                complete_action(
                    normative_gate_tokens=(_gate(_passive_datetime(CUTOFF)),)
                ),
                profile=self.profile,
                capability=complete_capability(),
                cutoff=CUTOFF,
            )


class ActionTimestampStructuralReviewTests(unittest.TestCase):
    def test_capability_revalidation_rejects_digest_equivalent_timezones_without_hooks(
        self,
    ):
        profile = DeploymentProfile.validate(complete_profile_declaration())
        capability = ValidatedCapability.validate(
            complete_capability(), profile=profile, cutoff=CUTOFF
        )
        for field_name in ("not_before", "not_after", "validation_cutoff"):
            forged = copy.copy(capability)
            object.__setattr__(
                forged,
                field_name,
                _custom_utc(getattr(capability, field_name)),
            )
            self.assertEqual(
                action_module._capability_digest(forged), capability.digest
            )

            _ArmedZeroOffsetTimezone.reset(armed=True)
            try:
                with (
                    self.subTest(field_name=field_name),
                    self.assertRaises(ValidationError),
                ):
                    require_validated_capability(forged, profile=profile)
            finally:
                _ArmedZeroOffsetTimezone.armed = False
            self.assertEqual(_ArmedZeroOffsetTimezone.calls, 0)

    def test_action_timestamps_reject_without_hooks_through_every_task4_boundary(self):
        profile, action, risk, trust = _evaluation_fixture(
            CUTOFF, action_id="action:timestamp:previous"
        )
        _profile, _action, _risk, current = _evaluation_fixture(
            CUTOFF + timedelta(seconds=1),
            action_id="action:timestamp:current",
        )
        velocity = calculate_velocity(trust, current)
        locations = (
            "action_cutoff",
            "moment",
            "gate",
            "capability_not_before",
            "capability_not_after",
            "capability_validation_cutoff",
        )
        for location in locations:
            forged_action = _forge_action_time(action, location)
            self.assertEqual(action_module._action_digest(forged_action), action.digest)
            forged_risk = copy.copy(risk)
            object.__setattr__(forged_risk, "_action", forged_action)
            forged_trust = copy.copy(trust)
            object.__setattr__(forged_trust, "_risk_result", forged_risk)
            forged_velocity = copy.copy(velocity)
            object.__setattr__(forged_velocity, "_previous", forged_trust)

            for boundary, forged in (
                ("action", forged_action),
                ("risk", forged_risk),
                ("trust", forged_trust),
                ("velocity", forged_velocity),
            ):
                _ArmedZeroOffsetTimezone.reset(armed=True)
                try:
                    with (
                        self.subTest(location=location, boundary=boundary),
                        self.assertRaises(ValidationError),
                    ):
                        if boundary == "action":
                            require_validated_action(forged, profile=profile)
                        elif boundary == "risk":
                            forged.factor(FactorName.MOMENT_CRITICALITY)
                        elif boundary == "trust":
                            require_validated_trust_snapshot(forged, profile=profile)
                        else:
                            require_validated_trust_velocity(forged)
                finally:
                    _ArmedZeroOffsetTimezone.armed = False
                self.assertEqual(_ArmedZeroOffsetTimezone.calls, 0)

    def test_passive_subclasses_and_unsealed_exact_utc_mutations_reject(self):
        profile, action, _risk, _trust = _evaluation_fixture(
            CUTOFF, action_id="action:timestamp:mutation"
        )
        passive = copy.copy(action)
        token = action.normative_gate_tokens[0]
        object.__setattr__(
            passive,
            "normative_gate_tokens",
            (replace(token, observed_at=_passive_datetime(token.observed_at)),),
        )
        with self.assertRaises(ValidationError):
            require_validated_action(passive, profile=profile)

        mutated = copy.copy(action)
        object.__setattr__(
            mutated,
            "normative_gate_tokens",
            (
                replace(
                    token,
                    observed_at=token.observed_at - timedelta(microseconds=1),
                ),
            ),
        )
        with self.assertRaises(ValidationError):
            require_validated_action(mutated, profile=profile)

    def test_exact_utc_values_continue_through_all_boundaries(self):
        profile, action, risk, trust = _evaluation_fixture(
            CUTOFF, action_id="action:timestamp:exact"
        )
        _profile, _action, _risk, current = _evaluation_fixture(
            CUTOFF + timedelta(seconds=1),
            action_id="action:timestamp:exact:current",
        )
        velocity = calculate_velocity(trust, current)

        self.assertIs(
            require_validated_capability(action.capability), action.capability
        )
        self.assertIs(require_validated_action(action, profile=profile), action)
        self.assertIs(
            risk.factor(FactorName.MOMENT_CRITICALITY),
            risk.factors[-1],
        )
        self.assertIs(require_validated_trust_snapshot(trust, profile=profile), trust)
        self.assertIs(require_validated_trust_velocity(velocity), velocity)


if __name__ == "__main__":
    unittest.main()
