"""Regression tests for Task 4 represented-value authority boundaries."""

from __future__ import annotations

import copy
import unittest
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone, tzinfo
from decimal import Decimal

from kinetic_trust_library._canonical import canonical_sha256
from kinetic_trust_library.core import risk as risk_module
from kinetic_trust_library.core.trust import (
    calculate_effective_trust,
    calculate_velocity,
    require_validated_trust_snapshot,
    require_validated_trust_velocity,
)
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.action import MomentCriticality
from kinetic_trust_library.models.profile import FactorName
from kinetic_trust_library.models.risk import (
    DomainFactorResult,
    RiskContext,
    RiskInput,
    SignalFactorResult,
)
from tests.unit.core.test_evidence import CUTOFF
from tests.unit.core.test_risk import (
    configured_profile,
    risk_state,
    standing,
)


class _PassiveDecimal(Decimal):
    pass


class _PassiveString(str):
    pass


class _MomentSubclass(MomentCriticality):
    pass


class _RiskContextSubclass(RiskContext):
    pass


class _SignalFactorResultSubclass(SignalFactorResult):
    pass


class _DomainFactorResultSubclass(DomainFactorResult):
    pass


class _RiskInputSubclass(RiskInput):
    pass


class _ArmedString(str):
    armed = False
    calls = 0

    def _observe(self, hook):
        if type(self).armed:
            type(self).calls += 1
            raise AssertionError(f"hostile string {hook} executed")

    def __eq__(self, other):
        self._observe("equality")
        return super().__eq__(other)

    def __hash__(self):
        self._observe("hashing")
        return super().__hash__()

    def __str__(self):
        self._observe("coercion")
        return super().__str__()

    def encode(self, encoding="utf-8", errors="strict"):
        self._observe("encoding")
        return super().encode(encoding, errors)


class _ArmedDecimal(Decimal):
    armed = False
    calls = 0

    def _observe(self, hook):
        if type(self).armed:
            type(self).calls += 1
            raise AssertionError(f"hostile decimal {hook} executed")

    def __eq__(self, other):
        self._observe("equality")
        return super().__eq__(other)

    def __ne__(self, other):
        self._observe("inequality")
        return super().__ne__(other)

    def __hash__(self):
        self._observe("hashing")
        return super().__hash__()

    def __str__(self):
        self._observe("coercion")
        return super().__str__()


class _ArmedDateTime(datetime):
    armed = False
    calls = 0

    def _observe(self, hook):
        if type(self).armed:
            type(self).calls += 1
            raise AssertionError(f"hostile datetime {hook} executed")

    def utcoffset(self):
        self._observe("UTC-offset")
        return super().utcoffset()

    def __eq__(self, other):
        self._observe("equality")
        return super().__eq__(other)

    def __hash__(self):
        self._observe("hashing")
        return super().__hash__()

    def __str__(self):
        self._observe("coercion")
        return super().__str__()


class _ArmedZeroOffsetTimezone(tzinfo):
    armed = False
    calls = 0

    def utcoffset(self, dt):
        if type(self).armed:
            type(self).calls += 1
            raise AssertionError("hostile timezone offset executed")
        return timedelta(0)

    def dst(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "UTC"


def _fixture(cutoff: datetime = CUTOFF, *, action_id: str = "action:review:one"):
    configured = configured_profile()
    action, soul, _prepared, risk = risk_state(
        configured,
        cutoff,
        ("0.1", "0.2", "0.3", "0.4", "0"),
        moment="0.75",
        action_id=action_id,
    )
    trust = calculate_effective_trust(
        configured,
        standing(configured, cutoff),
        risk,
        soul,
        action,
        cutoff,
    )
    return configured, action, risk, trust


def _moment(risk):
    return risk.factors[-1].supplied_value


def _with_supplied_moment(risk, moment):
    forged = copy.copy(risk)
    factors = list(risk.factors)
    factor = copy.copy(factors[-1])
    object.__setattr__(factor, "supplied_value", moment)
    factors[-1] = factor
    object.__setattr__(forged, "factors", tuple(factors))
    return forged


def _copy_as(value, result_type, **changes):
    result = object.__new__(result_type)
    for field in fields(type(value)):
        object.__setattr__(
            result,
            field.name,
            changes.get(field.name, getattr(value, field.name)),
        )
    return result


def _with_context(risk, context):
    forged = copy.copy(risk)
    object.__setattr__(forged, "context", context)
    return forged


def _with_factor(risk, factor_index, factor):
    forged = copy.copy(risk)
    factors = list(risk.factors)
    factors[factor_index] = factor
    object.__setattr__(forged, "factors", tuple(factors))
    return forged


def _with_domain_factor(risk, factor_index, domain_index, domain):
    factor = copy.copy(risk.factors[factor_index])
    domains = list(factor.domains)
    domains[domain_index] = domain
    object.__setattr__(factor, "domains", tuple(domains))
    return _with_factor(risk, factor_index, factor)


def _with_risk_input(risk, factor_index, domain_index, input_index, risk_input):
    domain = copy.copy(risk.factors[factor_index].domains[domain_index])
    inputs = list(domain.inputs)
    inputs[input_index] = risk_input
    object.__setattr__(domain, "inputs", tuple(inputs))
    return _with_domain_factor(risk, factor_index, domain_index, domain)


def _assert_risk_invalid(test, risk):
    with test.assertRaises(ValidationError):
        risk.factor(FactorName.EVIDENCE_DENSITY)


def _reseal(risk):
    object.__setattr__(
        risk,
        "digest",
        canonical_sha256(risk_module._risk_projection(risk, include_digest=False)),
    )
    return risk


class RiskContextAuthorityReviewTests(unittest.TestCase):
    def test_effective_trust_rejects_mutated_context_under_original_digest(self):
        configured, action, result, trust = _fixture()
        tampered_context = object.__new__(RiskContext)
        for name in (
            "evidence_density",
            "trust_trend",
            "adversarial_pressure",
            "update_resistance",
            "attestation_coverage",
            "moment_criticality",
        ):
            object.__setattr__(
                tampered_context,
                name,
                Decimal("0.99")
                if name == "trust_trend"
                else getattr(result.context, name),
            )
        object.__setattr__(result, "context", tampered_context)
        self.assertEqual(result.digest, trust.risk_digest)

        with self.assertRaises(ValidationError):
            calculate_effective_trust(
                configured,
                trust._standing,
                result,
                trust._soul,
                action,
                CUTOFF,
            )

    def test_nested_result_classes_must_be_exact(self):
        cases = ("context", "factor", "domain", "input")
        for location in cases:
            _configured, _action, risk, _trust = _fixture()
            if location == "context":
                forged = _with_context(
                    risk,
                    _copy_as(risk.context, _RiskContextSubclass),
                )
            elif location == "factor":
                forged = _with_factor(
                    risk,
                    0,
                    _copy_as(risk.factors[0], _SignalFactorResultSubclass),
                )
            elif location == "domain":
                domain = risk.factors[0].domains[0]
                forged = _with_domain_factor(
                    risk,
                    0,
                    0,
                    _copy_as(domain, _DomainFactorResultSubclass),
                )
            else:
                risk_input = risk.factors[0].domains[0].inputs[0]
                forged = _with_risk_input(
                    risk,
                    0,
                    0,
                    0,
                    _copy_as(risk_input, _RiskInputSubclass),
                )

            with self.subTest(location=location):
                _assert_risk_invalid(self, forged)

    def test_hostile_nested_primitives_reject_before_hooks(self):
        cases = (
            ("context_decimal", _ArmedDecimal, "trust_trend"),
            ("factor_decimal", _ArmedDecimal, "weight"),
            ("domain_decimal", _ArmedDecimal, "stress"),
            ("input_string", _ArmedString, "signal_id"),
            ("input_decimal", _ArmedDecimal, "stress"),
            ("cutoff_datetime", _ArmedDateTime, "cutoff"),
        )
        for location, hostile_type, member in cases:
            _configured, _action, risk, _trust = _fixture()
            if location == "context_decimal":
                hostile = hostile_type(getattr(risk.context, member))
                forged = _with_context(
                    risk,
                    _copy_as(risk.context, RiskContext, **{member: hostile}),
                )
            elif location == "factor_decimal":
                factor = risk.factors[0]
                hostile = hostile_type(getattr(factor, member))
                forged = _with_factor(
                    risk,
                    0,
                    _copy_as(factor, SignalFactorResult, **{member: hostile}),
                )
            elif location == "domain_decimal":
                domain = risk.factors[0].domains[0]
                hostile = hostile_type(getattr(domain, member))
                forged = _with_domain_factor(
                    risk,
                    0,
                    0,
                    _copy_as(domain, DomainFactorResult, **{member: hostile}),
                )
            elif location.startswith("input_"):
                risk_input = risk.factors[0].domains[0].inputs[0]
                hostile = hostile_type(getattr(risk_input, member))
                forged = _with_risk_input(
                    risk,
                    0,
                    0,
                    0,
                    _copy_as(risk_input, RiskInput, **{member: hostile}),
                )
            else:
                hostile = hostile_type(
                    risk.cutoff.year,
                    risk.cutoff.month,
                    risk.cutoff.day,
                    risk.cutoff.hour,
                    risk.cutoff.minute,
                    risk.cutoff.second,
                    risk.cutoff.microsecond,
                    tzinfo=timezone.utc,
                )
                forged = copy.copy(risk)
                object.__setattr__(forged, member, hostile)

            hostile_type.calls = 0
            hostile_type.armed = True
            try:
                with self.subTest(location=location):
                    _assert_risk_invalid(self, forged)
            finally:
                hostile_type.armed = False
            self.assertEqual(hostile_type.calls, 0)


class RiskMomentAuthorityReviewTests(unittest.TestCase):
    def test_digest_equivalent_nested_subclasses_are_rejected(self):
        _configured, _action, risk, _trust = _fixture()
        moment = _moment(risk)
        cases = (
            ("value", _PassiveDecimal(moment.value)),
            ("supplier", _PassiveString(moment.supplier)),
            ("unit", _PassiveString(moment.unit)),
            ("provenance_id", _PassiveString(moment.provenance_id)),
        )
        for field_name, hostile in cases:
            forged = _with_supplied_moment(
                risk,
                replace(moment, **{field_name: hostile}),
            )
            self.assertEqual(
                canonical_sha256(
                    risk_module._risk_projection(forged, include_digest=False)
                ),
                risk.digest,
            )
            with self.subTest(field_name=field_name):
                _assert_risk_invalid(self, forged)

    def test_exact_outer_moment_class_is_required(self):
        _configured, _action, risk, _trust = _fixture()
        moment = _moment(risk)
        forged = _with_supplied_moment(
            risk,
            _MomentSubclass(
                moment.value,
                moment.supplier,
                moment.unit,
                moment.observed_at,
                moment.provenance_id,
            ),
        )

        _assert_risk_invalid(self, forged)

    def test_exact_datetime_with_custom_zero_offset_timezone_is_rejected(self):
        _configured, _action, risk, _trust = _fixture()
        moment = _moment(risk)
        custom_utc = datetime(
            moment.observed_at.year,
            moment.observed_at.month,
            moment.observed_at.day,
            moment.observed_at.hour,
            moment.observed_at.minute,
            moment.observed_at.second,
            moment.observed_at.microsecond,
            tzinfo=_ArmedZeroOffsetTimezone(),
        )
        forged = _with_supplied_moment(
            risk,
            replace(moment, observed_at=custom_utc),
        )
        self.assertEqual(
            canonical_sha256(
                risk_module._risk_projection(forged, include_digest=False)
            ),
            risk.digest,
        )

        _assert_risk_invalid(self, forged)

    def test_noncanonical_exact_decimals_are_rejected_before_projection(self):
        _configured, _action, risk, _trust = _fixture()
        moment = _moment(risk)
        too_precise = Decimal("0.75" + ("0" * 33))
        self.assertEqual(too_precise, moment.value)
        forged = _with_supplied_moment(risk, replace(moment, value=too_precise))
        _assert_risk_invalid(self, forged)

        configured = configured_profile()
        _action, _soul, _prepared, zero_risk = risk_state(
            configured,
            CUTOFF,
            ("0.1", "0.2", "0.3", "0.4", "0"),
            moment="0",
            action_id="action:review:zero",
        )
        zero_moment = _moment(zero_risk)
        out_of_range_exponent = Decimal("0E-6144")
        self.assertEqual(out_of_range_exponent, Decimal(0))
        forged_zero = _with_supplied_moment(
            zero_risk,
            replace(zero_moment, value=out_of_range_exponent),
        )
        _assert_risk_invalid(self, forged_zero)

    def test_armed_nested_hooks_are_rejected_without_execution(self):
        _configured, _action, risk, _trust = _fixture()
        moment = _moment(risk)
        hostile_string = _ArmedString(moment.provenance_id)
        hostile_decimal = _ArmedDecimal(moment.value)
        hostile_datetime = _ArmedDateTime(
            moment.observed_at.year,
            moment.observed_at.month,
            moment.observed_at.day,
            moment.observed_at.hour,
            moment.observed_at.minute,
            moment.observed_at.second,
            moment.observed_at.microsecond,
            tzinfo=timezone.utc,
        )
        hostile_time = datetime(
            moment.observed_at.year,
            moment.observed_at.month,
            moment.observed_at.day,
            moment.observed_at.hour,
            moment.observed_at.minute,
            moment.observed_at.second,
            moment.observed_at.microsecond,
            tzinfo=_ArmedZeroOffsetTimezone(),
        )
        cases = (
            (
                _with_supplied_moment(risk, replace(moment, value=hostile_decimal)),
                _ArmedDecimal,
            ),
            (
                _with_supplied_moment(
                    risk, replace(moment, provenance_id=hostile_string)
                ),
                _ArmedString,
            ),
            (
                _with_supplied_moment(risk, replace(moment, observed_at=hostile_time)),
                _ArmedZeroOffsetTimezone,
            ),
            (
                _with_supplied_moment(
                    risk, replace(moment, observed_at=hostile_datetime)
                ),
                _ArmedDateTime,
            ),
        )
        for forged, hostile_type in cases:
            hostile_type.calls = 0
            hostile_type.armed = True
            try:
                with self.subTest(hostile_type=hostile_type.__name__):
                    _assert_risk_invalid(self, forged)
            finally:
                hostile_type.armed = False
            self.assertEqual(hostile_type.calls, 0)

    def test_supplied_moment_is_exactly_bound_to_action_and_cutoff(self):
        _configured, _action, risk, _trust = _fixture()
        moment = _moment(risk)
        cases = (
            ("value", Decimal("0.5")),
            ("supplier", "other-api"),
            ("unit", "other-unit"),
            ("observed_at", moment.observed_at - timedelta(microseconds=1)),
            ("observed_after_cutoff", moment.observed_at + timedelta(microseconds=1)),
            ("provenance_id", "moment:forged"),
        )
        for field_name, replacement in cases:
            actual_name = (
                "observed_at" if field_name == "observed_after_cutoff" else field_name
            )
            forged = _reseal(
                _with_supplied_moment(
                    risk,
                    replace(moment, **{actual_name: replacement}),
                )
            )
            with self.subTest(field_name=field_name):
                _assert_risk_invalid(self, forged)

    def test_private_action_moment_timezone_hook_is_not_executed(self):
        _configured, action, risk, _trust = _fixture()
        moment = action.moment_criticality
        hostile_time = datetime(
            moment.observed_at.year,
            moment.observed_at.month,
            moment.observed_at.day,
            moment.observed_at.hour,
            moment.observed_at.minute,
            moment.observed_at.second,
            moment.observed_at.microsecond,
            tzinfo=_ArmedZeroOffsetTimezone(),
        )
        forged_action = copy.copy(action)
        object.__setattr__(
            forged_action,
            "moment_criticality",
            replace(moment, observed_at=hostile_time),
        )
        forged_risk = copy.copy(risk)
        object.__setattr__(forged_risk, "_action", forged_action)

        _ArmedZeroOffsetTimezone.calls = 0
        _ArmedZeroOffsetTimezone.armed = True
        try:
            _assert_risk_invalid(self, forged_risk)
        finally:
            _ArmedZeroOffsetTimezone.armed = False
        self.assertEqual(_ArmedZeroOffsetTimezone.calls, 0)

    def test_nested_moment_hook_stays_unexecuted_through_trust_and_velocity(self):
        configured, _action, risk, trust = _fixture()
        next_at = CUTOFF + timedelta(seconds=1)
        _configured, _action, _risk, current = _fixture(
            next_at,
            action_id="action:review:two",
        )
        velocity = calculate_velocity(trust, current)
        moment = _moment(risk)

        for boundary in ("trust", "velocity"):
            hostile = _ArmedString(moment.provenance_id)
            forged_risk = _with_supplied_moment(
                risk,
                replace(moment, provenance_id=hostile),
            )
            forged_trust = copy.copy(trust)
            object.__setattr__(forged_trust, "_risk_result", forged_risk)
            if boundary == "velocity":
                forged_velocity = copy.copy(velocity)
                object.__setattr__(forged_velocity, "_previous", forged_trust)

            _ArmedString.calls = 0
            _ArmedString.armed = True
            try:
                with (
                    self.subTest(boundary=boundary),
                    self.assertRaises(ValidationError),
                ):
                    if boundary == "trust":
                        require_validated_trust_snapshot(
                            forged_trust, profile=configured
                        )
                    else:
                        require_validated_trust_velocity(forged_velocity)
            finally:
                _ArmedString.armed = False
            self.assertEqual(_ArmedString.calls, 0)

    def test_adjacent_task4_timestamps_reject_custom_timezones_before_hooks(self):
        configured, _action, risk, trust = _fixture()
        next_at = CUTOFF + timedelta(seconds=1)
        _configured, _action, _risk, current = _fixture(
            next_at,
            action_id="action:review:timestamp",
        )
        velocity = calculate_velocity(trust, current)

        forged_risk = copy.copy(risk)
        object.__setattr__(
            forged_risk,
            "cutoff",
            risk.cutoff.replace(tzinfo=_ArmedZeroOffsetTimezone()),
        )
        forged_trust = copy.copy(trust)
        object.__setattr__(
            forged_trust,
            "observed_at",
            trust.observed_at.replace(tzinfo=_ArmedZeroOffsetTimezone()),
        )
        forged_velocity = copy.copy(velocity)
        object.__setattr__(
            forged_velocity,
            "previous_at",
            velocity.previous_at.replace(tzinfo=_ArmedZeroOffsetTimezone()),
        )

        for boundary, forged in (
            ("risk", forged_risk),
            ("trust", forged_trust),
            ("velocity", forged_velocity),
        ):
            _ArmedZeroOffsetTimezone.calls = 0
            _ArmedZeroOffsetTimezone.armed = True
            try:
                with (
                    self.subTest(boundary=boundary),
                    self.assertRaises(ValidationError),
                ):
                    if boundary == "risk":
                        forged.factor(FactorName.EVIDENCE_DENSITY)
                    elif boundary == "trust":
                        require_validated_trust_snapshot(forged, profile=configured)
                    else:
                        require_validated_trust_velocity(forged)
            finally:
                _ArmedZeroOffsetTimezone.armed = False
            self.assertEqual(_ArmedZeroOffsetTimezone.calls, 0)


if __name__ == "__main__":
    unittest.main()
