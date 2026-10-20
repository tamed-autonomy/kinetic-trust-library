"""Independent Soul veto tests derived from KTP Core and Sensors."""

from __future__ import annotations

import copy
import unittest
from unittest import mock
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone, tzinfo

import kinetic_trust_library.core.soul as soul_module
import kinetic_trust_library.models._uri as uri_module
from kinetic_trust_library._canonical import canonical_sha256
from kinetic_trust_library.core.soul import assess_soul, require_validated_soul_assessment
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.action import ValidatedActionDemand
from kinetic_trust_library.models.profile import DeploymentProfile, ProfileRef
from kinetic_trust_library.models.soul import (
    SoulAssessment,
    SoulAssessmentState,
    SoulConstraint,
    SoulConstraintType,
    SoulFrameworkOutcome,
    SoulResponseDeclaration,
    SoulUndeterminedReason,
)
from tests.unit.models.test_profile import (
    _RaisingEqualityString,
    _RaisingStringSubclass,
    _ToggleHashString,
    _ToggleInt,
    UTC_NOW,
    complete_action,
    complete_capability,
    complete_profile_declaration,
)


CUTOFF = UTC_NOW


class ObservableZeroOffsetTimezone(tzinfo):
    def __init__(self):
        self.calls = 0

    def utcoffset(self, value):
        self.calls += 1
        return timedelta(0)

    def dst(self, value):
        self.calls += 1
        return timedelta(0)


def profile(*, frameworks=("soul.framework.a", "soul.framework.b")):
    return DeploymentProfile.validate(
        complete_profile_declaration(soul_frameworks=frameworks)
    )


def action(configured, *, cutoff=CUTOFF):
    return ValidatedActionDemand.validate(
        complete_action(),
        profile=configured,
        capability=complete_capability(),
        cutoff=cutoff,
    )


def response(configured, validated_action, framework_id, *, state="clear", **changes):
    values = {
        "framework_id": framework_id,
        "profile_ref": configured.ref,
        "profile_digest": configured.digest,
        "action_id": validated_action.action_id,
        "action_digest": validated_action.digest,
        "query_cutoff": CUTOFF,
        "state": state,
        "observed_at": CUTOFF,
        "provenance_id": f"soul-response:{framework_id.rsplit('.', 1)[-1]}",
        "constraint_type": None,
        "constraint_id": None,
        "authority": None,
        "undetermined_reason": None,
    }
    if state == "veto":
        values.update(
            constraint_type=SoulConstraintType.TK_LABEL,
            constraint_id="TK-NC-001",
            authority="https://localcontexts.org/label/tk-nc/",
        )
    elif state == "undetermined":
        values["undetermined_reason"] = SoulUndeterminedReason.ERROR
    values.update(changes)
    return SoulResponseDeclaration(**values)


def clear(configured, validated_action, framework_id, **changes):
    return response(configured, validated_action, framework_id, **changes)


def veto(configured, validated_action, framework_id, **changes):
    return response(configured, validated_action, framework_id, state="veto", **changes)


def undetermined(configured, validated_action, framework_id, **changes):
    return response(
        configured, validated_action, framework_id, state="undetermined", **changes
    )


class SoulAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.profile = profile()
        self.action = action(self.profile)

    def test_any_real_veto_returns_sovereignty_constraint(self):
        result = assess_soul(
            self.profile,
            [
                clear(self.profile, self.action, "soul.framework.a"),
                veto(self.profile, self.action, "soul.framework.b"),
            ],
            self.action,
            CUTOFF,
        )

        self.assertIs(result.state, SoulAssessmentState.VETO)
        self.assertTrue(result.vetoed)
        self.assertEqual(result.reason_code, "SOVEREIGNTY_CONSTRAINT")
        self.assertEqual(len(result.constraints), 1)
        constraint = result.constraints[0]
        self.assertEqual(constraint.framework_id, "soul.framework.b")
        self.assertIs(constraint.constraint_type, SoulConstraintType.TK_LABEL)
        self.assertEqual(constraint.constraint_id, "TK-NC-001")
        self.assertEqual(constraint.authority, "https://localcontexts.org/label/tk-nc/")
        self.assertEqual(constraint.provenance_id, "soul-response:b")

    def test_all_current_clearances_produce_clear_assessment(self):
        declarations = [
            clear(self.profile, self.action, framework)
            for framework in self.profile.soul_frameworks
        ]

        result = assess_soul(self.profile, reversed(declarations), self.action, CUTOFF)

        self.assertIs(result.state, SoulAssessmentState.CLEAR)
        self.assertFalse(result.vetoed)
        self.assertIsNone(result.reason_code)
        self.assertEqual(result.constraints, ())
        self.assertEqual(result.undetermined_frameworks, ())
        self.assertEqual(
            tuple(outcome.framework_id for outcome in result.outcomes),
            self.profile.soul_frameworks,
        )
        self.assertTrue(
            all(
                outcome.state is SoulAssessmentState.CLEAR
                for outcome in result.outcomes
            )
        )

    def test_missing_framework_is_undetermined_and_fails_closed(self):
        result = assess_soul(
            self.profile,
            [clear(self.profile, self.action, "soul.framework.a")],
            self.action,
            CUTOFF,
        )

        self.assertIs(result.state, SoulAssessmentState.UNDETERMINED)
        self.assertTrue(result.vetoed)
        self.assertEqual(result.reason_code, "SOVEREIGNTY_CONSTRAINT")
        self.assertEqual(result.undetermined_frameworks, ("soul.framework.b",))
        missing = result.outcomes[1]
        self.assertIs(missing.state, SoulAssessmentState.UNDETERMINED)
        self.assertIs(missing.undetermined_reason, SoulUndeterminedReason.MISSING)
        self.assertIsNone(missing.observed_at)
        self.assertIsNone(missing.provenance_id)
        self.assertIsNone(missing.constraint)

    def test_unreachable_error_timeout_and_empty_share_fail_closed_branch(self):
        configured = profile(
            frameworks=(
                "soul.framework.unreachable",
                "soul.framework.error",
                "soul.framework.timeout",
                "soul.framework.empty",
            )
        )
        validated_action = action(configured)
        declarations = [
            undetermined(
                configured,
                validated_action,
                "soul.framework.unreachable",
                undetermined_reason=SoulUndeterminedReason.UNREACHABLE,
            ),
            undetermined(
                configured,
                validated_action,
                "soul.framework.error",
                undetermined_reason=SoulUndeterminedReason.ERROR,
            ),
            undetermined(
                configured,
                validated_action,
                "soul.framework.timeout",
                undetermined_reason=SoulUndeterminedReason.TIMEOUT,
            ),
            undetermined(
                configured,
                validated_action,
                "soul.framework.empty",
                undetermined_reason=SoulUndeterminedReason.EMPTY,
            ),
        ]

        result = assess_soul(configured, declarations, validated_action, CUTOFF)

        self.assertIs(result.state, SoulAssessmentState.UNDETERMINED)
        self.assertTrue(result.vetoed)
        self.assertEqual(result.constraints, ())
        self.assertEqual(
            result.undetermined_frameworks,
            configured.soul_frameworks,
        )
        self.assertEqual(
            tuple(outcome.undetermined_reason for outcome in result.outcomes),
            (
                SoulUndeterminedReason.UNREACHABLE,
                SoulUndeterminedReason.ERROR,
                SoulUndeterminedReason.TIMEOUT,
                SoulUndeterminedReason.EMPTY,
            ),
        )
        self.assertTrue(all(outcome.constraint is None for outcome in result.outcomes))

    def test_real_veto_and_undetermined_are_both_retained(self):
        result = assess_soul(
            self.profile,
            [
                undetermined(
                    self.profile,
                    self.action,
                    "soul.framework.a",
                    undetermined_reason=SoulUndeterminedReason.TIMEOUT,
                ),
                veto(self.profile, self.action, "soul.framework.b"),
            ],
            self.action,
            CUTOFF,
        )

        self.assertIs(result.state, SoulAssessmentState.VETO)
        self.assertEqual(
            tuple(item.framework_id for item in result.constraints),
            ("soul.framework.b",),
        )
        self.assertEqual(result.undetermined_frameworks, ("soul.framework.a",))

    def test_result_binds_the_exact_profile_action_and_cutoff(self):
        result = assess_soul(
            self.profile,
            [
                clear(self.profile, self.action, framework)
                for framework in self.profile.soul_frameworks
            ],
            self.action,
            CUTOFF,
        )

        self.assertEqual(result.profile_ref, self.profile.ref)
        self.assertEqual(result.profile_digest, self.profile.digest)
        self.assertEqual(result.action_id, self.action.action_id)
        self.assertEqual(result.action_digest, self.action.digest)
        self.assertEqual(result.cutoff, CUTOFF)
        self.assertEqual(len(result.digest), 64)

    def test_input_order_cannot_change_framework_order_or_digest(self):
        first = clear(self.profile, self.action, "soul.framework.a")
        second = veto(self.profile, self.action, "soul.framework.b")

        ordered = assess_soul(self.profile, [first, second], self.action, CUTOFF)
        reversed_result = assess_soul(
            self.profile, [second, first], self.action, CUTOFF
        )

        self.assertEqual(ordered, reversed_result)
        self.assertEqual(ordered.digest, reversed_result.digest)


class SoulDeclarationValidationTests(unittest.TestCase):
    def setUp(self):
        self.profile = profile()
        self.action = action(self.profile)

    def test_missing_profile_reference_slot_is_a_validation_error(self):
        reference = copy.copy(self.profile.ref)
        declaration = clear(
            self.profile, self.action, "soul.framework.a", profile_ref=reference
        )
        object.__delattr__(reference, "version")

        with self.assertRaises(ValidationError):
            assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_duplicate_or_unknown_framework_response_is_rejected(self):
        duplicate = clear(self.profile, self.action, "soul.framework.a")
        for declarations in (
            [duplicate, duplicate],
            [clear(self.profile, self.action, "soul.framework.unknown")],
        ):
            with self.subTest(declarations=declarations):
                with self.assertRaises(ValidationError):
                    assess_soul(self.profile, declarations, self.action, CUTOFF)

    def test_wrong_action_id_or_digest_is_rejected(self):
        cases = (
            {"action_id": "action:other"},
            {"action_digest": "0" * 64},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                declaration = clear(
                    self.profile,
                    self.action,
                    "soul.framework.a",
                    **changes,
                )
                with self.assertRaisesRegex(ValidationError, "action"):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_wrong_profile_reference_or_digest_is_rejected(self):
        cases = (
            {"profile_ref": ProfileRef("profile.other", 4)},
            {"profile_digest": "0" * 64},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                declaration = clear(
                    self.profile,
                    self.action,
                    "soul.framework.a",
                    **changes,
                )
                with self.assertRaisesRegex(ValidationError, "profile"):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_query_cutoff_and_response_time_must_be_exactly_current(self):
        cases = (
            {"query_cutoff": CUTOFF - timedelta(microseconds=1)},
            {"query_cutoff": CUTOFF + timedelta(microseconds=1)},
            {"observed_at": CUTOFF - timedelta(microseconds=1)},
            {"observed_at": CUTOFF + timedelta(microseconds=1)},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                declaration = clear(
                    self.profile,
                    self.action,
                    "soul.framework.a",
                    **changes,
                )
                with self.assertRaisesRegex(ValidationError, "current|cutoff"):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_assessment_cutoff_must_match_validated_action_cutoff(self):
        with self.assertRaisesRegex(ValidationError, "action cutoff"):
            assess_soul(
                self.profile,
                [],
                self.action,
                CUTOFF + timedelta(microseconds=1),
            )

    def test_real_veto_requires_typed_constraint_id_authority_and_provenance(self):
        cases = (
            {"constraint_type": None},
            {"constraint_type": "tk_label"},
            {"constraint_id": None},
            {"constraint_id": ""},
            {"authority": None},
            {"authority": "not-a-uri"},
            {"provenance_id": ""},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                declaration = veto(
                    self.profile,
                    self.action,
                    "soul.framework.a",
                    **changes,
                )
                with self.assertRaises(ValidationError):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_constraint_types_exactly_match_the_canonical_schema(self):
        self.assertEqual(
            tuple(item.value for item in SoulConstraintType),
            (
                "tk_label",
                "ocap",
                "care",
                "sacred_land",
                "treaty",
                "lineage",
                "cultural_heritage",
            ),
        )

    def test_constraint_identifiers_and_authority_uris_are_bounded_and_canonical(self):
        malformed = (
            {"constraint_id": "has whitespace"},
            {"constraint_id": "x" * 257},
            {"constraint_id": "e\N{COMBINING ACUTE ACCENT}"},
            {"authority": "https:///missing-host"},
            {"authority": "urn:"},
            {"authority": "https://authority.example/\nforged"},
            {"authority": "urn:" + "x" * 2048},
        )
        for changes in malformed:
            with self.subTest(changes=changes):
                declaration = veto(
                    self.profile,
                    self.action,
                    "soul.framework.a",
                    **changes,
                )
                with self.assertRaises(ValidationError):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_authority_uri_rejects_malformed_rfc3986_and_http_syntax(self):
        malformed = (
            "https://example.com:abc/path",
            "https://example.com\\evil/path",
            "https://%zz/path",
            "https://exämple.test/path",
            "https://example.com:65536/path",
            "https://example.com:/path",
            "https://:443/path",
            "https://[not-an-ip]/path",
            "https://example.com/path with space",
            "https://example.com/path\\segment",
            "https://example.com/path%2",
            "https://example.com/path%GG",
            "https://example.com/[raw-brackets]",
            "custom://host^bad/path",
            "custom://user@@example.com/path",
            "urn:",
            "did:",
        )
        for authority in malformed:
            with self.subTest(authority=authority):
                declaration = veto(
                    self.profile,
                    self.action,
                    "soul.framework.a",
                    authority=authority,
                )
                with self.assertRaisesRegex(ValidationError, "authority|URI|port"):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_authority_uri_accepts_valid_absolute_rfc3986_forms(self):
        valid = (
            "https://example.com/resource",
            "https://127.0.0.1:8443/path",
            "https://[2001:db8::1]:443/path",
            "urn:isbn:0451450523",
            "did:web:example.com:user:123",
            "ssh://user@example.com:22/path",
            "https://example.com/%E2%82%AC?query=%7Bvalue%7D#part",
        )
        for authority in valid:
            with self.subTest(authority=authority):
                declaration = veto(
                    self.profile,
                    self.action,
                    "soul.framework.a",
                    authority=authority,
                )
                result = assess_soul(self.profile, [declaration], self.action, CUTOFF)
                self.assertEqual(result.constraints[0].authority, authority)

    def test_ipvfuture_flag_case_is_preserved_through_digest_revalidation(self):
        configured = profile(frameworks=("soul.framework.a",))
        validated_action = action(configured)
        results = []
        for authority in (
            "https://[v1.fe80]:443/",
            "https://[V1.fe80]:443/",
        ):
            result = assess_soul(
                configured,
                [
                    veto(
                        configured,
                        validated_action,
                        "soul.framework.a",
                        authority=authority,
                    )
                ],
                validated_action,
                CUTOFF,
            )
            self.assertEqual(result.constraints[0].authority, authority)
            self.assertEqual(result.outcomes[0].constraint.authority, authority)
            self.assertIs(require_validated_soul_assessment(result), result)
            self.assertEqual(
                canonical_sha256(
                    soul_module._assessment_projection(
                        result,
                        include_digest=False,
                    )
                ),
                result.digest,
            )
            results.append(result)
        self.assertNotEqual(results[0].digest, results[1].digest)

    def test_authority_uri_rejects_malformed_uppercase_ipvfuture_forms(self):
        malformed = (
            "https://[V.fe80]:443/",
            "https://[VG.fe80]:443/",
            "https://[V1]:443/",
            "https://[V1.]:443/",
            "https://[V1.fe80%25]:443/",
            "https://[V1.fe80]:abc/",
            "https://[V1.fe80]:65536/",
            "https://[V1.fe80]:/",
        )
        for authority in malformed:
            with self.subTest(authority=authority):
                declaration = veto(
                    self.profile,
                    self.action,
                    "soul.framework.a",
                    authority=authority,
                )
                with self.assertRaisesRegex(ValidationError, "authority|URI|port"):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_authority_parser_controls_ordinary_failures_only(self):
        declaration = veto(self.profile, self.action, "soul.framework.a")
        real_urlsplit = uri_module.urlsplit
        parser_failure = RuntimeError("parser failed")

        def parse(value):
            if value == declaration.authority:
                raise parser_failure
            return real_urlsplit(value)

        with mock.patch.object(uri_module, "urlsplit", side_effect=parse):
            with self.assertRaisesRegex(ValidationError, "absolute URI"):
                assess_soul(self.profile, [declaration], self.action, CUTOFF)
        parser_failure = KeyboardInterrupt()
        with mock.patch.object(uri_module, "urlsplit", side_effect=parse):
            with self.assertRaises(KeyboardInterrupt):
                assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_clear_and_undetermined_responses_cannot_fabricate_authority(self):
        cases = (
            clear(
                self.profile,
                self.action,
                "soul.framework.a",
                authority="https://authority.example/",
            ),
            undetermined(
                self.profile,
                self.action,
                "soul.framework.a",
                authority="https://authority.example/",
            ),
            undetermined(
                self.profile,
                self.action,
                "soul.framework.a",
                constraint_id="constraint:invented",
            ),
        )
        for declaration in cases:
            with self.subTest(declaration=declaration):
                with self.assertRaisesRegex(ValidationError, "constraint|authority"):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_clear_and_veto_reject_failure_reasons(self):
        for declaration in (
            clear(
                self.profile,
                self.action,
                "soul.framework.a",
                undetermined_reason=SoulUndeterminedReason.ERROR,
            ),
            veto(
                self.profile,
                self.action,
                "soul.framework.a",
                undetermined_reason=SoulUndeterminedReason.ERROR,
            ),
        ):
            with self.subTest(declaration=declaration):
                with self.assertRaisesRegex(ValidationError, "undetermined"):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_undetermined_requires_a_provider_failure_reason_and_provenance(self):
        cases = (
            {"undetermined_reason": None},
            {"undetermined_reason": SoulUndeterminedReason.MISSING},
            {"undetermined_reason": "timeout"},
            {"provenance_id": ""},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                declaration = undetermined(
                    self.profile,
                    self.action,
                    "soul.framework.a",
                    **changes,
                )
                with self.assertRaises(ValidationError):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_invalid_state_and_non_declaration_values_are_rejected(self):
        for declaration in (
            response(
                self.profile,
                self.action,
                "soul.framework.a",
                state="maybe",
            ),
            {"framework_id": "soul.framework.a"},
        ):
            with self.subTest(declaration=declaration):
                with self.assertRaises(ValidationError):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_exact_string_datetime_and_profile_reference_types_are_required(self):
        class StringSubclass(str):
            def __str__(self):
                raise AssertionError("Soul validation must not coerce strings")

            def __hash__(self):
                raise AssertionError("Soul validation must not hash string subclasses")

            def __eq__(self, other):
                raise AssertionError(
                    "Soul validation must not compare string subclasses"
                )

        class HostileValue:
            def __str__(self):
                raise AssertionError("Soul validation must not coerce hostile values")

            def __hash__(self):
                raise AssertionError("Soul validation must not hash hostile values")

            def __eq__(self, other):
                raise AssertionError("Soul validation must not compare hostile values")

        class DateTimeSubclass(datetime):
            pass

        subclass_time = DateTimeSubclass(2026, 8, 20, 12, tzinfo=timezone.utc)
        cases = (
            {"framework_id": StringSubclass("soul.framework.a")},
            {"framework_id": HostileValue()},
            {"provenance_id": StringSubclass("soul-response:a")},
            {"state": StringSubclass("clear")},
            {"query_cutoff": subclass_time},
            {"observed_at": subclass_time},
            {"profile_ref": object()},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                declaration = replace(
                    clear(self.profile, self.action, "soul.framework.a"),
                    **changes,
                )
                with self.assertRaises(ValidationError):
                    assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_cutoffs_require_exact_datetime_values_with_zero_utc_offset(self):
        non_utc = timezone(timedelta(hours=1))
        declaration = clear(
            self.profile,
            self.action,
            "soul.framework.a",
            query_cutoff=CUTOFF.astimezone(non_utc),
        )

        with self.assertRaisesRegex(ValidationError, "UTC"):
            assess_soul(self.profile, [declaration], self.action, CUTOFF)

    def test_soul_times_require_owned_utc_without_timezone_hooks(self):
        custom_timezone = ObservableZeroOffsetTimezone()
        custom_time = datetime(2026, 8, 20, 12, tzinfo=custom_timezone)
        declaration = clear(
            self.profile,
            self.action,
            "soul.framework.a",
            query_cutoff=custom_time,
        )

        with self.assertRaises(ValidationError):
            assess_soul(self.profile, [declaration], self.action, CUTOFF)
        self.assertEqual(custom_timezone.calls, 0)

    def test_upstream_construction_rejects_identifier_subclasses_at_source(self):
        class StringSubclass(str):
            pass

        with self.assertRaises(ValidationError):
            DeploymentProfile.validate(
                replace(
                    complete_profile_declaration(
                        soul_frameworks=("soul.framework.only",)
                    ),
                    profile_id=StringSubclass("profile.full-core"),
                )
            )

        normal_profile = profile(frameworks=("soul.framework.only",))
        with self.assertRaises(ValidationError):
            ValidatedActionDemand.validate(
                complete_action(action_id=StringSubclass("action:one")),
                profile=normal_profile,
                capability=complete_capability(),
                cutoff=CUTOFF,
            )

    def test_assessment_rejects_legacy_retained_identifiers_before_hashing(self):
        configured = profile(frameworks=("soul.framework.only",))
        validated_action = action(configured)
        hostile_values = (
            _ToggleHashString("soul.framework.only"),
            _RaisingEqualityString("soul.framework.only"),
            _RaisingStringSubclass("soul.framework.only"),
        )

        _ToggleHashString.armed = True
        _ToggleHashString.calls = 0
        _RaisingEqualityString.calls = 0
        _RaisingStringSubclass.calls = 0
        try:
            for hostile in hostile_values:
                with self.subTest(hostile_type=type(hostile).__name__):
                    forged_profile = copy.copy(configured)
                    object.__setattr__(forged_profile, "soul_frameworks", (hostile,))
                    forged_capability = copy.copy(validated_action.capability)
                    object.__setattr__(forged_capability, "action_classes", (hostile,))
                    forged_action = copy.copy(validated_action)
                    object.__setattr__(forged_action, "capability", forged_capability)
                    with self.assertRaises(ValidationError):
                        assess_soul(forged_profile, [], validated_action, CUTOFF)
                    with self.assertRaises(ValidationError):
                        assess_soul(configured, [], forged_action, CUTOFF)
        finally:
            _ToggleHashString.armed = False
        self.assertEqual(_ToggleHashString.calls, 0)
        self.assertEqual(_RaisingEqualityString.calls, 0)
        self.assertEqual(_RaisingStringSubclass.calls, 0)

    def test_assessment_rejects_retained_profile_integers_before_hooks(self):
        configured = profile(frameworks=("soul.framework.only",))
        validated_action = action(configured)
        for field_name, hostile in (
            ("version", _ToggleInt(configured.version)),
            (
                "external_root_hop_bound",
                _ToggleInt(configured.external_root_hop_bound),
            ),
        ):
            forged_profile = copy.copy(configured)
            if field_name == "version":
                ref = copy.copy(forged_profile.ref)
                object.__setattr__(ref, "version", hostile)
                object.__setattr__(forged_profile, "ref", ref)
            else:
                object.__setattr__(forged_profile, field_name, hostile)

            _ToggleInt.reset(armed=True)
            try:
                with (
                    self.subTest(field_name=field_name),
                    self.assertRaises(ValidationError),
                ):
                    assess_soul(
                        forged_profile,
                        [],
                        validated_action,
                        CUTOFF,
                    )
            finally:
                _ToggleInt.armed = False
            with self.subTest(field_name=field_name, assertion="hook count"):
                self.assertEqual(_ToggleInt.calls, 0)

    def test_assessment_rejects_retained_action_profile_version_before_hooks(self):
        configured = profile(frameworks=("soul.framework.only",))
        validated_action = action(configured)
        for location in ("action", "capability"):
            hostile = _ToggleInt(configured.version)
            ref = copy.copy(configured.ref)
            object.__setattr__(ref, "version", hostile)
            forged_action = copy.copy(validated_action)
            if location == "action":
                object.__setattr__(forged_action, "profile_ref", ref)
            else:
                capability = copy.copy(validated_action.capability)
                object.__setattr__(capability, "profile_ref", ref)
                object.__setattr__(forged_action, "capability", capability)

            _ToggleInt.reset(armed=True)
            try:
                with (
                    self.subTest(location=location),
                    self.assertRaises(ValidationError),
                ):
                    assess_soul(configured, [], forged_action, CUTOFF)
            finally:
                _ToggleInt.armed = False
            with self.subTest(location=location, assertion="hook count"):
                self.assertEqual(_ToggleInt.calls, 0)


class SoulBoundedIterableTests(unittest.TestCase):
    def setUp(self):
        self.profile = profile(frameworks=("soul.framework.only",))
        self.action = action(self.profile)

    def test_framework_inventory_bounds_an_infinite_response_iterable(self):
        first = clear(self.profile, self.action, "soul.framework.only")

        class GuardedInfinite:
            def __init__(self):
                self.pulls = 0

            def __iter__(self):
                return self

            def __next__(self):
                self.pulls += 1
                if self.pulls > 2:
                    raise AssertionError("Soul assessment pulled past its bound")
                return first

        declarations = GuardedInfinite()
        with self.assertRaisesRegex(ValidationError, "more responses"):
            assess_soul(self.profile, declarations, self.action, CUTOFF)
        self.assertEqual(declarations.pulls, 2)

    def test_exact_configured_response_count_is_accepted(self):
        configured = profile(
            frameworks=tuple(f"soul.framework.{index}" for index in range(300))
        )
        validated_action = action(configured)
        declarations = (
            clear(configured, validated_action, framework)
            for framework in configured.soul_frameworks
        )

        result = assess_soul(configured, declarations, validated_action, CUTOFF)

        self.assertEqual(len(result.outcomes), 300)
        self.assertFalse(result.vetoed)

    def test_hostile_iterable_failures_are_controlled(self):
        class BrokenIterator:
            def __iter__(self):
                raise ValueError("external iterator failed")

        class BrokenNext:
            def __iter__(self):
                return self

            def __next__(self):
                raise RuntimeError("external next failed")

        for declarations in (BrokenIterator(), BrokenNext()):
            with self.subTest(declarations=declarations):
                with self.assertRaisesRegex(ValidationError, "iterable"):
                    assess_soul(self.profile, declarations, self.action, CUTOFF)

    def test_process_control_signals_are_not_swallowed(self):
        class Interrupted:
            def __iter__(self):
                raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            assess_soul(self.profile, Interrupted(), self.action, CUTOFF)


class SoulIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.profile = profile()
        self.action = action(self.profile)

    def test_assessment_and_nested_results_are_constructor_guarded_and_frozen(self):
        result = assess_soul(
            self.profile,
            [
                clear(self.profile, self.action, "soul.framework.a"),
                veto(self.profile, self.action, "soul.framework.b"),
            ],
            self.action,
            CUTOFF,
        )

        for result_type in (SoulAssessment, SoulConstraint, SoulFrameworkOutcome):
            with self.subTest(result_type=result_type):
                with self.assertRaises(TypeError):
                    result_type()
        with self.assertRaises(FrozenInstanceError):
            result.vetoed = False
        with self.assertRaises(FrozenInstanceError):
            result.constraints[0].authority = "https://forged.example/"
        self.assertIs(require_validated_soul_assessment(result), result)
        exact_copy = copy.copy(result)
        self.assertIs(require_validated_soul_assessment(exact_copy), exact_copy)

    def test_assessment_owns_normalized_declarations(self):
        source = [clear(self.profile, self.action, "soul.framework.a")]
        result = assess_soul(self.profile, source, self.action, CUTOFF)
        object.__setattr__(source[0], "state", "veto")
        source.clear()

        self.assertIs(result.state, SoulAssessmentState.UNDETERMINED)
        self.assertIs(require_validated_soul_assessment(result), result)

    def test_retained_soul_times_reject_custom_timezone_without_hooks(self):
        result = assess_soul(
            self.profile,
            [clear(self.profile, self.action, "soul.framework.a")],
            self.action,
            CUTOFF,
        )
        custom_timezone = ObservableZeroOffsetTimezone()
        custom_time = datetime(2026, 8, 20, 12, tzinfo=custom_timezone)
        declaration = replace(result._declarations[0], observed_at=custom_time)
        outcome = copy.copy(result.outcomes[0])
        object.__setattr__(outcome, "observed_at", custom_time)
        forged = copy.copy(result)
        object.__setattr__(
            forged,
            "_declarations",
            (declaration, *result._declarations[1:]),
        )
        object.__setattr__(forged, "outcomes", (outcome, *result.outcomes[1:]))

        with self.assertRaises(ValidationError):
            require_validated_soul_assessment(forged)
        self.assertEqual(custom_timezone.calls, 0)

    def test_resealed_public_mutation_cannot_bypass_structural_rederivation(self):
        result = assess_soul(
            self.profile,
            [
                clear(self.profile, self.action, "soul.framework.a"),
                veto(self.profile, self.action, "soul.framework.b"),
            ],
            self.action,
            CUTOFF,
        )
        forged = copy.copy(result)
        outcomes = list(result.outcomes)
        altered = copy.copy(outcomes[1])
        object.__setattr__(altered, "state", SoulAssessmentState.CLEAR)
        outcomes[1] = altered
        object.__setattr__(forged, "outcomes", tuple(outcomes))
        object.__setattr__(
            forged,
            "digest",
            canonical_sha256(
                soul_module._assessment_projection(forged, include_digest=False)
            ),
        )

        with self.assertRaisesRegex(ValidationError, "integrity"):
            require_validated_soul_assessment(forged)

    def test_one_projection_binds_every_authoritative_public_field_once(self):
        result = assess_soul(
            self.profile,
            [
                veto(self.profile, self.action, "soul.framework.a"),
                undetermined(
                    self.profile,
                    self.action,
                    "soul.framework.b",
                    undetermined_reason=SoulUndeterminedReason.TIMEOUT,
                ),
            ],
            self.action,
            CUTOFF,
        )
        authoritative_fields = (
            "profile_ref",
            "profile_digest",
            "action_id",
            "action_digest",
            "cutoff",
            "state",
            "vetoed",
            "reason_code",
            "outcomes",
            "constraints",
            "undetermined_frameworks",
        )
        projection = soul_module._assessment_projection(result, include_digest=False)
        public_projection = soul_module._assessment_projection(result)

        self.assertEqual(tuple(projection), authoritative_fields)
        self.assertEqual(tuple(public_projection), authoritative_fields + ("digest",))
        self.assertEqual(public_projection["digest"], result.digest)
        self.assertEqual(canonical_sha256(projection), result.digest)
        for field_name in authoritative_fields:
            with self.subTest(field_name=field_name):
                mutated = dict(projection)
                mutated[field_name] = None
                self.assertNotEqual(canonical_sha256(mutated), result.digest)

        forged = copy.copy(result)
        object.__setattr__(forged, "digest", "0" * 64)
        with self.assertRaisesRegex(ValidationError, "integrity"):
            require_validated_soul_assessment(forged)

    def test_require_boundary_exact_matches_optional_profile_and_action(self):
        result = assess_soul(self.profile, [], self.action, CUTOFF)
        self.assertIs(
            require_validated_soul_assessment(
                result, profile=self.profile, action=self.action
            ),
            result,
        )

        other_profile = profile(frameworks=("soul.framework.other",))
        other_action = action(other_profile)
        with self.assertRaisesRegex(ValidationError, "profile"):
            require_validated_soul_assessment(result, profile=other_profile)
        with self.assertRaisesRegex(ValidationError, "action"):
            require_validated_soul_assessment(result, action=other_action)

    def test_outcomes_are_disclosure_minimal_and_do_not_invent_recovery(self):
        result = assess_soul(
            self.profile,
            [
                veto(self.profile, self.action, "soul.framework.a"),
                undetermined(
                    self.profile,
                    self.action,
                    "soul.framework.b",
                    undetermined_reason=SoulUndeterminedReason.TIMEOUT,
                ),
            ],
            self.action,
            CUTOFF,
        )

        constraint = result.constraints[0]
        self.assertFalse(hasattr(constraint, "community"))
        self.assertFalse(hasattr(constraint, "constraint_name"))
        self.assertFalse(hasattr(constraint, "remediation"))
        timeout = result.outcomes[1]
        self.assertIsNone(timeout.constraint)
        self.assertFalse(hasattr(timeout, "error_detail"))
        self.assertFalse(hasattr(result, "retry"))
        self.assertFalse(hasattr(result, "enforce"))

    def test_invalid_top_level_type_and_naive_cutoff_fail_closed(self):
        with self.assertRaises(ValidationError):
            require_validated_soul_assessment(object())
        with self.assertRaises(ValidationError):
            assess_soul(
                self.profile,
                [],
                self.action,
                CUTOFF.replace(tzinfo=None),
            )


if __name__ == "__main__":
    unittest.main()
