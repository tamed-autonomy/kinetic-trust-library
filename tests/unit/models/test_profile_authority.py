import copy
import unittest
from dataclasses import fields, replace
from decimal import Decimal
from types import MappingProxyType

from kinetic_trust_library._canonical import canonical_sha256
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models import action as action_module
from kinetic_trust_library.models import profile as profile_module
from kinetic_trust_library.models.action import (
    ValidatedActionDemand,
    ValidatedCapability,
    require_validated_action,
    require_validated_capability,
)
from kinetic_trust_library.models.profile import (
    DeploymentProfile,
    ProfileRef,
    require_validated_profile,
)
from tests.unit.models.test_profile import (
    _IntSubclass,
    _RaisingEqualityString,
    _RaisingStringSubclass,
    _ToggleHashString,
    _ToggleInt,
    UTC_NOW,
    complete_action,
    complete_capability,
    complete_profile_declaration,
)


def validated_profile():
    return DeploymentProfile.validate(complete_profile_declaration())


def validated_action(profile):
    return ValidatedActionDemand.validate(
        complete_action(),
        profile=profile,
        capability=complete_capability(),
        cutoff=UTC_NOW,
    )


def field_values(value):
    return {field.name: getattr(value, field.name) for field in fields(value)}


class ExternalProfileAuthorityTests(unittest.TestCase):
    def test_profile_context_factory_has_no_validator_injection_seam(self):
        profile = validated_profile()

        with self.assertRaises(TypeError):
            profile_module._validated_profile_context(
                profile,
                validator=lambda value: value,
            )

        forged = object.__new__(profile_module._ValidatedProfileContext)
        with self.assertRaises(ValidationError):
            profile_module._validated_profile_context(forged)

        try:
            ValidatedActionDemand.validate(
                complete_action(),
                profile=forged,
                capability=complete_capability(),
                cutoff=UTC_NOW,
            )
        except Exception as exc:
            self.assertIs(type(exc), ValidationError)
        else:
            self.fail("public action validation accepted a forged profile context")

    def test_profile_context_factory_rejects_semantically_invalid_resealed_profile(
        self,
    ):
        profile = validated_profile()
        object.__setattr__(profile, "standing_decay_rate", Decimal("101"))
        object.__setattr__(
            profile,
            "digest",
            canonical_sha256(profile_module._profile_digest_input(profile)),
        )

        with self.assertRaises(ValidationError):
            profile_module._validated_profile_context(profile)

    def test_public_action_surfaces_reject_exact_private_profile_context(self):
        profile = validated_profile()
        action = validated_action(profile)
        context = profile_module._validated_profile_context(profile)
        calls = {
            "ValidatedCapability.validate": lambda: ValidatedCapability.validate(
                complete_capability(),
                profile=context,
                cutoff=UTC_NOW,
            ),
            "ValidatedActionDemand.validate": lambda: ValidatedActionDemand.validate(
                complete_action(),
                profile=context,
                capability=complete_capability(),
                cutoff=UTC_NOW,
            ),
            "require_validated_capability": lambda: require_validated_capability(
                action.capability,
                profile=context,
            ),
            "require_validated_action": lambda: require_validated_action(
                action,
                profile=context,
            ),
        }

        for name, call in calls.items():
            with self.subTest(name=name), self.assertRaises(ValidationError):
                call()

    def test_mutated_resealed_context_cannot_authorize_public_action(self):
        profile = validated_profile()
        context = profile_module._validated_profile_context(profile)
        object.__setattr__(profile, "standing_decay_rate", Decimal("101"))
        object.__setattr__(
            profile,
            "digest",
            canonical_sha256(profile_module._profile_digest_input(profile)),
        )

        with self.assertRaises(ValidationError):
            ValidatedActionDemand.validate(
                complete_action(),
                profile=context,
                capability=complete_capability(),
                cutoff=UTC_NOW,
            )

    def test_profile_rejects_direct_and_no_argument_construction(self):
        profile = validated_profile()
        with self.assertRaises(TypeError):
            DeploymentProfile()
        with self.assertRaises(TypeError):
            DeploymentProfile(**field_values(profile))

    def test_profile_exact_copy_revalidates_but_invalid_copy_does_not(self):
        profile = validated_profile()
        with self.assertRaises(TypeError):
            replace(profile, peer_share=Decimal("20"))

        exact_copy = copy.copy(profile)
        self.assertIs(require_validated_profile(exact_copy), exact_copy)

        altered_copy = copy.copy(profile)
        object.__setattr__(altered_copy, "peer_share", Decimal("9"))
        object.__setattr__(
            altered_copy,
            "digest",
            canonical_sha256(profile_module._profile_digest_input(altered_copy)),
        )
        with self.assertRaises(ValidationError):
            require_validated_profile(altered_copy)

    def test_profile_nested_state_or_digest_tampering_fails_downstream(self):
        for field_name, value in (
            ("peer_share", Decimal("20")),
            ("action_demand_unit", "risk-points"),
            ("risk_domain_weights", MappingProxyType({})),
            ("digest", "0" * 64),
        ):
            profile = validated_profile()
            object.__setattr__(profile, field_name, value)
            with (
                self.subTest(field_name=field_name),
                self.assertRaises(ValidationError),
            ):
                ValidatedActionDemand.validate(
                    complete_action(),
                    profile=profile,
                    capability=complete_capability(),
                    cutoff=UTC_NOW,
                )

        profile = validated_profile()
        object.__setattr__(
            profile.risk_factors.evidence_density,
            "weight",
            Decimal("0.99"),
        )
        with self.assertRaises(ValidationError):
            profile.factor(profile_module.FactorName.EVIDENCE_DENSITY)
        with self.assertRaises(ValidationError):
            ValidatedActionDemand.validate(
                complete_action(),
                profile=profile,
                capability=complete_capability(),
                cutoff=UTC_NOW,
            )

    def test_builtin_feed_intervals_are_digest_bound_and_revalidate(self):
        """Catches construction and integrity using different integer rules."""
        declaration = complete_profile_declaration()
        feed = declaration.feeds["feed:1"]
        profile = DeploymentProfile.validate(
            replace(
                declaration,
                feeds={
                    **declaration.feeds,
                    "feed:1": replace(
                        feed,
                        refresh_interval_ms=2000,
                        stale_threshold_ms=9000,
                    ),
                },
            )
        )

        self.assertIs(type(profile.feed("feed:1").refresh_interval_ms), int)
        self.assertIs(type(profile.feed("feed:1").stale_threshold_ms), int)
        self.assertEqual(
            profile.digest,
            canonical_sha256(profile_module._profile_digest_input(profile)),
        )
        self.assertIs(require_validated_profile(profile), profile)

    def test_resealed_int_subclass_feed_intervals_fail_structural_authority(self):
        """Catches a digest-valid forged subclass bypassing exact primitives."""
        for field_name, value in (
            ("refresh_interval_ms", _IntSubclass(1000)),
            ("stale_threshold_ms", _IntSubclass(5000)),
        ):
            profile = validated_profile()
            feed = profile.feed("feed:1")
            forged = copy.copy(profile)
            object.__setattr__(
                forged,
                "feeds",
                MappingProxyType(
                    {
                        **forged.feeds,
                        "feed:1": replace(feed, **{field_name: value}),
                    }
                ),
            )
            object.__setattr__(
                forged,
                "digest",
                canonical_sha256(profile_module._profile_digest_input(forged)),
            )

            with (
                self.subTest(field_name=field_name),
                self.assertRaises(ValidationError),
            ):
                require_validated_profile(forged)

    def test_profile_require_rejects_retained_identifier_subclass_before_hashing(self):
        profile = validated_profile()
        hostile_values = (
            _ToggleHashString("soul.framework.primary"),
            _RaisingEqualityString("soul.framework.primary"),
            _RaisingStringSubclass("soul.framework.primary"),
        )
        _ToggleHashString.armed = True
        _ToggleHashString.calls = 0
        _RaisingEqualityString.calls = 0
        _RaisingStringSubclass.calls = 0
        try:
            for hostile in hostile_values:
                with self.subTest(hostile_type=type(hostile).__name__):
                    forged = copy.copy(profile)
                    object.__setattr__(forged, "soul_frameworks", (hostile,))
                    with self.assertRaises(ValidationError):
                        require_validated_profile(forged)
        finally:
            _ToggleHashString.armed = False
        self.assertEqual(_ToggleHashString.calls, 0)
        self.assertEqual(_RaisingEqualityString.calls, 0)
        self.assertEqual(_RaisingStringSubclass.calls, 0)

    def test_profile_require_rejects_retained_integer_subclasses_before_hooks(self):
        for field_name, hostile in (
            ("version", _ToggleInt(4)),
            ("external_root_hop_bound", _ToggleInt(6)),
        ):
            forged = copy.copy(validated_profile())
            if field_name == "version":
                ref = copy.copy(forged.ref)
                object.__setattr__(ref, "version", hostile)
                object.__setattr__(forged, "ref", ref)
            else:
                object.__setattr__(forged, field_name, hostile)

            _ToggleInt.reset(armed=True)
            try:
                with (
                    self.subTest(field_name=field_name),
                    self.assertRaises(ValidationError),
                ):
                    require_validated_profile(forged)
            finally:
                _ToggleInt.armed = False
            with self.subTest(field_name=field_name, assertion="hook count"):
                self.assertEqual(_ToggleInt.calls, 0)


class ExternalActionAuthorityTests(unittest.TestCase):
    def test_resealed_capability_cannot_retain_a_bare_subject(self):
        profile = validated_profile()
        capability = ValidatedCapability.validate(
            complete_capability(), profile=profile, cutoff=UTC_NOW
        )
        forged = copy.copy(capability)
        object.__setattr__(forged, "subject", "agent-one")
        object.__setattr__(forged, "digest", action_module._capability_digest(forged))

        with self.assertRaises(ValidationError):
            require_validated_capability(forged)

    def test_capability_exact_copy_revalidates_and_tampering_fails(self):
        profile = validated_profile()
        capability = ValidatedCapability.validate(
            complete_capability(), profile=profile, cutoff=UTC_NOW
        )
        exact_copy = copy.copy(capability)
        self.assertIs(
            require_validated_capability(exact_copy, profile=profile), exact_copy
        )
        forged = copy.copy(capability)
        object.__setattr__(forged, "action_classes", ("unknown",))
        with self.assertRaises(ValidationError):
            require_validated_capability(forged, profile=profile)

    def test_action_require_rejects_retained_action_class_before_hashing(self):
        profile = validated_profile()
        action = validated_action(profile)
        hostile_values = (
            _ToggleHashString("deploy"),
            _RaisingEqualityString("deploy"),
            _RaisingStringSubclass("deploy"),
        )
        _ToggleHashString.armed = True
        _ToggleHashString.calls = 0
        _RaisingEqualityString.calls = 0
        _RaisingStringSubclass.calls = 0
        try:
            for hostile in hostile_values:
                with self.subTest(hostile_type=type(hostile).__name__):
                    capability = copy.copy(action.capability)
                    object.__setattr__(capability, "action_classes", (hostile,))
                    forged = copy.copy(action)
                    object.__setattr__(forged, "capability", capability)
                    with self.assertRaises(ValidationError):
                        require_validated_capability(capability)
                    with self.assertRaises(ValidationError):
                        require_validated_action(forged)
        finally:
            _ToggleHashString.armed = False
        self.assertEqual(_ToggleHashString.calls, 0)
        self.assertEqual(_RaisingEqualityString.calls, 0)
        self.assertEqual(_RaisingStringSubclass.calls, 0)

    def test_capability_require_rejects_retained_policy_key_before_comparison(self):
        profile = validated_profile()
        capability = ValidatedCapability.validate(
            complete_capability(), profile=profile, cutoff=UTC_NOW
        )
        hostile_values = (
            _ToggleHashString("deploy"),
            _RaisingEqualityString("deploy"),
            _RaisingStringSubclass("deploy"),
        )
        hostile_policies = tuple(
            (
                hostile,
                MappingProxyType({hostile: capability.action_policies["deploy"]}),
            )
            for hostile in hostile_values
        )
        _ToggleHashString.armed = True
        _ToggleHashString.calls = 0
        _RaisingEqualityString.calls = 0
        _RaisingStringSubclass.calls = 0
        try:
            for hostile, policies in hostile_policies:
                with self.subTest(hostile_type=type(hostile).__name__):
                    forged = copy.copy(capability)
                    object.__setattr__(forged, "action_policies", policies)
                    with self.assertRaises(ValidationError):
                        require_validated_capability(forged)
        finally:
            _ToggleHashString.armed = False
        self.assertEqual(_ToggleHashString.calls, 0)
        self.assertEqual(_RaisingEqualityString.calls, 0)
        self.assertEqual(_RaisingStringSubclass.calls, 0)

    def test_action_require_boundaries_reject_profile_version_before_hooks(self):
        profile = validated_profile()
        action = validated_action(profile)
        for boundary in ("capability", "action"):
            hostile = _ToggleInt(profile.version)
            ref = ProfileRef(profile.profile_id, profile.version)
            object.__setattr__(ref, "version", hostile)
            if boundary == "capability":
                forged = copy.copy(action.capability)
            else:
                forged = copy.copy(action)
            object.__setattr__(forged, "profile_ref", ref)

            _ToggleInt.reset(armed=True)
            try:
                with (
                    self.subTest(boundary=boundary),
                    self.assertRaises(ValidationError),
                ):
                    if boundary == "capability":
                        require_validated_capability(forged)
                    else:
                        require_validated_action(forged)
            finally:
                _ToggleInt.armed = False
            with self.subTest(boundary=boundary, assertion="hook count"):
                self.assertEqual(_ToggleInt.calls, 0)

    def test_capability_integrity_rejects_resealed_cross_unit_envelope(self):
        """Catches structural revalidation comparing only constraint names."""
        profile = DeploymentProfile.validate(
            complete_profile_declaration(
                actions={
                    "deploy": profile_module.ActionPolicy(
                        action_class="deploy",
                        demand_min=Decimal("0"),
                        demand_max=Decimal("100"),
                        constraint_units={"rate": "ops-per-minute"},
                        normative_gates=(),
                    ),
                    "inspect": profile_module.ActionPolicy(
                        action_class="inspect",
                        demand_min=Decimal("0"),
                        demand_max=Decimal("100"),
                        constraint_units={"rate": "ops-per-minute"},
                        normative_gates=(),
                    ),
                }
            )
        )
        capability = ValidatedCapability.validate(
            complete_capability(action_classes=("deploy", "inspect")),
            profile=profile,
            cutoff=UTC_NOW,
        )
        forged = copy.copy(capability)
        object.__setattr__(
            forged,
            "action_policies",
            MappingProxyType(
                {
                    **forged.action_policies,
                    "inspect": profile_module.ActionPolicy(
                        action_class="inspect",
                        demand_min=Decimal("0"),
                        demand_max=Decimal("100"),
                        constraint_units=MappingProxyType(
                            {"rate": "megabytes-per-second"}
                        ),
                        normative_gates=(),
                    ),
                }
            ),
        )
        object.__setattr__(forged, "digest", action_module._capability_digest(forged))

        with self.assertRaises(ValidationError):
            require_validated_capability(forged)

    def test_action_rejects_direct_and_no_argument_construction(self):
        action = validated_action(validated_profile())
        with self.assertRaises(TypeError):
            ValidatedActionDemand()
        with self.assertRaises(TypeError):
            ValidatedActionDemand(**field_values(action))

    def test_action_exact_copy_revalidates_but_invalid_copies_do_not(self):
        profile = validated_profile()
        action = validated_action(profile)
        with self.assertRaises(TypeError):
            replace(action, demand=Decimal("99"))

        exact_copy = copy.copy(action)
        self.assertIs(require_validated_action(exact_copy), exact_copy)
        self.assertIs(require_validated_action(exact_copy, profile=profile), exact_copy)

        forged_values = (
            copy.copy(action),
            copy.copy(action),
            copy.copy(action),
            copy.copy(action),
        )
        object.__setattr__(forged_values[0], "demand", Decimal("999"))
        object.__setattr__(forged_values[1], "digest", "0" * 64)
        object.__setattr__(
            forged_values[2], "requested_constraints", MappingProxyType({})
        )
        object.__setattr__(forged_values[3], "demand_unit", "risk-points")
        for forged in forged_values:
            with self.subTest(forged=forged), self.assertRaises(ValidationError):
                require_validated_action(forged, profile=profile)

        action = validated_action(validated_profile())
        object.__setattr__(action.moment_criticality, "value", Decimal("0.99"))
        with self.assertRaises(ValidationError):
            require_validated_action(action)

    def test_action_structural_authority_rejects_zero_moment_factor_weight(self):
        action = copy.copy(validated_action(validated_profile()))
        factor = copy.copy(action.moment_criticality_factor)
        object.__setattr__(factor, "weight", Decimal("0"))
        object.__setattr__(action, "moment_criticality_factor", factor)
        object.__setattr__(action, "digest", action_module._action_digest(action))

        with self.assertRaises(ValidationError):
            require_validated_action(action)

    def test_action_authority_is_bound_to_its_exact_profile(self):
        profile = validated_profile()
        action = validated_action(profile)
        other_profile = DeploymentProfile.validate(
            replace(
                complete_profile_declaration(),
                profile_id="profile.other",
                version=5,
            )
        )
        self.assertIs(require_validated_action(action, profile=profile), action)
        with self.assertRaises(ValidationError):
            require_validated_action(action, profile=other_profile)

        same_ref_other_facts = (
            DeploymentProfile.validate(complete_profile_declaration(peer_share="20")),
            DeploymentProfile.validate(
                complete_profile_declaration(
                    risk_domain_weights={
                        profile_module.RiskDomain.NODE: "0.25",
                        profile_module.RiskDomain.NEIGHBORHOOD: "0.50",
                        profile_module.RiskDomain.GLOBAL: "0.25",
                    }
                )
            ),
            DeploymentProfile.validate(
                complete_profile_declaration(
                    actions={
                        "deploy": profile_module.ActionPolicy(
                            action_class="deploy",
                            demand_min=Decimal("0"),
                            demand_max=Decimal("90"),
                            constraint_units={"rate": "ops-per-minute"},
                            normative_gates=(),
                        )
                    }
                )
            ),
        )
        for other_facts in same_ref_other_facts:
            with self.subTest(profile_digest=other_facts.digest):
                self.assertEqual(other_facts.ref, profile.ref)
                self.assertEqual(
                    other_facts.action_demand_unit,
                    profile.action_demand_unit,
                )
                self.assertNotEqual(other_facts.digest, profile.digest)
                with self.assertRaises(ValidationError):
                    require_validated_action(action, profile=other_facts)

    def test_private_imports_cannot_bless_invalid_structural_values(self):
        profile = validated_profile()
        forged_profile = copy.copy(profile)
        object.__setattr__(
            forged_profile.risk_factors.evidence_density,
            "weight",
            Decimal("0.99"),
        )
        forged_profile_digest = canonical_sha256(
            profile_module._profile_digest_input(forged_profile)
        )
        object.__setattr__(forged_profile, "digest", forged_profile_digest)
        profile_registry = getattr(profile_module, "_PROFILE_AUTHORITIES", None)
        if profile_registry is not None:
            profile_registry.register(
                forged_profile,
                integrity=forged_profile_digest,
                digest=forged_profile_digest,
            )
        with self.assertRaises(ValidationError):
            require_validated_profile(forged_profile)

        profile = validated_profile()
        action = validated_action(profile)
        forged_action = copy.copy(action)
        object.__setattr__(forged_action, "demand", Decimal("999"))
        action_digest_input = getattr(action_module, "_action_digest_input", None)
        if action_digest_input is None:
            action_digest_input = action_module._action_integrity_input
        forged_action_digest = canonical_sha256(action_digest_input(forged_action))
        object.__setattr__(forged_action, "digest", forged_action_digest)
        action_registry = getattr(action_module, "_ACTION_AUTHORITIES", None)
        if action_registry is not None:
            action_registry.register(
                forged_action,
                integrity=forged_action_digest,
                digest=forged_action_digest,
            )
        with self.assertRaises(ValidationError):
            require_validated_action(forged_action)


if __name__ == "__main__":
    unittest.main()
