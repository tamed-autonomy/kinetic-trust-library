"""Explicit scope of the currently installed ordinary native implementation.

Optional declaration shape is not implementation evidence. This selected SDK
profile disables emergency and Byzantine-mesh capabilities by requiring their
bindings to be absent. Distinct software-substrate and downstream-effect
contracts are not provided by ordinary geometry/readiness/dispatch evidence.
"""
from kinetic_trust_library.errors import ValidationError

ORDINARY_NATIVE_EXECUTION_PROFILE="ordinary-native-v3"


def validate_native_capabilities(deployment_profile,*,execution_profile=ORDINARY_NATIVE_EXECUTION_PROFILE):
    if type(deployment_profile) is not dict:
        raise ValidationError("native capability selection requires an installed deployment object")
    if type(execution_profile) is not str or execution_profile!=ORDINARY_NATIVE_EXECUTION_PROFILE:
        raise ValidationError("unsupported native execution profile; no ordinary-profile fallback")
    for field,capability in (("emergency_policy","emergency"),("oracle_consensus","Byzantine Oracle consensus")):
        if field in deployment_profile:
            raise ValidationError("unsupported native "+capability+" capability; selected disabled-only profile requires omission of "+field)
    return ORDINARY_NATIVE_EXECUTION_PROFILE
