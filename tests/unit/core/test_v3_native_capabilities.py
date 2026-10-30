from importlib.util import find_spec
import unittest
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.native_capabilities import validate_native_capabilities


class NativeCapabilitiesTests(unittest.TestCase):
    def test_ordinary_disabled_only_profile_is_explicit(self):
        self.assertEqual(validate_native_capabilities({}),"ordinary-native-v3")

    def test_emergency_and_mesh_bindings_cannot_silently_pass_ordinary_path(self):
        for key in ("emergency_policy","oracle_consensus"):
            for value in (None,False,{},dict(policy_id="policy:a",version=1,digest="sha256:"+"a"*64)):
                with self.subTest(key=key,value=value),self.assertRaisesRegex(ValidationError,"unsupported"):
                    validate_native_capabilities({key:value})

    def test_distinct_execution_profiles_do_not_fall_back_to_generic_geometry(self):
        for profile in ("software-substrate-decision","consequential-action-evidence","emergency","oracle-consensus","unknown",None):
            with self.subTest(profile=profile),self.assertRaisesRegex(ValidationError,"unsupported"):
                validate_native_capabilities({},execution_profile=profile)


@unittest.skipUnless(find_spec("rfc8785"),"install v3-proofs")
class CoreCapabilityContextTests(unittest.TestCase):
    def test_native_core_context_cannot_select_enabled_unsupported_profiles(self):
        import rfc8785
        from kinetic_trust_library.v3.core_projection import NativeCoreContext
        op=dict(subject="subject:a",actor="agent:a",audience="service:a",operation="action:write",resource="resource:a",
            parameters={},request_id="request:1",replay_domain="domain:a")
        for dp,profile in ((dict(emergency_policy={}),"ordinary-native-v3"),
                           (dict(oracle_consensus={}),"ordinary-native-v3"),({},"software-substrate-decision")):
            with self.subTest(dp=dp,profile=profile),self.assertRaisesRegex(ValidationError,"unsupported"):
                NativeCoreContext(rfc8785.dumps(dp),rfc8785.dumps(op),1000,"sha256",execution_profile=profile)
