"""Reference-form enclosure arithmetic; source authority is explicitly modeled."""
from decimal import Decimal
from importlib.util import find_spec
import unittest

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.enclosure import EnclosureInputs, apply_enclosure_risk
from kinetic_trust_library.v3.core_risk import assess_five_factor_risk
from kinetic_trust_library.v3.evidence_state import assess_required_factor


NAMES=("evidence_density","trust_trend","adversarial_pressure","update_resistance","attestation_coverage")


def local(value="0.22",missing=False):
    factors=tuple(assess_required_factor(factor=name,required_signals=(name,),
        populated_signals={} if missing and index==0 else {name:0},measured_stress=value)
        for index,name in enumerate(NAMES))
    return assess_five_factor_risk(factors,weights=dict.fromkeys(NAMES,"0.2"))


def inputs(**changes):
    return EnclosureInputs(**dict(dict(depth=2,class_step=True,reach="0.5",attenuation="0.5",signed_risk="0.8",gateway_risk="0.3"),**changes))


class EnclosureArithmeticTests(unittest.TestCase):
    def test_reference_heat_gateway_floor_and_class_step(self):
        for changes,expected in (({},"0.31"),({"signed_risk":"0.05","gateway_risk":"0.1"},"0.22"),
                                 ({"signed_risk":"0.2","gateway_risk":"0.5"},"0.36"),({"class_step":False},"0.51")):
            with self.subTest(changes=changes):
                result=apply_enclosure_risk(local(),inputs(**changes))
                self.assertEqual(result.measured_risk,Decimal(expected))
                self.assertEqual(result.local_measured_risk,Decimal("0.22"))
                self.assertEqual(len(result.factors),5)
                with self.assertRaises(ValidationError):apply_enclosure_risk(result,inputs())

    def test_depth_zero_disabled_and_invalid_config(self):
        result=apply_enclosure_risk(local(),inputs(depth=0,class_step=False,reach=0,signed_risk=None,gateway_risk=None))
        self.assertEqual(result.measured_risk,Decimal("0.22"))
        for changes in ({"depth":6},{"depth":True},{"reach":0},{"reach":2},{"class_step":1},{"gateway_risk":-1},
                        {"depth":0},{"attenuation":-1}):
            with self.subTest(changes=changes),self.assertRaises(ValidationError):inputs(**changes)

    def test_missing_required_evidence_never_becomes_calm(self):
        for changes in ({"signed_risk":None},{"gateway_risk":None}):
            result=apply_enclosure_risk(local(),inputs(**changes))
            self.assertIsNone(result.measured_risk)
            self.assertEqual(result.decision_risk,1)
            self.assertTrue(any(entry.input.startswith("enclosure.") for entry in result.undefined_inputs))
        result=apply_enclosure_risk(local(missing=True),inputs())
        self.assertIsNone(result.measured_risk)
        self.assertGreaterEqual(result.decision_risk,result.local_decision_risk)

    def test_monotonicity_exact_arithmetic_and_receding_surcharge(self):
        readings=[apply_enclosure_risk(local(),inputs(signed_risk=str(Decimal(i)/100))).measured_risk for i in range(101)]
        self.assertEqual(readings,sorted(readings))
        self.assertGreaterEqual(min(readings),Decimal("0.22"))
        self.assertEqual(apply_enclosure_risk(local(),inputs(signed_risk="0",gateway_risk="0")).measured_risk,Decimal("0.22"))

    def test_reference_enclosure_risk_reaches_core_capacity(self):
        from kinetic_trust_library.v3.core_projection import project_native_core
        from tests.unit.core.test_v3_native_core_projection import soul
        from kinetic_trust_library.v3.base_trust import calculate_native_base_trust
        standing=calculate_native_base_trust(por_contribution=70,root_score=100,peer_share=0,peer_score=0,
            ceilings=dict(generation=100,ial=95,trajectory=100,adversity=100,deployment=80))
        for demand,relation in ((50,"below"),(60,"above")):
            result=project_native_core(soul("clear"),standing=standing,factors=local().factors,
                weights=dict.fromkeys(NAMES,"0.2"),demand=demand,enclosure=inputs())
            self.assertEqual(result.risk.measured_risk,Decimal("0.31"))
            self.assertEqual(result.capacity.measured_effective_trust,result.standing.base_trust*Decimal("0.69"))
            self.assertEqual(result.capacity.measured_effective_trust,Decimal("55.2"))
            self.assertEqual(result.capacity.relation,relation)


@unittest.skipUnless(all(find_spec(name) for name in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class InstalledEnclosureTests(unittest.TestCase):
    def test_current_source_binding_and_native_core_selection(self):
        import rfc8785,json
        from pathlib import Path
        from dataclasses import replace
        from kinetic_trust_library.v3.enclosure import InstalledEnclosureVerifier,AuthenticatedEnclosureEvidence
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.v3.demand_operation import digest_demand_operation
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/demand-supplier-v1.json").read_text())
        deployment,operation=vectors["deployment_profile"],vectors["operation"]
        profile=dict(id="urn:profile:enclosure-reference",version=1,formula="reference-floor-v1",zone_id="zone:alpha",depth=2,
                     reach="0.5",attenuation_per_class_step="0.5",overlap_policy_id="urn:overlap:no-feedback")
        body=dict(deployment_digest=_digest(deployment,"sha256"),operation_digest=digest_demand_operation(operation,algorithm="sha256"),
                  profile_digest=_digest(profile,"sha256"),checked_at=1030,zone_id="zone:alpha",depth=2,topology_epoch=5,
                  zone_class="blue",enclosure_class="cyan",enclosure_zone="zone:cyan",registry_reach="0.5",
                  signed_enclosure_risk="0.8",gateway_risk="0.3",expires_at=1040)
        calls=[]
        class Source:
            def resolve(self,**kwargs):
                calls.append(kwargs)
                return AuthenticatedEnclosureEvidence(rfc8785.dumps(body),b"modeled-current-topology/signed-enclosure/gateway/overlap")
        verifier=InstalledEnclosureVerifier(rfc8785.dumps(deployment),rfc8785.dumps(profile),Source(),"sha256")
        assessed=verifier.evaluate(actual_operation=operation,evaluated_at=1030,clock_healthy=True)
        self.assertEqual(apply_enclosure_risk(local(),assessed.inputs).measured_risk,Decimal("0.31"))
        self.assertEqual(assessed.authenticated_body_bytes,rfc8785.dumps(body))
        self.assertNotIn("local_risk",calls[0])
        body["zone_class"]="green"
        with self.assertRaises(ValidationError):verifier.evaluate(actual_operation=operation,evaluated_at=1030,clock_healthy=True)
        body["zone_class"]="blue";body["checked_at"]=1029
        with self.assertRaises(ValidationError):verifier.evaluate(actual_operation=operation,evaluated_at=1030,clock_healthy=True)
