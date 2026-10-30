"""Person claims preserve signed-act standing and do not become human capacity."""
import json,unittest
from pathlib import Path
from dataclasses import replace
from importlib.util import find_spec
from kinetic_trust_library.errors import ValidationError


def fixture(declared_boundary=False):
    import rfc8785
    from tests.unit.core.test_v3_installed_person_standing import fixture as standing_fixture
    from kinetic_trust_library.v3.installed_soul import InstalledSoulVerifier,AuthenticatedSoulResponse
    from kinetic_trust_library.v3.installed_environment import InstalledEnvironmentVerifier,AuthenticatedEnvironmentEvidence
    dp=json.loads((Path(__file__).parents[3]/"spec/proposals/demand-supplier-v1.json").read_text())["deployment_profile"]
    dp["peer_share"]=0;dp["external_root"]["hop_bound"]=4
    if declared_boundary:dp["boundary"]=dict(resources=["resource:a"],entitled_subjects=["person"],affected_outside=[],jurisdictions=["test"],authority_limits=["approved scope"])
    f=standing_fixture(dp);raw=f["v"].deployment_profile_bytes
    class Soul:
        state="clear"
        def query(self,*,required_frameworks,**kwargs):return tuple(AuthenticatedSoulResponse(framework,self.state,b"modeled authenticated Soul response",
            rfc8785.dumps(dict(soul=1,constraint_type="ocap",authority="urn:authority:person")) if self.state=="veto" else None) for framework in required_frameworks)
    class Environment:
        absent=False;stress=.25
        def verify(self,*args,**kwargs):return AuthenticatedEnvironmentEvidence(rfc8785.dumps({"factors":{
            name:dict(signals={} if self.absent else dict.fromkeys(config["signals"],0),measured_stress=self.stress)
            for name,config in dp["risk_factors"].items()}}))
    sa=Soul();ea=Environment();sv=InstalledSoulVerifier(raw,sa,"sha256");ev=InstalledEnvironmentVerifier(raw,ea,"sha256")
    standing=f["v"].evaluate(roots=f["roots"],actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)
    metadata=dict(iss="https://oracle.example.com",aud=f["op"]["audience"],jti="person:proof:a",exp=f["now"]+2,zone="zone:blue")
    def source():
        from kinetic_trust_library.v3.person_claims import NativePersonClaimsSource
        soul=sv.evaluate(actual_operation=f["op"],evaluated_at=f["now"])
        environment=None if sa.state!="clear" else ev.evaluate(b"person environment",actual_operation=f["op"],evaluated_at=f["now"])
        return NativePersonClaimsSource(raw,standing,soul,environment,rfc8785.dumps(metadata),"sha256",boundary=f.get("boundary"))
    f.update(source=source,soul=sa,environment=ea,metadata=metadata,standing=standing)
    return f


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")),"install v3-proofs")
class PersonClaimsTests(unittest.TestCase):
    def test_declared_person_boundary_is_required_and_bounds_expiry(self):
        import rfc8785
        from kinetic_trust_library.v3.boundary import InstalledBoundaryVerifier,AuthenticatedBoundaryContext
        from kinetic_trust_library.v3.demand_supplier import _digest
        from kinetic_trust_library.v3.demand_operation import digest_demand_operation
        f=fixture(declared_boundary=True)
        with self.assertRaises(ValidationError):f["source"]()
        state=dict(deployment_digest=_digest(f["dp"],"sha256"),operation_digest=digest_demand_operation(f["op"],algorithm="sha256"),
            enclosing_deployment_digest=None,checked_at=f["now"],expires_at=f["now"]+1,zone_id="zone:blue",enclosure_zone=None,topology_epoch=1,
            subject=f["op"]["actor"],subject_class="person",resource=f["op"]["resource"],affected_outside_classes=[],authority_within_limits=True,
            resolved_resources={f["op"]["resource"]:[f["op"]["resource"]]},enclosing_resolved_resources=None)
        class Source:
            def resolve(self,**kwargs):return AuthenticatedBoundaryContext(rfc8785.dumps(state),b"modeled actual person operation boundary")
        f["boundary"]=InstalledBoundaryVerifier(f["v"].deployment_profile_bytes,Source(),"sha256").evaluate(
            actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)
        with self.assertRaises(ValidationError):f["source"]()
        f["metadata"]["exp"]=f["now"]+1
        self.assertEqual(json.loads(f["source"]().produce(evaluated_at=f["now"]))["exp"],f["now"]+1)

    def test_real_person_proof_issuance_and_installed_verification(self):
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        from kinetic_trust_library.v3.native_issuance import InstalledProofIssuer,_segment
        from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier
        from kinetic_trust_library.v3.native_proof_profile import RootProofBinding,native_schema_bundle
        f=fixture();private=Ed25519PrivateKey.from_private_bytes(bytes(range(32)));m=f["metadata"];now=f["now"]
        key=dict(kid="person-proof:key",alg="EdDSA",kty="OKP",crv="Ed25519",issuer=m["iss"],zone=m["zone"],
            role="trust-proof-oracle",revoked=False,not_before=now-10,not_after=now+10,
            x=_segment(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)))
        verifier=InstalledProofVerifier(native_schema_bundle(),rfc8785.dumps({key["kid"]:key}),rfc8785.dumps(dict(
            issuer=m["iss"],audience=m["aud"],zone=m["zone"],subject=f["op"]["actor"],subject_kind="person",required_ceilings={},ring_depth=0)),
            ("EdDSA",),RootProofBinding(f["roots"],m["zone"]))
        class Signer:
            def sign(self,raw,**kwargs):return private.sign(raw)
        for state,absent,expected in (("clear",False,"TP_CLEAR"),("clear",True,"TP_UNDETERMINED"),("veto",False,"TP_VETO"),("unanswered",False,"TP_UNDETERMINED")):
            f["soul"].state=state;f["environment"].absent=absent
            with self.subTest(state=state,absent=absent):
                issued=InstalledProofIssuer(f["source"](),Signer(),verifier,"EdDSA",key["kid"]).issue(now=now,clock_healthy=True)
                self.assertEqual(issued.verification.reason,expected)
                self.assertEqual(json.loads(issued.payload_bytes)["ktp"]["subject_kind"],"person")

    def test_derived_person_claims_have_no_software_fields(self):
        f=fixture();body=json.loads(f["source"]().produce(evaluated_at=f["now"]));k=body["ktp"]
        self.assertEqual(body["sub"],f["op"]["actor"]);self.assertEqual(k["subject_kind"],"person")
        self.assertEqual((k["e_base"],k["e_trust"],k["r"],k["peer_share"]),(66,49.5,.25,0))
        self.assertFalse(set(k)&{"generation","lineage","sponsor","advancement_floor","capacity"})
        self.assertEqual(k["root_instrument"]["root_person"],body["sub"])

    def test_missing_person_root_removes_institutional_credit_without_software_defaults(self):
        import rfc8785
        from kinetic_trust_library.v3.assessed_root_selection import select_assessed_roots
        f=fixture();source=f["source"]()
        roots=select_assessed_roots((),context_bytes=f["roots"].context_bytes,evaluated_at=f["now"],algorithm="sha256")
        f["state"].update(root_digest=None,terminator=None)
        standing=f["v"].evaluate(roots=roots,actual_operation=f["op"],evaluated_at=f["now"],clock_healthy=True)
        k=json.loads(replace(source,standing=standing).produce(evaluated_at=f["now"]))["ktp"]
        self.assertEqual((k["e_base"],k["e_trust"]),(42,31.5))
        self.assertEqual(k["root_instrument"],dict(kind="none",status="none",reason="missing"))
        self.assertFalse(set(k)&{"generation","lineage","sponsor","advancement_floor"})

    def test_unknown_measurement_and_soul_veto_preserve_early_stop(self):
        f=fixture();f["environment"].absent=True
        k=json.loads(f["source"]().produce(evaluated_at=f["now"]))["ktp"]
        self.assertEqual(k["gate_state"],"undetermined");self.assertIsNone(k["r"]);self.assertIsNone(k["e_trust"])
        f["soul"].state="veto"
        k=json.loads(f["source"]().produce(evaluated_at=f["now"]))["ktp"]
        self.assertEqual(k["gate_state"],"veto");self.assertEqual(k["soul"]["soul"],1);self.assertIsNone(k["e_trust"])

    def test_unrelated_risk_and_expired_or_software_metadata_are_rejected(self):
        f=fixture();f["environment"].stress=.5
        with self.assertRaises(ValidationError):f["source"]().produce(evaluated_at=f["now"])
        for patch in (dict(exp=f["now"]+4),dict(advancement_floor=0),dict(zone="zone:other")):
            f=fixture();f["metadata"].update(patch)
            with self.subTest(patch=patch),self.assertRaises(ValidationError):f["source"]().produce(evaluated_at=f["now"])
