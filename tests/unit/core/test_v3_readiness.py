"""Fresh signed readiness, independent current state and exact scope binding."""
import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.v3.installed_readiness import InstalledReadinessVerifier, AuthenticatedReadinessContext


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class ReadinessTests(unittest.TestCase):
    def test_reference_signature_strength_and_low_s_boundaries(self):
        import rfc8785
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec,ed25519,ed448,utils
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        from kinetic_trust_library.v3._readiness_crypto import b64,verify_jws,InvalidRecord,ORDERS
        from kinetic_trust_library.v3.installed_readiness import _binding
        purpose="ktp-readiness-attestation-v1"
        payload={"fixture":"readiness-strength-test"}
        for algorithm,curve,level in (("ES256","P-256",2),("ES384","P-384",3),("EdDSA","Ed25519",2),("EdDSA","Ed448",3)):
            with self.subTest(algorithm=algorithm,curve=curve):
                if algorithm.startswith("ES"):
                    private=ec.derive_private_key(3,ec.SECP256R1() if curve=="P-256" else ec.SECP384R1())
                    size=32 if curve=="P-256" else 48
                    numbers=private.public_key().public_numbers()
                    key=dict(kty="EC",x=b64(numbers.x.to_bytes(size,"big")),y=b64(numbers.y.to_bytes(size,"big")))
                else:
                    private=ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32))) if curve=="Ed25519" else ed448.Ed448PrivateKey.from_private_bytes(bytes(range(57)))
                    key=dict(kty="OKP",x=b64(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)))
                key.update(kid="strength-key",subject="assessor-1",zone_id="zone:alpha",purpose=purpose,alg=algorithm,
                    crv=curve,revoked=False,not_before=0,not_after=2000)
                message=(b64(rfc8785.dumps(dict(alg=algorithm,kid=key["kid"],typ=purpose)))+"."+b64(rfc8785.dumps(payload))).encode()
                if algorithm.startswith("ES"):
                    r,s=utils.decode_dss_signature(private.sign(message,ec.ECDSA(hashes.SHA256() if curve=="P-256" else hashes.SHA384())))
                    s=min(s,ORDERS[algorithm]-s)
                    signature=r.to_bytes(size,"big")+s.to_bytes(size,"big")
                else: signature=private.sign(message)
                compact=message.decode()+"."+b64(signature)
                binding,_=_binding({key["kid"]:key},compact)
                verify_jws(compact,payload,binding,level=level)
                if level==2:
                    with self.assertRaises(InvalidRecord):verify_jws(compact,payload,binding,level=3)
                if algorithm.startswith("ES"):
                    high_s=message.decode()+"."+b64(r.to_bytes(size,"big")+(ORDERS[algorithm]-s).to_bytes(size,"big"))
                    with self.assertRaises(InvalidRecord):verify_jws(high_s,payload,binding,level=level)

    def test_signed_assessment_current_state_and_restrictive_failures(self):
        import base64
        import hashlib
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        def digest(value): return "sha256:"+hashlib.sha256(rfc8785.dumps(value)).hexdigest()
        d=lambda label:digest({"fixture":label})
        operation=json.loads((Path(__file__).parents[3]/"spec/proposals/demand-supplier-v1.json").read_text())["operation"]
        operation={**operation,"actor":"agent:guarantor:7gen:optimized:a1b2c3d4"}
        scope=dict(zone_id="zone:alpha",resource_id=operation["resource"],environment_digest=d("environment"),parameters_digest=digest(operation["parameters"]))
        subject=dict(agent_id=operation["actor"],lineage_id="fixture-lineage",**{n+"_digest":d(n) for n in
            ("software","model","configuration","toolchain","permissions")})
        profile=dict(profile_version="ktp-readiness-profile-v1",profile_id="fixture-readiness",version=2,conformance_level=2,
            assessor_registry_digest=d("registry"),operations=[dict(operation_id=operation["operation"],scope=scope,
                assessment_spec_digest=d("assessment-spec"),max_age_seconds=300,required_checks=["rollback","permissions"],assessor_ids=["assessor-1"])])
        deployment=json.loads((Path(__file__).parents[3]/"spec/proposals/demand-supplier-v1.json").read_text())["deployment_profile"]
        deployment["standing_policy"]=dict(mode="history-with-scoped-readiness-v1",profile_id=profile["profile_id"],version=2,digest=digest(profile))
        from tests.unit.core._v3_human_fixture import human_fixture
        human_fixture_data=human_fixture(operation)
        deployment["human_policy"]=dict(mode="operation-eligibility-v1",profile_id=human_fixture_data["profile"]["profile_id"],
            version=2,digest=digest(human_fixture_data["profile"]))
        deployment["boundary"]=dict(resources=[operation["resource"]],entitled_subjects=["guarantor"],
            affected_outside=[dict(**{"class":"customer"},review_route="urn:review:customer")],jurisdictions=["test"],authority_limits=["test approved scope"])
        request=dict(request_id=operation["request_id"],subject=subject,operation_id=operation["operation"],scope=scope,
            deployment_profile_digest=digest(deployment),readiness_profile_digest=digest(profile))
        challenge=dict(challenge_id="challenge-1",nonce=base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode(),issued_at=900)
        attestation=dict(attestation_version="ktp-readiness-attestation-v1",attestation_id="attestation-1",subject=subject,
            deployment_profile_digest=digest(deployment),readiness_profile_digest=digest(profile),readiness_epoch=3,
            operation_id=operation["operation"],scope=scope,challenge=challenge,assessment_spec_digest=d("assessment-spec"),
            checks=[dict(check_id="rollback",observed_at=920,evidence_digest=d("rollback")),dict(check_id="permissions",observed_at=930,evidence_digest=d("permissions"))],
            assessed_at=940,issued_at=945,expires_at=1220,assessor_id="assessor-1",outcome="passed")
        private=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        key=dict(kid="assessor-key",subject="assessor-1",zone_id="zone:alpha",purpose="ktp-readiness-attestation-v1",alg="EdDSA",
            kty="OKP",crv="Ed25519",x=base64.urlsafe_b64encode(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).rstrip(b"=").decode(),
            revoked=False,not_before=800,not_after=2000)
        def segment(raw): return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        def seal():
            payload=rfc8785.dumps({k:v for k,v in attestation.items() if k!="signature"})
            message=(segment(rfc8785.dumps(dict(alg="EdDSA",kid=key["kid"],typ=key["purpose"])))+"."+segment(payload)).encode()
            attestation["signature"]=message.decode()+"."+segment(private.sign(message))
        seal()
        keys={key["kid"]:key}
        state=dict(profile_id=profile["profile_id"],profile_digest=digest(profile),deployment_profile_digest=digest(deployment),
            assessor_registry_digest=d("registry"),minimum_profile_version=2,readiness_epoch=3,active_attestation_digest=digest(attestation),
            challenge=challenge,checked_at=1000,status="active")
        class Adapter:
            calls=0
            def resolve(self,**kwargs):
                self.calls+=1
                return AuthenticatedReadinessContext(rfc8785.dumps(request),rfc8785.dumps(state),rfc8785.dumps(keys))
        adapter=Adapter()
        verifier=InstalledReadinessVerifier(rfc8785.dumps(deployment),rfc8785.dumps(profile),adapter,2,"zone:alpha")
        def evaluate(raw=None,**kwargs):
            return verifier.evaluate(rfc8785.dumps(attestation) if raw is None else raw,actual_operation=operation,
                evaluated_at=kwargs.get("now",1000),clock_healthy=kwargs.get("clock",True))
        result=evaluate()
        self.assertEqual(result.reason,"READINESS_VALID")
        self.assertEqual(result.attestation_digest,digest(attestation))
        self.assertEqual(result.actual_request_bytes,rfc8785.dumps(request))
        self.assertEqual(result.expires_at,1220)
        from kinetic_trust_library.v3.readiness_decision import InstalledReadinessDecisionVerifier
        from kinetic_trust_library.v3.complete_proof_verifier import InstalledProofVerifier
        from kinetic_trust_library.v3.native_proof_profile import native_schema_bundle
        from kinetic_trust_library.v3.request_binding import digest_canonical_request,digest_complete_proof
        from kinetic_trust_library.v3.request_association import InstalledRequestAssociationVerifier
        root=Path(__file__).parents[3]
        proof_vectors=json.loads((root/"spec/proposals/trust-proof-v3.json").read_text())
        compact=next(c["jws"] for c in proof_vectors["cases"] if c["id"]=="clear")
        ordinary=json.loads(base64.urlsafe_b64decode(compact.split(".")[1]+"=="))
        ordinary.update(sub=operation["actor"],aud=operation["audience"],iat=998,exp=1008,jti="readiness-proof")
        ordinary["ktp"].update(subject_kind="software_agent",root_instrument=dict(kind="none",status="none",reason="missing"))
        ordinary["ktp"]["applicable_ceilings"].append(dict(ceiling="external_root_missing",value=70))
        ordinary["ktp"]["applicable_ceilings"].append(dict(ceiling="repair_reentry",value=75))
        ordinary_key={**key,"kid":"ordinary-key","issuer":ordinary["iss"],"zone":"zone:alpha","role":"trust-proof-oracle"}
        signing=(segment(rfc8785.dumps(dict(alg="EdDSA",kid=ordinary_key["kid"],typ="ktp-trust-proof+jwt")))+"."+segment(rfc8785.dumps(ordinary))).encode()
        ordinary_compact=signing.decode()+"."+segment(private.sign(signing))
        from kinetic_trust_library.v3.live_root import InstalledLiveRootVerifier,AuthenticatedRootInventory
        from kinetic_trust_library.v3.installed_root import InstalledRootVerifier
        root_context=rfc8785.dumps(dict(subject=operation["actor"],subject_profile="software"))
        class RootInventory:
            def resolve(self,*,context_bytes,evaluated_at):
                return AuthenticatedRootInventory((),b"fixture-current-complete-empty-root-inventory",context_bytes,evaluated_at)
        class RootInstrument:
            def verify(self,*args,**kwargs):raise AssertionError("empty inventory has no instrument")
        live_root=InstalledLiveRootVerifier(InstalledRootVerifier(RootInstrument(),"sha256"),RootInventory(),root_context,"zone:alpha")
        pv=InstalledProofVerifier(native_schema_bundle(),rfc8785.dumps({ordinary_key["kid"]:ordinary_key}),rfc8785.dumps(dict(
            issuer=ordinary["iss"],audience=operation["audience"],zone="zone:alpha",subject=operation["actor"],subject_kind="software_agent",required_ceilings={},ring_depth=0)),
            ("EdDSA",),live_root)
        actual={**operation,"version":"request-binding-v1","demand":{"value":35,"unit":"ktp-action-risk-points"},
            "classification_profile":{"id":"urn:ktp:classifier:readiness-test","digest":d("classifier")}}
        actual_bytes=rfc8785.dumps(actual)
        association_bytes=rfc8785.dumps(dict(version="request-proof-association-v1",request_digest=digest_canonical_request(actual,algorithm="sha256"),
            proof_digest=digest_complete_proof(ordinary_compact,algorithm="sha256"),proof_jti=ordinary["jti"]))
        class Invocation:
            def reconstruct(self,*args,**kwargs):return actual_bytes
        class Replay:
            def reserve(self,**kwargs):return "RB_BOUND"
        association=InstalledRequestAssociationVerifier(Invocation(),pv,Replay(),"sha256").verify(actual_bytes,association_bytes,ordinary_compact,
            invocation_evidence=b"fixture-actual-invocation",now=1000,clock_healthy=True)
        self.assertEqual(association.reason,"RB_BOUND")
        self.assertEqual(association.proof_verification.root_verification.checked_at,1000)
        issuer_key={**key,"kid":"decision-key","subject":"oracle-1","purpose":"ktp-readiness-decision-v1"}
        keys[issuer_key["kid"]]=issuer_key
        decision=dict(decision_version="ktp-readiness-decision-v1",request_digest=digest(request),
            proof_digest="sha256:"+hashlib.sha256(ordinary_compact.encode("ascii")).hexdigest(),attestation_digest=digest(attestation),
            readiness_profile_digest=digest(profile),deployment_profile_digest=digest(deployment),readiness_epoch=3,evaluated_at=1000,expires_at=1008,issuer_id="oracle-1")
        def seal_decision():
            message=(segment(rfc8785.dumps(dict(alg="EdDSA",kid=issuer_key["kid"],typ=issuer_key["purpose"])))+"."+
                segment(rfc8785.dumps({k:v for k,v in decision.items() if k!="signature"}))).encode()
            decision["signature"]=message.decode()+"."+segment(private.sign(message))
        seal_decision()
        dv=InstalledReadinessDecisionVerifier(verifier,pv)
        def level3(value):
            if type(value) is dict:return {k:level3(v) for k,v in value.items()}
            if type(value) is list:return [level3(v) for v in value]
            if type(value) is str and value.startswith("sha256:"):return "sha384:"+hashlib.sha384(value.encode()).hexdigest()
            return value
        stronger=level3(profile);stronger["conformance_level"]=3
        stronger_deployment=json.loads(rfc8785.dumps(deployment))
        stronger_deployment["standing_policy"]["digest"]="sha384:"+hashlib.sha384(rfc8785.dumps(stronger)).hexdigest()
        stronger_readiness=InstalledReadinessVerifier(rfc8785.dumps(stronger_deployment),rfc8785.dumps(stronger),adapter,3,"zone:alpha")
        from kinetic_trust_library.errors import ValidationError
        with self.assertRaisesRegex(ValidationError,"Level 3"):
            InstalledReadinessDecisionVerifier(stronger_readiness,pv)
        def check_decision(now=1000):return dv.verify(rfc8785.dumps(decision),rfc8785.dumps(attestation),association,evaluated_at=now,clock_healthy=True)
        self.assertEqual(check_decision().reason,"READINESS_DECISION_VALID")
        state["checked_at"]=1001
        current=check_decision(1001)
        self.assertEqual(current.reason,"READINESS_DECISION_VALID")
        self.assertEqual(current.proof_verification.root_verification.checked_at,1001)
        state["checked_at"]=1000
        from kinetic_trust_library.v3 import InstalledNativeEvaluationVerifier
        from kinetic_trust_library.v3.geometry_verifier import InstalledGeometryVerifier,AuthenticatedGeometryReproduction
        geometry=json.loads((root/"spec/proposals/decision-geometry-v1.json").read_text())["bodies"]["complete"]
        geometry.update(evaluated_at=1000,ktp_release="unreleased-v3.0.0",subject=operation["subject"],actor=operation["actor"],
            audience=operation["audience"],association=json.loads(association_bytes))
        class Reproduction:
            def reproduce(self,*,evaluated_at):
                return AuthenticatedGeometryReproduction(rfc8785.dumps(geometry),actual_bytes,ordinary_compact,True)
        gv=InstalledGeometryVerifier(Reproduction(),pv,"sha256")
        av=InstalledRequestAssociationVerifier(Invocation(),pv,Replay(),"sha256")
        from kinetic_trust_library.v3.boundary import InstalledBoundaryVerifier,AuthenticatedBoundaryContext
        from kinetic_trust_library.v3.demand_operation import digest_demand_operation
        boundary_state=dict(deployment_digest=digest(deployment),operation_digest=digest_demand_operation(operation,algorithm="sha256"),
            enclosing_deployment_digest=None,checked_at=1000,expires_at=1008,zone_id="zone:alpha",enclosure_zone=None,topology_epoch=5,
            subject=operation["actor"],subject_class="guarantor",resource=operation["resource"],affected_outside_classes=["customer"],
            authority_within_limits=True,resolved_resources={operation["resource"]:[operation["resource"]]},enclosing_resolved_resources=None)
        class BoundarySource:
            def resolve(self,**kwargs):return AuthenticatedBoundaryContext(rfc8785.dumps(boundary_state),b"modeled-current-boundary")
        bv=InstalledBoundaryVerifier(rfc8785.dumps(deployment),BoundarySource(),"sha256")
        native=InstalledNativeEvaluationVerifier(av,dv,gv,1000,1006,boundary_verifier=bv)
        def whole(body=None,token=None,tokens=()):
            return native.verify(actual_bytes,association_bytes,ordinary_compact,
                decision_bytes=rfc8785.dumps(decision),attestation_bytes=rfc8785.dumps(attestation),
                invocation_evidence=b"fixture-actual-invocation",now=1000,clock_healthy=True,
                geometry_body_bytes=rfc8785.dumps(geometry if body is None else body),adjudication_token=token,adjudication_tokens=tokens)
        combined=whole()
        self.assertEqual(combined.reason,"NATIVE_PREREQUISITES_VALID")
        self.assertEqual(combined.supervision,"stable")
        self.assertEqual(combined.expires_at,1006)
        boundary_state["subject_class"]="outsider"
        denied_boundary=whole()
        self.assertEqual(denied_boundary.reason,"BOUNDARY_SUBJECT")
        self.assertIsNone(denied_boundary.canonical_geometry_bytes)
        self.assertIsNone(denied_boundary.readiness)
        self.assertEqual(denied_boundary.boundary.review_routes,(("customer","urn:review:customer"),))
        boundary_state["subject_class"]="guarantor"
        boundary_state["expires_at"]=1002
        self.assertEqual(whole().expires_at,1002)
        boundary_state["expires_at"]=1008
        self.assertEqual(combined.readiness.proof_verification.root_verification.checked_at,1000)
        from dataclasses import replace
        nested_pv=replace(pv,expected_context_bytes=rfc8785.dumps({**json.loads(pv.expected_context_bytes),"ring_depth":1}))
        with self.assertRaisesRegex(ValidationError,"enclosing"):
            replace(native,association_verifier=replace(av,proof_verifier=nested_pv),
                readiness_verifier=replace(dv,proof_verifier=nested_pv),local_geometry_verifier=replace(gv,proof_verifier=nested_pv))
        from tests.unit.core.test_v3_adjudication import fixture as adjudication_fixture
        adjudication=adjudication_fixture(operation,deployment,1000)
        no_norm=native
        native=replace(native,adjudication_verifier=adjudication["verifier"])
        absent=whole()
        self.assertEqual(absent.reason,"ADJ_GATE_UNSATISFIED")
        self.assertEqual(absent.supervision,combined.supervision)
        self.assertEqual(absent.tightened_constraints_bytes,combined.tightened_constraints_bytes)
        favorable=whole(token=adjudication["sign"]())
        self.assertEqual(favorable.reason,"NATIVE_PREREQUISITES_VALID")
        self.assertEqual(favorable.canonical_geometry_bytes,combined.canonical_geometry_bytes)
        self.assertTrue(favorable.adjudication.gate_satisfied)
        self.assertEqual(favorable.expires_at,1006)
        adjudication["payload"]["favorable"]=False
        self.assertEqual(whole(token=adjudication["sign"]()).reason,"ADJ_GATE_UNSATISFIED")
        adjudication["payload"]["favorable"]=True
        adjudication["state"]["evidence_digest"]="sha256:"+"0"*64
        self.assertEqual(whole(token=adjudication["sign"]()).reason,"ADJ_GATE_UNSATISFIED")
        optional_profile=dict(adjudication["profile"],gate_required=False)
        optional_verifier=replace(adjudication["verifier"],profile_bytes=rfc8785.dumps(optional_profile))
        native=replace(no_norm,adjudication_verifier=optional_verifier)
        adjudication["source"].unavailable=True
        unchanged=whole(token=adjudication["sign"]())
        self.assertEqual(unchanged.reason,"NATIVE_PREREQUISITES_VALID")
        self.assertEqual(unchanged.supervision,combined.supervision)
        self.assertEqual(unchanged.canonical_geometry_bytes,combined.canonical_geometry_bytes)
        native=no_norm
        first=adjudication_fixture(operation,deployment,1000,gate_id="first")
        second=adjudication_fixture(operation,deployment,1000,gate_id="second")
        native=replace(no_norm,adjudication_verifiers=(first["verifier"],second["verifier"]))
        self.assertEqual(whole(tokens=(("first",first["sign"]()),)).reason,"ADJ_GATE_UNSATISFIED")
        both=(("first",first["sign"]()),("second",second["sign"]()))
        multiple=whole(tokens=both)
        self.assertEqual(multiple.reason,"NATIVE_PREREQUISITES_VALID")
        self.assertEqual(len(multiple.adjudications),2)
        self.assertEqual(multiple.canonical_geometry_bytes,combined.canonical_geometry_bytes)
        self.assertEqual(multiple.tightened_constraints_bytes,combined.tightened_constraints_bytes)
        self.assertEqual(multiple.supervision,combined.supervision)
        self.assertEqual(whole(tokens=(("first",second["sign"]()),("second",first["sign"]()))).reason,"ADJ_GATE_UNSATISFIED")
        second["payload"]["favorable"]=False
        self.assertEqual(whole(tokens=(("first",first["sign"]()),("second",second["sign"]()))).reason,"ADJ_GATE_UNSATISFIED")
        second["payload"]["favorable"]=True
        second["payload"]["exp"]=1003
        self.assertEqual(whole(tokens=(("first",first["sign"]()),("second",second["sign"]()))).expires_at,1003)
        native=replace(native,adjudication_verifiers=tuple(reversed(native.adjudication_verifiers)))
        self.assertEqual(whole(tokens=(("first",first["sign"]()),("second",second["sign"]()))).expires_at,1003)
        with self.assertRaises(ValidationError):whole(tokens=(("first",first["sign"]()),("first",first["sign"]())))
        with self.assertRaises(ValidationError):whole(tokens=(("unknown",first["sign"]()),))
        with self.assertRaises(ValidationError):replace(native,adjudication_verifiers=(first["verifier"],first["verifier"]))
        with self.assertRaises(ValidationError):replace(native,adjudication_verifier=first["verifier"])
        native=no_norm
        from tests.unit.core.test_v3_installed_repair import fixture as repair_fixture
        repair_verifier,repair_state,_,_,_=repair_fixture(operation,deployment)
        native=replace(no_norm,repair_verifier=repair_verifier)
        repair_state["breaches"][0]["standing_at_breach"]="40"
        repair_state["breaches"][0]["record_facts"]["standing_at_breach"]="40"
        # The accepted ordinary proof exceeds this repaired standing ceiling of 30.
        self.assertEqual(whole().reason,"REPAIR_STANDING")
        repair_state["breaches"][0]["standing_at_breach"]="100"
        repair_state["breaches"][0]["record_facts"]["standing_at_breach"]="100"
        def set_repair_ceiling(value):
            nonlocal ordinary_compact,association_bytes
            ordinary["ktp"]["applicable_ceilings"]=[item for item in ordinary["ktp"]["applicable_ceilings"] if item["ceiling"]!="repair_reentry"]
            if value is not None:ordinary["ktp"]["applicable_ceilings"].append(dict(ceiling="repair_reentry",value=value))
            message=(segment(rfc8785.dumps(dict(alg="EdDSA",kid=ordinary_key["kid"],typ="ktp-trust-proof+jwt")))+"."+segment(rfc8785.dumps(ordinary))).encode()
            ordinary_compact=message.decode()+"."+segment(private.sign(message))
            association_body=json.loads(association_bytes);association_body["proof_digest"]=digest_complete_proof(ordinary_compact,algorithm="sha256")
            association_bytes=rfc8785.dumps(association_body);geometry["association"]=association_body
            decision["proof_digest"]="sha256:"+hashlib.sha256(ordinary_compact.encode("ascii")).hexdigest()
            seal_decision()
        set_repair_ceiling(None)
        self.assertEqual(whole().reason,"REPAIR_CEILING")
        set_repair_ceiling(76)
        self.assertEqual(whole().reason,"REPAIR_CEILING")
        set_repair_ceiling(75)
        # Current assessment at 940 predates the reconciliation anchor at 950.
        self.assertEqual(whole().reason,"REPAIR_READINESS_STALE")
        repair_state["breaches"][0]["breached_at"]=850
        repair_state["breaches"][0]["record_facts"].update(breached_at=850,anchored_at=900)
        repaired=whole()
        self.assertEqual(repaired.reason,"NATIVE_PREREQUISITES_VALID")
        self.assertTrue(repaired.repair.reentry_eligible)
        self.assertEqual(repaired.canonical_geometry_bytes,combined.canonical_geometry_bytes)
        repair_state["expires_at"]=1002
        self.assertEqual(whole().expires_at,1002)
        repair_state["breaches"][0]["record_facts"]=None
        self.assertEqual(whole().reason,"REPAIR_UNRECONCILED")
        native=no_norm
        from tests.unit.core.test_v3_installed_ambient import fixture as ambient_fixture
        ambient_verifier,ambient_state,_,ambient_profile,_=ambient_fixture(operation,deployment,1000,"zone:alpha",None)
        ambient_state["current"].update(prior_stock=2,arrivals=[])
        ambient_state["current"]["prior_stock_by_class"]["act-outside-decision"]=2
        native=replace(no_norm,ambient_verifier=ambient_verifier)
        ambient_state["topology_epoch"]=4
        self.assertEqual(whole().reason,"AMBIENT_TOPOLOGY")
        ambient_state["topology_epoch"]=5
        self.assertEqual(whole().reason,"AMBIENT_BINDING")
        current_ambient=ambient_verifier.evaluate(actual_operation=operation,evaluated_at=1000,clock_healthy=True)
        item=dict(name="ambient_repair",layer="term",state="modeled",source="urn:test:ambient-source",
            value=current_ambient.geometry_value(),evidence_digests=sorted([current_ambient.profile_digest,current_ambient.frame_digest]))
        geometry["inputs"].append(item)
        with_ambient=whole()
        self.assertEqual(with_ambient.reason,"NATIVE_PREREQUISITES_VALID")
        self.assertEqual(with_ambient.ambient.pressure_floor,0)
        from tests.unit.core.test_v3_rule_repair import fixture as rule_fixture
        from kinetic_trust_library.v3.demand_supplier import _digest
        ambient_profile["recovery"]=dict(margin="0.1",stock_target=1,amendment_rate_limit="0.1",nonattendance_rate_limit="0.1",
            crisis_invariants_preserved=True,contingency=None,rule_repair=dict(recurrence_limit=2))
        ambient_state["recovery"]=dict(previous_tier="normal",history=[dict(starts_at=980,ends_at=990,
            utilization=0,open_stock=0,banked_excess=0,amendment_rate=0,nonattendance_rate=0)],
            amendment_rate=0,nonattendance_rate=0,rule_repair=rule_fixture())
        ambient_state["profile_digest"]=_digest(ambient_profile,"sha256")
        rule_verifier=replace(ambient_verifier,profile_bytes=rfc8785.dumps(ambient_profile))
        native=replace(native,ambient_verifier=rule_verifier)
        current_ambient=rule_verifier.evaluate(actual_operation=operation,evaluated_at=1000,clock_healthy=True)
        item["value"]=current_ambient.geometry_value();item["evidence_digests"]=sorted([current_ambient.profile_digest,current_ambient.frame_digest])
        self.assertEqual(whole().ambient.rule_repair.closed_patterns,("pattern:profile",))
        ambient_state["recovery"]["rule_repair"]["patterns"][0]["amendment"]["cites"]=[]
        self.assertEqual(whole().reason,"AMBIENT_BINDING")
        current_ambient=rule_verifier.evaluate(actual_operation=operation,evaluated_at=1000,clock_healthy=True)
        item["value"]=current_ambient.geometry_value();item["evidence_digests"]=sorted([current_ambient.profile_digest,current_ambient.frame_digest])
        self.assertEqual(whole().ambient.rule_repair.open_patterns,("pattern:profile",))
        del ambient_profile["recovery"];del ambient_state["recovery"]
        ambient_state["profile_digest"]=_digest(ambient_profile,"sha256");native=replace(native,ambient_verifier=ambient_verifier)
        current_ambient=ambient_verifier.evaluate(actual_operation=operation,evaluated_at=1000,clock_healthy=True)
        item["value"]=current_ambient.geometry_value();item["evidence_digests"]=sorted([current_ambient.profile_digest,current_ambient.frame_digest])
        ambient_state["expires_at"]=1002
        self.assertEqual(whole().expires_at,1002)
        ambient_state["expires_at"]=1007;ambient_state["ledger_head"]="sha256:"+"b"*64;ambient_state["window_ledger_head"]=ambient_state["ledger_head"]
        self.assertEqual(whole().reason,"AMBIENT_BINDING")
        current_ambient=ambient_verifier.evaluate(actual_operation=operation,evaluated_at=1000,clock_healthy=True)
        item["value"]=current_ambient.geometry_value()
        self.assertEqual(whole().reason,"AMBIENT_BINDING")
        item["evidence_digests"]=sorted([current_ambient.profile_digest,current_ambient.frame_digest])
        self.assertEqual(whole().reason,"NATIVE_PREREQUISITES_VALID")
        ambient_state["current"].update(prior_stock=10,arrivals=[dict(lineage="lineage:"+str(i),counts={"act-outside-decision":1}) for i in range(3)])
        ambient_state["current"]["prior_stock_by_class"]["act-outside-decision"]=10
        self.assertEqual(whole().reason,"AMBIENT_PRESSURE")
        ambient_state["reproduction_at_idle"]=".5"
        self.assertEqual(whole().reason,"AMBIENT_PROFILE_INVALID")
        ambient_state["reproduction_at_idle"]=".1"
        ambient_profile["declared_capacity"]=0
        from kinetic_trust_library.v3.demand_supplier import _digest
        zero=replace(ambient_verifier,profile_bytes=rfc8785.dumps(ambient_profile))
        ambient_state["profile_digest"]=_digest(ambient_profile,"sha256")
        native=replace(native,ambient_verifier=zero)
        self.assertEqual(whole().reason,"AMBIENT_HOSTING_FORBIDDEN")
        ambient_profile["declared_capacity"]=4
        ambient_profile["recovery"]=dict(margin="0.1",stock_target=1,amendment_rate_limit="0.1",nonattendance_rate_limit="0.1",
            crisis_invariants_preserved=False,contingency=None)
        ambient_state["recovery"]=dict(previous_tier="normal",history=[dict(starts_at=980,ends_at=990,
            utilization=0,open_stock=0,banked_excess=0,amendment_rate=0,nonattendance_rate=0)],amendment_rate=0,nonattendance_rate=0)
        ambient_state["profile_digest"]=_digest(ambient_profile,"sha256")
        native=replace(native,ambient_verifier=replace(ambient_verifier,profile_bytes=rfc8785.dumps(ambient_profile)))
        self.assertEqual(whole().reason,"AMBIENT_HOSTING_FORBIDDEN")
        geometry["inputs"].remove(item);native=no_norm
        from kinetic_trust_library.v3.human_eligibility import InstalledHumanEligibilityVerifier,AuthenticatedHumanContext,combine_human_origin
        class HumanSource:
            def resolve(self,**kwargs):return AuthenticatedHumanContext(rfc8785.dumps(human_fixture_data["request"]),
                rfc8785.dumps(human_fixture_data["context"]),b"fixture-authenticated-human-origin")
        hv=InstalledHumanEligibilityVerifier(rfc8785.dumps(deployment),rfc8785.dumps(human_fixture_data["profile"]),HumanSource(),2,"zone:alpha","service-recovery")
        def human_result():return hv.evaluate(rfc8785.dumps(human_fixture_data["claims"]),actual_operation=operation,evaluated_at=1000,clock_healthy=True)
        joined=combine_human_origin(combined,human_result(),now=1000,clock_healthy=True)
        self.assertEqual(joined.reason,"HUMAN_ORIGIN_PREREQUISITES_VALID")
        self.assertEqual(joined.supervision,combined.supervision)
        self.assertEqual(joined.expires_at,combined.expires_at)
        other_operation={**operation,"request_id":"other-human-invocation"}
        human_fixture_data["request"]["request_id"]=other_operation["request_id"]
        other_human=hv.evaluate(rfc8785.dumps(human_fixture_data["claims"]),actual_operation=other_operation,evaluated_at=1000,clock_healthy=True)
        self.assertEqual(other_human.reason,"HUMAN_ELIGIBLE")
        self.assertEqual(combine_human_origin(combined,other_human,now=1000,clock_healthy=True).reason,"HUMAN_CONTEXT_MISMATCH")
        human_fixture_data["request"]["request_id"]=operation["request_id"]
        delegation=human_fixture_data["claims"]["delegations"][0]
        delegation.update(expires_at=1002,version=2)
        human_fixture_data["context"]["active_delegations"][delegation["delegation_id"]]=digest(delegation)
        human_fixture_data["context"]["state_epoch"]+=1
        self.assertEqual(combine_human_origin(combined,human_result(),now=1000,clock_healthy=True).expires_at,1002)
        delegation.update(expires_at=1150,version=3)
        human_fixture_data["context"]["active_delegations"][delegation["delegation_id"]]=digest(delegation)
        human_fixture_data["context"]["state_epoch"]+=1
        human_fixture_data["context"]["status"]="suspended"
        self.assertEqual(combine_human_origin(combined,human_result(),now=1000,clock_healthy=True).supervision,"silent_veto")
        human_fixture_data["context"]["status"]="active"
        self.assertEqual(combine_human_origin(combined,human_result(),now=1001,clock_healthy=True).reason,"HUMAN_UNAVAILABLE")
        state["status"]="revoked"
        restricted=whole()
        self.assertEqual(restricted.supervision,"silent_veto")
        self.assertEqual(restricted.reason,"READINESS_INVALID")
        self.assertEqual(restricted.tightened_constraints_bytes,combined.tightened_constraints_bytes)
        state["status"]="active"
        calls=adapter.calls
        wrong={**geometry,"association":{**geometry["association"],"request_digest":d("different-request")}}
        self.assertEqual(whole(wrong).reason,"DG_BINDING")
        self.assertEqual(adapter.calls,calls)
        geometry["gates"]["consumer"]="passed"
        geometry["consumer_result"]={"supervision":"stable","tightenedConstraints":{
            "profile":geometry["evaluation_profile"]["id"],"ceilings":[{"magnitude":"max_calls","max":9}]}}
        self.assertEqual(whole().reason,"DG_CONSTRAINTS")
        geometry["consumer_result"]["supervision"]="assisted"
        geometry["consumer_result"]["tightenedConstraints"]["ceilings"][0]["max"]=5
        tightened=whole()
        self.assertEqual(tightened.supervision,"assisted")
        self.assertEqual(json.loads(tightened.tightened_constraints_bytes)["ceilings"][0]["max"],5)
        geometry.pop("consumer_result");geometry["gates"]["consumer"]="not_evaluated"
        geometry["capacity"]["capacityKnown"]=False
        self.assertEqual(whole().reason,"DG_CONSTRAINTS")
        geometry["capacity"]["capacityKnown"]=True
        geometry["capacity"]["E"]=46
        self.assertEqual(whole().reason,"DG_INPUTS")
        geometry["capacity"]["E"]=45
        geometry["capacity"]["A"]=34
        self.assertEqual(whole().reason,"DG_INPUTS")
        geometry["capacity"]["A"]=35
        from kinetic_trust_library.v3.geometry_carrier import InstalledGeometryCarrierVerifier
        from kinetic_trust_library.v3.geometry_issuance import InstalledGeometryCarrierIssuer
        from kinetic_trust_library.v3.carrier_association import AssociationGeometryCarrier
        carrier_key={**key,"kid":"geometry-key","curve":"Ed25519","role":"decision-geometry-evaluator",
            "issuer":geometry["evaluator"],"audience":operation["audience"]}
        carrier_context=rfc8785.dumps(dict(identity=dict(evaluator=geometry["evaluator"],audience=operation["audience"],evaluated_at=1000),
            request=actual,proof=ordinary_compact,profile_expires_at=1006))
        cv=InstalledGeometryCarrierVerifier(rfc8785.dumps({carrier_key["kid"]:carrier_key}),carrier_context,gv,("EdDSA",))
        class GeometrySource:
            def produce(self,*,evaluated_at):return rfc8785.dumps(geometry)
        class GeometrySigner:
            def sign(self,message,**kwargs):return private.sign(message)
        carrier=InstalledGeometryCarrierIssuer(GeometrySource(),GeometrySigner(),cv,"EdDSA",carrier_key["kid"]).issue(now=1000,clock_healthy=True)
        protected_av=InstalledRequestAssociationVerifier(Invocation(),pv,Replay(),"sha256",True,AssociationGeometryCarrier(carrier.compact,cv))
        protected=InstalledNativeEvaluationVerifier(protected_av,dv,boundary_verifier=bv)
        protected_result=protected.verify(actual_bytes,association_bytes,ordinary_compact,decision_bytes=rfc8785.dumps(decision),
            attestation_bytes=rfc8785.dumps(attestation),invocation_evidence=b"fixture-actual-invocation",now=1000,clock_healthy=True)
        self.assertEqual(protected_result.reason,"NATIVE_PREREQUISITES_VALID")
        self.assertEqual(protected_result.expires_at,1006)
        substitution=protected.verify(actual_bytes,association_bytes,ordinary_compact,decision_bytes=rfc8785.dumps(decision),
            attestation_bytes=rfc8785.dumps(attestation),invocation_evidence=b"fixture-actual-invocation",now=1000,clock_healthy=True,
            geometry_body_bytes=rfc8785.dumps(geometry))
        self.assertEqual(substitution.reason,"DG_BINDING")
        state["status"]="revoked"
        self.assertEqual(check_decision().reason,"READINESS_INVALID")
        state["status"]="active"
        decision["expires_at"]=1009;seal_decision()
        self.assertEqual(check_decision().reason,"READINESS_DECISION_INVALID")
        decision["expires_at"]=1008;seal_decision()
        calls=adapter.calls
        self.assertEqual(evaluate(clock=False).reason,"READINESS_UNAVAILABLE")
        self.assertEqual(adapter.calls,calls)
        for field,value in (("status","revoked"),("readiness_epoch",4),("checked_at",999),("active_attestation_digest",d("unregistered"))):
            with self.subTest(field=field):
                original=state[field];state[field]=value
                self.assertEqual(evaluate().reason,"READINESS_INVALID")
                state[field]=original
        key["revoked"]=True
        self.assertEqual(evaluate().reason,"READINESS_INVALID")
        key["revoked"]=False
        request["subject"]["software_digest"]=d("changed-software")
        self.assertEqual(evaluate().reason,"READINESS_INVALID")
        request["subject"]["software_digest"]=d("software")
        original=request["scope"]["parameters_digest"]
        request["scope"]["parameters_digest"]=d("wrong-parameters")
        self.assertEqual(evaluate().reason,"READINESS_INVALID")
        request["scope"]["parameters_digest"]=original
        self.assertEqual(evaluate(raw=rfc8785.dumps(attestation).replace(b'"readiness_epoch":3',b'"readiness_epoch":3.0')).reason,"READINESS_INVALID")
        attestation["checks"][0]["observed_at"]=899;seal();state["active_attestation_digest"]=digest(attestation)
        self.assertEqual(evaluate().reason,"READINESS_INVALID")


if __name__ == "__main__": unittest.main()
