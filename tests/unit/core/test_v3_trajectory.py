"""Native five-factor trajectory integrity and independently anchored head."""
import json
import unittest
from pathlib import Path
from importlib.util import find_spec
from kinetic_trust_library.v3.trajectory import InstalledTrajectoryVerifier,AuthenticatedTrajectoryContext,TrajectoryStateUnavailable


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class TrajectoryTests(unittest.TestCase):
    def test_level3_classical_floor_cannot_be_downgraded_by_registry(self):
        import rfc8785
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import ec,ed25519,ed448,utils
        from kinetic_trust_library.v3 import _trajectory_reference as t
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/trajectory-signatures-v3.json").read_text())
        for kind in ("Ed448","ES384","Ed25519"):
            with self.subTest(kind=kind):
                record=json.loads(json.dumps(vectors["cases"][0]["record"]))
                record["oracle_attestation"]["risk_factors"].pop("moment_criticality")
                record.update(conformance_level=3,evaluation_profile_digest=t.digest({"fixture":"level3-profile"},3))
                keys={};private={}
                for role,byte in (("agent",17),("oracle",34)):
                    private[role]=(ec.derive_private_key(byte,ec.SECP384R1()) if kind=="ES384" else
                        ed448.Ed448PrivateKey.from_private_bytes(bytes([byte])*57) if kind=="Ed448" else
                        ed25519.Ed25519PrivateKey.from_private_bytes(bytes([byte])*32))
                    public=private[role].public_key()
                    key=dict(kid=role+"-strong-test",subject="agent-test" if role=="agent" else "oracle-test",zone_id="zone-test",
                        purpose=t.AGENT_TYPE if role=="agent" else t.ORACLE_TYPE,alg="ES384" if kind=="ES384" else "EdDSA",
                        kty="EC" if kind=="ES384" else "OKP",crv="P-384" if kind=="ES384" else kind,
                        revoked=False,not_before=0,not_after=2000000000)
                    if kind=="ES384":
                        numbers=public.public_numbers();key.update(x=t.b64(numbers.x.to_bytes(48,"big")),y=t.b64(numbers.y.to_bytes(48,"big")))
                    else:key["x"]=t.b64(public.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
                    keys[key["kid"]]=key
                def sign(payload,role):
                    key=keys[role+"-strong-test"]
                    message=(t.b64(t.canonical(dict(alg=key["alg"],kid=key["kid"],typ=key["purpose"])))+"."+t.b64(t.canonical(payload))).encode()
                    if kind=="ES384":
                        r,s=utils.decode_dss_signature(private[role].sign(message,ec.ECDSA(hashes.SHA384())))
                        signature=r.to_bytes(48,"big")+min(s,t.ORDERS["ES384"]-s).to_bytes(48,"big")
                    else:signature=private[role].sign(message)
                    return message.decode()+"."+t.b64(signature)
                record["agent_signature"]=sign(t.body(record),"agent")
                record["oracle_attestation"]["oracle_signature"]=sign(t.oracle_payload(record),"oracle")
                record["record_hash"]=t.record_digest(record)
                expected={**vectors["cases"][0]["trusted_context"],"trusted_level":3,
                    "trusted_profile_digest":record["evaluation_profile_digest"],"minimum_record_format":t.VERSION}
                state=dict(checked_at=1800000000,context=expected,head=t.head_binding(record),predecessor=None,predecessor_context=None,migration=None)
                class Adapter:
                    def resolve(self,**kwargs):return AuthenticatedTrajectoryContext(rfc8785.dumps(state),rfc8785.dumps(keys),b"fixture-anchored-head")
                result=InstalledTrajectoryVerifier(rfc8785.dumps(expected),Adapter()).verify(rfc8785.dumps(record),now=1800000000,clock_healthy=True)
                self.assertEqual(result.reason,"TRAJECTORY_INVALID" if kind=="Ed25519" else "TRAJECTORY_VERIFIED")

    def test_signed_native_records_head_continuity_and_no_legacy_fallback(self):
        import rfc8785
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        from kinetic_trust_library.v3 import _trajectory_reference as t
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/trajectory-signatures-v3.json").read_text())
        cases=vectors["cases"]
        # Original six-factor draft bytes remain independently checked crypto
        # diagnostics, never an alternate accepted native record profile.
        for case in cases:
            for role,payload in (("agent",t.body(case["record"])),("oracle",t.oracle_payload(case["record"]))):
                binding=case[role+"_binding"]
                trusted=t.KeyBinding(binding["key_id"],binding["subject"],binding["algorithm"],binding["purpose"],
                    load_der_public_key(t.unb64(binding["public_key_spki_der_base64url"])),binding["zone_id"])
                compact=case["record"]["agent_signature"] if role=="agent" else case["record"]["oracle_attestation"]["oracle_signature"]
                t.verify_jws(compact,payload,trusted,level=case["trusted_context"]["trusted_level"])
                self.assertEqual(t.canonical(payload).decode(),case["expected"][role+"_payload_utf8"])
            self.assertEqual(t.record_digest(case["record"]),case["expected"]["record_hash"])
            self.assertEqual(t.commit_intent(case["record"]),case["expected"]["commit_intent"])
            self.assertEqual(t.head_binding(case["record"]),case["expected"]["final_head_binding"])
        records=[json.loads(json.dumps(c["record"])) for c in cases]
        private={role:Ed25519PrivateKey.from_private_bytes(bytes([byte])*32) for role,byte in (("agent",17),("oracle",34))}
        keys={}
        for role in private:
            binding=cases[0][role+"_binding"]
            keys[binding["key_id"]]=dict(kid=binding["key_id"],subject=binding["subject"],zone_id=binding["zone_id"],purpose=binding["purpose"],
                alg="EdDSA",kty="OKP",crv="Ed25519",x=t.b64(private[role].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)),
                revoked=False,not_before=0,not_after=2000000000)
        def sign(payload,role):
            kid=cases[0][role+"_binding"]["key_id"]
            message=(t.b64(t.canonical(dict(alg="EdDSA",kid=kid,typ=keys[kid]["purpose"])))+"."+t.b64(t.canonical(payload))).encode()
            return message.decode()+"."+t.b64(private[role].sign(message))
        def seal(record):
            record["agent_signature"]=sign(t.body(record),"agent")
            record["oracle_attestation"]["oracle_signature"]=sign(t.oracle_payload(record),"oracle")
            record["record_hash"]=t.record_digest(record)
        for index,record in enumerate(records):
            record["oracle_attestation"]["risk_factors"].pop("moment_criticality")
            if index:record["previous_hash"]=records[index-1]["record_hash"]
            seal(record)
        expected={**cases[0]["trusted_context"],"minimum_record_format":"ktp-trajectory-v3"}
        now=1800000000
        state=dict(checked_at=now,context=expected,head=t.head_binding(records[0]),predecessor=None,predecessor_context=None,migration=None)
        class Adapter:
            unavailable=False
            calls=0
            genesis_binding=None
            def resolve(self,**kwargs):
                self.calls+=1
                if self.unavailable:raise TrajectoryStateUnavailable()
                return AuthenticatedTrajectoryContext(rfc8785.dumps(state),rfc8785.dumps(keys),b"fixture-authenticated-commit-and-unique-head",
                    genesis_sponsorship=self.genesis_binding)
        adapter=Adapter()
        verifier=InstalledTrajectoryVerifier(rfc8785.dumps(expected),adapter)
        def verify(record):return verifier.verify(rfc8785.dumps(record),now=now,clock_healthy=True)
        result=verify(records[0])
        self.assertEqual(result.reason,"TRAJECTORY_VERIFIED")
        self.assertEqual(result.record_hash,records[0]["record_hash"])
        self.assertEqual(result.commit_intent,t.commit_intent(records[0]))
        from dataclasses import replace
        from kinetic_trust_library.errors import ValidationError
        from kinetic_trust_library.v3.trajectory import AuthenticatedGenesisSponsorship,_seconds
        from kinetic_trust_library.v3.demand_supplier import _digest
        from tests.unit.core.test_v3_sponsorship_repair import fixture as sponsorship_fixture
        sponsorship,opening,bond_context,bond_bytes,bond_body,_=sponsorship_fixture()
        birth=int(_seconds(records[0]["timestamp"]))
        bond_body.update(subject=records[0]["agent_id"],start_time=birth,end_time=birth+10)
        bond_context["subject"]=records[0]["agent_id"]
        opening.update(subject=records[0]["agent_id"],opened_at=birth,checked_at=now,expires_at=now+7,
            context_digest=_digest(bond_context,"sha256"),body_digest=_digest(bond_body,"sha256"))
        expected["sponsorship_repair_profile_digest"]=_digest(json.loads(sponsorship.profile_bytes),"sha256")
        original_verifier=verifier
        sponsorship=replace(sponsorship,expected_zone=records[0]["zone_id"])
        opening["zone_id"]=records[0]["zone_id"]
        verifier=replace(verifier,expected_context_bytes=rfc8785.dumps(expected),sponsorship_repair_verifier=sponsorship)
        self.assertEqual(verify(records[0]).reason,"TRAJECTORY_INVALID")
        adapter.genesis_binding=AuthenticatedGenesisSponsorship(records[0]["record_hash"],bond_bytes,rfc8785.dumps(bond_context))
        self.assertEqual(verify(records[0]).reason,"TRAJECTORY_VERIFIED")
        self.assertTrue(verify(records[0]).genesis_sponsorship.eligible)
        for start,end,opened in ((birth+1,birth+10,birth),(birth-10,birth,birth-10)):
            bond_body.update(start_time=start,end_time=end)
            opening.update(opened_at=opened,body_digest=_digest(bond_body,"sha256"))
            self.assertEqual(verify(records[0]).reason,"TRAJECTORY_INVALID")
        bond_body.update(start_time=birth,end_time=birth+10)
        opening.update(opened_at=birth,body_digest=_digest(bond_body,"sha256"))
        opening["counts"]["act-outside-decision"]=2
        self.assertEqual(verify(records[0]).reason,"TRAJECTORY_INVALID")
        state.update(head=t.head_binding(records[1]),predecessor=records[0],predecessor_context=expected)
        self.assertEqual(verify(records[1]).reason,"TRAJECTORY_INVALID")
        opening["counts"]["act-outside-decision"]=0
        self.assertEqual(verify(records[1]).reason,"TRAJECTORY_VERIFIED")
        state.update(head=t.head_binding(records[0]),predecessor=None,predecessor_context=None)
        adapter.genesis_binding=replace(adapter.genesis_binding,record_hash="sha256:"+"0"*64)
        self.assertEqual(verify(records[0]).reason,"TRAJECTORY_INVALID")
        with self.assertRaises(ValidationError):replace(verifier,sponsorship_repair_verifier=None)
        expected.pop("sponsorship_repair_profile_digest");verifier=original_verifier;adapter.genesis_binding=None
        self.assertEqual(verify(cases[0]["record"]).reason,"TRAJECTORY_INVALID")
        state.update(head=t.head_binding(records[1]),predecessor=records[0],predecessor_context=expected)
        self.assertEqual(verify(records[1]).reason,"TRAJECTORY_VERIFIED")
        changed=json.loads(json.dumps(records[1]));changed["action"]["details"]["nested"]["enabled"]=False
        def replace_payload(token,payload):
            head,_,signature=token.split(".")
            return head+"."+t.b64(t.canonical(payload))+"."+signature
        changed["agent_signature"]=replace_payload(changed["agent_signature"],t.body(changed))
        changed["oracle_attestation"]["oracle_signature"]=replace_payload(changed["oracle_attestation"]["oracle_signature"],t.oracle_payload(changed))
        changed["record_hash"]=t.record_digest(changed);state["head"]=t.head_binding(changed)
        self.assertEqual(verify(changed).reason,"TRAJECTORY_INVALID")
        changed=json.loads(json.dumps(records[1]));changed["previous_state"]["e_base"]=19;seal(changed);state["head"]=t.head_binding(changed)
        self.assertEqual(verify(changed).reason,"TRAJECTORY_INVALID")
        state["head"]=t.head_binding(records[1]);state["head"]["record_hash"]=records[0]["record_hash"]
        self.assertEqual(verify(records[1]).reason,"TRAJECTORY_INVALID")
        state["head"]=t.head_binding(records[1]);state["checked_at"]=now-1
        self.assertEqual(verify(records[1]).reason,"TRAJECTORY_UNAVAILABLE")
        state["checked_at"]=now;adapter.unavailable=True
        self.assertEqual(verify(records[1]).reason,"TRAJECTORY_UNAVAILABLE")
        adapter.unavailable=False
        migration_private=Ed25519PrivateKey.from_private_bytes(bytes([51])*32)
        migration_key={**keys[cases[0]["agent_binding"]["key_id"]],"kid":"migration-test-key","subject":"migration-authority",
            "purpose":t.MIGRATION_TYPE,"x":t.b64(migration_private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))}
        keys[migration_key["kid"]]=migration_key
        genesis=json.loads(json.dumps(records[0]))
        checkpoint=dict(checkpoint_version=t.MIGRATION_TYPE,checkpoint_id="migration-1",agent_id=genesis["agent_id"],zone_id=genesis["zone_id"],
            issued_at="2026-09-06T11:59:00Z",expires_at="2026-09-06T12:01:00Z",legacy_chain_id="legacy-chain",legacy_sequence=9,
            legacy_record_hash=t.digest({"fixture":"legacy-head"},2),legacy_archive_digest=t.digest({"fixture":"archive"},2),
            new_chain_id=genesis["chain_id"],new_genesis_record_id=genesis["record_id"],new_genesis_timestamp=genesis["timestamp"],
            conformance_level=2,evaluation_profile_digest=genesis["evaluation_profile_digest"],approved_state=genesis["current_state"],
            revalidation_evidence_digest=t.digest({"fixture":"independent-revalidation"},2))
        message=(t.b64(t.canonical(dict(alg="EdDSA",kid=migration_key["kid"],typ=t.MIGRATION_TYPE)))+"."+t.b64(t.canonical(checkpoint))).encode()
        token=message.decode()+"."+t.b64(migration_private.sign(message))
        checkpoint_digest=t.digest_bytes(token.encode(),2)
        genesis["migration_checkpoint"]=checkpoint_digest;seal(genesis)
        state.update(head=t.head_binding(genesis),predecessor=None,predecessor_context=None,migration=dict(token=token,
            checkpoint_digest=checkpoint_digest,approved_state=genesis["current_state"],activated_at="2026-09-06T12:00:01Z"))
        self.assertEqual(verify(genesis).reason,"TRAJECTORY_VERIFIED")
        state["migration"]["activated_at"]="2026-09-06T12:00:00Z"
        self.assertEqual(verify(genesis).reason,"TRAJECTORY_INVALID")
        state["migration"]["activated_at"]=checkpoint["expires_at"]
        self.assertEqual(verify(genesis).reason,"TRAJECTORY_INVALID")


if __name__ == "__main__":unittest.main()
