import base64
import json
import unittest
from pathlib import Path
from importlib.util import find_spec


@unittest.skipUnless(all(find_spec(n) for n in ("rfc8785","jsonschema","cryptography")), "install v3-proofs")
class RootFixtureSignatures(unittest.TestCase):
    def test_complete_instrument_witness_and_event_signatures(self):
        import rfc8785
        from tests.unit.core._v3_root_fixture import RootFixtureAdapter
        from kinetic_trust_library.v3.installed_root import InstalledRootVerifier
        vectors=json.loads((Path(__file__).parents[3]/"spec/proposals/external-root-v1.json").read_text())
        adapter=RootFixtureAdapter(vectors)
        verifier=InstalledRootVerifier(adapter,"sha256")
        for name,lineage,generation in (("bond","sponsored",2),("attestation","guarantor",7)):
            with self.subTest(instrument=name):
                instrument=vectors["instruments"][name]
                raw=base64.urlsafe_b64decode(instrument["complete_bytes_base64url"]+"==")
                context=rfc8785.dumps(dict(subject=instrument["body"]["subject"],subject_profile="software",lineage=lineage,generation=generation,hop_bound=4))
                def evaluate(data=raw,now=1800000000):return verifier.evaluate(data,context_bytes=context,evaluated_at=now)
                adapter.event_jws=()
                current=evaluate()
                projection=json.loads(current.projection_bytes)
                self.assertEqual(projection["status"],"current")
                self.assertEqual(projection["bond_digest" if name=="bond" else "attestation_digest"],instrument["complete_digest"])
                adapter.event_jws=(vectors["events"][name+"-for-cause"]["jws"],)
                self.assertEqual(json.loads(evaluate(now=1800000002).projection_bytes)["reason"],"for_cause_pending")
                adapter.event_jws+=(vectors["events"][name+"-sustained"]["jws"],)
                self.assertEqual(json.loads(evaluate(now=1800000003).projection_bytes)["reason"],"for_cause_sustained")
                adapter.event_jws=()
                envelope=json.loads(raw)
                jws=envelope["instrument_jws"]
                head,payload,signature=jws.split(".")
                envelope["instrument_jws"]=head+"."+payload+"."+("A" if signature[0]!="A" else "B")+signature[1:]
                self.assertEqual(evaluate(rfc8785.dumps(envelope)).score,0)
                if name=="bond":
                    envelope=json.loads(raw);envelope.pop("oracle_witness")
                    self.assertEqual(evaluate(rfc8785.dumps(envelope)).score,0)
                    envelope=json.loads(raw);envelope["oracle_witness"]=envelope["instrument_jws"]
                    self.assertEqual(evaluate(rfc8785.dumps(envelope)).score,0)


if __name__ == "__main__":unittest.main()
