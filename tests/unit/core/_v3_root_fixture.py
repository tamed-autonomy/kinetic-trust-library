"""Unsafe RFC test-envelope adapter: real crypto, modeled world prerequisites.

The fixture signatures do not establish actual exposure, accountable chains,
issuer independence, current registry truth or inventory completeness. This
adapter is test-only and does not define a production Root envelope.
"""
import hashlib
from kinetic_trust_library.v3.installed_root import AuthenticatedRootInstrument,RootVerificationFailure
from kinetic_trust_library.v3.trust_proof_json import _parse_jcs_object,parse_proof_json_objects
from kinetic_trust_library.v3.trust_proof_framing import parse_compact_framing
from kinetic_trust_library.v3.trust_proof_signature import trust_proof_signature_valid
from kinetic_trust_library.v3.root_lifecycle import RootLifecycleEvent


class RootFixtureAdapter:
    def __init__(self,vectors):
        self.keys=vectors["keys"]
        self.event_jws=()

    def signed(self,compact,typ,role):
        framing=parse_compact_framing(compact)
        header,body=parse_proof_json_objects(framing)
        key=self.keys.get(header.get("kid"))
        if (type(key) is not dict or key["role"]!=role
                or header!={"alg":"ES256","kid":header.get("kid"),"typ":typ}
                or not trust_proof_signature_valid(compact,algorithm="ES256",trusted_key={**key,"kty":"EC","crv":"P-256"})):
            raise RootVerificationFailure("unverifiable")
        return body,key

    def verify(self,evidence,*,context_bytes,evaluated_at):
        import rfc8785
        envelope=_parse_jcs_object(evidence)
        if "instrument_jws" not in envelope or set(envelope)-{"instrument_jws","oracle_witness"}:
            raise RootVerificationFailure("unverifiable")
        raw=envelope["instrument_jws"]
        _,body=parse_proof_json_objects(parse_compact_framing(raw))
        role="sponsor" if body.get("kind")=="sponsorship_bond" else "attestor"
        body,key=self.signed(raw,"ktp-root-instrument-test-v1",role)
        if body["issuer"]!=key["issuer"]:
            raise RootVerificationFailure("unverifiable")
        if role=="sponsor" and "oracle_witness" not in envelope:
            raise RootVerificationFailure("unwitnessed")
        if "oracle_witness" in envelope:
            witness,_=self.signed(envelope["oracle_witness"],"ktp-root-witness-test-v1","oracle-witness")
            if witness!={"instrument_digest":"sha256:"+hashlib.sha256(raw.encode("ascii")).hexdigest(),"subject":body["subject"]}:
                raise RootVerificationFailure("unwitnessed")
        complete_digest="sha256:"+hashlib.sha256(evidence).hexdigest()
        events=[]
        for compact in self.event_jws:
            _,event=parse_proof_json_objects(parse_compact_framing(compact))
            event,key=self.signed(compact,"ktp-root-event-test-v1","adjudicator" if event["action"]=="finding" else role)
            if (event["issuer"]!=key["issuer"] or event["instrument_digest"]!=complete_digest
                    or event["subject"]!=body["subject"] or event["action"]!="finding" and event["issuer"]!=body["issuer"]):
                raise RootVerificationFailure("unverifiable")
            events.append(RootLifecycleEvent("sha256:"+hashlib.sha256(compact.encode("ascii")).hexdigest(),
                complete_digest,event["subject"],event["event_time"],event["action"],event.get("claim_digest"),event.get("finding")))
        return AuthenticatedRootInstrument(rfc8785.dumps(body),tuple(events))
