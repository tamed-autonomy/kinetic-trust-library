"""Explicit development composition of RFC PR #164/#195/#201/#203 schemas.

The refreshed source schemas reference the native five-factor v3 ID directly.
Root/person overlays remain explicitly selected. Prior snapshots are archived;
the released v2 registry is unchanged and is not selected as a fallback.
"""
from dataclasses import dataclass
from importlib.resources import files
import json
from kinetic_trust_library.errors import ValidationError
from .complete_proof_verifier import InstalledSchemaBundle
from .assessed_root_selection import AssessedRootSelection
from .trust_proof_json import _parse_jcs_object
from .trust_proof_invariants import _number
from .federated_sponsorship import SPONSOR_CREDIT_PREFIX


def native_schema_bundle() -> InstalledSchemaBundle:
    import rfc8785
    base = files("kinetic_trust_library.v3").joinpath("schemas")
    schemas = tuple(json.loads(base.joinpath(name).read_text("utf-8")) for name in (
        "trust-proof-composed-v3.json", "risk-factors-native-v3.json",
        "soul-constraint-v2.json", "root-instrument-v3.json"))
    context = schemas[0]["$defs"]["ktpClaims"]["properties"]["context"]["anyOf"][0]
    if context["$ref"] != schemas[1]["$id"]:
        raise ValidationError("proof composition source reference changed; reconcile the RFC snapshots")
    return InstalledSchemaBundle(tuple(rfc8785.dumps(s) for s in schemas), schemas[0]["$id"])


@dataclass(frozen=True, slots=True)
class RootProofBinding:
    selection: AssessedRootSelection
    expected_zone: str
    no_credit_reason: str = "missing"

    def __post_init__(self):
        if type(self.selection) is not AssessedRootSelection or type(self.expected_zone) is not str or not self.expected_zone:
            raise ValidationError("installed proof root binding is invalid")
        if _parse_jcs_object(self.selection.context_bytes).get("subject_profile") not in ("software", "person"):
            raise ValidationError("root source subject class must be independently declared")
        if self.selection.selected is None:
            reasons = set()
            for candidate in self.selection.candidates:
                projection = _parse_jcs_object(candidate.projection_bytes)
                if projection["kind"] == "none":
                    reasons.add(projection["reason"])
                elif candidate.score_numerator == 0:
                    reasons.add("no_exposure")
            if not reasons:
                reasons.add("missing")
            if self.no_credit_reason not in reasons:
                raise ValidationError("no-credit reason is not established by the root source")

    def __call__(self, payload_bytes: bytes, now: int) -> bool:
        payload = _parse_jcs_object(payload_bytes)
        source = _parse_jcs_object(self.selection.context_bytes)
        ktp = payload["ktp"]
        person = source.get("subject_profile") == "person"
        if (type(now) is not int or now != self.selection.evaluated_at
                or payload["sub"] != source.get("subject") or ktp["zone"] != self.expected_zone
                or ktp.get("subject_kind") != ("person" if person else "software_agent")):
            return False
        if any(name in source and ktp.get(name) != source[name] for name in ("generation", "lineage")):
            return False
        selected = self.selection.selected
        cross=None if selected is None else selected.federated_sponsorship
        credits=[item for item in ktp.get("applicable_ceilings",[]) if item["ceiling"].startswith(SPONSOR_CREDIT_PREFIX)]
        caps=[item for item in ktp.get("applicable_ceilings",[]) if item["ceiling"]=="federated_sponsor"]
        if cross is None and (credits or caps):return False
        if selected is not None:
            expected = _parse_jcs_object(selected.projection_bytes)
            if expected["kind"]=="sponsorship_bond":
                if selected.issuer_zone is None or selected.issuer_zone!=self.expected_zone and cross is None:return False
            if cross is not None:
                if (not cross.active or cross.receiving_zone!=self.expected_zone or cross.checked_at!=now or payload["exp"]>cross.expires_at
                        or len(caps)!=1 or not 0<=_number(caps[0]["value"])<=cross.sponsor_measure
                        or len(credits)!=1 or credits[0]["ceiling"]!=cross.credit_ceiling_name or not 0<=_number(credits[0]["value"])<=cross.sponsor_measure
                        or ktp.get("e_base") is not None and _number(ktp["e_base"])>_number(credits[0]["value"])
                        or ktp.get("e_base") is not None and _number(ktp["e_base"])>_number(caps[0]["value"])):
                    return False
            sponsorship=selected.sponsorship_repair
            if sponsorship is not None and (not sponsorship.eligible or sponsorship.zone_id!=self.expected_zone
                    or sponsorship.checked_at!=now or payload["exp"]>sponsorship.expires_at):
                return False
            if person and (expected["kind"] != "external_attestation" or expected["root_person"] != payload["sub"]):
                return False
            return (ktp["root_instrument"] == expected and payload["exp"] <= expected["end_time"]
                    and (expected["kind"] != "sponsorship_bond" or ktp.get("sponsor") == expected["sponsor_id"]))
        expected = {"kind":"none", "status":"none", "reason":self.no_credit_reason}
        actual = ktp["root_instrument"]
        if {k:v for k,v in actual.items() if k != "diagnostic_ref"} != expected:
            return False
        if person:
            return True
        ceilings = {item["ceiling"]: _number(item["value"]) for item in ktp["applicable_ceilings"]}
        cap = ceilings.get("external_root_missing")
        base = _number(ktp.get("e_base")) if ktp.get("e_base") is not None else None
        return cap is not None and 0 <= cap <= 70 and (base is None or base <= cap)


__all__ = ["native_schema_bundle", "RootProofBinding"]
