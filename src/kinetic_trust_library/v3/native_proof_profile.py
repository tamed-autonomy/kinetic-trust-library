"""Explicit development composition of RFC PR #195/#201/#203 schemas.

The #203 five-factor schema retains a v2 ID upstream. This bundle scopes that
definition to the native development profile and never replaces the released
v2 registry or the original diagnostic snapshot. Reconcile IDs at final tag.
"""
from dataclasses import dataclass
from importlib.resources import files
import json
from kinetic_trust_library.errors import ValidationError
from .complete_proof_verifier import InstalledSchemaBundle
from .assessed_root_selection import AssessedRootSelection
from .trust_proof_json import _parse_jcs_object
from .trust_proof_invariants import _number


def native_schema_bundle() -> InstalledSchemaBundle:
    import rfc8785
    base = files("kinetic_trust_library.v3").joinpath("schemas")
    schemas = tuple(json.loads(base.joinpath(name).read_text("utf-8")) for name in (
        "trust-proof-composed-v3.json", "risk-factors-composed-v3.json",
        "soul-constraint-v2.json", "root-instrument-v3.json"))
    return InstalledSchemaBundle(tuple(rfc8785.dumps(s) for s in schemas), schemas[0]["$id"])


@dataclass(frozen=True, slots=True)
class RootProofBinding:
    selection: AssessedRootSelection
    expected_zone: str
    no_credit_reason: str = "missing"

    def __post_init__(self):
        if type(self.selection) is not AssessedRootSelection or type(self.expected_zone) is not str or not self.expected_zone:
            raise ValidationError("installed proof root binding is invalid")
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
        if (type(now) is not int or now != self.selection.evaluated_at
                or payload["sub"] != source.get("subject") or ktp["zone"] != self.expected_zone
                or ktp.get("subject_kind") != "software_agent"):
            return False
        if any(name in source and ktp.get(name) != source[name] for name in ("generation", "lineage")):
            return False
        selected = self.selection.selected
        if selected is not None:
            expected = _parse_jcs_object(selected.projection_bytes)
            return (ktp["root_instrument"] == expected and payload["exp"] <= expected["end_time"]
                    and (expected["kind"] != "sponsorship_bond" or ktp.get("sponsor") == expected["sponsor_id"]))
        expected = {"kind":"none", "status":"none", "reason":self.no_credit_reason}
        actual = ktp["root_instrument"]
        if {k:v for k,v in actual.items() if k != "diagnostic_ref"} != expected:
            return False
        ceilings = {item["ceiling"]: _number(item["value"]) for item in ktp["applicable_ceilings"]}
        cap = ceilings.get("external_root_missing")
        base = _number(ktp.get("e_base")) if ktp.get("e_base") is not None else None
        return cap is not None and 0 <= cap <= 70 and (base is None or base <= cap)


__all__ = ["native_schema_bundle", "RootProofBinding"]
