"""Derive native software proof claims from an installed-input Core snapshot.

Issuer metadata is installed trusted state, not requester-selected claims. This
producer retains exact Core arithmetic; it refuses wire values whose canonical
JSON number would change the decimal value, pending a final precision profile.
Person standing uses a separate source contract and is not synthesized here.
"""
from dataclasses import dataclass
from decimal import Decimal
from kinetic_trust_library.errors import ValidationError
from .core_projection import NativeCoreContext, NativeCoreProjection
from .installed_standing import NativeStandingAssessment
from .native_proof_profile import RootProofBinding, native_schema_bundle
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import digest_demand_operation


def _wire_number(value):
    if value is None:
        return None
    value = Decimal(value)
    number = int(value) if value == value.to_integral_value() else float(value)
    # Compare the actual JCS spelling, not Python's float repr (which may use
    # a different shortest spelling at the integer/scientific boundary).
    import rfc8785
    try:
        spelling = rfc8785.dumps(number).decode("ascii")
    except (ValueError, OverflowError) as error:
        raise ValidationError("Core number has no supported canonical wire representation") from error
    if Decimal(spelling) != value:
        raise ValidationError("Core number requires a declared wire precision rule")
    return number


@dataclass(frozen=True, slots=True)
class NativeCoreClaimsSource:
    core: NativeCoreProjection
    standing: NativeStandingAssessment
    context: NativeCoreContext
    assertion_metadata_bytes: bytes
    no_credit_reason: str = "missing"

    def __post_init__(self):
        if (type(self.core) is not NativeCoreProjection or type(self.standing) is not NativeStandingAssessment
                or type(self.context) is not NativeCoreContext or type(self.assertion_metadata_bytes) is not bytes):
            raise ValidationError("native Core claims require installed immutable assessments")
        metadata = _parse_jcs_object(self.assertion_metadata_bytes)
        required = {"iss", "aud", "jti", "exp", "zone", "advancement_floor"}
        if not required <= set(metadata) or set(metadata) - required - {"sponsor", "ingress_path"}:
            raise ValidationError("installed assertion metadata is invalid")
        profile = _parse_jcs_object(self.context.deployment_profile_bytes)
        operation = _parse_jcs_object(self.context.operation_bytes)
        if metadata["aud"] != operation["audience"]:
            raise ValidationError("proof audience differs from the actual operation")
        deployment = _digest(profile, self.context.algorithm)
        invocation = digest_demand_operation(operation, algorithm=self.context.algorithm)
        soul = self.core.soul_assessment
        if (soul is None or soul.deployment_digest != deployment or soul.operation_digest != invocation
                or soul.evaluated_at != self.context.evaluated_at
                or self.standing.deployment_digest != deployment or self.standing.operation_digest != invocation
                or self.standing.evaluated_at != self.context.evaluated_at
                or self.core.standing_assessment is not None and self.core.standing_assessment is not self.standing):
            raise ValidationError("Core claim assessments belong to another invocation")
        RootProofBinding(self.standing.roots, metadata["zone"], self.no_credit_reason)

    def produce(self, *, evaluated_at: int) -> bytes:
        import rfc8785
        if type(evaluated_at) is not int or evaluated_at != self.context.evaluated_at:
            raise ValidationError("Core claim snapshot belongs to another evaluation time")
        metadata = _parse_jcs_object(self.assertion_metadata_bytes)
        standing = _parse_jcs_object(self.standing.authenticated_body_bytes)
        roots = self.standing.roots
        root = (_parse_jcs_object(roots.selected.projection_bytes) if roots.selected is not None else
                {"kind": "none", "status": "none", "reason": self.no_credit_reason})
        state = self.core.soul.state.value
        measured = self.core.risk is not None and self.core.risk.has_complete_measurement
        if state == "clear" and not measured:
            state = "undetermined"
        soul_claim = None if self.core.soul.state.value == "undetermined" else {"soul": 0}
        if state == "veto":
            responses = {r.framework: r for r in self.core.soul_assessment.responses}
            # Preserve the first veto in installed framework order; the full
            # assessment retains every applicable response and its evidence.
            response = next(responses[f] for f in self.core.soul_assessment.required_frameworks
                            if f in responses and responses[f].state == "veto")
            if response.proof_claim_bytes is None:
                raise ValidationError("veto proof requires authenticated constraint details")
            soul_claim = _parse_jcs_object(response.proof_claim_bytes)
        generation = standing["generation"]
        ktp = dict(version="ktp-trust-proof-v3", subject_kind="software_agent", gate_state=state,
            e_base=_wire_number(self.core.standing.base_trust) if self.core.standing is not None else None,
            e_trust=_wire_number(self.core.capacity.measured_effective_trust) if self.core.capacity is not None else None,
            r=_wire_number(self.core.risk.measured_risk) if self.core.risk is not None else None,
            context={f.factor: _wire_number(f.value) for f in self.core.risk.factors} if measured else None,
            soul=soul_claim,
            generation=generation,lineage="sponsored" if generation < 3 else "independent" if generation < 7 else "guarantor",
            zone=metadata["zone"],peer_share=_wire_number(self.standing.base.peer_share),
            applicable_ceilings=[{"ceiling": name,"value": _wire_number(value)} for name,value in self.standing.base.ceilings],
            advancement_floor=metadata["advancement_floor"],root_instrument=root)
        for name in ("sponsor", "ingress_path"):
            if name in metadata:
                ktp[name] = metadata[name]
        payload = rfc8785.dumps(dict(iss=metadata["iss"],sub=standing["subject"],aud=metadata["aud"],
            iat=evaluated_at,exp=metadata["exp"],jti=metadata["jti"],ktp=ktp))
        if (not native_schema_bundle().valid(payload)
                or not RootProofBinding(roots, metadata["zone"], self.no_credit_reason)(payload, evaluated_at)):
            raise ValidationError("derived Core claims violate the native proof contract")
        return payload


__all__ = ["NativeCoreClaimsSource"]
