"""Derive native software proof claims from an installed-input Core snapshot.

Issuer metadata is installed trusted state, not requester-selected claims. This
producer retains exact Core arithmetic; it refuses wire values whose canonical
JSON number would change the decimal value, pending a final precision profile.
Person standing uses a separate source contract and is not synthesized here.
"""
from dataclasses import dataclass
from decimal import Decimal
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library._decimal import as_decimal
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
        federation=self.standing.federation
        if (self.context.federation_profile_bytes is not None)!=(federation is not None):
            raise ValidationError("Core claims disagree on federation selection")
        if federation is not None and (federation.profile_bytes!=self.context.federation_profile_bytes or not federation.admitted
                or federation.deployment_digest!=deployment or federation.operation_digest!=invocation
                or federation.evaluated_at!=self.context.evaluated_at or federation.receiving_zone!=metadata["zone"]
                or type(metadata["exp"]) is not int or metadata["exp"]>federation.expires_at):
            raise ValidationError("Core proof cannot omit, contradict or outlive federation admission evidence")
        ambient=None if self.core.environment_assessment is None else self.core.environment_assessment.ambient
        if self.core.risk is not None:
            if (self.context.ambient_profile_bytes is not None)!=(ambient is not None):
                raise ValidationError("Core claims disagree on ambient profile selection")
            if ambient is not None and (ambient.profile_bytes!=self.context.ambient_profile_bytes
                    or ambient.deployment_digest!=deployment or ambient.operation_digest!=invocation
                    or ambient.evaluated_at!=self.context.evaluated_at or ambient.zone_id!=metadata["zone"]
                    or type(metadata["exp"]) is not int or metadata["exp"]>ambient.expires_at):
                raise ValidationError("Core proof cannot omit, contradict or outlive ambient evidence")
        repair=self.standing.repair
        if (self.context.repair_profile_bytes is not None)!=(repair is not None):
            raise ValidationError("Core claims disagree on repair policy selection")
        if repair is not None:
            if (repair.profile_bytes!=self.context.repair_profile_bytes or not repair.reentry_eligible
                    or repair.deployment_digest!=deployment or repair.operation_digest!=invocation
                    or repair.evaluated_at!=self.context.evaluated_at or repair.zone_id!=metadata["zone"]
                    or type(metadata["exp"]) is not int or metadata["exp"]>repair.expires_at):
                raise ValidationError("Core proof cannot omit, contradict or outlive repair evidence")
        boundary=self.core.boundary_assessment
        if ("boundary" in profile)!=(boundary is not None):
            raise ValidationError("Core claims disagree on boundary selection")
        if boundary is not None:
            if (not boundary.allowed or boundary.deployment_digest!=deployment or boundary.operation_digest!=invocation
                    or boundary.evaluated_at!=self.context.evaluated_at or boundary.zone_id!=metadata["zone"]
                    or type(metadata["exp"]) is not int or metadata["exp"]>boundary.expires_at):
                raise ValidationError("Core proof cannot omit, contradict or outlive its boundary")
        soul = self.core.soul_assessment
        if (soul is None or soul.deployment_digest != deployment or soul.operation_digest != invocation
                or soul.evaluated_at != self.context.evaluated_at
                or self.standing.deployment_digest != deployment or self.standing.operation_digest != invocation
                or self.standing.evaluated_at != self.context.evaluated_at
                or self.core.standing_assessment is not None and self.core.standing_assessment is not self.standing):
            raise ValidationError("Core claim assessments belong to another invocation")
        RootProofBinding(self.standing.roots, metadata["zone"], self.no_credit_reason)
        if self.core.risk is not None:
            selected = self.context.enclosure_profile_bytes is not None
            assessed = self.core.enclosure_assessment is not None
            adjusted = self.core.risk.enclosure_projection is not None
            if selected != assessed or adjusted != assessed:
                raise ValidationError("Core evidence and claims context disagree on enclosure selection")
        if self.context.enclosure_profile_bytes is not None:
            enclosure_profile = _parse_jcs_object(self.context.enclosure_profile_bytes)
            if metadata["zone"] != enclosure_profile["zone_id"]:
                raise ValidationError("proof zone differs from selected enclosure profile")
            if self.core.risk is not None:
                enclosure = self.core.enclosure_assessment
                if (enclosure is None or enclosure.profile_bytes != self.context.enclosure_profile_bytes
                        or type(metadata["exp"]) is not int or metadata["exp"] > enclosure.expires_at):
                    raise ValidationError("proof cannot outlive or omit its enclosure assessment")

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
            zone=metadata["zone"],peer_share=_wire_number(as_decimal(_parse_jcs_object(self.context.deployment_profile_bytes)["peer_share"],name="declared peer share",minimum=0,maximum=20)),
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
