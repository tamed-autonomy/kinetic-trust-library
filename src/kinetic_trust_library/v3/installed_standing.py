"""Context-bound native software standing from an installed evidence provider.

The provider authenticates PoR acts/corrections, derives their Identity-defined
contribution and adversity exposure, verifies identity/trajectory and independent
peer evidence, extra ceilings and the complete required root candidate set. This
boundary derives Core shares and ceilings; it supplies no human standing model.
"""
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import ValidationError
from .assessed_root_selection import AssessedRootSelection
from .base_trust import NativeBaseTrust, calculate_native_base_trust
from .demand_operation import canonical_demand_operation_bytes, digest_demand_operation
from .demand_supplier import _digest
from .root_lifecycle import _time
from .trust_proof_json import _parse_jcs_object
from .installed_repair import InstalledRepairVerifier,RepairAssessment


@dataclass(frozen=True, slots=True)
class AuthenticatedStandingEvidence:
    body_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class NativeStandingAssessment:
    base: NativeBaseTrust
    roots: AssessedRootSelection
    original_evidence: bytes
    authenticated_body_bytes: bytes
    deployment_digest: str
    operation_digest: str
    evaluated_at: int
    repair: RepairAssessment | None

    def __init__(self, *args, **kwargs):
        raise TypeError("NativeStandingAssessment is derived by an installed standing verifier")


@dataclass(frozen=True, slots=True)
class InstalledStandingVerifier:
    deployment_profile_bytes: bytes
    adapter: object
    algorithm: str
    repair_verifier: InstalledRepairVerifier | None = None

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or self.algorithm not in ("sha256", "sha384")
                or not callable(getattr(self.adapter, "verify", None))):
            raise ValidationError("installed standing verifier is invalid")
        _parse_jcs_object(self.deployment_profile_bytes)
        if self.repair_verifier is not None and (type(self.repair_verifier) is not InstalledRepairVerifier
                or self.repair_verifier.deployment_profile_bytes!=self.deployment_profile_bytes
                or self.repair_verifier.algorithm!=self.algorithm):
            raise ValidationError("repair and standing policies must share a deployment/digest algorithm")

    def evaluate(self, evidence: bytes, *, roots: AssessedRootSelection,
                 actual_operation: dict, evaluated_at: int) -> NativeStandingAssessment:
        if type(evidence) is not bytes or type(roots) is not AssessedRootSelection or not _time(evaluated_at):
            raise ValidationError("installed standing inputs are invalid")
        operation_bytes = canonical_demand_operation_bytes(actual_operation)
        operation = _parse_jcs_object(operation_bytes)
        profile = _parse_jcs_object(self.deployment_profile_bytes)
        deployment_digest = _digest(profile, self.algorithm)
        repair=None
        if self.repair_verifier is not None:
            repair=self.repair_verifier.evaluate(actual_operation=operation,evaluated_at=evaluated_at,clock_healthy=True)
            if not repair.reentry_eligible:raise ValidationError(repair.reason)
        root_context = _parse_jcs_object(roots.context_bytes)
        if (roots.evaluated_at != evaluated_at or roots.algorithm != self.algorithm
                or root_context.get("deployment_digest") != deployment_digest
                or root_context.get("subject") != operation["actor"]
                or root_context.get("subject_profile") != "software"
                or root_context.get("hop_bound") != profile.get("external_root", {}).get("hop_bound")):
            raise ValidationError("root selection belongs to another standing context")
        authenticated = self.adapter.verify(evidence, deployment_profile_bytes=self.deployment_profile_bytes,
                                            operation_bytes=operation_bytes, evaluated_at=evaluated_at,
                                            root_selection=roots)
        if type(authenticated) is not AuthenticatedStandingEvidence or type(authenticated.body_bytes) is not bytes:
            raise ValidationError("standing adapter returned invalid evidence")
        body = _parse_jcs_object(authenticated.body_bytes)
        try:
            generation, ial, trajectory = body["generation"], body["identity_assurance_level"], body["trajectory_length"]
            if (type(generation) is not int or generation < 0 or type(ial) is not int or ial not in (1, 2, 3)
                    or type(trajectory) is not int or trajectory < 0 or trajectory > 2**53 - 1
                    or body["subject"] != operation["actor"]):
                raise ValidationError("standing identity or trajectory is invalid")
            lineage = "sponsored" if generation < 3 else "independent" if generation < 7 else "guarantor"
            if root_context.get("generation") != generation or root_context.get("lineage") != lineage:
                raise ValidationError("standing identity differs from root evaluation")
            friction = as_decimal(body["maximum_adversity_friction"], name="adversity friction", minimum=0, maximum=1)
            crisis = body["crisis_exposure"]
            if type(crisis) is not bool or (crisis and friction < Decimal("0.9")):
                raise ValidationError("standing adversity evidence is inconsistent")
            extra = body["additional_ceilings"]
            if type(extra) is not dict or set(extra) & {"generation", "ial", "trajectory", "adversity", "external_root_missing","repair_reentry"}:
                raise ValidationError("additional ceilings cannot replace built-in ceilings")
            ceilings = {**extra, "generation": (25,35,45,55,65,75,85)[generation] if generation < 7 else 100,
                        "ial": {1:40,2:80,3:95}[ial],
                        "trajectory": 50 if trajectory < 1000 else 70 if trajectory < 10000 else 100,
                        "adversity": 100 if crisis else 90 if friction > Decimal("0.7") else 80 if friction > Decimal("0.5") else 60}
            if repair is not None and repair.standing_ceiling is not None:ceilings["repair_reentry"]=repair.standing_ceiling
            base = calculate_native_base_trust(
                por_contribution=body["por_contribution"], root_score=0 if roots.selected is None else
                    Fraction(roots.selected.score_numerator,roots.selected.score_denominator),
                peer_share=profile["peer_share"], peer_score=body["peer_score"], ceilings=ceilings)
        except (KeyError, TypeError) as exc:
            raise ValidationError("standing evidence is incomplete") from exc
        result = object.__new__(NativeStandingAssessment)
        for name, value in (("base", base), ("roots", roots), ("original_evidence", evidence),
                            ("authenticated_body_bytes", authenticated.body_bytes),
                            ("deployment_digest", deployment_digest),
                            ("operation_digest", digest_demand_operation(operation, algorithm=self.algorithm)),
                            ("evaluated_at", evaluated_at),("repair",repair)):
            object.__setattr__(result, name, value)
        return result


__all__ = ["AuthenticatedStandingEvidence", "NativeStandingAssessment", "InstalledStandingVerifier"]
