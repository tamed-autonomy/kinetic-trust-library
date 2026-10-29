"""Exact strongest-single selection over installed root assessments.

The installed source must supply the complete required candidate set. Keeping
the set makes the choice reproducible; this calculation cannot prove that the
source disclosed every required candidate.
"""
from dataclasses import dataclass
from fractions import Fraction
import hashlib
from kinetic_trust_library.errors import ValidationError
from .installed_root import RootAssessment
from .root_projection import validate_root_projection
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time


@dataclass(frozen=True, slots=True, init=False)
class AssessedRootSelection:
    candidates: tuple[RootAssessment, ...]
    selected: RootAssessment | None
    context_bytes: bytes
    evaluated_at: int
    algorithm: str

    def __init__(self, *args, **kwargs):
        raise TypeError("AssessedRootSelection is derived by select_assessed_roots()")


def select_assessed_roots(candidates: tuple[RootAssessment, ...], *, context_bytes: bytes,
                          evaluated_at: int, algorithm: str) -> AssessedRootSelection:
    if (type(candidates) is not tuple or type(context_bytes) is not bytes
            or not _time(evaluated_at) or algorithm not in ("sha256", "sha384")):
        raise ValidationError("root selection context is invalid")
    _parse_jcs_object(context_bytes)
    eligible = []
    identities = set()
    for candidate in candidates:
        if (type(candidate) is not RootAssessment or candidate.context_bytes != context_bytes
                or candidate.evaluated_at != evaluated_at):
            raise ValidationError("root assessment belongs to another context or evaluation time")
        projection = _parse_jcs_object(candidate.projection_bytes)
        if not validate_root_projection(projection):
            raise ValidationError("root assessment projection is invalid")
        if (type(candidate.score_numerator) is not int or type(candidate.score_denominator) is not int
                or candidate.score_denominator <= 0):
            raise ValidationError("root exact score is invalid")
        score = Fraction(candidate.score_numerator, candidate.score_denominator)
        if not 0 <= score <= 100:
            raise ValidationError("root exact score is outside Core bounds")
        if projection["kind"] == "none":
            if score != 0:
                raise ValidationError("no-credit root cannot carry a score")
            continue
        prefix = "bond" if projection["kind"] == "sponsorship_bond" else "attestation"
        digest = f"{algorithm}:{hashlib.new(algorithm, candidate.complete_instrument_bytes).hexdigest()}"
        if projection[prefix + "_digest"] != digest:
            raise ValidationError("eligible root digest or score is inconsistent")
        identity = (projection["kind"], projection[prefix + "_id"])
        if identity in identities:
            raise ValidationError("duplicate root instrument in candidate set")
        identities.add(identity)
        if score == 0:
            continue
        eligible.append((score, digest, candidate))
    selected = min(eligible, key=lambda item: (-item[0], item[1]))[2] if eligible else None
    result = object.__new__(AssessedRootSelection)
    for name, value in (("candidates", candidates), ("selected", selected),
                        ("context_bytes", context_bytes), ("evaluated_at", evaluated_at), ("algorithm", algorithm)):
        object.__setattr__(result, name, value)
    return result


__all__ = ["AssessedRootSelection", "select_assessed_roots"]
