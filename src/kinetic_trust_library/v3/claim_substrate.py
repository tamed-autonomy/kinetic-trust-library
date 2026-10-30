"""Claim substrate metadata, not evidence of implemented conformance.

The RFC-set profile inventory is independently installed. Recognizing a profile
does not enable its execution, verify tests, or authorize publishing a claim.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError


def _literal(value):
    return type(value) is str and bool(value) and not any(c.isspace() for c in value)


@dataclass(frozen=True,slots=True,init=False)
class ClaimSubstrateAssessment:
    accepted: bool
    reason: str
    level: str | None
    specified_test_ids_run_under: tuple[str,str] | None
    evidence_verified: bool
    runtime_conformance_established: bool

    def __init__(self,*args,**kwargs):raise TypeError("claim substrate assessment requires an installed RFC-set inventory")


def assess_claim_substrate(claim,*,profiles_in_set):
    """Check exactly which carried substrate qualifies the stated level.

    This intentionally does not validate an entire claim, evidence URL, test
    count, execution trace or independence assertion. Even accepted metadata
    retains explicitly unverified evidence and runtime conformance.
    """
    if (type(profiles_in_set) is not tuple or len(profiles_in_set)>4096
            or any(type(p) is not tuple or len(p)!=2 or any(not _literal(v) for v in p) for p in profiles_in_set)
            or len(set(profiles_in_set))!=len(profiles_in_set)):
        raise ValidationError("RFC-set substrate inventory must be immutable, exact and unambiguous")
    accepted=False;reason="CLAIM_METADATA_INVALID";profile=None;level=None
    if type(claim) is dict:
        level=claim.get("level") if type(claim.get("level")) is str else None
        if (all(type(claim.get(k)) is str and bool(claim[k]) for k in ("product","version","level","status"))
                and level in ("Basic","Standard","Full")
                and claim["status"] in ("proposed","specified","tested","independently reproduced")):
            candidate=claim.get("substrateProfile")
            reason="CLAIM_SUBSTRATE_MISSING"
            if type(candidate) is dict and set(candidate)=={"id","version"} and all(_literal(candidate[k]) for k in ("id","version")):
                profile=(candidate["id"],candidate["version"])
                accepted=profile in profiles_in_set
                reason="CLAIM_SUBSTRATE_RECOGNIZED" if accepted else "CLAIM_SUBSTRATE_NOT_IN_SET"
    result=object.__new__(ClaimSubstrateAssessment)
    for k,v in dict(accepted=accepted,reason=reason,level=level,specified_test_ids_run_under=profile if accepted else None,
            evidence_verified=False,runtime_conformance_established=False).items():object.__setattr__(result,k,v)
    return result
