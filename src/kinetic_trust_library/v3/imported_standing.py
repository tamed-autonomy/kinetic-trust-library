"""Exact crossing-time federation standing; no local/imported accumulation.

Pure inputs require authentication by an installed receiving-zone source. The
exportable amount must be independently established as earned within the sender;
a foreign proof's total E_base, R or E_trust is not a substitute. No PoR/root/peer
shares are invented for this route.
"""
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import ValidationError
from .ambient_repair import ratio
from .base_trust import NativeBaseTrust,_REQUIRED_CEILINGS,_BUILT_IN_VALUES
from ._exact import finite_decimal


@dataclass(frozen=True,slots=True,init=False)
class FederationFactorProjection:
    applied_factor: Fraction | None
    clause_void: bool
    floor_valid: bool | None
    reason: str

    def __init__(self,*args,**kwargs):raise TypeError("derive a federation factor from authenticated directional terms")


def derive_federation_factor(*,signed_factor,receiver_signed,class_ceiling=1,lowered_factor=None,declared_floor=0):
    """Use one factor, capped by the signed receiver term and class ceiling.

    Lowered factor and floor must come from a declared agreement policy. An
    invalid high floor is ignored and reported; it never increases the signed or
    class bound. No unavailable direction becomes reciprocal by default.
    """
    if type(receiver_signed) is not bool:raise ValidationError("receiver signature status must be explicit")
    signed=None if signed_factor is None else ratio(signed_factor,name="signed federation factor")
    ceiling=ratio(class_ceiling,name="enforcement class factor ceiling",maximum=1)
    lowered=None if lowered_factor is None else ratio(lowered_factor,name="declared lowered factor")
    floor=ratio(declared_floor,name="declared factor floor")
    applied=None;valid=None;void=False;reason="FEDERATION_DIRECTION_UNAVAILABLE"
    if signed is not None and signed>1:
        void=True;reason="FEDERATION_FACTOR_CLAUSE_VOID"
    elif receiver_signed and signed is not None:
        cap=min(signed,ceiling);valid=floor<=cap
        applied=min(cap,cap if lowered is None else lowered)
        if valid:applied=max(applied,floor)
        reason="FEDERATION_FACTOR_DERIVED"
    result=object.__new__(FederationFactorProjection)
    for name,value in dict(applied_factor=applied,clause_void=void,floor_valid=valid,reason=reason).items():
        object.__setattr__(result,name,value)
    return result


@dataclass(frozen=True,slots=True,init=False)
class NativeImportedStanding:
    source_zone: str
    receiving_zone: str
    exportable_base: Fraction
    factor: FederationFactorProjection
    raw_base: Fraction
    base_trust: Decimal
    ceilings: tuple[tuple[str,Decimal],...]
    binding_ceilings: tuple[str,...]

    def __init__(self,*args,**kwargs):raise TypeError("imported standing requires the derived crossing-time route")


def calculate_imported_standing(*,exportable_base,factor,source_zone,receiving_zone,ceilings,root_available):
    """Apply authenticated exportable standing, one factor and receiver ceilings.

    This software crossing route preserves independently derived receiver
    ceilings and the missing-root bound. Person standing is a separate route.
    It supplies no combined local/imported standing formula or permission.
    """
    if (type(factor) is not FederationFactorProjection or factor.applied_factor is None
            or any(type(zone) is not str or not zone for zone in (source_zone,receiving_zone))
            or source_zone==receiving_zone or type(root_available) is not bool):
        raise ValidationError("imported standing requires an available directional factor and distinct zones")
    base=ratio(exportable_base,name="sender locally earned exportable standing",maximum=100)
    if (type(ceilings) is not dict or any(type(name) is not str or not name for name in ceilings)
            or not _REQUIRED_CEILINGS<=ceilings.keys()):
        raise ValidationError("imported software standing requires every receiver ceiling")
    bounded={name:as_decimal(value,name="receiver "+name+" ceiling",minimum=0,maximum=100) for name,value in ceilings.items()}
    if any(bounded[name] not in allowed for name,allowed in _BUILT_IN_VALUES.items()):
        raise ValidationError("receiver built-in ceiling is not an RFC value")
    if not root_available:bounded["external_root_missing"]=min(bounded.get("external_root_missing",Decimal(70)),Decimal(70))
    raw=base*factor.applied_factor
    try:effective=finite_decimal(min(raw,*(Fraction(value) for value in bounded.values())))
    except ValueError as exc:raise ValidationError("nonterminating imported standing requires a declared wire precision profile") from exc
    result=object.__new__(NativeImportedStanding)
    for name,value in dict(source_zone=source_zone,receiving_zone=receiving_zone,exportable_base=base,factor=factor,
            raw_base=raw,base_trust=effective,ceilings=tuple(sorted(bounded.items())),
            binding_ceilings=tuple(sorted(name for name,value in bounded.items() if value==effective))).items():
        object.__setattr__(result,name,value)
    return result


BoundedStanding = NativeBaseTrust | NativeImportedStanding
BOUNDED_STANDING_TYPES=(NativeBaseTrust,NativeImportedStanding)

__all__=("FederationFactorProjection","derive_federation_factor","NativeImportedStanding","calculate_imported_standing","BoundedStanding")
