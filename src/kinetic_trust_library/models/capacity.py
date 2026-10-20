"""Immutable, Library-derived KTP-Core capacity facts."""

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from kinetic_trust_library.models.profile import ProfileRef


class CapacityRelation(StrEnum):
    BELOW_CAPACITY = "below_capacity"
    AT_CAPACITY = "at_capacity"
    ABOVE_CAPACITY = "above_capacity"


@dataclass(frozen=True, slots=True, init=False)
class CoreCapacityResult:
    operation_id: str
    profile_ref: ProfileRef
    profile_digest: str
    action_id: str
    action_digest: str
    trust_digest: str
    cutoff: datetime
    autonomy_demand: Decimal
    effective_trust: Decimal
    relation: CapacityRelation
    digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("CoreCapacityResult values are created by evaluate()")

    @property
    def within_capacity(self) -> bool:
        from kinetic_trust_library.core.capacity import (
            require_validated_core_capacity_result,
        )

        require_validated_core_capacity_result(self)
        return self.relation is not CapacityRelation.ABOVE_CAPACITY


__all__ = ["CapacityRelation", "CoreCapacityResult"]
