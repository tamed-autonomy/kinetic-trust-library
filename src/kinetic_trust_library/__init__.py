"""Kinetic Trust Library."""

from .errors import KTPError, ValidationError
from .models.action import ValidatedActionDemand
from .models.envelope import (
    EvaluationBundle,
    EvaluationRequest,
    RejectedRequest,
)
from .models.profile import DeploymentProfile
from .models._uri import validate_absolute_uri


__version__ = "2.1.0"
KTP_SPEC_TAG = "v2.1.0"
KTP_SPEC_COMMIT = "15520035267546e1035aad7beea0cc3cf9ef8f2c"

__all__ = (
    "DeploymentProfile",
    "EvaluationBundle",
    "EvaluationRequest",
    "KTPError",
    "KTP_SPEC_TAG",
    "KTP_SPEC_COMMIT",
    "RejectedRequest",
    "ValidatedActionDemand",
    "ValidationError",
    "validate_absolute_uri",
    "__version__",
)
