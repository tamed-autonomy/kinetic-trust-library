"""Exact decimal conversion at public scalar boundaries."""

from decimal import Context, Decimal, InvalidOperation, localcontext
from typing import TypeAlias

from .errors import ConfigurationError, ValidationError

DecimalLike: TypeAlias = int | float | str | Decimal
KTP_CONTEXT = Context(prec=34)
MAX_DECIMAL_SIGNIFICANT_DIGITS = 34
MIN_DECIMAL_ADJUSTED_EXPONENT = -6143
MAX_DECIMAL_ADJUSTED_EXPONENT = 6144
# With public A bounded to 100 and the smallest canonical positive E equal to
# 1E-6143, the exact Kinetic Envelope margin 1-A/E may have adjusted exponent
# 6145. At precision 34, the smallest nonzero positive margin is 1E-34.
MIN_DERIVED_MARGIN_ADJUSTED_EXPONENT = -34
MAX_DERIVED_MARGIN_ADJUSTED_EXPONENT = 6145
MAX_DECIMAL_TEXT_LENGTH = 128
_MAX_INTEGER_MAGNITUDE = 10**MAX_DECIMAL_SIGNIFICANT_DIGITS


def as_decimal(
    value: DecimalLike,
    *,
    name: str,
    minimum: DecimalLike | None = None,
    maximum: DecimalLike | None = None,
) -> Decimal:
    """Convert a finite scalar to Decimal and enforce optional inclusive bounds."""
    minimum_value = (
        as_decimal(minimum, name=f"{name} minimum") if minimum is not None else None
    )
    maximum_value = (
        as_decimal(maximum, name=f"{name} maximum") if maximum is not None else None
    )
    if (
        minimum_value is not None
        and maximum_value is not None
        and minimum_value > maximum_value
    ):
        raise ConfigurationError(f"{name} minimum exceeds maximum")
    if isinstance(value, bool):
        raise ValidationError(f"{name} must be numeric, not bool")
    if isinstance(value, str) and len(value) > MAX_DECIMAL_TEXT_LENGTH:
        raise ValidationError(f"{name} decimal text is too long")
    if isinstance(value, int) and abs(value) >= _MAX_INTEGER_MAGNITUDE:
        raise ValidationError(f"{name} exceeds decimal precision")
    try:
        source = repr(value) if isinstance(value, float) else value
        with localcontext(KTP_CONTEXT):
            result = Decimal(source)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValidationError(f"{name} is not a decimal") from exc
    if not result.is_finite():
        raise ValidationError(f"{name} must be finite")
    if len(result.as_tuple().digits) > MAX_DECIMAL_SIGNIFICANT_DIGITS:
        raise ValidationError(f"{name} exceeds decimal precision")
    adjusted = result.adjusted()
    if (
        adjusted < MIN_DECIMAL_ADJUSTED_EXPONENT
        or adjusted > MAX_DECIMAL_ADJUSTED_EXPONENT
    ):
        raise ValidationError(f"{name} exceeds decimal exponent range")
    if minimum_value is not None and result < minimum_value:
        raise ValidationError(f"{name} is below its minimum")
    if maximum_value is not None and result > maximum_value:
        raise ValidationError(f"{name} is above its maximum")
    return result


def require_derived_margin(value: object) -> Decimal:
    """Validate an internally derived exact margin without widening inputs."""

    if type(value) is not Decimal or not value.is_finite():
        raise ValidationError("derived margin must be an exact finite Decimal")
    if len(value.as_tuple().digits) > MAX_DECIMAL_SIGNIFICANT_DIGITS:
        raise ValidationError("derived margin exceeds decimal precision")
    if not value.is_zero() and (
        value.adjusted() < MIN_DERIVED_MARGIN_ADJUSTED_EXPONENT
        or value.adjusted() > MAX_DERIVED_MARGIN_ADJUSTED_EXPONENT
    ):
        raise ValidationError("derived margin exceeds its closed exponent range")
    if value > 1:
        raise ValidationError("derived margin must not exceed one")
    return value
