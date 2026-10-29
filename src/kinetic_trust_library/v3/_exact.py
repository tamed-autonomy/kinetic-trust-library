"""Context-independent conversion of terminating rational arithmetic."""
from decimal import Decimal
from fractions import Fraction


def finite_decimal(value: Fraction) -> Decimal:
    """Construct the exact Decimal without a rounded division or string limit."""
    numerator, denominator = value.numerator, value.denominator
    twos = (denominator & -denominator).bit_length() - 1
    denominator >>= twos
    fives = 0
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        raise ValueError("rational has no finite decimal expansion")
    scale = max(twos, fives)
    coefficient = abs(numerator) * 2 ** (scale - twos) * 5 ** (scale - fives)
    digits = Decimal(coefficient).as_tuple().digits
    return Decimal((int(numerator < 0), digits, -scale))
