from __future__ import annotations

import re
from typing import Literal, cast

from ..errors import ValidationError


_RFC3339 = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?"
    r"([Zz]|([+-])([0-9]{2}):([0-9]{2}))"
)


def _month_lengths(year: int) -> tuple[int, ...]:
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    return (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _ordinal(year: int, month: int, day: int) -> int:
    # Count from Gregorian year 0000; floor division also handles UTC year -1.
    before_year = 365 * year + (year + 3) // 4 - (year + 99) // 100 + (year + 399) // 400
    return before_year + sum(_month_lengths(year)[:month - 1]) + day - 1


def _parse_rfc3339(value: object, name: str) -> tuple[int, str, bool]:
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be an RFC 3339 string")
    match = _RFC3339.fullmatch(value)
    if match is None:
        raise ValidationError(f"{name} must use RFC 3339 syntax")
    year, month, day, hour, minute, second = (int(match[i]) for i in range(1, 7))
    if not 1 <= month <= 12 or not 1 <= day <= _month_lengths(year)[month - 1]:
        raise ValidationError(f"{name} has an invalid Gregorian date")
    if hour > 23 or minute > 59 or second > 60:
        raise ValidationError(f"{name} has an invalid time")
    offset = 0
    if match[9] is not None:
        offset_hour, offset_minute = int(match[10]), int(match[11])
        if offset_hour > 23 or offset_minute > 59:
            raise ValidationError(f"{name} has an invalid offset")
        offset = (offset_hour * 60 + offset_minute) * 60
        if match[9] == "-":
            offset = -offset
    leap = second == 60
    seconds = (
        _ordinal(year, month, day) * 86400
        + hour * 3600 + minute * 60 + min(second, 59) - offset
    )
    if leap:
        utc_day, utc_second = divmod(seconds, 86400)
        insertion_days = {
            _ordinal(candidate, insertion_month, insertion_day)
            for candidate in (year - 1, year, year + 1)
            for insertion_month, insertion_day in ((6, 30), (12, 31))
        }
        if utc_second != 86399 or utc_day not in insertion_days:
            raise ValidationError(f"{name} is not a possible UTC positive-leap insertion")
    return seconds, match[7] or "", leap


def _validate_rfc3339(value: object, name: str) -> str:
    _parse_rfc3339(value, name)
    return cast(str, value)


def _compare_rfc3339(left: str, right: str) -> Literal[-1, 0, 1] | None:
    """Return left-vs-right order, or None when ordering is undefined."""
    left_seconds, left_fraction, left_leap = _parse_rfc3339(left, "left timestamp")
    right_seconds, right_fraction, right_leap = _parse_rfc3339(right, "right timestamp")
    if left_leap or right_leap:
        return None
    precision = max(len(left_fraction), len(right_fraction))
    left_instant = (left_seconds, left_fraction.ljust(precision, "0"))
    right_instant = (right_seconds, right_fraction.ljust(precision, "0"))
    if left_instant < right_instant:
        return -1
    if left_instant > right_instant:
        return 1
    return 0
