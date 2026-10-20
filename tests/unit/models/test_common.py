import unittest
import importlib
import importlib.util
from datetime import datetime, timedelta, timezone, tzinfo
from decimal import Decimal
from enum import Enum, StrEnum

from kinetic_trust_library._canonical import canonical_json_bytes
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models._common import freeze_mapping, utc_time, validate_identifier


class _DuplicateKeyMapping(dict):
    def __iter__(self):
        yield from ("first", "first")


class Status(StrEnum):
    READY = "ready"


class MutableStatus(Enum):
    LEAK = ["mutable"]


class HostileDatetime(datetime):
    def replace(self, *args, **kwargs):
        return "not-a-datetime"


class HostileTimezone(tzinfo):
    def utcoffset(self, value):
        raise RuntimeError("hostile timezone")

    def dst(self, value):
        return timedelta(0)


class ObservableZeroOffsetTimezone(tzinfo):
    def __init__(self):
        self.calls = 0

    def utcoffset(self, value):
        self.calls += 1
        return timedelta(0)

    def dst(self, value):
        self.calls += 1
        return timedelta(0)


class HostileString(str):
    calls = 0

    def __hash__(self):
        type(self).calls += 1
        raise AssertionError("hostile string hash ran")

    def __eq__(self, other):
        type(self).calls += 1
        raise AssertionError("hostile string equality ran")

    def __str__(self):
        type(self).calls += 1
        raise AssertionError("hostile string coercion ran")


class CommonModuleBoundaryTests(unittest.TestCase):
    def test_old_common_module_path_is_absent(self):
        self.assertIsNone(
            importlib.util.find_spec("kinetic_trust_library.models.common")
        )
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module("kinetic_trust_library.models.common")


class CommonValueTests(unittest.TestCase):
    def test_copies_nested_mapping_and_sorts_canonical_keys(self):
        source = {"z": [Decimal("1.0")], "a": "ok"}
        owned = freeze_mapping(source)
        source["z"].append(Decimal("2"))
        self.assertEqual(owned["z"], (Decimal("1.0"),))
        self.assertEqual(
            canonical_json_bytes(owned),
            b'{"a":"ok","z":[1]}',
        )

    def test_requires_lossless_utc_and_strict_identifier(self):
        self.assertEqual(
            utc_time(datetime(2026, 8, 20, tzinfo=timezone.utc), name="cutoff").tzinfo,
            timezone.utc,
        )
        self.assertEqual(
            validate_identifier("profile.one", name="profile"), "profile.one"
        )

    def test_rejects_noncanonical_identifiers(self):
        invalid_values = ("", "Profile", "profile/one", "1" * 129, 3)
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate_identifier(value, name="profile")

    def test_identifier_rejects_string_subclasses_before_observable_hooks(self):
        HostileString.calls = 0

        with self.assertRaisesRegex(ValidationError, "exact string"):
            validate_identifier(HostileString("profile.one"), name="profile")

        self.assertEqual(HostileString.calls, 0)

    def test_rejects_naive_and_non_utc_times(self):
        values = (
            datetime(2026, 8, 20),
            datetime(2026, 8, 20, tzinfo=timezone(timedelta(hours=1))),
            datetime(2026, 8, 20, tzinfo=HostileTimezone()),
            HostileDatetime(2026, 8, 20, tzinfo=timezone.utc),
            "2026-08-20T00:00:00Z",
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                utc_time(value, name="cutoff")

    def test_rejects_custom_zero_offset_timezone_without_invoking_its_hooks(self):
        custom_timezone = ObservableZeroOffsetTimezone()
        value = datetime(2026, 8, 20, tzinfo=custom_timezone)

        with self.assertRaisesRegex(ValidationError, "exact UTC"):
            utc_time(value, name="cutoff")

        self.assertEqual(custom_timezone.calls, 0)

    def test_rejects_observable_duplicate_keys_and_mutable_aliases(self):
        shared = ["one"]
        for value in (
            _DuplicateKeyMapping(first="one"),
            {"first": shared, "second": shared},
        ):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                freeze_mapping(value)

    def test_rejects_mutable_enum_values_without_rejecting_scalar_enums(self):
        owned = freeze_mapping({"status": Status.READY})
        self.assertEqual(canonical_json_bytes(owned), b'{"status":"ready"}')
        with self.assertRaises(ValidationError):
            freeze_mapping({"status": MutableStatus.LEAK})
