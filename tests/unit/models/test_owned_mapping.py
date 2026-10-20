"""Portable ownership invariants for the private immutable mapping module."""

import unittest

from kinetic_trust_library._owned_mapping import (
    _owned_mapping_from_dict,
    _require_owned_mapping_items,
)
from kinetic_trust_library.errors import ValidationError


class _ArmedValue:
    calls = 0

    def __eq__(self, _other):
        type(self).calls += 1
        raise RuntimeError("armed mapping equality")

    def __hash__(self):
        type(self).calls += 1
        raise RuntimeError("armed mapping hashing")


class OwnedMappingTests(unittest.TestCase):
    def test_mapping_owns_source_and_exposes_only_read_only_mapping_behavior(self):
        source = {"one": object(), "two": object()}
        owned = _owned_mapping_from_dict(source)

        self.assertEqual(tuple(owned), ("one", "two"))
        self.assertEqual(len(owned), 2)
        self.assertIs(owned["one"], source["one"])
        source.clear()
        self.assertEqual(tuple(owned), ("one", "two"))
        with self.assertRaises(TypeError):
            owned["three"] = object()

    def test_forged_internal_index_rejects_without_hostile_hooks(self):
        owned = _owned_mapping_from_dict({"one": object()})
        hostile = _ArmedValue()
        object.__setattr__(owned, "_index", {"one": hostile})
        _ArmedValue.calls = 0

        with self.assertRaises(ValidationError):
            _require_owned_mapping_items(owned, name="test mapping")
        self.assertEqual(_ArmedValue.calls, 0)


if __name__ == "__main__":
    unittest.main()
