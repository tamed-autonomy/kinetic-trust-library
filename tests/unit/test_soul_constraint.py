"""Official KTP v2.1 Soul Constraint document parsing."""

from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from decimal import Decimal
import json
from pathlib import Path
import unittest

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.soul_constraint import (
    SoulConstraintDocument,
    SoulConstraintType,
    parse_soul_constraint,
)


_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "spec"
    / "v2.1.0"
    / "schemas"
    / "soul-constraint.json"
)


class _StringSubclass(str):
    pass


class SoulConstraintDocumentTests(unittest.TestCase):
    def test_all_official_examples_parse_to_detached_frozen_values(self) -> None:
        schema = json.loads(_SCHEMA_PATH.read_bytes())
        expected = (
            (0, None, None, None, None, None, None),
            (
                1,
                SoulConstraintType.TK_LABEL,
                "TK-NC-001",
                "TK Non-Commercial",
                "https://localcontexts.org/label/tk-nc/",
                "Example Indigenous Community",
                "Contact community data steward for commercial licensing",
            ),
            (
                1,
                SoulConstraintType.SACRED_LAND,
                "geofence-001",
                "Sacred Site Boundary",
                "https://tribal-lands.example.org/",
                "Example Tribe",
                "Activity not permitted within sacred site boundaries",
            ),
            (
                1,
                SoulConstraintType.OCAP,
                "ocap-possession",
                "OCAP Possession Principle",
                "https://fnigc.ca/ocap/",
                "First Nation Community",
                "Data must remain within community-controlled infrastructure",
            ),
        )

        for source_example, expected_fields in zip(
            schema["examples"], expected, strict=True
        ):
            source = copy.deepcopy(source_example)
            parsed = parse_soul_constraint(source)
            with self.subTest(soul=parsed.soul, type=parsed.constraint_type):
                self.assertIsInstance(parsed, SoulConstraintDocument)
                self.assertEqual(
                    (
                        parsed.soul,
                        parsed.constraint_type,
                        parsed.constraint_id,
                        parsed.constraint_name,
                        parsed.authority,
                        parsed.community,
                        parsed.remediation,
                    ),
                    expected_fields,
                )
                source.clear()
                self.assertEqual(parsed.soul, expected_fields[0])
                with self.assertRaises(FrozenInstanceError):
                    parsed.soul = 1  # type: ignore[misc]

    def test_all_published_constraint_types_are_accepted(self) -> None:
        for constraint_type in SoulConstraintType:
            with self.subTest(constraint_type=constraint_type.value):
                parsed = parse_soul_constraint(
                    {
                        "soul": 1,
                        "constraint_type": constraint_type.value,
                        "authority": "",
                    }
                )
                self.assertIs(parsed.constraint_type, constraint_type)

    def test_root_shape_required_member_and_unknown_members_are_rejected(self) -> None:
        invalid_documents = (
            None,
            [],
            {},
            {"soul": 0, "unknown": None},
            {"soul": 0, 1: "not-a-string-key"},
        )

        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(ValidationError):
                parse_soul_constraint(document)  # type: ignore[arg-type]

    def test_soul_requires_exact_integer_zero_or_one(self) -> None:
        for value in (True, False, -1, 2, 0.0, Decimal("0"), "0", None):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                parse_soul_constraint({"soul": value})

    def test_optional_members_require_exact_strings_or_none(self) -> None:
        text_members = (
            "constraint_id",
            "constraint_name",
            "authority",
            "community",
            "remediation",
        )
        for member in text_members:
            for value in (1, True, _StringSubclass("text"), [], {}):
                with (
                    self.subTest(member=member, value=value),
                    self.assertRaises(ValidationError),
                ):
                    parse_soul_constraint({"soul": 0, member: value})

        for value in ("unknown", 1, True, _StringSubclass("care"), [], {}):
            with self.subTest(constraint_type=value), self.assertRaises(ValidationError):
                parse_soul_constraint({"soul": 0, "constraint_type": value})

        for member in (*text_members, "constraint_type"):
            with self.subTest(member=member):
                parsed = parse_soul_constraint({"soul": 0, member: None})
                self.assertIsNone(getattr(parsed, member))

    def test_veto_requires_non_null_type_and_authority(self) -> None:
        invalid_documents = (
            {"soul": 1},
            {"soul": 1, "constraint_type": "care"},
            {"soul": 1, "authority": "authority"},
            {"soul": 1, "constraint_type": None, "authority": "authority"},
            {"soul": 1, "constraint_type": "care", "authority": None},
        )

        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(ValidationError):
                parse_soul_constraint(document)

    def test_clear_details_and_annotation_only_authority_are_schema_valid(self) -> None:
        clear = parse_soul_constraint(
            {
                "soul": 0,
                "constraint_type": "care",
                "constraint_id": "",
                "constraint_name": "Clear detail",
                "authority": "not an absolute URI",
                "community": "Community",
                "remediation": "None required",
            }
        )
        veto = parse_soul_constraint(
            {
                "soul": 1,
                "constraint_type": "care",
                "authority": "not an absolute URI",
            }
        )

        self.assertEqual(clear.constraint_type, SoulConstraintType.CARE)
        self.assertEqual(clear.authority, "not an absolute URI")
        self.assertEqual(veto.authority, "not an absolute URI")


if __name__ == "__main__":
    unittest.main()
