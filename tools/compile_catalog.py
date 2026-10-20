#!/usr/bin/env python3
"""Verify pinned KTP v2 artifacts and compile the signal catalogue."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPOSITORY = "nmcitra/ktp-rfc"
TAG = "v2.1.0"
COMMIT = "15520035267546e1035aad7beea0cc3cf9ef8f2c"
EXPECTED_ARTIFACTS = {
    "catalog/body.json": (
        "catalog/body.json",
        "ba2a9bebcdf5e2d276714605384594594c8e58a1e9913efd164f294d4b88ae9d",
    ),
    "catalog/index.json": (
        "catalog/index.json",
        "fc7d5d08d870d6ff45231f871f858f4d8f95240a1e5b43b43b06c22554102736",
    ),
    "catalog/information.json": (
        "catalog/information.json",
        "40575732b38b7e28f2f2b36849fbaf1dae603bfa40b19d56772692e2596ab925",
    ),
    "catalog/meta.json": (
        "catalog/meta.json",
        "98eafb50ab50c2bfdec0ff63acde2f4e25287c91e872db04d4a34180cd6eb403",
    ),
    "catalog/relational.json": (
        "catalog/relational.json",
        "4e65ba4a894b67ddeca7e1672ca1f55f680a84e5ecbece077c6b570d2c6cfd5c",
    ),
    "catalog/soul.json": (
        "catalog/soul.json",
        "c08c0247a3670dd65b423e3dafc9cf3f4e6b258db0d05d17b45a135f2735b6dd",
    ),
    "catalog/time.json": (
        "catalog/time.json",
        "3f1af85df393cfba9e775d1e7c057e925c5f2f7c720c4cd2e05f50e6acab6b84",
    ),
    "catalog/world.json": (
        "catalog/world.json",
        "3604705de9a8af97a3001ad38ca3047a3c0d4bd838863b40f96ba2e3e9dab6e2",
    ),
    "conformance/aggregation-empty-window-v1.json": (
        "specifications/conformance/aggregation-empty-window-v1.json",
        "8b3403ed7889f6b3d708d2e75f7cb8b9b700e75aaa00959ef46bf6d2d35aaa73",
    ),
    "conformance/ros2-reference-v0.1.json": (
        "specifications/conformance/ros2-reference-v0.1.json",
        "fbb11fefe441c10154c5bf99bd88b63d79a6885b5b1f3a70852f83d325a8b024",
    ),
    "schemas/deployment-profile.json": (
        "schemas/deployment-profile.json",
        "c0087dc3662b8ef1988f7d612a779ca38f2b771454a45fc33abaaed6f2ebb3f2",
    ),
    "schemas/risk-factors.json": (
        "schemas/risk-factors.json",
        "a2f497489b94e727398278794389e6fbae0a44c851f19a1e5d1daafc1daa16e0",
    ),
    "schemas/sensor-config.json": (
        "schemas/sensor-config.json",
        "a9f70585fc9ba85334f972dc8dbccb9dfa0446cb18ce3d8b79cadf5d59f3ad22",
    ),
    "schemas/soul-constraint.json": (
        "schemas/soul-constraint.json",
        "94dae2a47bab45ea324e11df43d3030c4850a78e72846f46ab60a9b1399f8fd5",
    ),
    "schemas/sponsorship-bond.json": (
        "schemas/sponsorship-bond.json",
        "2718d44a473370caaf9d278f6514bd1e5ba111f3e00ff6bff2a72739c6a5025e",
    ),
    "schemas/transaction-record.json": (
        "schemas/transaction-record.json",
        "d0649fd4d7c77eb85243b37f115b48adf145cbcfd4d8b43cff912d8014fc0f12",
    ),
    "schemas/trust-proof.json": (
        "schemas/trust-proof.json",
        "41d5dd2506893094d41e21193cf95eed396dc99b8d32d7264f50ea1a7972d4e0",
    ),
}

DOMAINS = ("world", "information", "time", "soul", "relational", "body", "meta")
OBSERVATION_CLASSES = ("D", "N", "A", "P", "S")
VALUE_TYPES = frozenset({"bool", "duration", "enum", "float", "int", "string", "timestamp"})
ZERO_ONE_KINDS = frozenset({"determined", "ratio", "synthetic"})
_PART = re.compile(r"^[a-z0-9_]+$")
_SIGNAL_ID = re.compile(
    r"^(world|information|time|soul|relational|body|meta)\."
    r"[a-z0-9_]+\.[a-z0-9_]+$"
)


class CatalogCompileError(ValueError):
    """Raised when pinned inputs cannot produce the runtime catalogue."""


@dataclass(frozen=True, slots=True)
class SignalRecord:
    signal_id: str
    domain: str
    group: str
    name: str
    value_type: str
    value_range: str | None
    observation_class: str
    zero_one: str | None
    population_required: bool


@dataclass(frozen=True, slots=True)
class CatalogueData:
    signals: tuple[SignalRecord, ...]
    aliases: tuple[tuple[str, tuple[str, ...]], ...]


def parse_json_bytes(data: bytes, *, path: str) -> Any:
    """Parse strict UTF-8 JSON, rejecting duplicate keys and non-finite values."""

    def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CatalogCompileError(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise CatalogCompileError(f"{path}: non-finite JSON number {value}")

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CatalogCompileError(f"{path}: artifact is not UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=object_from_pairs,
            parse_constant=reject_constant,
        )
    except CatalogCompileError:
        raise
    except json.JSONDecodeError as exc:
        raise CatalogCompileError(f"{path}: malformed JSON: {exc.msg}") from exc


def compile_catalog(spec_root: Path) -> str:
    """Verify all pinned artifacts and return deterministic generated Python."""
    documents = _load_pinned_artifacts(spec_root)
    index = documents["catalog/index.json"]
    if not isinstance(index, dict):
        raise CatalogCompileError("catalog/index.json: root must be an object")
    domains = [documents[f"catalog/{domain}.json"] for domain in DOMAINS]
    return render_catalog_module(build_catalogue(index, domains))


def build_catalogue(index: Any, domain_documents: list[Any]) -> CatalogueData:
    """Validate parsed catalogue declarations and return sorted immutable records."""
    index_object = _require_object(index, "catalog/index.json")
    _require_exact_keys(
        index_object,
        {
            "$comment",
            "catalogue",
            "count",
            "domains",
            "classes",
            "observation_classes",
            "alias_sets",
        },
        "catalog/index.json",
    )
    _require_nonempty_string(index_object["$comment"], "catalog/index.json $comment")
    catalogue_name = _require_nonempty_string(
        index_object["catalogue"], "catalog/index.json catalogue"
    )
    if catalogue_name != "Context Signals":
        raise CatalogCompileError("catalog/index.json: unexpected catalogue identity")
    observation_class_values = _require_list(
        index_object["observation_classes"],
        "catalog/index.json observation_classes",
    )
    observation_classes = tuple(
        _require_observation_class(
            value, f"catalog/index.json observation_classes {position}"
        )
        for position, value in enumerate(observation_class_values)
    )
    if observation_classes != OBSERVATION_CLASSES:
        raise CatalogCompileError(
            "catalog/index.json: malformed observation class declaration"
        )
    index_domains = _require_count_mapping(
        index_object["domains"], DOMAINS, "catalog/index.json domains"
    )
    index_classes = _require_count_mapping(
        index_object["classes"], OBSERVATION_CLASSES, "catalog/index.json classes"
    )
    declared_total = _require_int(index_object["count"], "catalog/index.json count")

    if len(domain_documents) != len(DOMAINS):
        raise CatalogCompileError("catalogue must contain exactly seven domain documents")

    signals_by_id: dict[str, SignalRecord] = {}
    actual_domain_counts: Counter[str] = Counter()
    actual_class_counts: Counter[str] = Counter()
    seen_domains: set[str] = set()
    for position, document in enumerate(domain_documents):
        location = f"domain document {position}"
        domain_object = _require_object(document, location)
        _require_exact_keys(
            domain_object,
            {"$comment", "title", "domain", "count", "classes", "groups"},
            location,
        )
        _require_nonempty_string(
            domain_object["$comment"], f"{location} $comment"
        )
        _require_nonempty_string(domain_object["title"], f"{location} title")
        domain = _require_nonempty_string(domain_object["domain"], f"{location} domain")
        if domain not in DOMAINS or domain in seen_domains:
            raise CatalogCompileError(f"{location}: duplicate or unknown domain {domain!r}")
        seen_domains.add(domain)
        domain_classes = _require_object(
            domain_object["classes"], f"catalog/{domain}.json classes"
        )
        expected_domain_classes = _require_count_mapping(
            domain_classes,
            tuple(key for key in OBSERVATION_CLASSES if key in domain_classes),
            f"catalog/{domain}.json classes",
        )
        groups = _require_list(domain_object["groups"], f"catalog/{domain}.json groups")
        domain_class_counts: Counter[str] = Counter()
        domain_signal_count = 0
        seen_groups: set[str] = set()
        for group_position, group_value in enumerate(groups):
            group_location = f"catalog/{domain}.json group {group_position}"
            group_object = _require_object(group_value, group_location)
            _require_exact_keys(
                group_object,
                {"group", "class", "signals", "title"},
                group_location,
            )
            group = _require_part(group_object["group"], f"{group_location} group")
            if group in seen_groups:
                raise CatalogCompileError(f"{group_location}: duplicate group {group!r}")
            seen_groups.add(group)
            group_class = _require_observation_class(
                group_object["class"], f"{group_location} observation class"
            )
            _require_nonempty_string(group_object["title"], f"{group_location} title")
            signal_values = _require_list(group_object["signals"], f"{group_location} signals")
            if not signal_values:
                raise CatalogCompileError(f"{group_location}: signals must not be empty")
            for signal_position, signal_value in enumerate(signal_values):
                signal_location = f"{group_location} signal {signal_position}"
                signal = _require_object(signal_value, signal_location)
                unknown_keys = set(signal) - {
                    "id",
                    "name",
                    "type",
                    "range",
                    "class",
                    "zero_one",
                    "p",
                }
                missing_keys = {"id", "name", "type"} - set(signal)
                if unknown_keys or missing_keys:
                    raise CatalogCompileError(
                        f"{signal_location}: malformed signal fields; "
                        f"missing={sorted(missing_keys)!r}, unknown={sorted(unknown_keys)!r}"
                    )
                signal_id = _require_signal_id(signal["id"], f"{signal_location} id")
                prefix = f"{domain}.{group}."
                if not signal_id.startswith(prefix):
                    raise CatalogCompileError(
                        f"{signal_location}: signal ID does not match its domain and group"
                    )
                if signal_id in signals_by_id:
                    raise CatalogCompileError(f"duplicate signal ID {signal_id!r}")
                name = _require_nonempty_string(signal["name"], f"{signal_location} name")
                value_type = _require_nonempty_string(
                    signal["type"], f"{signal_location} type"
                )
                if value_type not in VALUE_TYPES:
                    raise CatalogCompileError(f"{signal_location}: unknown signal type")
                value_range = signal.get("range")
                if value_range is not None:
                    value_range = _require_nonempty_string(
                        value_range, f"{signal_location} range"
                    )
                observation_class = _require_observation_class(
                    signal.get("class", group_class),
                    f"{signal_location} observation class",
                )
                zero_one = signal.get("zero_one")
                if zero_one is not None:
                    zero_one = _require_nonempty_string(
                        zero_one, f"{signal_location} zero_one"
                    )
                    if zero_one not in ZERO_ONE_KINDS:
                        raise CatalogCompileError(
                            f"{signal_location}: malformed zero_one declaration"
                        )
                population_required = signal.get("p", False)
                if not isinstance(population_required, bool):
                    raise CatalogCompileError(
                        f"{signal_location}: p declaration must be boolean"
                    )
                signals_by_id[signal_id] = SignalRecord(
                    signal_id=signal_id,
                    domain=domain,
                    group=group,
                    name=name,
                    value_type=value_type,
                    value_range=value_range,
                    observation_class=observation_class,
                    zero_one=zero_one,
                    population_required=population_required,
                )
                domain_signal_count += 1
                domain_class_counts[observation_class] += 1
                actual_domain_counts[domain] += 1
                actual_class_counts[observation_class] += 1
        _require_declared_count(
            domain_object["count"], domain_signal_count, f"catalog/{domain}.json count"
        )
        if dict(domain_class_counts) != expected_domain_classes:
            raise CatalogCompileError(f"catalog/{domain}.json: class counts do not match")

    if seen_domains != set(DOMAINS):
        raise CatalogCompileError("catalogue domain set is incomplete")
    if dict(actual_domain_counts) != index_domains:
        raise CatalogCompileError("catalog/index.json: domain counts do not match")
    if dict(actual_class_counts) != index_classes:
        raise CatalogCompileError("catalog/index.json: class counts do not match")
    if declared_total != len(signals_by_id) or declared_total != 1644:
        raise CatalogCompileError("catalog/index.json: signal count must be exactly 1644")

    aliases = _validate_alias_sets(index_object["alias_sets"], signals_by_id)
    return CatalogueData(
        signals=tuple(signals_by_id[key] for key in sorted(signals_by_id)),
        aliases=tuple((key, aliases[key]) for key in sorted(aliases)),
    )


def render_catalog_module(catalogue: CatalogueData) -> str:
    """Render deterministic, dependency-minimal runtime constants."""
    lines = [
        '"""Generated immutable KTP v2 signal catalogue; do not edit by hand."""',
        "",
        "from collections.abc import Mapping",
        "from dataclasses import dataclass",
        "from types import MappingProxyType",
        "",
        "from .models._common import validate_identifier",
        "",
        "",
        "@dataclass(frozen=True, slots=True)",
        "class SignalDefinition:",
        "    signal_id: str",
        "    domain: str",
        "    group: str",
        "    name: str",
        "    value_type: str",
        "    value_range: str | None",
        "    observation_class: str",
        "    zero_one: str | None",
        "    population_required: bool",
        "",
        "",
        "CATALOG: Mapping[str, SignalDefinition] = MappingProxyType({",
    ]
    for signal in catalogue.signals:
        lines.extend(
            [
                f"    {signal.signal_id!r}: SignalDefinition(",
                f"        signal_id={signal.signal_id!r},",
                f"        domain={signal.domain!r},",
                f"        group={signal.group!r},",
                f"        name={signal.name!r},",
                f"        value_type={signal.value_type!r},",
                f"        value_range={signal.value_range!r},",
                f"        observation_class={signal.observation_class!r},",
                f"        zero_one={signal.zero_one!r},",
                f"        population_required={signal.population_required!r},",
                "    ),",
            ]
        )
    lines.extend(["})", "", "ALIASES: Mapping[str, frozenset[str]] = MappingProxyType({"])
    for name, members in catalogue.aliases:
        member_text = ", ".join(repr(member) for member in members)
        lines.append(f"    {name!r}: frozenset(({member_text},)),")
    lines.extend(
        [
            "})",
            "",
            "ENVELOPE_ELIGIBILITY: Mapping[str, str] = MappingProxyType(",
            "    {signal_id: definition.observation_class for signal_id, definition in CATALOG.items()}",
            ")",
            "_ALIAS_MEMBERSHIP: Mapping[str, str] = MappingProxyType(",
            "    {member: name for name, members in ALIASES.items() for member in members}",
            ")",
            "",
            "",
            "def validate_signal_id(value: str) -> str:",
            '    """Return a known canonical signal ID without changing it."""',
            '    validated = validate_identifier(value, name="signal ID")',
            "    if validated not in CATALOG:",
            '        raise ValueError(f"unknown signal ID: {validated}")',
            "    return validated",
            "",
            "",
            "def validate_signal_subset(values: tuple[str, ...]) -> tuple[str, ...]:",
            '    """Validate an ordered unique subset without alias double-counting."""',
            "    if not isinstance(values, tuple):",
            '        raise ValueError("signal subset must be a tuple")',
            "    seen_ids: set[str] = set()",
            "    seen_aliases: set[str] = set()",
            "    validated: list[str] = []",
            "    for value in values:",
            "        signal_id = validate_signal_id(value)",
            "        if signal_id in seen_ids:",
            '            raise ValueError(f"duplicate signal ID: {signal_id}")',
            "        alias = _ALIAS_MEMBERSHIP.get(signal_id)",
            "        if alias is not None and alias in seen_aliases:",
            '            raise ValueError(f"signal subset contains multiple members of alias set: {alias}")',
            "        seen_ids.add(signal_id)",
            "        if alias is not None:",
            "            seen_aliases.add(alias)",
            "        validated.append(signal_id)",
            "    return tuple(validated)",
            "",
        ]
    )
    return "\n".join(lines)


def _load_pinned_artifacts(spec_root: Path) -> dict[str, Any]:
    root = spec_root.resolve()
    manifest_path = root / "upstream.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise CatalogCompileError(f"cannot read {manifest_path}") from exc
    manifest = _require_object(
        parse_json_bytes(manifest_bytes, path="upstream.json"), "upstream.json"
    )
    _require_exact_keys(
        manifest, {"repository", "tag", "commit", "artifacts"}, "upstream.json"
    )
    if (
        manifest["repository"] != REPOSITORY
        or manifest["tag"] != TAG
        or manifest["commit"] != COMMIT
    ):
        raise CatalogCompileError("upstream.json: source identity does not match pinned v2")
    entries = _require_list(manifest["artifacts"], "upstream.json artifacts")
    declared: dict[str, tuple[str, str]] = {}
    for position, value in enumerate(entries):
        location = f"upstream.json artifact {position}"
        entry = _require_object(value, location)
        _require_exact_keys(entry, {"source_path", "path", "sha256"}, location)
        path = _require_nonempty_string(entry["path"], f"{location} path")
        source_path = _require_nonempty_string(
            entry["source_path"], f"{location} source_path"
        )
        digest = _require_nonempty_string(entry["sha256"], f"{location} sha256")
        if path in declared:
            raise CatalogCompileError(f"upstream.json: duplicate artifact path {path!r}")
        declared[path] = (source_path, digest)
    if declared != EXPECTED_ARTIFACTS:
        raise CatalogCompileError(
            "upstream.json: artifact inventory or digest differs from the independent pin"
        )

    documents: dict[str, Any] = {}
    for path, (_, expected_digest) in EXPECTED_ARTIFACTS.items():
        artifact_path = root / path
        try:
            resolved = artifact_path.resolve(strict=True)
            resolved.relative_to(root)
            data = resolved.read_bytes()
        except (OSError, ValueError) as exc:
            raise CatalogCompileError(f"cannot read pinned artifact {path}") from exc
        actual_digest = hashlib.sha256(data).hexdigest()
        if actual_digest != expected_digest:
            raise CatalogCompileError(
                f"{path}: digest mismatch; expected {expected_digest}, got {actual_digest}"
            )
        documents[path] = parse_json_bytes(data, path=path)
    return documents


def _validate_alias_sets(
    value: Any, signals: dict[str, SignalRecord]
) -> dict[str, tuple[str, ...]]:
    entries = _require_list(value, "catalog/index.json alias_sets")
    aliases: dict[str, tuple[str, ...]] = {}
    claimed_members: set[str] = set()
    seen_names: set[str] = set()
    common_keys = {"set", "quantity", "shape", "note", "unit_action"}
    for position, entry_value in enumerate(entries):
        location = f"catalog/index.json alias set {position}"
        entry = _require_object(entry_value, location)
        unknown = set(entry) - (common_keys | {"canonical", "aliases", "members"})
        if unknown:
            raise CatalogCompileError(f"{location}: unknown alias fields {sorted(unknown)!r}")
        name = _require_part(entry.get("set"), f"{location} set")
        if name in seen_names:
            raise CatalogCompileError(f"{location}: duplicate alias set {name!r}")
        seen_names.add(name)
        _require_nonempty_string(entry.get("quantity"), f"{location} quantity")
        for optional_field in ("note", "unit_action"):
            if optional_field in entry:
                _require_nonempty_string(
                    entry[optional_field], f"{location} {optional_field}"
                )
        shape = _require_nonempty_string(entry.get("shape"), f"{location} shape")
        if shape == "duplicate":
            if "members" in entry or "canonical" not in entry or "aliases" not in entry:
                raise CatalogCompileError(f"{location}: malformed duplicate alias set")
            canonical = _require_string_list(entry["canonical"], f"{location} canonical")
            alias_members = _require_string_list(entry["aliases"], f"{location} aliases")
            if not canonical or not alias_members:
                raise CatalogCompileError(f"{location}: alias membership must not be empty")
            members = canonical + alias_members
            if len(set(members)) != len(members):
                raise CatalogCompileError(f"{location}: duplicate alias member")
            for member in members:
                if member not in signals:
                    raise CatalogCompileError(f"{location}: unknown alias member {member!r}")
                if member in claimed_members:
                    raise CatalogCompileError(f"{location}: repeated alias member {member!r}")
                claimed_members.add(member)
            aliases[name] = tuple(sorted(members))
        elif shape == "collision":
            if "canonical" in entry or "aliases" in entry or "members" not in entry:
                raise CatalogCompileError(f"{location}: malformed collision declaration")
            members = _require_string_list(entry["members"], f"{location} members")
            if len(members) < 2 or len(set(members)) != len(members):
                raise CatalogCompileError(f"{location}: invalid collision membership")
            for member in members:
                if member not in signals:
                    raise CatalogCompileError(f"{location}: unknown collision member {member!r}")
        else:
            raise CatalogCompileError(f"{location}: unknown alias shape {shape!r}")
    return aliases


def _require_object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogCompileError(f"{location}: must be an object")
    return value


def _require_list(value: Any, location: str) -> list[Any]:
    if not isinstance(value, list):
        raise CatalogCompileError(f"{location}: must be an array")
    return value


def _require_exact_keys(
    value: dict[str, Any], expected: set[str], location: str
) -> None:
    if set(value) != expected:
        raise CatalogCompileError(
            f"{location}: fields differ; missing={sorted(expected - set(value))!r}, "
            f"unknown={sorted(set(value) - expected)!r}"
        )


def _require_nonempty_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise CatalogCompileError(f"{location}: must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CatalogCompileError(f"{location}: invalid Unicode") from exc
    return value


def _require_part(value: Any, location: str) -> str:
    text = _require_nonempty_string(value, location)
    if not _PART.fullmatch(text):
        raise CatalogCompileError(f"{location}: malformed identifier component")
    return text


def _require_signal_id(value: Any, location: str) -> str:
    text = _require_nonempty_string(value, location)
    if not _SIGNAL_ID.fullmatch(text):
        raise CatalogCompileError(f"{location}: malformed signal ID")
    return text


def _require_observation_class(value: Any, location: str) -> str:
    if not isinstance(value, str) or value not in OBSERVATION_CLASSES:
        raise CatalogCompileError(f"{location}: malformed observation class")
    return value


def _require_int(value: Any, location: str) -> int:
    if type(value) is not int or value < 0:
        raise CatalogCompileError(f"{location}: must be a non-negative integer")
    return value


def _require_declared_count(value: Any, actual: int, location: str) -> None:
    if _require_int(value, location) != actual:
        raise CatalogCompileError(f"{location}: declared count does not match content")


def _require_count_mapping(
    value: Any, keys: tuple[str, ...], location: str
) -> dict[str, int]:
    mapping = _require_object(value, location)
    if set(mapping) != set(keys):
        raise CatalogCompileError(f"{location}: keys do not match expected declarations")
    return {key: _require_int(mapping[key], f"{location} {key}") for key in mapping}


def _require_string_list(value: Any, location: str) -> list[str]:
    entries = _require_list(value, location)
    return [_require_signal_id(entry, f"{location} member") for entry in entries]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="fail if generated output is not current"
    )
    args = parser.parse_args(argv)
    repository_root = Path(__file__).resolve().parents[1]
    output_path = repository_root / "src/kinetic_trust_library/_catalog.py"
    try:
        generated = compile_catalog(repository_root / "spec/v2.1.0")
    except CatalogCompileError as exc:
        print(f"catalogue compilation failed: {exc}", file=sys.stderr)
        return 1
    if args.check:
        try:
            current = output_path.read_bytes()
        except OSError:
            current = None
        if current != generated.encode("utf-8"):
            print(f"generated catalogue is stale: {output_path}", file=sys.stderr)
            return 1
        return 0
    output_path.write_bytes(generated.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
