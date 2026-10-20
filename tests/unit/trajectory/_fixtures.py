from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path


def official_transaction() -> dict[str, object]:
    path = Path(__file__).resolve().parents[3] / "spec/v2.1.0/schemas/transaction-record.json"
    return deepcopy(json.loads(path.read_text(encoding="utf-8"))["examples"][0])


def adjacent_transaction(previous: dict[str, object]) -> dict[str, object]:
    current = deepcopy(previous)
    current.update(
        record_id="tr-002",
        chain_id=previous["chain_id"],
        sequence=previous["sequence"] + 1,
        timestamp="2025-01-15T10:00:02Z",
        previous_hash=previous["record_hash"],
        previous_state=deepcopy(previous["current_state"]),
        record_hash="sha256:def456...",
    )
    return current
