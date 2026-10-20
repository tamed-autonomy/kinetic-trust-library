from __future__ import annotations

from ._json import _state_equal
from ._models import TrajectoryLinkFinding, TrajectoryTransaction
from ._time import _compare_rfc3339


def assess_trajectory_link(
    previous: TrajectoryTransaction,
    current: TrajectoryTransaction,
    /,
) -> tuple[TrajectoryLinkFinding, ...]:
    """Assess one parser-validated adjacent pair, without authenticating it."""
    if not isinstance(previous, TrajectoryTransaction) or not isinstance(
        current, TrajectoryTransaction,
    ):
        raise TypeError("both arguments must be TrajectoryTransaction values")
    findings: list[TrajectoryLinkFinding] = []
    if current.chain_id != previous.chain_id:
        findings.append(TrajectoryLinkFinding.CHAIN_ID_MISMATCH)
    if current.sequence != previous.sequence + 1:
        findings.append(TrajectoryLinkFinding.SEQUENCE_DISCONTINUITY)
    if current.previous_hash is None:
        findings.append(TrajectoryLinkFinding.MISSING_PREVIOUS_HASH)
    elif current.previous_hash != previous.record_hash:
        findings.append(TrajectoryLinkFinding.PREVIOUS_HASH_MISMATCH)
    order = _compare_rfc3339(current.timestamp, previous.timestamp)
    if order is None:
        findings.append(TrajectoryLinkFinding.TIMESTAMP_ORDER_UNDEFINED)
    elif order <= 0:
        findings.append(TrajectoryLinkFinding.NON_INCREASING_TIMESTAMP)
    if current.previous_state is None:
        findings.append(TrajectoryLinkFinding.MISSING_PREVIOUS_STATE)
    elif not _state_equal(current.previous_state, previous.current_state):
        findings.append(TrajectoryLinkFinding.PREVIOUS_STATE_MISMATCH)
    return tuple(findings)
