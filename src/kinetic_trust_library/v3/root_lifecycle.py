"""Pure External Root lifecycle over independently authenticated events.

The installed instrument adapter must establish issuer/adjudicator roles,
signatures, exact complete event/instrument digests, non-conflicting authoritative
history and subject bindings. This primitive never authenticates those claims.
"""
from dataclasses import dataclass
import re
from kinetic_trust_library.errors import ValidationError


_DIGEST = re.compile(r"(?:sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96})\Z")


def _time(value):
    return type(value) is int and 0 <= value <= 2**53 - 1


@dataclass(frozen=True, slots=True)
class RootLifecycleEvent:
    digest: str
    instrument_digest: str
    subject: str
    event_time: int
    action: str
    claim_digest: str | None = None
    finding: str | None = None

    def __post_init__(self):
        if (not _time(self.event_time) or type(self.subject) is not str or not self.subject
                or any(type(d) is not str or _DIGEST.fullmatch(d) is None
                       for d in (self.digest, self.instrument_digest))
                or self.action not in ("withdraw_for_cause", "withdraw_without_cause", "finding")):
            raise ValidationError("root lifecycle event is invalid")
        if self.action == "finding":
            if (type(self.claim_digest) is not str or _DIGEST.fullmatch(self.claim_digest) is None
                    or self.finding not in ("rejected", "sustained", "misattestation")):
                raise ValidationError("root lifecycle finding is invalid")
        elif self.claim_digest is not None or self.finding is not None:
            raise ValidationError("withdrawal cannot contain a finding")


def project_root_lifecycle(*, instrument_digest: str, subject: str, start_time: int,
                           end_time: int, now: int, events: tuple[RootLifecycleEvent, ...]) -> str:
    """Return current/non_renewable or an established no-credit lifecycle reason."""
    if (any(not _time(t) for t in (start_time, end_time, now)) or start_time >= end_time
            or type(events) is not tuple or any(type(e) is not RootLifecycleEvent for e in events)
            or type(instrument_digest) is not str or _DIGEST.fullmatch(instrument_digest) is None
            or type(subject) is not str or not subject):
        raise ValidationError("root lifecycle context is invalid")
    if now < start_time:
        return "invalid_instrument"
    if any(e.instrument_digest != instrument_digest or e.subject != subject for e in events):
        return "unverifiable"
    distinct = {}
    for event in events:
        if event.digest in distinct and distinct[event.digest] != event:
            return "unverifiable"
        distinct[event.digest] = event
    active = tuple(e for e in distinct.values() if e.event_time <= now)
    if any(e.event_time < start_time or e.event_time >= end_time for e in active):
        return "unverifiable"
    claims = {e.digest: e for e in active if e.action == "withdraw_for_cause"}
    findings = {}
    for event in active:
        if event.action != "finding":
            continue
        claim = claims.get(event.claim_digest)
        if claim is None or event.event_time < claim.event_time:
            return "unverifiable"
        prior = findings.get(event.claim_digest)
        if prior is not None and prior != event.finding:
            return "unverifiable"
        findings[event.claim_digest] = event.finding
    unresolved = set(claims) - set(findings)
    if now >= end_time:
        return "unresolved_lapse" if unresolved else "expired"
    if "misattestation" in findings.values():
        return "misattestation"
    if "sustained" in findings.values():
        return "for_cause_sustained"
    if unresolved:
        return "for_cause_pending"
    if findings:
        return "for_cause_rejected"
    if any(e.action == "withdraw_without_cause" for e in active):
        return "non_renewable"
    return "current"


__all__ = ["RootLifecycleEvent", "project_root_lifecycle"]
