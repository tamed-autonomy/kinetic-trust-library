"""Bounded erasure accounting from independently authenticated live evidence.

The installed resolver authenticates the complete receipt, approved privacy
policy, fenced inventory, disposal, every usable key path, retention authority
and recipient acknowledgements. It receives the installed lookup context only.
This module checks that evidence; it never deletes data or clears safety state.
"""
from dataclasses import dataclass

from kinetic_trust_library.errors import ValidationError, ProofFormatError
from .root_lifecycle import _time
from .trust_proof_json import _parse_jcs_object


class ErasureContextUnavailable(Exception):
    """No current authenticated accounting context can be established."""


@dataclass(frozen=True, slots=True)
class AuthenticatedErasureContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class ErasureAccountingResult:
    reason: str
    status: str | None
    conformance_level: int
    checked_at: int
    expected_context_bytes: bytes
    receipt_bytes: bytes | None
    authenticated_state_bytes: bytes | None
    source_evidence_bytes: bytes | None
    overdue_retention_copy_ids: tuple[str, ...]

    def __init__(self, *args, **kwargs):
        raise TypeError("erasure accounting results are derived by an installed verifier")


@dataclass(frozen=True, slots=True)
class InstalledErasureReceiptVerifier:
    """Verify accounting within the exact declared scope and cutoff.

    expected_context_bytes is an installed Library lookup contract, not a new
    RFC wire format. The resolver owns authenticating the receipt independently
    of candidate bytes and rechecking inventory/evidence at checked_at. Receipt
    metadata and retained source evidence remain purpose-limited personal data.
    """
    expected_context_bytes: bytes
    adapter: object

    def __post_init__(self):
        from . import _human_reference as h
        if (type(self.expected_context_bytes) is not bytes
                or not callable(getattr(self.adapter, "resolve", None))):
            raise ValidationError("installed erasure verifier is invalid")
        context = _parse_jcs_object(self.expected_context_bytes)
        if (set(context) != {"receipt_id", "request_digest", "subject_scope_digest",
                             "privacy_policy_digest", "conformance_level"}
                or type(context["conformance_level"]) is not int
                or context["conformance_level"] not in (1, 2, 3)):
            raise ValidationError("installed erasure lookup context is invalid")
        try:
            h.literal(context["receipt_id"])
            for field in ("request_digest", "subject_scope_digest", "privacy_policy_digest"):
                h.check_digest(context[field], context["conformance_level"])
        except h.InvalidRecord as error:
            raise ValidationError(str(error)) from error

    def verify(self, receipt_bytes: bytes, *, now: int, clock_healthy: bool) -> ErasureAccountingResult:
        from . import _human_reference as h
        if type(receipt_bytes) is not bytes or not _time(now):
            raise ValidationError("erasure accounting requires immutable receipt bytes and trusted time")
        expected = _parse_jcs_object(self.expected_context_bytes)
        level = expected["conformance_level"]
        values = dict(reason="ERASURE_UNAVAILABLE", status=None, conformance_level=level,
                      checked_at=now, expected_context_bytes=self.expected_context_bytes,
                      receipt_bytes=None, authenticated_state_bytes=None, source_evidence_bytes=None,
                      overdue_retention_copy_ids=())

        def result():
            value = object.__new__(ErasureAccountingResult)
            for name, member in values.items():
                object.__setattr__(value, name, member)
            return value

        if clock_healthy is not True:
            return result()
        try:
            source = self.adapter.resolve(expected_context_bytes=self.expected_context_bytes, checked_at=now)
        except ErasureContextUnavailable:
            return result()
        if (type(source) is not AuthenticatedErasureContext
                or type(source.state_bytes) is not bytes
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("erasure resolver returned invalid authenticated evidence")
        try:
            state = _parse_jcs_object(source.state_bytes)
            if (set(state) != {"context", "checked_at", "authenticated_receipt_digest", "inventory"}
                    or not _time(state["checked_at"]) or state["checked_at"] != now
                    or h.canonical(state["context"]) != self.expected_context_bytes):
                return result()
            if len(receipt_bytes) > 262144:
                raise h.InvalidRecord("receipt exceeds installed byte limit")
            receipt = _parse_jcs_object(receipt_bytes)
            h.check_digest(state["authenticated_receipt_digest"], level)
            if h.digest(receipt, level) != state["authenticated_receipt_digest"]:
                raise h.InvalidRecord("complete receipt is not independently authenticated")
            for field in ("receipt_id", "request_digest", "subject_scope_digest"):
                if receipt[field] != expected[field]:
                    raise h.InvalidRecord("receipt substituted its installed lookup scope")
            inventory = h.TrustedErasureInventory(**state["inventory"])
            status = h.verify_erasure_receipt(receipt, inventory=inventory, now=now, level=level)
            overdue = tuple(sorted(item["copy_id"] for item in receipt["copies"]
                                   if item["disposition"] == "retained" and item["retention"]["delete_by"] <= now))
        except (ValueError, ValidationError, ProofFormatError, KeyError, TypeError, UnicodeError, RecursionError):
            values["reason"] = "ERASURE_INVALID"
            return result()
        values.update(reason="ERASURE_ACCOUNTING_VERIFIED", status=status, receipt_bytes=receipt_bytes,
                      authenticated_state_bytes=source.state_bytes, source_evidence_bytes=source.evidence_bytes,
                      overdue_retention_copy_ids=overdue)
        return result()


__all__ = ("InstalledErasureReceiptVerifier", "ErasureAccountingResult",
           "AuthenticatedErasureContext", "ErasureContextUnavailable")
