"""Authenticated encrypted archive envelopes and purpose-bound byte recovery.

Archive consensus, approved policy, access authority, key custody, retention
and destruction belong to installed sources. Outer integrity and decryption
never establish the truth or original signatures of recovered evidence.
"""
from dataclasses import dataclass, field

from kinetic_trust_library.errors import ValidationError, ProofFormatError
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time
from .demand_operation import canonical_demand_operation_bytes


class PrivacyArchiveUnavailable(Exception):
    pass


class PrivacyAccessUnavailable(Exception):
    pass


@dataclass(frozen=True, slots=True)
class AuthenticatedPrivacyArchive:
    state_bytes: bytes
    trusted_keys_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True)
class AuthenticatedPrivacyAccess:
    context_bytes: bytes
    data_key: bytes = field(repr=False)
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class PrivacyEnvelopeResult:
    reason: str
    checked_at: int
    expected_context_bytes: bytes
    envelope_bytes: bytes | None
    record_hash: str | None
    delete_after: int | None
    authenticated_state_bytes: bytes | None
    trusted_keys_bytes: bytes | None
    source_evidence_bytes: bytes | None

    def __init__(self, *args, **kwargs):
        raise TypeError("privacy envelope results are derived by an installed verifier")


def _derived(kind, values):
    result = object.__new__(kind)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


@dataclass(frozen=True, slots=True)
class InstalledPrivacyEvidenceVerifier:
    expected_context_bytes: bytes
    adapter: object

    def __post_init__(self):
        from . import _human_reference as h
        if (type(self.expected_context_bytes) is not bytes
                or not callable(getattr(self.adapter, "resolve", None))):
            raise ValidationError("installed privacy verifier is invalid")
        context = _parse_jcs_object(self.expected_context_bytes)
        if (set(context) != {"envelope_id", "zone_id", "chain_id", "purpose_id",
                             "privacy_policy_digest", "issuer_id", "conformance_level"}
                or type(context["conformance_level"]) is not int
                or context["conformance_level"] not in (1, 2, 3)):
            raise ValidationError("installed privacy archive context is invalid")
        try:
            for name in ("envelope_id", "zone_id", "chain_id", "purpose_id", "issuer_id"):
                h.literal(context[name])
            h.check_digest(context["privacy_policy_digest"], context["conformance_level"])
        except h.InvalidRecord as error:
            raise ValidationError(str(error)) from error

    def verify(self, envelope_bytes: bytes, *, now: int, clock_healthy: bool) -> PrivacyEnvelopeResult:
        from . import _privacy_reference as p
        from ._jws_keys import load_key_binding
        if type(envelope_bytes) is not bytes or not _time(now):
            raise ValidationError("privacy verification requires immutable bytes and trusted time")
        expected = _parse_jcs_object(self.expected_context_bytes)
        values = dict(reason="PRIVACY_UNAVAILABLE", checked_at=now, expected_context_bytes=self.expected_context_bytes,
                      envelope_bytes=None, record_hash=None, delete_after=None, authenticated_state_bytes=None,
                      trusted_keys_bytes=None, source_evidence_bytes=None)
        if clock_healthy is not True:
            return _derived(PrivacyEnvelopeResult, values)
        try:
            source = self.adapter.resolve(expected_context_bytes=self.expected_context_bytes, checked_at=now)
        except PrivacyArchiveUnavailable:
            return _derived(PrivacyEnvelopeResult, values)
        if (type(source) is not AuthenticatedPrivacyArchive
                or any(type(value) is not bytes for value in (source.state_bytes, source.trusted_keys_bytes, source.evidence_bytes))
                or not source.evidence_bytes):
            raise ValidationError("privacy resolver returned invalid authenticated archive evidence")
        try:
            state = _parse_jcs_object(source.state_bytes)
            if (set(state) != {"context", "checked_at", "anchor"}
                    or not _time(state["checked_at"]) or state["checked_at"] != now
                    or p.canonical(state["context"]) != self.expected_context_bytes):
                return _derived(PrivacyEnvelopeResult, values)
            if len(envelope_bytes) > 262144:
                raise p.InvalidRecord("privacy envelope exceeds installed byte limit")
            envelope = _parse_jcs_object(envelope_bytes)
            if envelope.get("envelope_id") != expected["envelope_id"]:
                raise p.InvalidRecord("privacy envelope lookup identity mismatch")
            anchor = state["anchor"]
            if type(anchor) is not dict or set(anchor) != {"sequence", "previous_hash", "record_hash"}:
                raise p.InvalidRecord("invalid independently anchored archive position")
            binding, key = load_key_binding(_parse_jcs_object(source.trusted_keys_bytes), envelope["signature"])
            context = p.ExpectedEnvelope(
                expected["zone_id"], expected["chain_id"], anchor["sequence"], anchor["previous_hash"], anchor["record_hash"],
                expected["purpose_id"], expected["privacy_policy_digest"], expected["issuer_id"], expected["conformance_level"],
                key["not_before"], key["not_after"])
            p.verify_envelope(envelope, binding, context, now=now)
        except (ValueError, ValidationError, ProofFormatError, KeyError, TypeError, UnicodeError, RecursionError):
            values["reason"] = "PRIVACY_INVALID"
            return _derived(PrivacyEnvelopeResult, values)
        values.update(reason="PRIVACY_OUTER_INTEGRITY_ONLY", envelope_bytes=envelope_bytes,
                      record_hash=envelope["record_hash"], delete_after=envelope["delete_after"],
                      authenticated_state_bytes=source.state_bytes, trusted_keys_bytes=source.trusted_keys_bytes,
                      source_evidence_bytes=source.evidence_bytes)
        return _derived(PrivacyEnvelopeResult, values)


@dataclass(frozen=True, slots=True, init=False)
class PrivacyRecoveryResult:
    reason: str
    checked_at: int
    envelope: PrivacyEnvelopeResult
    operation_bytes: bytes
    plaintext_bytes: bytes | None = field(repr=False)
    access_context_bytes: bytes | None
    access_evidence_bytes: bytes | None
    expires_at: int | None

    def __init__(self, *args, **kwargs):
        raise TypeError("privacy recovery results are derived by an installed reader")


@dataclass(frozen=True, slots=True)
class InstalledPrivacyEvidenceReader:
    verifier: InstalledPrivacyEvidenceVerifier
    access_adapter: object

    def __post_init__(self):
        if (type(self.verifier) is not InstalledPrivacyEvidenceVerifier
                or not callable(getattr(self.access_adapter, "authorize_and_resolve_key", None))):
            raise ValidationError("installed privacy reader is invalid")

    def open(self, envelope_bytes: bytes, *, actual_operation: dict, now: int,
             clock_healthy: bool) -> PrivacyRecoveryResult:
        from . import _privacy_reference as p
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        operation_bytes = canonical_demand_operation_bytes(actual_operation)
        verified = self.verifier.verify(envelope_bytes, now=now, clock_healthy=clock_healthy)
        values = dict(reason=verified.reason, checked_at=now, envelope=verified, operation_bytes=operation_bytes,
                      plaintext_bytes=None, access_context_bytes=None, access_evidence_bytes=None, expires_at=None)
        if verified.reason != "PRIVACY_OUTER_INTEGRITY_ONLY":
            return _derived(PrivacyRecoveryResult, values)
        if now >= verified.delete_after:
            values["reason"] = "PRIVACY_RETENTION_EXPIRED"
            return _derived(PrivacyRecoveryResult, values)
        values["reason"] = "PRIVACY_ACCESS_UNAVAILABLE"
        try:
            source = self.access_adapter.authorize_and_resolve_key(
                expected_context_bytes=self.verifier.expected_context_bytes, operation_bytes=operation_bytes,
                envelope_bytes=verified.envelope_bytes, record_hash=verified.record_hash, checked_at=now)
        except PrivacyAccessUnavailable:
            return _derived(PrivacyRecoveryResult, values)
        if (type(source) is not AuthenticatedPrivacyAccess or type(source.context_bytes) is not bytes
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes
                or type(source.data_key) is not bytes or len(source.data_key) != 32):
            raise ValidationError("privacy access resolver returned invalid authenticated evidence/key")
        try:
            access = _parse_jcs_object(source.context_bytes)
            envelope = _parse_jcs_object(verified.envelope_bytes)
            if (set(access) != {"context", "operation", "record_hash", "key_ref", "checked_at", "expires_at"}
                    or p.canonical(access["context"]) != self.verifier.expected_context_bytes
                    or p.canonical(access["operation"]) != operation_bytes
                    or access["record_hash"] != verified.record_hash or access["key_ref"] != envelope["encryption"]["key_ref"]
                    or not _time(access["checked_at"]) or access["checked_at"] != now
                    or not _time(access["expires_at"]) or not now < access["expires_at"] <= verified.delete_after):
                raise p.InvalidRecord("access evidence differs from exact current invocation/envelope")
        except (ValueError, ValidationError, ProofFormatError, KeyError, TypeError, UnicodeError, RecursionError):
            values["reason"] = "PRIVACY_ACCESS_INVALID"
            return _derived(PrivacyRecoveryResult, values)
        try:
            plaintext = AESGCM(source.data_key).decrypt(p.unb64(envelope["encryption"]["nonce"]),
                p.unb64(envelope["encryption"]["ciphertext"]), p.associated_data(envelope))
        except InvalidTag:
            values["reason"] = "PRIVACY_DECRYPTION_FAILED"
            return _derived(PrivacyRecoveryResult, values)
        values.update(reason="PRIVACY_BYTES_RECOVERED_UNREVIEWED", plaintext_bytes=plaintext,
                      access_context_bytes=source.context_bytes, access_evidence_bytes=source.evidence_bytes,
                      expires_at=access["expires_at"])
        return _derived(PrivacyRecoveryResult, values)


__all__ = ("InstalledPrivacyEvidenceVerifier", "InstalledPrivacyEvidenceReader", "PrivacyEnvelopeResult",
           "PrivacyRecoveryResult", "AuthenticatedPrivacyArchive", "AuthenticatedPrivacyAccess",
           "PrivacyArchiveUnavailable", "PrivacyAccessUnavailable")
