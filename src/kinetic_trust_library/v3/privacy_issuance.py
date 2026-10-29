"""Fresh encrypted evidence production through installed policy/key adapters.

The ingest source authenticates actual bytes and permitted processing metadata.
The signer owns private keys. The storage adapter must durably protect the new
data key before acknowledging its exact binding. Archive append/consensus,
reservation consumption, cleanup and retention enforcement remain external.
"""
from dataclasses import dataclass

from kinetic_trust_library.errors import ValidationError, ProofFormatError
from .privacy_evidence import InstalledPrivacyEvidenceVerifier
from .trust_proof_json import _parse_jcs_object
from .demand_operation import canonical_demand_operation_bytes
from .root_lifecycle import _time


@dataclass(frozen=True, slots=True)
class AuthenticatedPrivacyIngest:
    state_bytes: bytes
    trusted_keys_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True)
class AuthenticatedPrivacyKeyStorage:
    context_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class IssuedPrivacyEvidence:
    reason: str
    checked_at: int
    envelope_bytes: bytes
    record_hash: str
    source_state_bytes: bytes
    trusted_keys_bytes: bytes
    source_evidence_bytes: bytes
    key_storage_context_bytes: bytes
    key_storage_evidence_bytes: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError("privacy issuance results are derived by an installed issuer")


@dataclass(frozen=True, slots=True)
class InstalledPrivacyEvidenceIssuer:
    expected_context_bytes: bytes
    ingest_source: object
    signer: object
    key_storage: object

    def __post_init__(self):
        # Reuse the exact installed archive lookup contract, without resolving
        # or claiming an anchor for an artifact that has not yet been appended.
        InstalledPrivacyEvidenceVerifier(self.expected_context_bytes, self.ingest_source)
        if (not callable(getattr(self.signer, "sign", None))
                or not callable(getattr(self.key_storage, "store", None))):
            raise ValidationError("installed privacy issuance adapters are invalid")

    def issue(self, plaintext: bytes, *, actual_operation: dict, now: int,
              clock_healthy: bool) -> IssuedPrivacyEvidence:
        from . import _privacy_reference as p
        from . import _trajectory_reference as t
        from ._jws_keys import load_key_binding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets
        if (type(plaintext) is not bytes or not 0 < len(plaintext) <= 65536
                or not _time(now) or clock_healthy is not True):
            raise ValidationError("privacy issuance requires 1–65536 exact bytes and a healthy clock")
        operation_bytes = canonical_demand_operation_bytes(actual_operation)
        context = _parse_jcs_object(self.expected_context_bytes)
        level = context["conformance_level"]
        source = self.ingest_source.resolve(expected_context_bytes=self.expected_context_bytes,
                                            operation_bytes=operation_bytes, checked_at=now)
        if (type(source) is not AuthenticatedPrivacyIngest
                or any(type(raw) is not bytes for raw in (source.state_bytes, source.trusted_keys_bytes, source.evidence_bytes))
                or not source.evidence_bytes):
            raise ValidationError("privacy ingest source returned invalid authenticated evidence")
        try:
            state = _parse_jcs_object(source.state_bytes)
            if (set(state) != {"context", "operation", "checked_at", "plaintext_digest", "metadata", "kid", "algorithm"}
                    or p.canonical(state["context"]) != self.expected_context_bytes
                    or p.canonical(state["operation"]) != operation_bytes
                    or not _time(state["checked_at"]) or state["checked_at"] != now
                    or state["plaintext_digest"] != t.digest_bytes(plaintext, level)):
                raise p.InvalidRecord("ingest evidence differs from current actual bytes/invocation/policy")
            metadata = state["metadata"]
            if type(metadata) is not dict or set(metadata) != {
                "envelope_id", "zone_id", "chain_id", "sequence", "previous_hash", "purpose_id",
                "privacy_policy_digest", "created_at", "delete_after", "issuer_id",
            }:
                raise p.InvalidRecord("exact approved privacy metadata required")
            if any(metadata[name] != context[name] for name in context if name != "conformance_level"):
                raise p.InvalidRecord("approved metadata differs from installed context")
            if not _time(metadata["created_at"]) or metadata["created_at"] != now:
                raise p.InvalidRecord("new privacy envelope requires current creation time")
            envelope = dict(metadata, format=p.FORMAT, conformance_level=level,
                            encryption=dict(algorithm="A256GCM", key_ref="pending", nonce=t.b64(bytes(12)), ciphertext=t.b64(bytes(17))),
                            signature="e30.e30.AA", record_hash=p.digest({}, level))
            p.validate_envelope(envelope)
            algorithm, kid = state["algorithm"], state["kid"]
            if algorithm not in ("ES256", "ES384", "EdDSA"):
                raise p.InvalidRecord("unsupported installed privacy signing algorithm")
            header = dict(alg=algorithm, kid=kid, typ=t.PRIVACY_EVIDENCE_TYPE)
            framing = t.b64(p.canonical(header))+"."+t.b64(b"{}")+".AA"
            binding, key = load_key_binding(_parse_jcs_object(source.trusted_keys_bytes), framing)
            if (binding.algorithm != algorithm or binding.purpose != t.PRIVACY_EVIDENCE_TYPE
                    or binding.subject != context["issuer_id"] or binding.zone_id != context["zone_id"]
                    or not key["not_before"] <= now < key["not_after"]):
                raise p.InvalidRecord("privacy signer role/issuer/zone/current validity mismatch")
            t.check_key(binding.public_key, algorithm, level)
        except (ValueError, ValidationError, ProofFormatError, KeyError, TypeError, UnicodeError, RecursionError) as error:
            raise ValidationError("privacy issuance precondition failed: "+str(error)) from error

        data_key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        envelope["encryption"].update(key_ref=t.b64(secrets.token_bytes(24)), nonce=t.b64(nonce))
        envelope["encryption"]["ciphertext"] = t.b64(AESGCM(data_key).encrypt(nonce, plaintext, p.associated_data(envelope)))
        message = (t.b64(p.canonical(header))+"."+t.b64(p.canonical(p.body(envelope)))).encode("ascii")
        signature = self.signer.sign(message, algorithm=algorithm, kid=kid)
        if type(signature) is not bytes:
            raise ValidationError("privacy signer must return raw signature bytes")
        envelope["signature"] = message.decode("ascii")+"."+t.b64(signature)
        envelope["record_hash"] = p.record_digest(envelope, level)
        raw = p.canonical(envelope)
        if len(raw) > 262144:
            raise ValidationError("issued privacy envelope exceeds installed byte limit")
        try:
            # Local complete-artifact crypto check only. This computed expected
            # hash is deliberately not treated as independent archive evidence.
            local = p.ExpectedEnvelope(context["zone_id"], context["chain_id"], metadata["sequence"], metadata["previous_hash"],
                envelope["record_hash"], context["purpose_id"], context["privacy_policy_digest"], context["issuer_id"], level,
                key["not_before"], key["not_after"])
            p.verify_envelope(envelope, binding, local, now=now)
        except (ValueError, ValidationError, ProofFormatError, KeyError, TypeError, UnicodeError, RecursionError) as error:
            raise ValidationError("issued privacy envelope failed complete local verification") from error
        custody_context = p.canonical(dict(context=context, operation=_parse_jcs_object(operation_bytes), metadata=metadata,
            plaintext_digest=state["plaintext_digest"], record_hash=envelope["record_hash"], key_ref=envelope["encryption"]["key_ref"],
            nonce=envelope["encryption"]["nonce"], key_digest=t.digest_bytes(data_key, level), checked_at=now))
        stored = self.key_storage.store(data_key, context_bytes=custody_context)
        if (type(stored) is not AuthenticatedPrivacyKeyStorage or type(stored.context_bytes) is not bytes
                or stored.context_bytes != custody_context or type(stored.evidence_bytes) is not bytes or not stored.evidence_bytes):
            raise ValidationError("privacy key storage did not authenticate the exact durable binding")
        result = object.__new__(IssuedPrivacyEvidence)
        for name, value in dict(reason="PRIVACY_ENVELOPE_SIGNED_UNANCHORED", checked_at=now, envelope_bytes=raw,
                                record_hash=envelope["record_hash"], source_state_bytes=source.state_bytes,
                                trusted_keys_bytes=source.trusted_keys_bytes, source_evidence_bytes=source.evidence_bytes,
                                key_storage_context_bytes=stored.context_bytes, key_storage_evidence_bytes=stored.evidence_bytes).items():
            object.__setattr__(result, name, value)
        return result


__all__ = ("InstalledPrivacyEvidenceIssuer", "IssuedPrivacyEvidence", "AuthenticatedPrivacyIngest", "AuthenticatedPrivacyKeyStorage")
