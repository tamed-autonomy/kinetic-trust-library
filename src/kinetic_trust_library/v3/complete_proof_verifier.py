"""Ordered native proof verification with an independently installed profile.

Schema bundles are immutable local policy, never candidate-selected. The root
verifier must establish exact authenticated instrument/lifecycle/proof binding;
ingress verification must establish the installed topology's receipt contract.
TP_CLEAR permits attempting remaining authorization; it never grants execution.
"""
from dataclasses import dataclass
from typing import Callable
from kinetic_trust_library.errors import ValidationError, ProofFormatError
from ._trust_proof_preconditions import first_precondition_failure
from .trust_proof_framing import parse_compact_framing
from .trust_proof_json import parse_proof_json_objects, _parse_jcs_object
from .trust_proof_invariants import _invariants_hold, trust_proof_stage7_reason
from .schema_formats import installed_format_checker
from .live_root import RootProofVerificationResult


@dataclass(frozen=True, slots=True)
class InstalledSchemaBundle:
    schemas: tuple[bytes, ...]
    root_id: str

    def __post_init__(self):
        if type(self.schemas) is not tuple or not self.schemas or any(type(s) is not bytes for s in self.schemas):
            raise ValidationError("installed schemas must be immutable canonical bytes")
        parsed = [_parse_jcs_object(s) for s in self.schemas]
        ids = [s.get("$id") for s in parsed]
        if any(type(i) is not str or not i for i in ids) or len(set(ids)) != len(ids) or self.root_id not in ids:
            raise ValidationError("installed schema identities are invalid")
        from jsonschema import Draft202012Validator
        for schema in parsed:
            Draft202012Validator.check_schema(schema)

    def valid(self, payload_bytes: bytes) -> bool:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        schemas = [_parse_jcs_object(s) for s in self.schemas]
        def no_network(uri):
            raise LookupError("schema reference is not installed")
        registry = Registry(retrieve=no_network).with_resources((s["$id"], Resource.from_contents(s)) for s in schemas)
        root = next(s for s in schemas if s["$id"] == self.root_id)
        try:
            return Draft202012Validator(root, registry=registry, format_checker=installed_format_checker()).is_valid(_parse_jcs_object(payload_bytes))
        except Exception:
            return False


@dataclass(frozen=True, slots=True, init=False)
class ProofVerificationResult:
    compact: str
    reason: str
    stage: int
    authenticated_payload_bytes: bytes | None
    root_verification: RootProofVerificationResult | None

    def __init__(self, *args, **kwargs):
        raise TypeError("ProofVerificationResult is derived by an installed verifier")


@dataclass(frozen=True, slots=True)
class InstalledProofVerifier:
    schema_bundle: InstalledSchemaBundle
    trusted_keys_bytes: bytes
    expected_context_bytes: bytes
    installed_algorithms: tuple[str, ...]
    root_verifier: Callable[[bytes, int], bool | RootProofVerificationResult]
    ingress_verifier: Callable[[tuple[object, ...]], bool] | None = None
    extension_handlers: tuple[tuple[str, Callable[[bytes], bool]], ...] = ()
    fixture_software_default: bool = False

    def __post_init__(self):
        if (type(self.schema_bundle) is not InstalledSchemaBundle
                or type(self.trusted_keys_bytes) is not bytes or type(self.expected_context_bytes) is not bytes
                or type(self.installed_algorithms) is not tuple or not callable(self.root_verifier)
                or type(self.extension_handlers) is not tuple):
            raise ValidationError("installed proof verifier policy is invalid")
        _parse_jcs_object(self.trusted_keys_bytes)
        context = _parse_jcs_object(self.expected_context_bytes)
        if (type(self.fixture_software_default) is not bool
                or context.get("subject_kind") not in ("software_agent", "person")
                and not (self.fixture_software_default and "subject_kind" not in context)):
            raise ValidationError("installed subject kind must be independently declared")
        names = []
        for entry in self.extension_handlers:
            if type(entry) is not tuple or len(entry) != 2 or type(entry[0]) is not str or not callable(entry[1]):
                raise ValidationError("installed extension handler is invalid")
            names.append(entry[0])
        if len(set(names)) != len(names):
            raise ValidationError("duplicate installed extension handler")

    def verify(self, compact: str, *, now: int, clock_healthy: bool) -> ProofVerificationResult:
        import rfc8785
        context = _parse_jcs_object(self.expected_context_bytes)
        keys = _parse_jcs_object(self.trusted_keys_bytes)
        reason = first_precondition_failure(compact, expected_issuer=context["issuer"],
            expected_audience=context["audience"], expected_zone=context["zone"], now=now,
            clock_healthy=clock_healthy, installed_algorithms=self.installed_algorithms, trusted_keys=keys)
        stages = {"TP_FORMAT":1, "TP_TYPE":2, "TP_ALGORITHM":2, "TP_HEADER":2,
                  "TP_KEY_UNTRUSTED":3, "TP_KEY_REVOKED":3, "TP_KEY_ROLE":3, "TP_KEY_ALGORITHM":3,
                  "TP_SIGNATURE":4, "TP_ISSUER":5, "TP_AUDIENCE":5, "TP_TIME":5}
        if reason is not None:
            return _result(compact, reason, stages[reason], None)
        framing = parse_compact_framing(compact)
        _, payload = parse_proof_json_objects(framing)
        raw = framing.payload_bytes
        if not self.schema_bundle.valid(raw):
            return _result(compact, "TP_SCHEMA", 6, raw)
        handlers = dict(self.extension_handlers)
        for namespace, extension in payload.get("extensions", {}).items():
            handler = handlers.get(namespace)
            if handler is None:
                if extension["critical"]:
                    return _result(compact, "TP_EXTENSION_CRITICAL", 6, raw)
            else:
                try:
                    accepted = handler(rfc8785.dumps(extension["value"])) is True
                except Exception:
                    accepted = False
                if not accepted:
                    return _result(compact, "TP_EXTENSION_CRITICAL", 6, raw)
        root_evidence = None
        try:
            invariant = _invariants_hold(payload, expected_subject=context["subject"], expected_zone=context["zone"],
                                         required_ceilings=context["required_ceilings"], expected_subject_kind=context.get("subject_kind", "software_agent"))
            root_check = self.root_verifier(raw, now) if invariant else False
            if type(root_check) is RootProofVerificationResult:
                root_evidence = root_check
                root_valid = root_check.valid and root_check.checked_at == now and root_check.payload_bytes == raw
            else:
                root_valid = root_check is True
        except Exception:
            root_valid = False
        if not root_valid:
            return _result(compact, "TP_INVARIANT", 7, raw, root_evidence)
        reason = trust_proof_stage7_reason(payload, expected_subject=context["subject"], expected_zone=context["zone"],
            required_ceilings=context["required_ceilings"], ring_depth=context["ring_depth"], ingress_verifier=self.ingress_verifier, expected_subject_kind=context.get("subject_kind", "software_agent"))
        if reason is not None:
            return _result(compact, reason, 7, raw, root_evidence)
        gate = payload["ktp"]["gate_state"]
        return _result(compact, {"clear":"TP_CLEAR", "veto":"TP_VETO", "undetermined":"TP_UNDETERMINED"}[gate], 8, raw, root_evidence)


def _result(compact, reason, stage, payload, root_evidence=None):
    result = object.__new__(ProofVerificationResult)
    for name, value in (("compact",compact), ("reason",reason), ("stage",stage), ("authenticated_payload_bytes",payload), ("root_verification",root_evidence)):
        object.__setattr__(result,name,value)
    return result
