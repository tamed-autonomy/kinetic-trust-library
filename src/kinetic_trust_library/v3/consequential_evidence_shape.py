"""Strict canonical shape prerequisite; a parsed record establishes no effect."""
from functools import lru_cache
from importlib.resources import files
import hashlib,json
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time

SCHEMA_SHA256="53dbf2be7270470bc51c2a94fe71e4551e5ce972b1ec6e89a2b3762c50ef2b36"

@lru_cache(maxsize=1)
def consequential_evidence_validator():
    from jsonschema import Draft202012Validator
    raw=files("kinetic_trust_library.v3").joinpath("schemas/consequential-action-evidence.json").read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SCHEMA_SHA256:raise ValidationError("consequential evidence schema differs from pinned proposal")
    schema=json.loads(raw);Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)

def parse_consequential_evidence(raw):
    if type(raw) is not bytes or len(raw)>262144:raise ValidationError("bounded immutable canonical evidence bytes required")
    body=_parse_jcs_object(raw)
    if not consequential_evidence_validator().is_valid(body):raise ValidationError("consequential evidence fails pinned schema")
    if any(not _time(body['observation'][n]) for n in ('interval_start','interval_end')):
        raise ValidationError("evidence interval requires safe integer Unix-second tokens")
    return body
