"""Strict shape prerequisite for the unreleased software consumption artifact.

A parsed dictionary is not verified signature, current evidence or authority.
The bounded local parser rejects noncanonical encodings and float control tokens.
"""
from functools import lru_cache
from importlib.resources import files
import hashlib
import json
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time


SOFTWARE_SCHEMA_SHA256="32af0e975fe6c37aa26452bc7d7c9d365eb552ed702a1cf763d7e2a88836a8f2"


@lru_cache(maxsize=1)
def software_decision_validator():
    from jsonschema import Draft202012Validator
    raw=files("kinetic_trust_library.v3").joinpath("schemas/software-substrate-decision.json").read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SOFTWARE_SCHEMA_SHA256:
        raise ValidationError("software decision schema differs from retained optional proposal")
    schema=json.loads(raw);Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def parse_software_decision(raw):
    if type(raw) is not bytes or len(raw)>262144:
        raise ValidationError("software decision requires bounded immutable canonical bytes")
    body=_parse_jcs_object(raw)
    if not software_decision_validator().is_valid(body):
        raise ValidationError("software decision does not satisfy the installed proposal schema")
    if any(not _time(body[k]) for k in ("consumption_epoch","evaluated_at","expires_at")) or body["consumption_epoch"]==0:
        raise ValidationError("software decision control fields require safe integer tokens")
    if any(not _time(c["max"]) for c in body["result"]["tightenedConstraints"]["ceilings"]):
        raise ValidationError("software decision magnitude counts require safe integer tokens")
    return body
