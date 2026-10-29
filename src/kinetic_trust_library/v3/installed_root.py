"""Native External Root projection behind an installed authentication adapter.

The adapter must authenticate complete signed instrument bytes and witnesses,
current source inputs, exposure semantics, a finite noncyclic person/institution
chain outside the agent graph, and complete authoritative event history with
authorized issuer/adjudicator roles. No production envelope is invented here.
"""
from dataclasses import dataclass
from decimal import Decimal, Context, localcontext
import hashlib
from fractions import Fraction
from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import ValidationError, ProofFormatError
from .root_lifecycle import RootLifecycleEvent, project_root_lifecycle, _time
from .root_projection import validate_root_projection
from .trust_proof_json import _parse_jcs_object
from .sponsorship_repair import InstalledSponsorshipRepairVerifier,SponsorshipRepairAssessment


class RootVerificationFailure(Exception):
    pass


@dataclass(frozen=True, slots=True)
class AuthenticatedRootInstrument:
    body_bytes: bytes
    events: tuple[RootLifecycleEvent, ...]


@dataclass(frozen=True, slots=True, init=False)
class RootAssessment:
    projection_bytes: bytes
    complete_instrument_bytes: bytes
    authenticated_body_bytes: bytes | None
    events: tuple[RootLifecycleEvent, ...]
    score: Decimal
    context_bytes: bytes
    evaluated_at: int
    score_numerator: int
    score_denominator: int
    sponsorship_repair: SponsorshipRepairAssessment | None

    def __init__(self, *args, **kwargs):
        raise TypeError("RootAssessment is derived by an installed root verifier")


@dataclass(frozen=True, slots=True)
class InstalledRootVerifier:
    adapter: object
    algorithm: str
    sponsorship_repair_verifier: InstalledSponsorshipRepairVerifier | None = None

    def __post_init__(self):
        if self.algorithm not in ("sha256", "sha384") or not callable(getattr(self.adapter, "verify", None)):
            raise ValidationError("installed root verifier is invalid")
        if self.sponsorship_repair_verifier is not None and (type(self.sponsorship_repair_verifier) is not InstalledSponsorshipRepairVerifier
                or self.sponsorship_repair_verifier.algorithm!=self.algorithm):
            raise ValidationError("root and sponsorship repair policies differ")

    def evaluate(self, evidence: bytes, *, context_bytes: bytes, evaluated_at: int) -> RootAssessment:
        import rfc8785
        if type(evidence) is not bytes or type(context_bytes) is not bytes or not _time(evaluated_at):
            raise ValidationError("root evidence/context must be immutable with a valid evaluation time")
        context = _parse_jcs_object(context_bytes)
        projection = {"kind": "none", "status": "none", "reason": "unverifiable"}
        score = Decimal(0)
        exact_score = Fraction(0)
        authenticated = None
        sponsorship_repair=None
        in_adapter = False
        try:
            if not evidence:
                raise RootVerificationFailure("missing")
            hop = context.get("hop_bound")
            if type(hop) is not int or not 1 <= hop <= 12:
                raise RootVerificationFailure("invalid_instrument")
            in_adapter = True
            authenticated = self.adapter.verify(evidence, context_bytes=context_bytes, evaluated_at=evaluated_at)
            in_adapter = False
            if (type(authenticated) is not AuthenticatedRootInstrument
                    or type(authenticated.body_bytes) is not bytes or type(authenticated.events) is not tuple
                    or any(type(e) is not RootLifecycleEvent for e in authenticated.events)):
                authenticated = None
                raise RootVerificationFailure("unverifiable")
            body = _parse_jcs_object(authenticated.body_bytes)
            digest = f"{self.algorithm}:{hashlib.new(self.algorithm, evidence).hexdigest()}"
            if body.get("subject") != context.get("subject"):
                raise RootVerificationFailure("invalid_instrument")
            chain = body.get("chain_length")
            if type(chain) is not int or not 1 <= chain <= 12:
                raise RootVerificationFailure("invalid_instrument")
            if chain > hop:
                raise RootVerificationFailure("over_hop_bound")
            state = project_root_lifecycle(
                instrument_digest=digest, subject=body["subject"], start_time=body["start_time"],
                end_time=body["end_time"], now=evaluated_at, events=authenticated.events)
            if state not in ("current", "non_renewable"):
                raise RootVerificationFailure(state)
            if "proof_exp" in context and (not _time(context["proof_exp"]) or context["proof_exp"] > body["end_time"]):
                raise RootVerificationFailure("invalid_instrument")
            kind = body["kind"]
            subject_kind = context.get("subject_profile")
            if subject_kind not in ("software", "person"):
                raise RootVerificationFailure("invalid_instrument")
            if subject_kind == "person" and body.get("root_person") != body["subject"]:
                raise RootVerificationFailure("invalid_instrument")
            projection = {"kind": kind, "status": state, "end_time": body["end_time"],
                          "terminator": body["terminator"], "root_person": body["root_person"], "chain_length": chain}
            inputs = body["inputs"]
            with localcontext(Context(prec=34)):
                if kind == "sponsorship_bond":
                    generation = context.get("generation")
                    if (subject_kind != "software" or context.get("lineage") != "sponsored"
                            or type(generation) is not int or not 0 <= generation <= 2):
                        raise RootVerificationFailure("invalid_instrument")
                    if "proof_sponsor" in context and context["proof_sponsor"] != body["issuer"]:
                        raise RootVerificationFailure("invalid_instrument")
                    if self.sponsorship_repair_verifier is not None:
                        in_adapter=True
                        sponsorship_repair=self.sponsorship_repair_verifier.evaluate(evidence,context_bytes=context_bytes,
                            evaluated_at=evaluated_at,clock_healthy=True)
                        in_adapter=False
                        if (not sponsorship_repair.eligible or sponsorship_repair.authenticated_bond_body_bytes!=authenticated.body_bytes
                                or "proof_exp" in context and context["proof_exp"]>sponsorship_repair.expires_at):
                            raise RootVerificationFailure("invalid_instrument")
                    elif "sponsorship_repair_profile_digest" in context:
                        raise RootVerificationFailure("invalid_instrument")
                    sponsor = as_decimal(inputs["sponsor_e_base"], name="sponsor standing", minimum=0, maximum=100)
                    stake = as_decimal(inputs["stake_percentage"], name="stake", minimum=1, maximum=50)
                    exact_score = Fraction(sponsor) * Fraction(stake) / 50
                    score = Decimal(exact_score.numerator) / Decimal(exact_score.denominator)
                    projection.update(bond_id=body["id"], bond_digest=digest, sponsor_id=body["issuer"], bond_inputs=inputs)
                elif kind == "external_attestation":
                    if subject_kind == "software":
                        generation = context.get("generation")
                        if (type(generation) is not int or generation < 3
                                or context.get("lineage") != ("independent" if generation < 7 else "guarantor")):
                            raise RootVerificationFailure("invalid_instrument")
                    exposure = as_decimal(inputs["declared_exposure"], name="exposure", minimum=0)
                    capacity = as_decimal(inputs["anchored_capacity"], name="anchored capacity", minimum=0)
                    if capacity <= 0:
                        raise RootVerificationFailure("invalid_instrument")
                    if exposure == 0:
                        raise RootVerificationFailure("no_exposure")
                    exact_score = min(Fraction(100), 100 * Fraction(exposure) / Fraction(capacity))
                    score = Decimal(exact_score.numerator) / Decimal(exact_score.denominator)
                    projection.update(attestation_id=body["id"], attestation_digest=digest, attestor_id=body["issuer"], **inputs)
                else:
                    raise RootVerificationFailure("invalid_instrument")
            if not validate_root_projection(projection):
                raise RootVerificationFailure("invalid_instrument")
            if "candidate_projection" in context and context["candidate_projection"] != projection:
                raise RootVerificationFailure("invalid_instrument")
        except RootVerificationFailure as exc:
            reason = str(exc)
            projection = {"kind": "none", "status": "none", "reason": reason}
            if not validate_root_projection(projection):
                projection["reason"] = "unverifiable"
            score = Decimal(0)
            exact_score = Fraction(0)
        except (ValidationError, ProofFormatError, KeyError, TypeError, ValueError):
            if in_adapter:
                raise
            projection = {"kind": "none", "status": "none", "reason": "invalid_instrument"}
            score = Decimal(0)
            exact_score = Fraction(0)
        result = object.__new__(RootAssessment)
        for name, value in (("projection_bytes", rfc8785.dumps(projection)), ("score", score),
                            ("complete_instrument_bytes", evidence), ("context_bytes", context_bytes),
                            ("evaluated_at", evaluated_at),
                            ("score_numerator", exact_score.numerator), ("score_denominator", exact_score.denominator),
                            ("authenticated_body_bytes", None if authenticated is None else authenticated.body_bytes),
                            ("events", () if authenticated is None else authenticated.events),("sponsorship_repair",sponsorship_repair)):
            object.__setattr__(result, name, value)
        return result
