"""Deterministic rule-repair inventory checks, not a ratification mechanism.

The installed source authenticates complete applicable pattern counts, actual
governing/affected parties and the exact driving citations per pattern, current anchors, independent-party facts at the record
date, ratification and the current valid reconciliation citation inventory.
These closed semantic projections are not new RFC audit record wire formats.
"""
from dataclasses import dataclass
import re
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time


@dataclass(frozen=True,slots=True)
class RuleRepairProjection:
    records_complete: bool
    open_patterns: tuple[str,...]
    closed_patterns: tuple[str,...]
    outcomes: tuple[tuple[str,str],...]


def _identifier(value):return type(value) is str and bool(value)


def _identifiers(value):
    if type(value) is not list or len(value)>4096 or any(not _identifier(item) for item in value) or len(set(value))!=len(value):
        raise ValidationError("rule repair requires distinct complete party/citation identifiers")
    return set(value)


def project_rule_repairs(state,*,recurrence_limit,tier_record_required,evaluated_at,algorithm):
    """Keep triggered patterns open until a valid anchored citing amendment.

    The caller binds this inventory to current profile/zone/ledger/time. An
    Previously triggered state or an existing record retains a pattern even
    below today's recurrence threshold.
    Missing record/amendment evidence is an outstanding obligation, not repair.
    """
    if (type(recurrence_limit) is not int or not 1<=recurrence_limit<=4096
            or type(tier_record_required) is not bool or not _time(evaluated_at)
            or algorithm not in ("sha256","sha384") or type(state) is not dict
            or set(state)!={"tier_pattern_id","patterns","reconciliation_records"}
            or type(state["patterns"]) is not list or len(state["patterns"])>4096
            or state["tier_pattern_id"] is not None and not _identifier(state["tier_pattern_id"])):
        raise ValidationError("invalid complete rule-repair inventory")
    def digest(value):
        return type(value) is str and re.fullmatch(algorithm+r":[0-9a-f]{"+str(64 if algorithm=="sha256" else 96)+"}",value) is not None
    if type(state["reconciliation_records"]) is not list or len(state["reconciliation_records"])>4096:
        raise ValidationError("invalid complete reconciliation citation inventory")
    citations={}
    for item in state["reconciliation_records"]:
        if (type(item) is not dict or set(item)!={"anchor","anchored_at","current_anchor_verified"}
                or not digest(item["anchor"]) or item["anchor"] in citations or not _time(item["anchored_at"])
                or item["anchored_at"]>evaluated_at or type(item["current_anchor_verified"]) is not bool):
            raise ValidationError("invalid or duplicate current reconciliation citation")
        citations[item["anchor"]]=item
    outcomes=[];seen=set();record_anchors=set();amendment_anchors=set();opened=[];closed=[];records_complete=True
    for item in state["patterns"]:
        if (type(item) is not dict or set(item)!={"pattern_id","kind","profile_digest","definition_digest","occurrences","previously_triggered","governing_authority","affected_parties","driving_reconciliation_anchors","record","amendment"}
                or not _identifier(item["pattern_id"]) or item["pattern_id"] in seen
                or item["kind"] not in ("rule","profile","consequence-class") or not digest(item["profile_digest"])
                or not digest(item["definition_digest"]) or item["kind"]=="profile" and item["definition_digest"]!=item["profile_digest"]
                or not _time(item["occurrences"]) or type(item["previously_triggered"]) is not bool or not _identifier(item["governing_authority"])):
            raise ValidationError("invalid or duplicate applicable rule-repair pattern")
        seen.add(item["pattern_id"]);affected=_identifiers(item["affected_parties"])
        drivers=_identifiers(item["driving_reconciliation_anchors"])
        if any(not digest(anchor) for anchor in drivers):raise ValidationError("invalid pattern driving citation")
        record=item["record"];amendment=item["amendment"]
        required=(item["previously_triggered"] or item["occurrences"]>=recurrence_limit or record is not None
                  or tier_record_required and item["pattern_id"]==state["tier_pattern_id"])
        record_valid=False
        if record is not None:
            if (type(record) is not dict or set(record)!={"anchor","pattern_id","profile_digest","cause","anchored_at","current_anchor_verified"}
                    or not digest(record["anchor"]) or record["anchor"] in record_anchors
                    or type(record["current_anchor_verified"]) is not bool or not _time(record["anchored_at"])):
                raise ValidationError("invalid or duplicate rule-repair record")
            record_anchors.add(record["anchor"])
            record_valid=(record["pattern_id"]==item["pattern_id"] and record["profile_digest"]==item["profile_digest"]
                and _identifier(record["cause"]) and record["current_anchor_verified"] and record["anchored_at"]<=evaluated_at)
        amendment_valid=False
        if amendment is not None:
            if (type(amendment) is not dict or set(amendment)!={"anchor","record_anchor","pattern_id","profile_digest","previous_definition_digest","amended_definition_digest","anchored_at",
                    "current_anchor_verified","ratified","parties","acknowledged_by","residual_harm","verifier","oracle",
                    "independent_of","declined_parties","open_to","route_followed","route_published","cites"}
                    or not digest(amendment["anchor"]) or not digest(amendment["record_anchor"])
                    or not digest(amendment["previous_definition_digest"]) or not digest(amendment["amended_definition_digest"])
                    or amendment["anchor"] in amendment_anchors or not _time(amendment["anchored_at"])
                    or any(type(amendment[name]) is not bool for name in ("current_anchor_verified","ratified","route_followed","route_published"))
                    or not _identifier(amendment["verifier"]) or not _identifier(amendment["oracle"])):
                raise ValidationError("invalid or duplicate rule-repair amendment")
            amendment_anchors.add(amendment["anchor"])
            parties=_identifiers(amendment["parties"]);independent=_identifiers(amendment["independent_of"])
            declined=_identifiers(amendment["declined_parties"]);open_to=_identifiers(amendment["open_to"])
            cites=_identifiers(amendment["cites"])
            amendment_valid=(record_valid and amendment["record_anchor"]==record["anchor"]
                and amendment["anchor"]!=record["anchor"] and amendment["pattern_id"]==item["pattern_id"]
                and amendment["profile_digest"]==item["profile_digest"]
                and amendment["previous_definition_digest"]==item["definition_digest"]
                and amendment["amended_definition_digest"]!=item["definition_digest"]
                and record["anchored_at"]<=amendment["anchored_at"]<=evaluated_at
                and amendment["current_anchor_verified"] and amendment["ratified"]
                and affected|{item["governing_authority"]}<=parties
                and amendment["acknowledged_by"]==item["governing_authority"]
                and _identifier(amendment["residual_harm"])
                and amendment["verifier"]!=amendment["oracle"] and amendment["verifier"] not in parties
                and parties<=independent and affected<=open_to and declined<=affected
                and (not declined or amendment["route_followed"] and amendment["route_published"])
                and bool(cites) and cites==drivers and cites<=citations.keys() and amendment["anchor"] not in cites
                and record["anchor"] not in cites
                and all(citations[anchor]["current_anchor_verified"]
                    and citations[anchor]["anchored_at"]<=amendment["anchored_at"] for anchor in cites))
        reason="RULE_REPAIR_NOT_TRIGGERED"
        if required:
            if not record_valid:records_complete=False
            if amendment_valid:closed.append(item["pattern_id"]);reason="RULE_REPAIR_CLOSED"
            else:opened.append(item["pattern_id"]);reason="RULE_REPAIR_AMENDMENT_REQUIRED" if record_valid else "RULE_REPAIR_RECORD_REQUIRED"
        outcomes.append((item["pattern_id"],reason))
    if tier_record_required and state["tier_pattern_id"] not in seen:records_complete=False
    return RuleRepairProjection(records_complete,tuple(opened),tuple(closed),tuple(outcomes))


__all__=("RuleRepairProjection","project_rule_repairs")
