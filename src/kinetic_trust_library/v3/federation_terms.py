"""Closed semantic agreement projection for a selected federation profile.

An installed adapter authenticates the actual signed agreement and classifies
clauses. This internal representation is not a new Federation Agreement wire.
"""
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time
from .ambient_repair import ratio

VOID_EFFECTS=frozenset(("delegate-veto","waive-veto","override-veto","foreign-evaluation","coordinate-inputs","bind-foreign-act"))


def name(value):return type(value) is str and bool(value)


def identifiers(value):
    if (type(value) is not list or len(value)>4096 or any(not name(item) for item in value)
            or len(set(value))!=len(value)):
        raise ValidationError("federation identifiers must be exact and distinct")
    return set(value)


def agreement_terms(body):
    required={"id","version","starts_at","expires_at","parties","signed_by","directions","data_handling",
        "sovereignty_enforced","dispute_route","incident_notification_seconds","leaving_notice_seconds","severance_causes","clauses"}
    if (type(body) is not dict or set(body)!=required or not name(body["id"]) or not _time(body["version"]) or body["version"]==0
            or not _time(body["starts_at"]) or not _time(body["expires_at"]) or body["starts_at"]>=body["expires_at"]
            or type(body["parties"]) is not list or len(body["parties"])!=2
            or type(body["directions"]) is not list or not 1<=len(body["directions"])<=2):
        raise ValidationError("incomplete bilateral federation agreement")
    parties=set()
    for party in body["parties"]:
        if (type(party) is not dict or set(party)!={"zone_id","terminator","signing_authority"}
                or any(not name(value) for value in party.values()) or party["zone_id"] in parties):
            raise ValidationError("agreement parties require distinct zones, terminators and signing authorities")
        parties.add(party["zone_id"])
    if identifiers(body["signed_by"])!=parties:raise ValidationError("agreement version lacks both party signatures")
    pairs=set()
    for direction in body["directions"]:
        if (type(direction) is not dict or set(direction)!={"from_zone","to_zone","signed_by","factor","factors_by_action_class",
                "factors_by_substrate_profile","lowering_policies","floor","lowest_enforcement_class"}
                or any(not name(direction[key]) for key in ("from_zone","to_zone","signed_by","lowest_enforcement_class"))
                or {direction["from_zone"],direction["to_zone"]}!=parties):
            raise ValidationError("agreement direction is incomplete")
        pair=(direction["from_zone"],direction["to_zone"])
        if pair in pairs:raise ValidationError("duplicate agreement direction")
        pairs.add(pair)
        for cell in ("factors_by_action_class","factors_by_substrate_profile"):
            if type(direction[cell]) is not dict or any(not name(key) for key in direction[cell]):
                raise ValidationError("invalid scoped directional factor table")
        identifiers(direction["lowering_policies"])
        # Factor values are checked when selected: one void clause must not void
        # the other direction or unrelated scoped terms.
    handling=body["data_handling"]
    if (type(handling) is not dict or set(handling)!={"attestation_types","trajectories","persons","cross_zone_sponsorship","breach_records"}
            or any(type(handling[key]) is not bool for key in ("trajectories","cross_zone_sponsorship"))
            or handling["breach_records"]!="exposure"):
        raise ValidationError("agreement must declare exactly what crosses, with breach exposure")
    identifiers(handling["attestation_types"])
    if handling["persons"] is not None:
        person=handling["persons"]
        if (type(person) is not dict or set(person)!={"standing","terms"} or type(person["standing"]) is not bool
                or person["terms"]!="signed-acts-only"):
            raise ValidationError("person terms must preserve signed-act scope")
    if type(body["sovereignty_enforced"]) is not dict or body["sovereignty_enforced"].keys()!=parties:
        raise ValidationError("agreement must name each party's sovereignty constraints")
    for values in body["sovereignty_enforced"].values():identifiers(values)
    route=body["dispute_route"]
    if (type(route) is not dict or set(route)!={"route","deadline_seconds"} or not name(route["route"])
            or not _time(route["deadline_seconds"])
            or any(not _time(body[key]) for key in ("incident_notification_seconds","leaving_notice_seconds"))
            or not identifiers(body["severance_causes"])):
        raise ValidationError("agreement lacks its review and incident/severance terms")
    if type(body["clauses"]) is not list or len(body["clauses"])>4096:raise ValidationError("invalid classified agreement clauses")
    seen=set();void=[]
    for clause in body["clauses"]:
        if (type(clause) is not dict or set(clause)!={"id","effect"} or not name(clause["id"]) or clause["id"] in seen
                or type(clause["effect"]) is not str or clause["effect"] not in VOID_EFFECTS|{"format-version","recognition-only","other"}):
            raise ValidationError("invalid or duplicate classified agreement clause")
        seen.add(clause["id"])
        if clause["effect"] in VOID_EFFECTS:void.append(clause["id"])
    return tuple(void)


def profile_terms(body):
    if (type(body) is not dict or set(body)-{"standing_binding"}!={"id","version","receiving_zone","formula","enforcement_classes","subject_profiles","lowering_policies"}
            or not name(body["id"]) or not name(body["receiving_zone"]) or not _time(body["version"]) or body["version"]==0
            or body["formula"]!="minimum-applicable-directional-terms-v1"
            or type(body["enforcement_classes"]) is not dict or not body["enforcement_classes"]
            or identifiers(body["subject_profiles"])!={"software"}):
        raise ValidationError("invalid selected software federation profile")
    if "standing_binding" in body and body["standing_binding"]!="admission-digest-ceiling-v1":
        raise ValidationError("unsupported federation standing binding")
    identifiers(body["lowering_policies"])
    for key,value in body["enforcement_classes"].items():
        if (not name(key) or type(value) is not dict or set(value)!={"rank","factor_ceiling"} or not _time(value["rank"])):
            raise ValidationError("invalid receiver Enforcement Class declaration")
        ratio(value["factor_ceiling"],name="class factor ceiling",maximum=1)
    return body
