"""Audit-grade hand-back §5 authority and measurement separation checks.

Inputs describe actual capability/access inventories, not merely file locations.
Authenticating the architectural audit and its completeness remains Source work.
This does not prove private-key custody, independence or physical deployment.
"""
from dataclasses import dataclass,field
from kinetic_trust_library.errors import ValidationError
from .execution_observation import _name
from .root_lifecycle import _time


def _names(values):
    if (type(values) is not list or len(values)>4096 or any(not _name(v) for v in values)
            or len(set(values))!=len(values)):raise ValidationError("distinct complete authority inventory required")
    return set(values)


@dataclass(frozen=True,slots=True)
class AuthoritySeparationProjection:
    valid: bool
    reason: str
    external_measurers: tuple
    evidence_grade: str=field(default="architectural-audit",init=False)
    action_permitted: bool=field(default=False,init=False)


def project_authority_separation(*,inventory,quorum_members,quorum_k,zone_class,single_measurer_limit):
    members=_names(quorum_members)
    if (not members or not _time(quorum_k) or not 1<=quorum_k<=len(members)
            or zone_class not in ("green","cyan","blue","deep_blue")
            or zone_class in ("blue","deep_blue") and quorum_k<2
            or single_measurer_limit is not None and (type(single_measurer_limit) is not str or not 0<len(single_measurer_limit)<=4096)
            or quorum_k==1 and single_measurer_limit is None):
        raise ValidationError("invalid declared zone-specific measurer quorum/limitation")
    f=inventory
    if (type(f) is not dict or set(f)!={"agent_processes","agent_boundary_processes","lease_constructor_processes",
            "accepted_lease_keys","operator_boundary","measurers","key_custody","used_measurers"}
            or not _name(f["operator_boundary"])):raise ValidationError("actual complete authority audit inventory required")
    agent=_names(f["agent_processes"]);boundary=_names(f["agent_boundary_processes"])
    constructors=_names(f["lease_constructor_processes"]);lease_keys=_names(f["accepted_lease_keys"])
    used=_names(f["used_measurers"])
    if not agent or not agent<=boundary or not lease_keys:raise ValidationError("actual agent boundary and lease accepted keys required")
    if type(f["measurers"]) is not list or len(f["measurers"])>4096:raise ValidationError("complete measurer roster required")
    roster={};all_keys=set(lease_keys);measurement_processes=set();shared=False;seen_measurement_keys=set()
    counted_processes=set();shared_process=False
    for m in f["measurers"]:
        if (type(m) is not dict or set(m)!={"id","operator_boundary","processes","accepted_keys"}
                or not _name(m["id"]) or not _name(m["operator_boundary"]) or m["id"] in roster):
            raise ValidationError("actual distinct measurer identity and boundary required")
        processes=_names(m["processes"]);keys=_names(m["accepted_keys"])
        if not processes or not keys:raise ValidationError("measurer processes and accepted keys required")
        shared=shared or bool(keys&seen_measurement_keys)
        if m["id"] in used:
            shared_process=shared_process or bool(processes&counted_processes)
            counted_processes|=processes
        seen_measurement_keys|=keys;all_keys|=keys;measurement_processes|=processes;roster[m["id"]]=m
    if set(roster)!=members or not used<=members:raise ValidationError("used measurers differ from actual declared quorum roster")
    if type(f["key_custody"]) is not list or len(f["key_custody"])>4096:raise ValidationError("complete accepted-key access inventory required")
    custody={}
    for entry in f["key_custody"]:
        if (type(entry) is not dict or set(entry)!={"key","processes"} or not _name(entry["key"]) or entry["key"] in custody):
            raise ValidationError("distinct actual accepted-key custody required")
        custody[entry["key"]]=_names(entry["processes"])
        if not custody[entry["key"]]:raise ValidationError("accepted-key custody cannot be omitted")
    if not all_keys<=set(custody):raise ValidationError("accepted key missing from actual custody audit")
    external=tuple(sorted(m for m in used if roster[m]["operator_boundary"]!=f["operator_boundary"]))
    reason=("AGENT_CAN_CONSTRUCT_LEASE" if boundary&constructors else
            "AGENT_HOLDS_ACCEPTED_KEY" if any(boundary&custody[key] for key in all_keys) else
            "MEASUREMENT_EXECUTION_PROCESS_OVERLAP" if agent&measurement_processes else
            "MEASURER_KEYS_SHARED" if shared else
            "MEASURER_PROCESS_SHARED" if shared_process else
            "MEASURER_QUORUM_NOT_MET" if len(used)<quorum_k else
            "NO_EXTERNAL_MEASURER" if not external else "AUTHORITY_SEPARATION_VALID")
    return AuthoritySeparationProjection(reason=="AUTHORITY_SEPARATION_VALID",reason,external)
