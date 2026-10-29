"""Exact reference demonstrated repair capacity from authenticated audit facts.

The source owns complete windows, sustained-backlog classification, accountable
roots, current anchors and repairer history. Excluding a record from durable
throughput never unanchors it or removes its effect on stock/re-entry.
"""
from dataclasses import dataclass
from fractions import Fraction
import re
from kinetic_trust_library.errors import ValidationError
from .ambient_repair import ratio
from .root_lifecycle import _time


@dataclass(frozen=True,slots=True)
class RepairCapacityRecord:
    anchor: str
    repairer: str
    anchored_at: object
    hard: bool
    current_anchor_verified: bool
    anchor_order: int | None = None


@dataclass(frozen=True,slots=True)
class RepairCapacityWindow:
    starts_at: object
    ends_at: object
    backlog_positive: bool
    records: tuple[RepairCapacityRecord,...]


@dataclass(frozen=True,slots=True)
class RepairCapacityProjection:
    effective_capacity: Fraction | None
    demonstrated_capacity: Fraction | None
    declared_capacity: Fraction | None
    eligible_record_counts: tuple[int,...]
    anchored_record_counts: tuple[int,...]
    latest_hard_times: tuple[tuple[str,Fraction],...]


def project_repair_capacity(*,declared_capacity,windows,repairer_interval=0,prior_hard_times=(),accountable_roots=1):
    declared=None if declared_capacity is None else ratio(declared_capacity,name="declared repair capacity")
    interval=ratio(repairer_interval,name="declared repairer interval")
    if (type(windows) is not tuple or len(windows)>4096 or any(type(window) is not RepairCapacityWindow for window in windows)
            or type(prior_hard_times) is not tuple or not _time(accountable_roots)):
        raise ValidationError("repair capacity requires bounded exact windows and authenticated root history")
    hard_times={}
    for entry in prior_hard_times:
        if (type(entry) is not tuple or len(entry)!=2 or type(entry[0]) is not str or not entry[0] or entry[0] in hard_times):
            raise ValidationError("invalid prior repairer history")
        hard_times[entry[0]]=ratio(entry[1],name="prior hard record time")
    previous_end=duration=None;seen=set();eligible_counts=[];anchored_counts=[];backlogged=[]
    for window in windows:
        start=ratio(window.starts_at,name="capacity window start");end=ratio(window.ends_at,name="capacity window end")
        if (end<=start or previous_end is not None and start!=previous_end or duration is not None and end-start!=duration
                or type(window.backlog_positive) is not bool or type(window.records) is not tuple or len(window.records)>65536
                or any(type(record) is not RepairCapacityRecord for record in window.records)):
            raise ValidationError("capacity windows must be complete, contiguous and equal length")
        if previous_end is None and any(at>start for at in hard_times.values()):
            raise ValidationError("prior repairer history is from the future")
        previous_end=end;duration=end-start
        ordered=[];same_instant={}
        for record in window.records:
            at=ratio(record.anchored_at,name="repair record anchor time")
            if (type(record.anchor) is not str or re.fullmatch(r"(?:sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96})",record.anchor) is None
                    or record.anchor in seen or type(record.repairer) is not str or not record.repairer
                    or type(record.hard) is not bool or type(record.current_anchor_verified) is not bool or not start<=at<end
                    or record.anchor_order is not None and not _time(record.anchor_order)):
                raise ValidationError("invalid, duplicate or out-of-window repair anchor")
            group=same_instant.setdefault((record.repairer,at),[])
            group.append(record.anchor_order)
            seen.add(record.anchor);ordered.append((at,0 if record.anchor_order is None else record.anchor_order,record.anchor,record))
        if interval and any(len(group)>1 and (None in group or len(set(group))!=len(group)) for group in same_instant.values()):
            raise ValidationError("same-instant repairer records require authenticated anchor order")
        eligible=anchored=0
        for at,_,_,record in sorted(ordered):
            if not record.current_anchor_verified:continue
            anchored+=1
            prior=hard_times.get(record.repairer)
            if prior is None or at-prior>=interval:eligible+=1
            if record.hard:hard_times[record.repairer]=at
        eligible_counts.append(eligible);anchored_counts.append(anchored)
        if window.backlog_positive:backlogged.append(eligible)
    demonstrated=None if not backlogged else Fraction(sum(backlogged),len(backlogged))
    effective=(Fraction(0) if accountable_roots==0 or declared==0 else
               None if declared is None or demonstrated is None else min(declared,demonstrated))
    return RepairCapacityProjection(effective,demonstrated,declared,tuple(eligible_counts),tuple(anchored_counts),tuple(sorted(hard_times.items())))


__all__=("RepairCapacityRecord","RepairCapacityWindow","RepairCapacityProjection","project_repair_capacity")
