# Hand-back delivery effort

Implement the deterministic parts of hand-back §§4.1/10.3/10.16 at
`17f37b772eac8b2f84248c1912f3aeb3f5fa26d1`, especially HB-03 and HB-16.
Use inline TDD, supplier review, full/installed checks and push checkpoints.

1. Project complete recorded delivery attempts, capacity evidence, sealed escrow,
   receipts and declared retry/escalation timing without any I/O or permission.
2. Install a Source-backed delivery verifier around the existing hand-back
   validator. Authenticate original grant-time schedule/route/capacity declaration,
   immutable message/context identity, durable escrow and complete audit history.
3. Preserve stop construction and independent denial when delivery work is late,
   missing or parked. Delivery cannot renew authority, reprice a stop or grant Clear.
4. Exercise unreachable, exhausted, unknown capacity, recovered capacity, recorded
   receipt, missed attempts/escalation and restart/history binding cases.
5. Record exact reference-policy choices and actual Service obligations; push
   without PR, merge or release.

Selected private schedule: initial attempt due at issue, retries relative to the
previous unsuccessful attempt, declared recording tolerance, and anchored periodic
escalation levels with a declared delivery-level cap. This cap is not the separate
reissue/hysteresis cap. Missing/late work creates recording obligations and never
changes the stop. Escalation does not disclose plaintext or invent a new decider;
any alternate channel must be predeclared for the same original endpoint,
principal and sealed key. The original hand-back wire remains immutable;
its construction-time delivery annotation is not rewritten into current status.

## Implemented selected lifecycle

`delivery_effort.project_delivery_effort` validates actual complete attempt,
capacity-observation, receipt and escalation histories. Every event binds the
same immutable hand-back digest and declared capacity binding. A reachable
address is insufficient: acceptance requires a fresh available-capacity snapshot
and actual recipient receipt. Exhausted or unknown capacity parks; stale claimed
capacity produces a defect and cannot establish acceptance. Receipt acceptance
and authoritative recording times are distinct. Retries before the worker knew
delivery was confirmed are not labeled duplicates; work missed before a late
confirmation remains recording debt.

The selected schedule makes an initial attempt due at issue, retries relative to
the previous unsuccessful/unconfirmed attempt and periodic escalation levels
relative to issue, with explicit declared recording tolerance. Known confirmed
delivery stops retry/escalation work. Missing/late/early work remains visible;
it never changes `reissue_not_before`, increments hysteresis or authorizes action.
The selected acknowledgment clock starts at the earliest accepted receipt in
the authenticated inventory and uses the original recipient's declared SLA.
The RFC does not fix that clock origin or numeric cadence; this is a private
reference policy to reconcile at final-tag adoption.

`InstalledHandBackDeliveryVerifier` separately validates the original hand-back,
then authenticates its actual grant-time schedule declaration, original
template/lease/capacity binding, complete queue counters/history/head, audit owner
and append protocol. Any alternate channel must have been registered before the
grant for the same original logical endpoint, principal and sealed key. It cannot
substitute a different person, key, plaintext destination or undeclared route at
stop time. Actual capacity snapshots and recipient receipts must match the
original message/context/attempt; escrow must retain that same sealed material.

The immutable original wire is not silently rewritten with a current delivery
annotation. The original record's annotation can remain parked while the
separate lifecycle proves delivery completed. The complete lifecycle cannot
discard attempts or delivery facts already established by the original record.
Operational Source failure does not become an empty successful history.

Missing escrow and overdue work do not invalidate independently valid original
hand-back construction. They return obligations, not an orphan stop or Clear.
An immediate successful delivery needs no parked escrow; optional storage added
after that completion is not falsely recorded as late required escrow. A capacity
pressure recording obligation is keyed by the original hand-back digest.
Per-attempt exhaustion anchors are evidence, not separate hand-backs to count in
the required pressure feed. No normalized Risk Factor value or standing penalty
is invented; Service/provider owns deduplication, the actual feed and its declared
measurement/normalization policy.

Source must establish genuine pre-grant declarations, real complete histories,
durable storage, capacity facts, recipient acknowledgments and receipt signatures.
Fixtures verify the original sealed AES-GCM context with real test cryptography;
new queue/receipt/storage facts are modeled. The Library performs no transport,
retry, escrow write, notification, ledger append, acknowledgment or metric write.
All assessments remain `action_permitted=False`. Service must actually carry out
and record each owed operation and preserve independent denial throughout.

This selected adapter bounds authenticated state to 262,144 bytes, histories and
route records to 4,096 entries, and escalation levels to 4,096. It rejects oversized
or truncated histories rather than claiming effort from partial evidence. A
production provider needing larger histories must supply a separately specified
complete-history/archival adapter; no unsigned summary is accepted as full proof.
No complete HB-03/HB-16 deployment claim follows from modeled fixtures alone.
Broader hand-back cases, complete deployment selection and final-tag adoption
remain open. The released baseline is unchanged; no PR, merge or release occurs.

Verification: supplier review found no actionable defects, including delayed
receipt causality, optional escrow and original-history consistency checks.
All 1,201 regression tests passed. The built package passed 39 focused delivery,
original hand-back/template and signed native-readiness checks. All 13 pure
delivery tests passed without optional dependencies. RFC refresh found unchanged
main and no final 3.0 tag. This verifies the selected Library contracts, not
actual production transport/storage or the complete hand-back family.
