# Existing invocation revalidation without ordinary replay acceptance

Request-binding proposal `d67d3cca77ad00d00971dd87e96ec7ca4184ccf2`
Section 6 requires an exact repeated association to fail as `RB_REPLAY`.
Software execution proposal `8dda717a51818a5e9ef00e36898ddae6af890230`
separately requires current-use and continuing-operation checkpoints. Repeating
ordinary acceptance cannot implement those checkpoints. Neither proposal grants
target idempotency or exactly-once release.

The private installed `reserved-invocation-current-use-v1` Source contract checks
an already accepted immutable association. It authenticates the actual complete
original durable reservation, issuer/JTI mapping, active replay-domain floor and
restore continuity. Its exact registry/profile, original anchor/acceptance time,
complete scope, positive epoch/revision and current check/expiry are validated.
Retained current-use results reject rollback and rewriting the original record.
Source remains responsible for complete durable state and actual authenticated
registry truth; neither a label nor a digest establishes those properties.

`InstalledExistingAssociationVerifier` reruns actual invocation reconstruction,
proof/Root and any carrier verification before the reservation query. It never
calls `reserve`. `RB_CURRENT` records this narrower continuing-use prerequisite;
it is not ordinary `RB_BOUND`, a replay exception or execution permission.
Ordinary `verify()` still uses atomic reservation and rejects exact replay.
Only a trusted installer may select the Source/profile; candidate workloads may
not choose them. The subsequent software checkpoint facade will pin that choice
alongside the installed consumer declaration.

`InstalledNativeEvaluationVerifier.revalidate_existing` requires the exact
original installed successful evaluation, uses that current reservation check,
and reruns every selected current native gate including readiness, live proof/
Root, boundary and original geometry verification. Original proof and artifact
deadlines remain binding. Current reservation expiry caps the returned result.
The standalone readiness API likewise requires `RB_CURRENT` to have been checked
at this use time, rejects exact expiration and retains its shorter deadline.
This is current prerequisite checking, not a new ordinary invocation or target
release. Service must still atomically fence current state and effects.
