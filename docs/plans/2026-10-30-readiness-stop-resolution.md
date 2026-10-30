# Current readiness failure and bounded adverse result validity

The existing native stop-resolution protocol now has a distinct
`native-readiness-return-path-v1` selector. It accepts only a bound ordinary
request whose actual current readiness assessment failed with one of
`READINESS_UNAVAILABLE`, `READINESS_INVALID`, `READINESS_PROOF_INVALID` or
`READINESS_DECISION_INVALID`. It resolves an adverse permit-condition hand-back
through the same original template, sealing/preparation and current full-graph
revalidation checks. Valid native prerequisites, unrelated failures and ordinary
proof expiry cannot enter this family.

Native results retain hashes of the original readiness decision and attestation
bytes when that stage was entered. Readiness results retain audit-only hashes
of the observed Source request, state and key context even when subsequent
validation fails. Invalid state remains absent from accepted-authority fields.
The stop cause binds those identities and the installed measurement/readiness
profile; an unavailable Source has no invented context bytes or measurement.
Actual Source truth, genuine unavailable-state evidence and complete encrypted
recipient context remain preparation/provider obligations.

A regression exposed by this runtime composition is fixed centrally: every
current clearance variant with an expiry, including adverse and lease-expired
results, is bounded by selected management validity. It is not enough to apply
that limit only to Clear or proof refresh. Tests establish the former 1007 versus
1002 discrepancy and verify resolution retains 1002.

New-stop-only semantics, durable/idempotent actual preparation, parked delivery
and no execution permission remain as documented in the native-stop plan.
