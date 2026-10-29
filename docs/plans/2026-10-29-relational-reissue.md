# Relational reconciliation and token reissue

Continue the hand-back plan inline with TDD/supplier review. Sources: hand-back
`17f37b772eac8b2f84248c1912f3aeb3f5fa26d1` §§6–8, repair
`e1f124b64de3234bc96f94fcd7c8ee612d965517` record/independence/decline rules.

1. Extract common reconciliation-record prerequisites from actor re-entry;
   preserve existing breach costs. Relationship-only reconciliation must not
   fabricate actor breach, confession or standing loss.
2. Install a selected relationship-record reissue policy. Source authenticates
   actual grant/nonce/current epoch, persistent latest adverse relational barrier,
   complete relevant stop inventory and current anchored reconciliation records.
   Bind cause, parties/terminators, acknowledgment, residual/disposition,
   independent non-Oracle verifier and declared no-show route/clock.
3. Require the replacement grant to follow all required records in actual audit
   order and time, and the protected epoch to preserve invalidation of old tokens
   across retention/restart. Actual consumed/revoked nonce state stays independent.
4. Compose the selected gate into historical reissue checking. Keep relational
   Clear disabled until the separate accountable human/adjudication and commit-
   time single-use contract is installed. No scores or delegation are inherited.
5. Review/full/installed tests, document precise draft mapping and push checkpoint.

Draft seam: repair's record names a breach and its acknowledgment, but hand-back
explicitly says a lawful stop is not a breach while requiring reconciliation for
relational reissue. The selected private mapping targets the relationship's stop
anchors and acknowledges reconciliation occurrence, never wrongdoing. This is
provisional evidence, not a new RFC wire or full conformance claim. Source owns
actual anchoring, authority, attendance and privacy; Service owns durable barrier,
nonce invalidation/consumption and atomic effects.

## Implemented checkpoint: persistent relational reissue

`InstalledRelationalReissueVerifier` selects the private
`adverse-stop-relationship-record-v1` policy. Its authenticated Source owns a
complete subject-specific relational stop inventory, including stops older than
pricing retention and stops whose penalty was expunged. The latest barrier must
match that inventory; stop epochs strictly increase and cannot exceed the current
protected epoch. Complete actual grant bytes/digest and audit position are bound
to the current operation. Independently authenticated live consumed/revoked nonce
state overrides stale flags in a transported grant. Returning eligibility does
not mint or consume a grant and never grants action authority.

Each stop requires a current anchored reconciliation naming its actual cause,
accountability terminators, acknowledgment, residual declaration and independent
non-Oracle verifier. Both audit order and occurrence time must precede issuance;
reconciliation after an early mint cannot repair that mint. Declined parties stay
named and the record stays open. The selected private clock starts at the stop,
uses declared positive integer seconds and requires route completion after that
deadline before the record can qualify. The Source separately authenticates the
actual registered route/clock/anchor, registration before the stop and grant, and
current withdrawal status. This is a selected reference policy, not an invented
universal RFC clock. This profile accepts exact integer-second facts and never
rounds fractional timestamps into permission.

The historical reissue verifier optionally selects this child by digest and the
exact same installed ledger verifier. It cross-checks current ledger head, epoch,
full actual grant audit record and retained stop inventory across both Sources.
Historical pricing bounds remain independently required; removed penalties do
not discharge relationship reconciliation. The combined evidence expires at the
earliest supporting deadline. A policy declaring the child without installing
it, installing it without declaring it, or substituting another ledger verifier
is refused.

Source fixtures model durable history/anchoring/nonce authority. These tests do
not establish a production database, signature registry, crash-safe barrier,
nonce fencing or actual consumption. Human decision/accountability and meaningful
refusal evidence remain the next gate. Relational Clear stays unsupported until
that gate and the commit-time single-use contract are installed. No claim that
all hand-back families or the full 3.0 deployment are complete is made here.

Verification: supplier review found no actionable defects. The final full suite
passed 1,115 tests. Source and built-wheel focused runs passed 34 tests across
relational/historical reissue and shared/actor repair. The pure repair projections
also passed 10 tests with site-package loading disabled. RFC refresh still found
no final 3.0 tag; released package version and normative baseline remain unchanged.
