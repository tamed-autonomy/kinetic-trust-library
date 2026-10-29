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

## Implemented checkpoint: accountable decision and endogenous refusal

`InstalledRelationalDecisionVerifier` combines the exact installed relational
reissue gate with a required signed adjudication policy. Its selected private
`accountable-adjudication-endogenous-v1` profile is SHA-256/Standard-endogenous;
it rejects optional adjudication and Full-exogenous claims. This is an additional
gate, not a score, capacity measurement, approval to execute or nonce consumer.

Source separately authenticates the current person/key registry, signed liability
reference and anchor, actual signed decision record and declared certification
run. The verified token issuer/key must resolve to that person/key holder, never
the acting agent. Liability and current key registration must precede the run and
decision; revocation or expiry blocks the gate. The actual decision record binds
the full signed token hash, whole operation, exact lease, current evidence, grant
epoch, topology epoch and registered repair route. Current ledger head and grant
epoch must agree with relational reissue. Acknowledgment is distinguished from
review, and the recorded decision must have offered refusal as well as approval.

Every deployment-declared refusal case is pinned by case digest, whole-operation
digest and enforcement-boundary identifier. The complete anchored run must use
the current registered principal/key, precede this decision and remain within its
declared age. Its case records must show substantive review and actual refusal.
The shared execution-observation projection additionally requires an actual
denial record and an explicitly bound non-dispatch observation at that boundary,
within the run's time and topology epoch. Missing observation, actual dispatch,
wrong operation/decision hash or another boundary cannot certify refusal. These
are authenticated historical facts, not an absence-of-dispatch shortcut. Neither
the run nor acknowledgment substitutes for the current signed favorable decision.

The result expires at the earliest of reissue, adjudication token/context, human
Source, principal registration and refusal-run validity. Operational Source
failures propagate; they are not converted into authenticated human evidence.
Tests use real test-profile token signatures; identity/liability, audit anchors,
key custody and actual certification runs are modeled Source evidence. Protocol
does not attest humanity, review quality, physical agency or production refusal
rates. Full stochastic sampling, outcome-triggered review and uniform-approval
findings are still pending. So are the atomic single-use commit contract and
conditional relational Clear composition. No full HB-10 or deployment claim is
made by this selected endogenous checkpoint.

Decision checkpoint verification: supplier review found no actionable defects;
all 1,129 regression tests passed. The built distribution passed 41 focused
decision/reissue/adjudication/execution-observation tests. The new module also
imports with site-package loading disabled. Source cases HB-10-001, HB-10-002
and HB-10-004 motivate the implemented semantic checks; HB-10-003's production
exogenous schedule remains unsupported rather than silently claimed complete.

## Implemented checkpoint: conditional relational Clear and commit conditions

`InstalledRelationalCommitVerifier` selects the private
`conditional-single-use-commit-v1` policy. It requires the installed accountable
decision gate plus Source-authenticated actual authority registration, nonce
ownership/live state/revision, grant epoch, topology epoch, ledger head and seven
protected prerequisite fences. Authority registration and nonce registration
must precede the grant; withdrawal, revocation, consumption or disagreement
between current Sources prevents construction. The named authority protocol is
`compare-nonce-epoch-fences-with-effect-v1`; its registration is authenticated
Source evidence, not a claim established by a string or by this test suite.

The contract pins the exact operation/subject/zone/deployment, nonce namespace,
actual full grant, authority and nonce revisions, current epochs/head, original
template, native geometry evidence, human decision and repair reference. Fence
anchors must match the corresponding verified facts, not arbitrary caller
references. Source owns the durable revisions and complete dependency coverage:

| Fence | Anchor and protected dependency |
| --- | --- |
| grant | Actual grant audit record and current grant state |
| nonce | Actual authority-owned nonce record/live revision |
| human_decision | Actual signed accountable decision and its current supporting registry/run evidence |
| template | Original registered template digest and current registration/return-path status |
| native_evidence | Verified native geometry digest and an aggregate protected revision covering all native prerequisite dependencies, including current readiness and boundary evidence |
| adverse_stop | Current ledger head and active-stop/epoch state |
| authority | Actual authority registration anchor and current protocol/custody/namespace registration |

The selected clearance policy `conditional-single-use-v1` installs this exact
decision/reissue/ledger graph and lease authority by digest and identity. It
requires a native boundary verifier, matching topology epoch, the original
template's repair reference, current native prerequisites, supervision and
constraints. Conditional Clear bounds the commit contract itself by the shortest
supporting native/template/registry/reissue/decision expiry; the contract cannot
outlive the Clear result. Duration Clear keeps its independent duration bound.

`check_relational_commit` accepts the installed typed assessment, never an unsigned
wire contract. It compares the exact actual operation and a separately
authenticated current protected frame at commit time, rejecting changed nonce or
authority revision, consumed/revoked tokens, changed epochs/head/fences and
expired evidence. Matching conditions return `action_permitted=False`: they
are neither full Clear nor ordinary authorization. A timestamp alone cannot
prove a frame is current; the caller must read the real protected authority state
under the same transaction/lock that consumes the nonce and commits the exact
protected mutation or durable dispatch intent. Serialization does not preserve
authority: a remote consumer must independently authenticate its complete decision
path or rerun the installed verifiers, not deserialize these bytes into permission.

The modeled authority test serializes two attempts against one nonce and observes
one accepted consumption/one modeled effect. This tests compare-before-consume
semantics, not a production database, crash recovery, actual durable consumption,
remote delivery or downstream effect confirmation. Service must still provide
those adapters and complete ordinary authorization. Returning conditional Clear
does not dispatch. Full exogenous decision meaningfulness and the remaining
hand-back families/capability-selection work remain open. This private selected
contract must be reconciled with the final RFC tag; no RFC wire is added.

Clear/commit checkpoint verification: supplier review found no actionable defects.
All 1,137 regression tests passed. The final source and built-wheel focused runs
passed 48 tests, including the actual signed native composition and modeled
concurrent consumption check. The comparison result's API cannot construct
action permission and imports without optional dependencies. RFC refresh found
no final 3.0 tag and unchanged main; the released baseline remains untouched.
