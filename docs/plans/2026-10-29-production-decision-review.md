# Production decision review

Sources: hand-back `17f37b772eac8b2f84248c1912f3aeb3f5fa26d1` §10.10 and
retained source case HB-10-003. This is a selected provisional monitor, not a
Full hand-back claim or a new RFC wire. The subsequent dual-schedule-gating
checkpoint composes this monitor with the endogenous decision gate and protected
commit view. It still does not establish overall Full conformance.

## Implemented reference policy

`uniform-draw-and-outcome-review-v1` declares an exact positive rational sampling
rate, sampler, review authority, outcome triggers, rolling window, positive
review SLA, uniform-approval count threshold, ledger owner and append protocol.
No risk score, human quality score or standing penalty is inferred.

Each actual production decision has one Source-authenticated first uniform draw
over the declared denominator. A draw below the numerator selects the decision
with exactly that declared probability; no floating-point approximation is used.
Source must establish the real sampler, first-draw provenance, lack of redraw or
selection bias, and complete actual history. Neither an integer nor this Library
can prove that it came from a real stochastic source.

Sampling and every declared triggered outcome create separate review obligations.
Review must follow the actual cause in time and audit order, bind the decision,
use the independent registered review authority and identify covered outcomes.
Acknowledgment cannot satisfy review. A later outcome cannot be discharged by
an earlier review. Missing review becomes overdue at its declared deadline;
late completion retains a recording obligation even when no longer overdue.
Older open work remains required after the decision leaves the rolling window.

Uniform approval is assessed over all sampled production decisions for the same
decider in the current zone/window, across acting subjects. At the declared
count threshold, all approvals with exact indistinguishable original review and
acknowledgment times produce a finding. A staged endogenous refusal is not in
this population. Fractional timestamps are compared exactly; input precision
must represent the actual events and must not be rounded to manufacture a
finding. This is a finding/recording signal, not an adjudication of intent or an
automatic sanction.

`InstalledDecisionReviewVerifier` binds deployment, actual operation, decider,
zone, profile, current complete window coverage, actual ledger owner/head and
append protocol. It checks registered sampler/reviewer identities, independence
from the actual decider/actors, registration before historical use and current
withdrawal status. A separately authenticated durable open-obligation inventory
must match pending and overdue causes; empty pricing/history retention cannot
erase an old backlog marker. Source failures propagate rather than becoming an
empty successful review. Evidence validity stops at the next pending deadline
or rolling-population change, bounded by Source expiry.

The initial adapter rejected historical policy transitions. The historical
checkpoint below now authenticates each event's governing body and role registry;
it does not reprice an old draw/SLA/trigger under current rules or omit historical
decisions and their open obligations. The subsequent dual-schedule-gating plan
documents the implemented decision-gate and commit-fence composition.

## Required continuation

1. Completed by the historical checkpoint below: preserve governing sampling/SLA/trigger policies without changing
   actual draws or erasing older outstanding obligations.
2. Completed by the dual-schedule checkpoint: compose the monitor symmetrically into a selected accountable decision policy;
   bind its actual decider/current ledger and preserve the endogenous gate.
3. Completed by the dual-schedule checkpoint: carry review-ledger/backlog revisions through conditional relational Clear and
   the protected commit contract, with shortest validity and failure routing.
4. Completed for the selected family by the dual-schedule checkpoint: exercise HB-10-003 through actual signed native composition, including finding,
   overdue review, policy transition and commit-time invalidation cases.
5. Continue the broader hand-back/RFC capability work. This monitor alone never
   reports `gate_satisfied`, `conditional_clear` or action permission.

Production fixtures model actual histories, draws, review quality, independent
registries and durable backlog. Actual entropy, audits, record persistence,
escalation and sanctions remain Service/governance responsibilities. Source must
provide every relevant decision in the window and every older open obligation;
the monitor does not discover or authenticate omitted real-world events itself.
The draft does not fix this draw algorithm, threshold population or review clock
formula; their selected interpretation is isolated here for final-tag review.

Verification: supplier review found no actionable defects. All 1,155 regression
tests passed. The built package passed 40 focused monitor/relational-decision/
commit tests; all 12 pure review checks also passed without optional dependencies.

## Historical policy and finding checkpoint

The installed Source now supplies digest-pinned `profile_registry` bodies and
per-policy `registries`. Each actual decision maps to its governing body. The
pure projection preserves its actual sampling space/rate, trigger list, review
authority and review SLA; it does not replace those terms with today's policy.
Current rolling diagnostics combine all genuinely sampled decisions across
policy versions under the current window/count threshold, avoiding population
splitting by version. Ledger owner, append protocol and zone must remain the
same; changing that authority namespace requires a separate explicit adapter.

Historical sampler/reviewer registrations are checked at actual use time. A
later retirement does not invalidate a draw/review that was valid when made;
use before registration or at/after withdrawal rejects. The current selected
roles must also remain registered now. Source authenticates the actual governing
policy at each historical event and any role/protocol transition; a matching
digest cannot independently establish authorization or stochastic provenance.

Persisted findings survive changes to today's threshold or population window.
Their exact then-known sampled population is reconstructed with original event
policies, the finding's governing window/threshold, complete historical coverage,
and time/audit position. Later draws or decisions cannot rewrite that basis.
Each unresolved finding has a separate authenticated durable open marker; a
missing record cannot silently clear that marker. Resolving a finding requires
an actual forward audit record, governing policy and independent authorized
reviewer whose registration was valid at resolution time. A valid old resolution
survives later reviewer replacement or retirement. An exact resolved current-
policy/population pattern is not reopened without new evidence; changed evidence
can produce a new recording obligation. These are monitor conditions and audit
obligations, not automatic standing penalties or persisted effects.

Supplier review exposed and verified the fix for a historical-authority bug:
initially resolution authority was compared with today's reviewer. It now uses
the resolution's authenticated governing policy and historical reviewer interval.
Focused regression tests cover reviewer replacement, unresolved-finding retention,
resolved-pattern deduplication and new-evidence recurrence.

This completes historical-policy handling for this selected fixed-ledger family.
The remaining continuation is symmetric Full decision-gate selection, binding
review-ledger/backlog/finding revisions into conditional Clear/commit, and actual
signed native coverage. There is still no Full hand-back or deployment claim.

## RFC refresh observed during verification

RFC main remained `9612f7955d88e25d193dab2a17d51d0c9d9075d0` with no final 3.0
tag. These proposal branches were force-updated and require separate pin/vector
reconciliation before an alignment claim:

- canonical Trust Proof: `223f4259f7441ca97a916d26476a71b6114005a6`
- request association: `1ea01e4d0454d51583bd2eb7bf1e898c9252d722`
- decision geometry: `5878df1fcbb50f5f45672ddaf2a13c98d666e3d7`
- one Core contract: `40f00a02be58f8b43c31485c9ffcb021758372f6`

Observed tree changes include informative-only Risk Domains, the native v3
Risk Factor schema identifier with separately archived legacy v2 schemas, exact
worked-example/demand-vector decimals and associated schema references/hashes.
The hand-back source pin governing this monitor is unchanged. Reconcile these
refreshed primary contracts next; do not silently update released v2 pins or
claim that the current package already implements every refreshed tree change.

Historical checkpoint verification: supplier final review found no remaining
actionable defects after the resolution-authority correction. All 1,166 regression
tests passed. The built distribution passed 53 focused review/decision/commit/
native-readiness tests; all 14 pure review tests also passed without optional
dependencies. No PR, merge or release is part of this checkpoint.

The subsequent native-schema-refresh checkpoint reconciles the observed native
Risk Factor identifiers, proof/record references and exact example/vector scope;
see `2026-10-29-native-schema-refresh.md`. Broader release-set and Full production-
review composition work remain pending.
