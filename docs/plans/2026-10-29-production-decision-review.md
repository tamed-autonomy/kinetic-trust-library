# Production decision review

Sources: hand-back `17f37b772eac8b2f84248c1912f3aeb3f5fa26d1` §10.10 and
retained source case HB-10-003. This is a selected provisional monitor, not a
Full hand-back claim or a new RFC wire. The current endogenous decision gate
continues to reject Full-exogenous selection until the complete composition is
implemented and verified.

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

The adapter currently requires each event's authenticated governing profile to
match the installed profile. A historical policy transition is explicitly
unsupported; the adapter must not reprice an old draw/SLA/trigger under current
rules or omit historical decisions and their open obligations. A historical
registry adapter remains implementable next work, alongside the Full decision
gate and commit-fence composition.

## Required continuation

1. Preserve historical governing sampling/SLA/trigger policies without changing
   actual draws or erasing older outstanding obligations.
2. Compose the monitor symmetrically into a selected accountable decision policy;
   bind its actual decider/current ledger and preserve the endogenous gate.
3. Carry review-ledger/backlog revisions through conditional relational Clear and
   the protected commit contract, with shortest validity and failure routing.
4. Exercise HB-10-003 through actual signed native composition, including finding,
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
