# Dual-schedule relational decisions and protected review state

Sources: hand-back `17f37b772eac8b2f84248c1912f3aeb3f5fa26d1` §§8/10 and
HB-10-001 through HB-10-004. This selects the dual-schedule meaningfulness path;
it is not a Full hand-back, deployment or cryptographic conformance claim.

## Selected decision policy

`accountable-adjudication-dual-schedule-v1` declares `full-exogenous` and the
digest of the exact installed `InstalledDecisionReviewVerifier`. Constructor
checks require symmetric selection, identical deployment bytes and zone, and
the declared review profile. The separate `standard-endogenous` policy cannot
silently claim or substitute this path.

The prior observed refusal run remains mandatory. The current actual signed
adjudication token, grant, accountability, original repair route and current
epoch bindings remain independently required. The production inventory must
contain this actual signed human decision by anchor, actor, decider, approval,
review kind and exact decision/acknowledgment/review times. An unrelated healthy
history cannot satisfy this decision's gate.

The installed production monitor checks sampled and outcome-triggered reviews,
historical governing policies, original role intervals, overdue work, persisted
findings/resolutions and current complete coverage. Its failure blocks the human
gate. Source errors propagate. Satisfying the declared certification run does
not mask a production uniform-approval finding. The earliest monitor validity
also bounds the decision and downstream Clear/commit evidence.

## Protected view and commit

Source now authenticates a protected review-view `state_revision` with continuity
across updates/restart. The sealed review assessment carries a data frame with:

- selected review-profile digest and actual decider;
- actual review-ledger head and protected revision;
- full history, open review/finding backlog and finding/resolution digests;
- historical profile bodies, actual role registries and governing-map digest;
- an authenticated `covered_through` watermark.

The stable data fingerprint excludes only the advancing coverage watermark.
Observation-time metadata alone is not a protected revision. Actual Source
changes must appear in the data/ledger/revision; a watermark must attest genuine
complete coverage and cannot be advanced merely by assigning a new timestamp.

For this selected decision, `InstalledRelationalCommitVerifier` requires the
exact authenticated `review_state` and a `production_review` fence. They bind
the independently verified frame/revision, not a generic approval Boolean.
Removing either state or fence cannot downgrade to Standard. The conditional
contract includes this review view and all previous grant/nonce/authority/native
conditions. Its expiry is bounded by the monitor and all other supporting
evidence, including the parent Clear result.

At commit, the separately authenticated protected frame must report actual
review coverage through the exact commit instant. Stale coverage rejects even
when the authority frame's own timestamp is current. An unchanged data view can
remain valid when its genuine watermark advances; any changed history, backlog,
finding, registry, ledger, revision or fence rejects. Comparison success remains
`action_permitted=False` and is not native Clear or complete authorization.

Service must authenticate/read the actual current review view under its declared
fence protocol and atomically compare all conditions, consume the nonce and
commit the exact protected mutation or durable dispatch intent. This Library
does none of those I/O effects and cannot establish distributed coherence,
actual entropy, honest human review or a production database from test fixtures.

## Exercised paths and remaining scope

The existing signed native integration now exercises dual-schedule positive
Clear, real signed favorable approval blocked by production finding, preserved
endogenous refusal, review-SLA expiry bounding Clear and its contract, and old
sampling/SLA terms surviving a current-policy change. Commit tests distinguish
stale coverage, unchanged freshly covered data and changed protected data.
Model histories/registries/storage remain explicit; token and native proof
signatures use real named test-profile cryptography.

The selected HB-10 composition is now implemented. Actual adapters, broader
hand-back families (delivery/escalation, formation/revocation, unmanaged/demotion
and other architectural/source cases), complete capability selection and the
rest of the release-set inventory remain open. The final RFC tag is still
required for normative adoption, not for continuing implementable work. No new
RFC wire, PR, merge or release is supplied by this checkpoint.

Verification: supplier review found no actionable defect in the dual-schedule
composition or commit-time coverage change. All 1,178 regression tests passed.
The final built package passed 61 focused review/decision/commit/native-readiness
tests, including the additional signed native overdue/historical-policy cases;
14 pure review checks passed without optional dependencies.
