# Provisional 3.0 release-set coverage audit

Initial inventory checked 2026-10-29 on `codex/ktp-v3-library-planning`, checkpoint
`3432c9e`. Subsequent scoped checkpoints below refine that inventory.
This is an implementation inventory, not a conformance claim. The latest
available released baseline remains RFC `v2.1.0`, commit
`15520035267546e1035aad7beea0cc3cf9ef8f2c`. A fresh fetch found no 3.0 tag;
RFC `origin/main` remains `9612f7955d88e25d193dab2a17d51d0c9d9075d0`.
The package and root public API still declare 2.1.0. Native 3.0 work is staged
separately, without a v2 runtime/wire fallback in that path.

The earlier readiness audit concentrated on native inputs, proof and record
composition. That is not the whole release set. The original impact research
already named broader proposals, but those names were not converted into a
complete Library implementation queue. This audit makes that missing work
explicit. An RFC freeze today would still leave substantial Library changes.

## Evidence method and limits

Inspected the original implementation plans, current `v3/` source and focused
tests, package exports/pin, RFC proposal source text/schemas and boundary suites.
The initial inventory checkpoint passed 926 tests. That count establishes the
tested branch behavior only; it is not a denominator for RFC coverage.
The newly inventoried suites below have not been executed against a native
implementation merely because their files and vector counts were inspected.

“Present” means named code and tests exist for that scoped path; see
[checkpoint findings](../research/2026-10-26-v3-first-implementation-findings.md)
for actually run validation and limitations. “Gap” means no implementation of
the named native contract was located in the inspected v3 source/tests; generic
tightening or legacy v2 behavior is not counted as the new contract. This is
not an exhaustive audit of every normative sentence in every RFC. Each gap
still needs requirement-by-requirement implementation and validation.

## Implemented native families and remaining limits

| Requirement family | Code and exercised evidence | Current limit |
|---|---|---|
| Five-factor R, missing evidence, Soul-first ordering | `core_risk.assess_five_factor_risk`, `evidence_state`, `installed_soul`, `installed_environment`, `core_projection`; `test_v3_native_core_projection`, `test_v3_installed_soul`, `test_v3_installed_environment` | Operational source authenticity/aggregation remains external; exact nonrepresentable wire numbers reject. |
| Demand declaration/supplier/classification | `demand_operation`, `installed_demand`, `demand_classification`; their focused tests and native Core/claim integration | Installed formula calibration/source independence remains provider-owned; moment criticality is not a sixth R factor. |
| Software standing and External Root | `base_trust`, `installed_standing`, `installed_root`, `live_root`; real fixture signatures, exact-root and refresh tests | Person signed-act standing is not implemented by the software standing path. Effective repeating standing still needs an explicit wire rule. |
| Complete proof and native issuance | `complete_proof_verifier`, `native_proof_profile`, `native_issuance`, `core_claims`; proof/claim/issuance tests | Named stronger ordinary-proof profiles and independently reproduced acceptance arithmetic remain unfinished. Draft schema composition is explicit; full selected-profile conformance is unproven. |
| Request association, geometry and carrier | `request_association`, `geometry_verifier`, `native_geometry`, `geometry_carrier`, `geometry_issuance`, `carrier_association`; complete signed-path tests | Durable replay, production source profiles, actual operation reconstruction and final execution fencing remain Service/provider work. |
| Readiness and combined prerequisites | `installed_readiness`, `readiness_decision`, `native_evaluation`; current epoch/challenge/artifact/signature and facade tests | Level 3 ordinary-proof support is explicitly rejected. This result is not a complete release-set authorizer. |
| Trajectory and migration | `trajectory`, `_trajectory_reference`, `_jws_keys`; real classical signature/head/predecessor/migration tests | Consensus, commitment/registry durability and migration activation remain external. Final official five-factor fixture reconciliation is pending. |
| Human eligibility | `human_eligibility`, restriction-only human-origin join; exact scope/current-map/delegation tests | Direct-human capacity/execution remains separate; the provisional person signed-act standing route does not supply it. |
| Person signed-act standing | `person_standing`, `installed_person_standing`; exact retained source arithmetic, signed stress-act and current Root/institution/scope tests | Selected zero-peer/single-current-Root profile only, with explicit provisional trajectory policy. Person proof production, authenticated federation agreement composition, multi-instrument ranking and human operational capacity remain. |
| Privacy evidence and erasure accounting | `privacy_evidence`, `privacy_issuance`, `privacy_erasure`; real crypto plus modeled current-source tests | Actual lawful disclosure/retention, inventory discovery, custody/destruction, restoration and storage fencing remain external. |
| Nested ingress, enclosure risk and selected egress | `ingress`, `enclosure`, `egress`; complete proof, exact floor/capacity, new signed egress and source-binding tests | Receipt crypto/link encoding needs an interoperable named profile. Other enclosure/egress profiles and deployed containment/disclosure are not proven. |

These families do not close the native SDK gaps in the next table. In particular,
an installed source supplying an ordinary assessment is not a substitute for
the Library checking a newly defined deterministic restriction.

## Broader release-set gaps and ownership

Later dated checkpoint notes below supersede the earlier gap observations in
this table. Optional capabilities are now explicitly rejected by the selected
ordinary native profile as documented in the capability-selection checkpoint;
they are not implemented or implicitly claimed.

The vector counts are source-suite sizes, not passing-test counts. Commit links
pin the inspected proposal; an untagged proposal is not released authority.
Optional profiles are conditional scope decisions: either implement the named
SDK contract and validate it, or explicitly withhold that capability/claim.
Ordinary Core evaluation does not automatically claim an optional emergency,
mesh, software-consumption or execution runtime merely because its deployment
declaration can describe one. The goal still includes completing implementable
selected native paths; unsupported claims must not be silently accepted.

| Proposed requirement and source | Verified current gap / reusable seam | Library work owed | Service/provider work |
|---|---|---|---|
| [Emergency capability/protected policy](https://github.com/nmcitra/ktp-rfc/blob/9612f7955d88e25d193dab2a17d51d0c9d9075d0/specifications/emergency-capability.md), unreleased main companion | Native deployment schema carries `emergency_policy`, but no selected native emergency-policy/capability validator or explicit enabled-profile rejection was located. Ordinary proof expiry checks are not emergency authorization. | Exact action/subject/resource/parameters/budget/profile binding, time/veto preservation and protected predecessor/version/time/evidence checks if supported. Since support is optional, a declared disabled-only profile that rejects emergency use/enabled claims is a valid scoped alternative. | Approved emergency authority, signatures, durable policy activation, safe transitions, actual execution, key custody and operational evidence. |
| [Oracle consensus integration](https://github.com/nmcitra/ktp-rfc/blob/9612f7955d88e25d193dab2a17d51d0c9d9075d0/specifications/oracle-consensus.md), unreleased main companion | `oracle_consensus` shape is bundled; no native selected-protocol roster/quorum/certificate validator or explicit unsupported-claim decision was located. Fixture threshold metadata is not commitment evidence. | Make a supported-or-unsupported profile choice. If supported, validate roster uniqueness, fault/quorum arithmetic, exact configuration/specification identity and certificate/content bindings without inventing a consensus algorithm. | Reviewed protocol and independence assumptions, real signatures/votes, persistence, locks, membership transition, consensus/commitment and current revocation. |
| [Software-substrate execution profile, PR #131](https://github.com/gatekeeper454/ktp-rfc/tree/8dda717a51818a5e9ef00e36898ddae6af890230), 38 modeled consumption cases + 26 shape cases | Updated 2026-10-30: strict pinned shape (26 cases), real ES256/Ed25519 signatures, restriction arithmetic, current authenticated evidence/continuity and selected native-duration consumer exist. Complete proof/request/epoch/evidence/readiness/vendor grant-intent bindings preserve current native restrictions. | Selected duration adapter only; supplemental prerequisite families remain explicit unsupported. Final source adoption, stronger signing profiles and complete release-set qualification remain pending. | Real measurements, original vendor artifact authentication, calibrated assessment truth, repair/supervision reachability, complete protected history and actual atomic enforcement. |
| [Consequential-action evidence, PR #139](https://github.com/gatekeeper454/ktp-rfc/tree/7855966e8c061dae165d4d66ee2527bacbb59d6c), 20 modeled contract cases + 11 shape cases | Current request replay and decision geometry do not implement shared effect reservation or the four-state evidence-correlation contract. | If selected, immutable fingerprint/decision/target/reservation/evidence record validation and exact `withheld`/`dispatched`/`effect_confirmed`/`unknown` classification. Keep dispatch separate from confirmed effect, and unknown evidence conservative. Coordinate with the simpler execution-observation proposal rather than inventing a merged wire format. | Release-time target revalidation, atomic durable reservations, execution, protected non-dispatch/effect evidence, restart/retry/reconciliation and actual shared-load state. |
| [L11 adjudication direction](https://github.com/nmcitra/ktp-rfc/tree/c8f912e27108d1493672a5787d98d31f95d0659a), `ktp-core` L11, `adjudication-token.json`, 23 vectors | Updated 2026-10-29: current exact adjudication binding and multiple all-required gates compose with own-increment supervision holds/releases. Selected external-schema importance/supplied inputs now raise whole-action demand through classifier/Core/claims/geometry and current-use refresh without changing measurement, ceilings or prior vetoes; closed schema resolution preserves determinism. Signed producer/current-use tests cover mixed required-gate/prior-veto restriction. No complete 23-case implementation claim. | Expand source-vector coverage and mandatory composite policy selection. Preserve measurement and whole-action scope; finalize token wire/stronger-profile declarations and actual normative adapters. | External schema/issuer authority, current grants/evidence/session and complete hold/input inventory, actual judgment calibration and token signatures/profile with gate domain separation, accountable release process. |
| [Repair and re-entry](https://github.com/nmcitra/ktp-rfc/tree/e1f124b64de3234bc96f94fcd7c8ee612d965517), `ktp-repair`, 41 vectors | Updated 2026-10-29: record/re-entry, earned recovery and sponsorship/genesis paths exist. `installed_ambient_repair.py` composes exact stock/capacity primitives with authenticated current zone-wide evidence and a pinned pressure normalizer. Selected environment/Core/claims/geometry and request verification enforce profile/topology, current semantic frame, pressure, hosting and expiry. Pooled and per-class capacity, stock and debt are composed under a named reference policy; global cooldown precedes class partitioning. Selected installed recovery binds sustained tier predicates, class-aware current measures and declared crisis capability; geometry and current-use hosting gates enforce the result. Selected rule repair validates recurring patterns, current anchored records, ratified changed definitions and exact authenticated driving citations; open obligations remain visible in geometry. No complete 41-case claim. | Mandatory complete-deployment recovery and rule-repair selection; broader source-vector coverage. Clarify empty-backlog capacity, zero-threshold recovery and durable-vs-observed growth. Final public composition must select all applicable policies and validate actual genesis lineage. | Actual complete lineage/audit windows and current head/anchors/order, ordinary act admission/calibration, opening history and actual birth bond, independence/attendance, amendments, durable lineage/bond reservations, backlog/reproduction, source-signal interpretation and repair-capacity state. |
| [Sponsorship capital and ancestral liability](https://github.com/nmcitra/ktp-rfc/blob/8a733c4ab9e9063eb9cd64f92bc2cd34b4f84169/rfc-src/ktp-identity.md), Identity Sections 6.3/6.4/8.2 | Updated 2026-10-29: exact pure capital taper/floor, prior closure, expiry, for-cause discharge, transferred residual preservation and complete home inventory/overcommit arithmetic exist in `sponsorship_capital.py`. A selected cross-zone source/verifier now binds historical opening and current capital, all-zone limits, receiver measure and earliest end while preserving residuals and intrinsic standing. This is accounting, not a tapered External Root term. | Selected Root/whole-standing/genesis paths now enforce authenticated home classification, exact credit identity and historical birth bounds. Remaining: complete deployment selection and broader source/operational integration. Apply earliest agreement/severance end while retaining residuals and independently earned standing. | Complete home/foreign active and residual inventory, current intrinsic standing and actual ownership/transfer/finding truth, atomic reserve/penalty/closure recording and enforcement. |
| [Federation rule and crossing](https://github.com/nmcitra/ktp-rfc/tree/8a733c4ab9e9063eb9cd64f92bc2cd34b4f84169), `ktp-federation`, 40 vectors | Updated 2026-10-29: distinct pure imported standing applies one receiver/class/lowering-bounded factor and independent receiver software ceilings; shared Core capacity keeps local Soul/R. Installed bilateral software evidence validates current directional agreement/admission bindings, one-link sender-earned exportable standing, receiver signature/class/lowering/sovereignty and current witness/registry/expiry facts from an authenticated source. The selected import-only standing/Core/claims/geometry/current-use route binds one reserved admission ceiling and refreshes current factor/frame/expiry; real signed native production exists under a named provisional profile. Exact source suite retained; not a full 40-case claim. | Current bond source, Root/whole-standing/genesis integration now exist under explicit provisional ceiling profiles; authenticated home metadata and receiving-scope selection prevent local fallback. Additional record/person/multilateral routes remain. Resolve FD27 earned-at-80 versus Identity intrinsic-80 closure semantics; complete deployment/API selection. Mixed local/imported accumulation and exportable extraction remain undefined by the draft. No propagation of foreign R as local authority. | Signed agreements/factors, registry/witness truth, reserves and bonds at home, record delivery, actual reached-zone history and revocations. |
| [Boundary declaration](https://github.com/nmcitra/ktp-rfc/tree/7cbcac84395dd8bcf84f8819ac63c28e36dbca44), deployment profile + `ktp-zones`, 5 vectors | Updated 2026-10-29: exact required declaration composed into native schema; `boundary.py` checks authenticated literal resources, actor class, authority-limit outcome, affected review routes and enclosing-resource subset. Core stops before other inputs on denial; claims preserve zone/expiry; native facade checks current boundary before geometry/readiness and matches nested ingress parent/epoch. Source vectors retained. | Final deployment/API cutover must validate the complete composite declaration; partial historical component fixtures do not establish conformance. Reconcile resource-resolution and authority-adapter contracts with the final tag. | Authenticate actual resource/principal class, authority/jurisdictions, affected outsiders, literal pattern resolution and real review routes; durably record/serve denials. |
| [Execution observation](https://github.com/nmcitra/ktp-rfc/tree/151cfe46e447be68794dfadf8bf11cfde79110d1), Core/execution observation, 3 vectors | Updated 2026-10-29: immutable semantic decision/observation model and selected installed Source wrapper classify the three retained EO cases. Exact actual operation, actor, zone/epoch, historical record digests, decision identity and time are bound; missing/misbound observations remain unverified. Denied dispatch and authenticated absent-decision/unenforced-route dispatch produce bypass and recording obligations. | Complete deployment/API selection and actual boundary adapters. Do not confuse observed dispatch with optional #139 downstream effect confirmation or record obligations with persistence. | Observe the real execution boundary, authenticate and durably bind receipts; record/open the breach and enforce the stop. |
| [Hand-back](https://github.com/nmcitra/ktp-rfc/tree/17f37b772eac8b2f84248c1912f3aeb3f5fa26d1), `hand-back.md` + `hand-back.json`, 73 vectors | Updated 2026-10-29: installed records/templates, leases and conditional duration Clear preserve return paths, native restrictions and expiry. Adjudicated pricing and grant reissue enforce historical profiles, actual audit order/issuance, corrected surviving bounds and current protected epoch; expunged history cannot impose delay. Selected relational reissue requires persistent stop barriers, current anchored reconciliation, actual registered route/clock and live nonce. A selected signed human-decision gate binds person/key/liability and declared endogenous refusal cases to explicit scoped non-dispatch evidence. Selected conditional relational Clear composes the exact native/template/reissue/decision graph with current authority/nonce/fence commit conditions and shortest validity. | Selected dual-schedule decision, protected review-view composition and declared delivery lifecycle checks now exist; remaining work includes actual Service single-use/review/delivery adapters, runtime resolution of new stops, broader source cases and complete capability selection. Resolve bootstrap/disclosure ambiguities before full adoption. | Actual signatures/custody/registration and complete historical policy/ledger authority, durable epoch continuity, append/expungement/sanctions, delivery/crash recovery, atomic commit/nonce consumption, review capacity/deadlines, regime truth/revocation. |
| [Person signed-act standing](https://github.com/nmcitra/ktp-rfc/tree/07b877ed1f8cdc532a1f92a07878be0cf77442f2), Core/Identity/Human, 12 vectors | Updated 2026-10-30: separate signed-act standing, zero-peer/single-current-Root installed assessment, directional person federation and independent reviewed operational-capacity adapter exist. Eligibility, standing and capacity remain separate. | Person proof/execution composition and multiple-current-Root ranking remain incomplete. Source trajectory ceilings require an explicit provisional policy; mixed imported/local composition needs a source decision. | Authenticate acts, complete current ledger, person/institution authority, measurements and independent review. |
| [Charter amendment](https://github.com/nmcitra/ktp-rfc/tree/2573ca401997850a635e6bf48b9353ec14b5e1b2), Governance, 16 vectors | Updated 2026-10-30: pure forward-amendment floors, protected rules/standing routes, immutable historical evaluation selection, procedural seek and authority-attendance checks exist. Exact coarse ratification-time ties remain unresolved rather than inferred. | Installed governance ledger/workflow composition and actual adoption remain external; source publishing-copy drift and immutable recurrence scope need reconciliation. | Actual consent, deliberation, signatures, authority, complete records, clocks, publication and forward adoption. |
| [Recognition is not an imported term](https://github.com/nmcitra/ktp-rfc/tree/66778fad83659a32d52216baaaf4ae2951134cda), 3 recognition vectors | Updated 2026-10-30: recognition-only clauses supply no obligation; recognition-as-membership/obligation clauses are void in shared bilateral validation. Own-zone adoption/withdrawal history remains separate and non-widening. | Complete deployment selection and actual policy adoption remain external. | Authenticate local adoption/withdrawal, original offered rule and actual bilateral authority. |
| [Claim names substrate](https://github.com/nmcitra/ktp-rfc/tree/b016dac2fe93e12c668b224dc5ef9e317026e359), 3 vectors | Updated 2026-10-30: exact claim product/version/level/status and independently installed in-set substrate identity/version validation exist. Metadata acceptance establishes neither runtime conformance nor evidence validity. | Final independently accessible implementation release and evidence-backed conformance qualification remain pending. | Evidence supporting a real substrate/deployment claim and accountable owner. |
| [L15 composition limit](https://github.com/nmcitra/ktp-rfc/tree/717751d9851eae14e59a18141e3a1c0aad361f50) and [v3 named limits](https://github.com/nmcitra/ktp-rfc/tree/25f55d15239f2bae6cba7112742a107885dd7ac2) | No claim should imply solved cross-request composition or settled contradictory crypto/control floors. | Explicit capability/limit statements and no invented universal precision/crypto/quarantine rule. Keep unresolved dependencies visible. | Any optional additional composition policy and the evidence for its own stronger claims. |

Federation record checkpoint (2026-10-29): the selected private
`InstalledFederationRecordVerifier` now derives exposure destinations from complete
reached-subject coverage, and two-anchor notifications from actual prior breach
deliveries. Exact record/profile/subject/origin/time, registry/witness facts,
signed bilateral agreement terms/expiry and sovereignty are checked or bound to
the authenticated Source. History binds subject, breach, origin, exact original
agreement digest and delivery time. Blocked sovereignty retains the obligation;
no notification closes receiver exposure or exports personal reconciliation.
This covers selected FD33/35/37/39/40 behavior, not every FD31–40 route. Actual
delivery/wire construction, amended-term migration, person standing and full
deployment/API composition remain pending. Raw retained evidence is internal,
not a notification payload. See the native evaluation guide and federation plan.

Hand-back hysteresis pricing checkpoint (2026-10-29): declared finite capped
arithmetic and installed complete current audit-backed inventory/head/actual-stop
checks now enforce selected hand-back issued bounds. Timelines retain original
pricing and current corrections, excluding expiry/pending/wrongful history;
actual causation/expungement and separate zone-wide revoker accounting are bound.
Grant-time enforcement now composes with Clear under symmetric selection; its
historical profiles and actual issuance/audit/epoch checks preserve surviving
bounds. Relational gates remain pending; no ledger write or sanction is claimed.

Hand-back delivery checkpoint (2026-10-29): selected pure and installed lifecycle
checks now bind original grant-time schedules/routes/capacity, sealed escrow,
actual attempts, recipient receipts, retries/escalation and acknowledgment clocks.
Unknown/exhausted capacity parks without vetoing original stop construction;
causal receipt-recording time prevents false duplicate-retry claims. Missing/late
work and capacity-pressure feed records are returned obligations, never I/O or
permission. Original wire identity and already established delivery facts cannot
be silently replaced/truncated. Actual transport, durable history, receipt/key
provenance and feed normalization remain Service/provider work. See the hand-
back-delivery plan for private schedule choices, limits and remaining scope.

Dual-schedule decision checkpoint (2026-10-29): the selected relational decision
now requires both endogenous refusal evidence and current production review,
including this exact signed decision in the reviewed history. Overdue work and
new/unresolved findings block it. Conditional native Clear carries the selected
monitor's earliest validity, and commit conditions bind its actual ledger,
protected revision, history/backlog/finding/registry digests and current coverage.
Missing review state cannot downgrade to Standard; stale coverage or changed data
reject at commit. This completes the selected HB-10 composition, not all hand-
back/deployment conformance. See the dual-schedule-gating plan for Source and
Service obligations and the remaining release-set work.

Native RFC schema refresh checkpoint (2026-10-29): refreshed proof/record schemas
directly reference native v3 Risk Factors. Native proof and trajectory validation
no longer rewrite v2 risk references; obsolete native-package aliases are archived.
Stage 6 accepts the published five-factor clear shape and rejects a sixth member.
Twelve primary-source snapshot hashes, installed resource closure and exact
worked-example decimals are checked. Original root/person composition stays
explicit; frozen released v2 resources are unchanged. This closes the observed
reference gap, not the complete refreshed RFC/release set. See the native-schema-
refresh plan for source heads, scope and remaining work.

Historical decision-review checkpoint (2026-10-29): digest-pinned original event
policies and role intervals preserve actual sampling/trigger/reviewer/SLA terms.
Current diagnostics combine actual samples across versions. Persisted findings
and independent open markers survive a new threshold/window; their complete
then-known basis and explicit forward historical-authority resolution are checked.
Full decision/commit composition remains pending. A concurrent RFC refresh also
changed core proposal trees; the production-decision-review plan records the
new heads and exact follow-up. No refreshed-contract alignment claim is made yet.

Production decision-review monitor checkpoint (2026-10-29): a selected pure and
installed Source-backed monitor now applies exact stochastic-draw selection,
separate sampled/outcome-triggered review deadlines and cross-actor decider-wide
uniform-approval findings. Acknowledgment is not review; late work retains record
obligations, and durable older backlog cannot disappear with the window. Current
registry/owner/head/coverage and governing policy are bound. The subsequent
historical checkpoint adds policy/role/finding preservation. Full decision-gate
composition and review-ledger commit fencing remain pending. Actual randomness, review quality and complete event provenance
remain Source/audit obligations. No Full claim or action authority is returned.
See the production-decision-review plan for the exact provisional interpretation.

Conditional relational Clear checkpoint (2026-10-29): the selected native path
now composes original template/lease, historical and persistent reissue,
accountable signed decision and immutable single-use commit conditions. Authority,
nonce revisions, prerequisite fences, current epochs/head and original repair
route are bound; native supervision/constraints and the earliest supporting
expiry bound both Clear and its contract. The pure commit checker requires the
installed assessment and exact current protected state; wire contract bytes are
not authority. Modeled concurrent consumption accepts one attempt. Actual atomic
consume/protected mutation or durable dispatch, dependency-revision coverage,
crash recovery and ordinary authorization remain Service responsibilities. Full
exogenous meaningfulness and broader hand-back families remain open.

Relational decision checkpoint (2026-10-29): a selected installed Standard-
endogenous gate composes required signed adjudication and relational reissue.
It binds the actual favorable token to current person/key/signed liability,
decision record, grant/evidence/operation, repair route and shared current ledger.
The declared prior refusal run requires actual scoped denial and explicit bound
non-dispatch observations; acknowledgment or missing telemetry cannot certify it.
Humanity, substantive review quality, actual custody and registry/run provenance
remain audit/Source obligations. Full exogenous review, atomic single-use and
relational Clear composition remain pending. No action authority is returned.

Relational reissue checkpoint (2026-10-29): a selected installed persistent-stop
gate now composes with historical pricing. Complete relational adversity remains
independent of retention/penalty expungement. Actual grant/audit/epoch/live nonce,
current anchored reconciliation, actual registered decline route and clock, and
cross-Source ledger/retained-stop consistency are required. Eligibility authorizes
no action. The subsequent decision checkpoint adds accountable signed decisions
and endogenous refusal evidence. Full exogenous review and atomic single-use
commit remain pending; relational Clear stays unsupported. See the relational
reissue plan for the exact private integer-second clock and Source obligations.

Relational reconciliation preparation (2026-10-29): the shared pure anchored-
record checks now serve actor re-entry without carrying its standing penalties
into relationship-only reconciliation. Current cause binding, terminator parties,
acknowledgment, residual declaration, independent non-Oracle verifier and published
decline route remain required. This is preparatory code, not an installed
relational reissue gate on its own. The subsequent checkpoint adds persistent
barriers and grant ordering; accountable human decisions and atomic single-use
consumption remain pending. A lawful stop
does not become a breach through this projection. See the relational reissue plan
for the provisional stop-versus-breach record mapping.

Hand-back duration Clear checkpoint (2026-10-29): selected installed original-
template verification shares record invariants and pre-registers v2 recourse
branches, avoiding stop-time edits to the grant's template. Conditional Clear
requires the exact installed fresh native policy/result, whole operation/current
geometry, active duration lease and original pre-grant current template. Native
supervision/constraints and shortest supporting validity are preserved; another
policy, required-gate failure, late/withdrawn template or active adversity cannot
clear. Relational Clear, anchored reissue/repair, adjudicated hysteresis and new
adverse-stop runtime resolution remain open. No dispatch or full capability claim.

Hand-back lease/non-Clear checkpoint (2026-10-29): exact pure lease/intent checks
enforce whole-action/class/principal/authority/template bindings, mint freshness,
72-hour/30-minute duration ceilings and relational nonce form/live status. The
installed private non-Clear sum validates actual managed-relation/stop registry
state and original validated hand-back. Routine Expired is reissue-only, not
adversity, and cannot replace an active stop. Clear/native composition, relational
repair/reissue and adjudicated hysteresis remain open. Actual signatures/custody,
live registry, durable nonce consumption and delivery remain Service evidence.

Hand-back record checkpoint (2026-10-29): `InstalledHandBackVerifier` now validates
the pinned wire schema plus actual registered template/stop/scope, original grant
template digest, accountable primary recipient, recourse, repair, precise times,
class SLA/floor, sealed context and capacity-aware delivery facts. Protocol errors
return recording/routing obligations and no domain record. Delivery/parking never
grants action. All 73 source cases are retained, not all implemented. Clearance,
lease validity, hysteresis, native composition and remaining runtime families
remain pending, as do actual production Source/delivery adapters. See findings for
the bootstrap-template and agent-visible-reason draft ambiguities.

L11 normative-demand checkpoint (2026-10-29): selected max-of-whole-action demand
inputs now bind declared external schema/authorities and complete current actual
input inventory. Classifier/Core/claims/geometry and current-use refresh preserve
the measured standing/risk/capacity, prior vetoes, executable ceilings and all-
required adjudication gates. Exact classifier/profile/semantic-frame/topology/time
and expiry are retained; unresolved schema references cannot retrieve resources.
Real signed producer/current-use fixtures use modeled Source judgment authority.
Broader L11 source-vector coverage, production adapters and mandatory composite
deployment selection remain; do not claim all 23 cases or normative adequacy.

Execution-observation checkpoint (2026-10-29): immutable semantic scope/decision/
boundary observations and `InstalledExecutionObservationVerifier` now classify
all three retained EO cases against the pinned source. Missing/misbound observation
is unverified; bound non-dispatch is not-executed; denied dispatch or authenticated
absent-decision dispatch on an unenforced route is a bypass with failure/breach
record obligations. Exact raw record digests, whole actual operation, actor,
zone/epoch, decision identity and time are bound. Source tests are modeled.
Actual boundary capture, durable failure/breach recording and complete deployment
selection remain pending; `executed` here attests dispatch, not #139 effect confirmation.

## Implementation order

1. **Bound normative carriage and boundary preconditions.** Add actual native
   contract checks at the existing restriction/early-stop seams. A favorable
   token must never become capacity or clear an existing veto. A missing or
   invalid token leaves a declared gate unsatisfied while preserving the
   no-norm measurement; it does not become a new measurement or arbitrary denial.
2. **Repair before readiness/re-entry.** Add typed reconciliation inputs and
   ceiling composition, then make the selected native readiness path require
   the resulting restriction. A generic provider boolean is insufficient.
3. **Federation and person-specific standing.** Implement receiver calculations
   and explicit subject/profile routes; do not synthesize person generation or
   turn foreign standing into local permission.
4. **Adverse-result and execution records.** Add pure hand-back/template checks
   and observed-effect classification. Keep persistence/delivery/dispatch in
   Service. Cover the relevant source cases without pretending to execute a
   gateway, lease authority or reconciliation workflow in unit tests.
   Explicitly reconcile the opt-in software-consumption/evidence proposals
   with generic geometry and observation before advertising their profiles.
5. **Native declarations, optional capabilities, public API and package cutover.** Compose accepted
   declaration changes, update the public contract map and examples, replace
   incompatible v2 APIs in the 3.0 branch, and test installation. Keep the
   published version/pin/release unchanged until final adoption; do not release.
   Explicitly support or reject enabled emergency/consensus/profile claims;
   accepting declaration shape must not imply implementing the capability.
6. **Final source reconciliation.** Diff all inspected proposal heads against
   the final tag, resolve named precision/profile/subject ambiguities, run
   requirement-specific gates plus the complete suite and consuming Service
   integration, then adopt the final pin/version when authorized.

## Public API cutover audit

`src/kinetic_trust_library/__init__.py` still exports the v2
`DeploymentProfile`, `EvaluationRequest`, `EvaluationBundle`, `RejectedRequest`
and `ValidatedActionDemand`. `pyproject.toml` still builds 2.1.0 and links RFC
2.1.0. `docs/traceability/library-contracts.md` remains the released v2 contract
map. These facts are deliberate staging state, not evidence of a 3.0 SDK surface.

The cutover needs an explicit replacement map for each public v2 contract,
stable native imports and examples, a no-fallback assertion, supported optional
dependency/profile declarations, packaged resource validation, migration notes
and Service compatibility evidence. It must not simply alias the old profile
or rename the package version while continuing to execute v2 semantics. Preserve
the historical v2 requirement/evidence map as historical documentation.

## Completion gate

Bootstrap-refusal checkpoint (2026-10-29): missing-template mint refusals have a
separately typed, sealed request-principal/default-endpoint path, authenticated
historical absence and predeclared defaults. Authority monitoring preserves
actual template selection and the exact adjudicated pricing graph. Explicit
v2 delivery origin supports request/template-based refusals without inventing
a lease and preserves complete retry/escrow/receipt checks. See
`docs/plans/2026-10-29-bootstrap-mint-refusal.md`; no template or Clear authority
is fabricated, and actual Service transport/storage remains external.

Later RFC-refresh checkpoint (2026-10-29): 18 exact current schema/vector
snapshots adopt the coalesced `4ea1b6774dbe823659d305a4e5be4fa1af0e69ba`
proposal and current hand-back/repair/L11 heads. Native units use the canonical
URN without an old-unit alias; root/person proof composition is now supplied
directly by the source. Sponsorship reopens at/below its published count,
including zero. Decision Geometry reason/control-token changes are reconciled.
Two original upstream geometry cases retain stale request preimages and are
correctly rejected, not counted as passing. See
`docs/plans/2026-10-29-late-rfc-refresh.md`. Source L23 explicitly records the
remaining numeric-writing decision; settled bootstrap routing remains
implementable independently.

Management-clearance checkpoint (2026-10-29): exact installed current management
history now composes into conditional Clear, binds the actual native credential
and grant's current admission anchor, and blocks demoted/unmanaged requests.
Retained-checkpoint validation rejects pre-head backfill as well as rewriting;
Source-authenticated restored canonical checkpoints support restart continuity.
See `docs/plans/2026-10-29-management-clearance.md` for Source durability,
first-observation and protected commit boundaries.

Capability-selection checkpoint (2026-10-29): Native Core contexts and installed
native evaluation select `ordinary-native-v3` explicitly. Emergency-policy and
Oracle-consensus bindings are rejected under the selected disabled-only scope;
software-substrate, downstream-effect and other execution-profile selectors
cannot fall back to ordinary geometry/readiness. See
`docs/plans/2026-10-29-native-capability-selection.md`. This closes silent
unsupported-profile acceptance, not implementation of those optional protocols.

Structural authority checkpoint (2026-10-29): actual capability/process/key
inventories, accepted-key custody, actually used outside-operator measurers,
zone-specific quorum and explicit single-measurer limitations are checked by
pure and installed audit-grade validators. Selected native conditional
clearance composes the exact authority audit and earliest expiry. See
`docs/plans/2026-10-29-authority-separation.md`; actual audited completeness,
physical custody and protected commit currentness remain external evidence.

Management checkpoint (2026-10-29): pure and installed classification histories
preserve admissions, immediate demotions and original final hand-backs, with
retained-checkpoint anti-rewrite validation. Uniform unmanaged denial, declared
wire silence and articulate admission responses are implemented. Demoted wire
silence requires exact installed current delivery/acknowledgment validation.
See `docs/plans/2026-10-29-management-history.md` for first-observation,
archival-bound, operational timing and actual ingress identity limits. Full
managed-action clearance/commit composition remains required separately.

Authority-stop checkpoint (2026-10-29): installed pending/refusal monitor binds
actual mint request/response history and validated sealed hand-back; silence
past the declared SLA creates authority-attributed record/routing obligations
that survive late refusal. Recording and actual routing receipts are checked
separately. See `docs/plans/2026-10-29-mint-authority-stops.md`; successful minting
still requires the existing full clearance gates and the missing-template
bootstrap remains unresolved.

Formation/revocation checkpoint (2026-10-29): installed conditional clearance now
requires relation/template/class-bound countersigned formation and blocks an
unresolved formation objection. Direct counterparty revocation requires the
matching Relational formation witness; unwitnessed claims require suspension,
human classification and identity siting, never direct `Revoked`. Principal
revocation requires actual claimant authority and remains independent. See
`docs/plans/2026-10-29-formation-authority.md` for exact Source boundaries and
remaining bootstrap, successful mint integration and structural authority work.

Ordinary proof expiry checkpoint (2026-10-29): an installed signature/schema/
scope/lifetime classifier supplies refresh metadata without historical Root
evaluation. Selected current management and active-lease composition yields
`Expired` with a distinct proof-refresh path; existing stops, revoked/changed
grants and lease expiry retain precedence. No permission, renewal, hand-back or
hysteresis event is created. Authenticated absence of a current grant also
allows routine refresh with current management/admission and valid relation
facts, without a fabricated template or lease. See
`docs/plans/2026-10-29-proof-expiry.md` for source completeness boundaries.

Person standing checkpoint (2026-10-29): exact published person examples now
exercise a separate signed-act-only arithmetic path and directional import.
An installed local profile binds complete corrected signed acts, contribution
policy, explicit provisional trajectory ceiling, current zone risk and the
actual institution behind the person's current Root. Multiple current Root
instruments are explicitly unsupported; software Root ranking cannot select
among person institutional standings. This is standing evidence only, never
human capacity, execution, eligibility or a general score. See
`docs/plans/2026-10-29-person-standing.md` for source and remaining scope.

Person federation checkpoint (2026-10-29): a distinct installed import-only
profile now validates current signed-act-only person terms and reuses complete
bilateral agreement/version/direction/signature/witness/sovereignty validation.
The receiver's class/lowering-bounded factor and explicit zone ceiling apply
once, with no software defaults. Missing direction/acceptance supplies no import;
zero factor can retain admission. No local/imported accumulation, human capacity
or execution is supplied. See `docs/plans/2026-10-29-person-federation.md`.

Human capacity checkpoint (2026-10-29): a distinct installed prerequisite now
validates approved measurement identity, review authority/anchor/time, actual
human request/zone, comparable units and observation freshness. Soul-first
evaluation preserves missing/zero/over-capacity and envelope equality vetoes,
without software standing or credential-derived capacity. Native derived exact
precision is preserved in the shared arithmetic. Real reviewed calibration and
complete human authorization remain separate. See
`docs/plans/2026-10-29-human-capacity.md`.

Native policy-selection checkpoint (2026-10-29): installed v3 proof verification
requires the canonical native schema identity; arbitrary/legacy schema roots
cannot be selected through this API. Native evaluation and proof issuance also
reject explicit fixture semantics. Generic local schema utilities and clearly
marked published-fixture verifier tests remain available. See
`docs/plans/2026-10-29-native-schema-selection.md`; identity alone does not prove
trusted schema content or Source correctness.

Native stop-resolution checkpoint (2026-10-30): a selected required native
adjudication failure now resolves its exact original registered return path,
derives a bound cause, and revalidates the newly current `Exceeded` against
original sealed bytes, stop anchor, active grant and admission. Source-only
acknowledgments cannot establish completion; changed grants and substituted
causes fail. Parked delivery remains owed. See
`docs/plans/2026-10-30-native-stop-resolution.md` for bounded reason scope and
actual durable preparation/sealing/delivery obligations.

Readiness stop-resolution checkpoint (2026-10-30): a distinct selected profile
resolves an actual failed current readiness assessment through its registered
return path. Cause records bind original input and observed-context hashes,
without labeling failed state as accepted authority. All expiring clearance
variants now respect current management validity, including adverse results.
See `docs/plans/2026-10-30-readiness-stop-resolution.md` for exact supported
failures, unavailable-state and production preparation boundaries.

Human-capacity deployment reconciliation (2026-10-30): its private installed
profile binds the exact deployment digest without adding an undeclared field
to the closed normative deployment wire. A complete schema-valid native
deployment now exercises the capacity path, and profile/deployment mismatch
rejects. See the updated human-capacity plan.

Claim-substrate checkpoint (2026-10-30): a pure metadata assessment exercises
all three exact retained claim-substrate cases. It requires an independently
installed, immutable RFC-set inventory and exact profile identifier/version,
preserves the claimed level, and rejects missing or uncarried profiles. Accepted
metadata explicitly leaves evidence and runtime conformance unverified and
enables no execution profile. See `docs/plans/2026-10-30-claim-substrate.md`.

Forward amendment checkpoint (2026-10-30): a pure authenticated-record helper
checks breach/constant measurement citations, exact predecessor, approved
measurement sources, full established council denominator, actual stricter
charter terms, immutable classified effects and the governor capacity veto.
Forward version selection preserves in-flight evaluations; equal coarse
timestamps provide no version until ordering is established. This supplies no
adoption authority or governance workflow. See
`docs/plans/2026-10-30-charter-amendment.md` for exact proposal source, source-copy
discrepancy, recurrence wording and remaining petition/ledger scope.

Charter seek/attendance checkpoint (2026-10-30): pure procedural projections
check bound-rule record-citing seeks, declared current recurrence/window,
published route and actual scoped authority publications. Missing recurrence
does not blame the filer or close the council route. Incomplete refusals remain
contestable; late attendance retains authority debt, and later notice preserves
earlier refusal. The translated AM16 chain reaches forward version metadata
without a gate bypass or mutation. See `docs/plans/2026-10-30-charter-seek.md`
for actual ledger, publication, response-adequacy and zone-gate obligations.

Recognition checkpoint (2026-10-30): exact retained RC01–RC03 cases exercise
recognition with no imported term, own-zone offered-coordination adoption/
withdrawal, and protected class standing to amend/contest/object. Selected
agreement validation marks recognition-derived obligation and membership
clauses void while preserving unrelated terms and import arithmetic. Actual
semantic classification, complete original history and enforcement remain
authenticated provider responsibilities. See `docs/plans/2026-10-30-recognition.md`.

Software-consumption prerequisite checkpoint (2026-10-30): exact retained
optional-profile/schema/vector evidence now exercises all 26 shape cases,
strict raw JCS/control/count rejection, selected non-widening magnitude/
supervision cases and real P-256/Ed25519 signature checks under a distinct
purpose and installed issuer/profile/policy. Availability loss zeros every
effect magnitude; earlier vetoes and unknown-capacity floors remain. These are
prerequisites only: complete current evidence/epoch/request/prerequisite
composition remains unverified and ordinary-native still rejects substitution.
See `docs/plans/2026-10-30-software-consumption.md`.

Pre-tag readiness is unproven until every applicable Library-owned row is
implemented and evidenced, or the source itself leaves a precise unresolved
contract recorded as such. External ownership must be justified by actual I/O,
authority, factual assessment, persistence or workflow responsibility; it is
not a reason to omit deterministic SDK validation or a record model. Neither
the absence of the final tag nor passing the current suite closes these gaps.
# 2026-10-30 current software evidence checkpoint

The optional software profile now has a private installed evidence verifier:
actual invocation/destination/session binding, complete ordered original-evidence
hashes, current authenticated source heads/health, exclusive original freshness
deadlines, independent current keys and protected restriction continuity. A
retained assessment rejects rollback, rewritten heads, sequence/epoch gaps and
erased restriction history. Resolution must address the original hold and cause
under the installed authority. Current input expiry and next-checkpoint expiry
are retained separately. Source owns authentication, calibration, complete
durable history and actual restore. This stage does not authorize consumption.

## 2026-10-30 native duration software consumer

`software_consumption.InstalledSoftwareConsumptionVerifier` composes actual
native conditional Clear, current management/authority, readiness, current
software evidence and separately signed decisions under an exact private
installed profile. Complete original proof/readiness/grant/intent, request,
evidence and epoch bindings are checked; A/E, ceilings and supervision cannot
widen the native/current restrictions. Denials retain software and management
continuity checkpoints. Original validity and recheck cadence remain separate.
Both native and software constraints survive into conditional commit conditions;
the actual Service must revalidate the native graph and atomically fence current
state before effects. No target effects, release, queue/budget or #139 claim.
This adapter explicitly rejects relational/reissue and supplemental prerequisite
families until their complete original-artifact bindings are implemented. See
`docs/plans/2026-10-30-native-software-consumption.md` for the exact scope and
modeled-versus-real cryptographic integration evidence.

## 2026-10-30 software decision producer

`software_issuance.InstalledSoftwareDecisionIssuer` now validates an installed
Source's canonical unsigned payload against the same complete scoped input graph
before invoking a separate private signing adapter. Current key purpose, issuer,
zone, algorithm, exact curve/type/public material and validity are checked first.
Unsigned preparation never has verified/conditional-consumption status, a signed
decision or commit conditions. The completed signed artifact is independently
rechecked against current software/clearance Sources while retaining protected
continuity checkpoints. Actual native freshness and atomic execution remain
explicit caller/Service obligations; issuance does not release effects.

## 2026-10-30 replay-safe current native use

`existing_association.InstalledExistingAssociationVerifier` checks an installed
Source's complete current protected original reservation under an exact private
registry/profile, without calling ordinary reserve. The distinct `RB_CURRENT`
prerequisite binds current actual invocation, proof/Root/carrier and original
request/proof/issuer/JTI identity. Retained current-use evidence rejects rollback
or rewritten original acceptance. Ordinary repeated acceptance remains
`RB_REPLAY`. Native `revalidate_existing` reruns current selected gates and caps
validity by the reservation's current deadline. Standalone readiness rejects
stale/expired current reservations and preserves that shorter deadline. No new
ordinary invocation, grant, replay exception or target release is implied.

## 2026-10-30 continuing software checkpoint composition

`software_checkpoint.InstalledSoftwareCheckpointVerifier` pins the exact installed
consumer/reservation graph and revalidates current native gates plus software
conditions while preserving the original invocation. The same signed decision,
ordinary proof and original observations can survive a routine recheck while
their original deadlines remain live. Each use ends at its shorter current-state
deadline. Temporary native denials retain the last successful native, software
and management checkpoints for fresh validation; retained data grants no action.
Exact original observation expiration still withholds use. Conditional commit
conditions include the checkpoint profile and current protected original
reservation; scheduling, interruption and atomic enforcement remain Service work.

## 2026-10-30 current software Exceeded return paths

`software_stop_resolution.InstalledSoftwareStopResolver` now rechecks the pinned
current-use graph and resolves actual software permit-condition loss through the
original grant's registered template. Obligations follow authenticated current
availability, capacity vetoes and already applicable ceilings independently of
stale signed candidate values. Causes bind the actual calibrated assessment,
current frame/state, grant, operation and candidate provenance. Shared registered
stop validation requires the exact current `Exceeded` hand-back, unchanged grant/
intent/relation/admission and system recourse; acknowledgment without append,
substituted cause and revocation during preparation are rejected. Readiness stops
also support fresh unexpired `RB_CURRENT`. Actual genuine sealing, durable cause/
stop registration, delivery, retry and interruption remain provider/Service work.

## 2026-10-30 provisional person standing proof production

`person_claims.NativePersonClaimsSource` now binds current person signed-act/
institutional standing, Soul, Root, actual operation, five-factor environment and
any declared boundary. It derives exact R and E_trust, rejects an unrelated
standing risk, preserves unknown/veto states and original support expiry, and
omits all software generation/lineage/sponsor/advancement fields. Real Ed25519
person proofs traverse the existing installed issuer/verifier in clear, unknown,
veto and unanswered states. This supplies standing assertions only, not human
eligibility, operational capacity or execution. The exact person-versus-software
prose conflict, provisional trajectory policy, multiple Root ranking and mixed
import/local composition remain explicit source-adoption decisions; see
`docs/plans/2026-10-30-person-standing-proof-claims.md`.

## 2026-10-30 native import independence

Native modules now use shared version-neutral base64url, signature-shape and URI
helpers directly. They no longer import the legacy proof parser, claim models or
Core packages. A minimal-root subprocess with those legacy packages blocked
loads the native/person/software graph, and a static dependency guard catches
deferred/relative legacy imports. Isolation also passes without optional proof
dependencies. Legacy locations retain the same helper behavior, URI public
identity/parser-error boundary and tested contract. The root API, package version
and normative RFC pin remain 2.1.0 pending deliberate adoption; this prepares the
independent v3 tree for that eventual switch without runtime fallback.

## 2026-10-30 sovereign Soul stop resolution

`InstalledNativeSoulStopResolver` accepts an actual current authenticated native
Soul veto, binds its literal authority URI through a pinned named sovereign
mapping, and selects the active original grant's registered closed destination.
Post-registration validation requires exact `Exceeded`/`exceeded_soul`, sovereign
origin, named authority, original wire and unchanged grant/admission. Unknown
authorities are not inferred, and a system contest cannot substitute for the
community's closed protocol. Real signed integration exercises both rejections
and the correct closed return path. Actual genuine sealing, durable registration,
delivery and interruption remain Source/Service responsibilities.

## 2026-10-30 native capacity stop resolution

`InstalledNativeCapacityStopResolver` resolves the current verified native
capacity restriction through the active original grant/template. Known measured
A>E uses `exceeded_zeroth_law`; equality and uncertain conservative capacity use
the required-condition reason. It preserves the passed Soul boundary, rejects
unrelated restriction attribution, never divides by zero and post-validates the
exact derived wire reason. Real signed integration covers measured excess,
equality, known/unknown zero and substituted reason rejection. Current schema
ordering rejects earlier-gate records that improperly retain a capacity pair.
