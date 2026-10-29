# Provisional 3.0 release-set coverage audit

Checked 2026-10-29 on `codex/ktp-v3-library-planning`, checkpoint `3432c9e`.
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
The latest completed checkpoint passed 926 tests. That count establishes the
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
| Human eligibility | `human_eligibility`, restriction-only human-origin join; exact scope/current-map/delegation tests | Neither direct-human capacity/execution nor proposed person signed-act standing is supplied. |
| Privacy evidence and erasure accounting | `privacy_evidence`, `privacy_issuance`, `privacy_erasure`; real crypto plus modeled current-source tests | Actual lawful disclosure/retention, inventory discovery, custody/destruction, restoration and storage fencing remain external. |
| Nested ingress, enclosure risk and selected egress | `ingress`, `enclosure`, `egress`; complete proof, exact floor/capacity, new signed egress and source-binding tests | Receipt crypto/link encoding needs an interoperable named profile. Other enclosure/egress profiles and deployed containment/disclosure are not proven. |

These families do not close the native SDK gaps in the next table. In particular,
an installed source supplying an ordinary assessment is not a substitute for
the Library checking a newly defined deterministic restriction.

## Broader release-set gaps and ownership

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
| [Software-substrate execution profile, PR #131](https://github.com/gatekeeper454/ktp-rfc/tree/8dda717a51818a5e9ef00e36898ddae6af890230), 38 modeled consumption cases + 26 shape cases | Generic geometry magnitudes/ceilings and carrier signatures exist, but the proposed separately signed `software-substrate-decision` contract is not implemented or claimed by them. | If selected, validate software magnitude/condition declarations and signed complete-proof/request/profile/current-evidence/prerequisite bindings, including `repairPathVerified` and `supervisionAvailable`; preserve independent vetoes and zero ceilings on failure. Otherwise explicitly mark the profile unsupported. | Real software measurements, repair/supervision reachability, current local evidence, actual target/destination and protected consumption. |
| [Consequential-action evidence, PR #139](https://github.com/gatekeeper454/ktp-rfc/tree/7855966e8c061dae165d4d66ee2527bacbb59d6c), 20 modeled contract cases + 11 shape cases | Current request replay and decision geometry do not implement shared effect reservation or the four-state evidence-correlation contract. | If selected, immutable fingerprint/decision/target/reservation/evidence record validation and exact `withheld`/`dispatched`/`effect_confirmed`/`unknown` classification. Keep dispatch separate from confirmed effect, and unknown evidence conservative. Coordinate with the simpler execution-observation proposal rather than inventing a merged wire format. | Release-time target revalidation, atomic durable reservations, execution, protected non-dispatch/effect evidence, restart/retry/reconciliation and actual shared-load state. |
| [L11 adjudication direction](https://github.com/nmcitra/ktp-rfc/tree/c8f912e27108d1493672a5787d98d31f95d0659a), `ktp-core` L11, `adjudication-token.json`, 23 vectors | Updated 2026-10-29: current exact adjudication binding and multiple all-required gates compose with own-increment supervision holds/releases. Selected external-schema importance/supplied inputs now raise whole-action demand through classifier/Core/claims/geometry and current-use refresh without changing measurement, ceilings or prior vetoes; closed schema resolution preserves determinism. Signed producer/current-use tests cover mixed required-gate/prior-veto restriction. No complete 23-case implementation claim. | Expand source-vector coverage and mandatory composite policy selection. Preserve measurement and whole-action scope; finalize token wire/stronger-profile declarations and actual normative adapters. | External schema/issuer authority, current grants/evidence/session and complete hold/input inventory, actual judgment calibration and token signatures/profile with gate domain separation, accountable release process. |
| [Repair and re-entry](https://github.com/nmcitra/ktp-rfc/tree/e1f124b64de3234bc96f94fcd7c8ee612d965517), `ktp-repair`, 41 vectors | Updated 2026-10-29: record/re-entry, earned recovery and sponsorship/genesis paths exist. `installed_ambient_repair.py` composes exact stock/capacity primitives with authenticated current zone-wide evidence and a pinned pressure normalizer. Selected environment/Core/claims/geometry and request verification enforce profile/topology, current semantic frame, pressure, hosting and expiry. Pooled and per-class capacity, stock and debt are composed under a named reference policy; global cooldown precedes class partitioning. Selected installed recovery binds sustained tier predicates, class-aware current measures and declared crisis capability; geometry and current-use hosting gates enforce the result. Selected rule repair validates recurring patterns, current anchored records, ratified changed definitions and exact authenticated driving citations; open obligations remain visible in geometry. No complete 41-case claim. | Mandatory complete-deployment recovery and rule-repair selection; broader source-vector coverage. Clarify empty-backlog capacity, zero-threshold recovery and durable-vs-observed growth. Final public composition must select all applicable policies and validate actual genesis lineage. | Actual complete lineage/audit windows and current head/anchors/order, ordinary act admission/calibration, opening history and actual birth bond, independence/attendance, amendments, durable lineage/bond reservations, backlog/reproduction, source-signal interpretation and repair-capacity state. |
| [Sponsorship capital and ancestral liability](https://github.com/nmcitra/ktp-rfc/blob/8a733c4ab9e9063eb9cd64f92bc2cd34b4f84169/rfc-src/ktp-identity.md), Identity Sections 6.3/6.4/8.2 | Updated 2026-10-29: exact pure capital taper/floor, prior closure, expiry, for-cause discharge, transferred residual preservation and complete home inventory/overcommit arithmetic exist in `sponsorship_capital.py`. A selected cross-zone source/verifier now binds historical opening and current capital, all-zone limits, receiver measure and earliest end while preserving residuals and intrinsic standing. This is accounting, not a tapered External Root term. | Selected Root/whole-standing/genesis paths now enforce authenticated home classification, exact credit identity and historical birth bounds. Remaining: complete deployment selection and broader source/operational integration. Apply earliest agreement/severance end while retaining residuals and independently earned standing. | Complete home/foreign active and residual inventory, current intrinsic standing and actual ownership/transfer/finding truth, atomic reserve/penalty/closure recording and enforcement. |
| [Federation rule and crossing](https://github.com/nmcitra/ktp-rfc/tree/8a733c4ab9e9063eb9cd64f92bc2cd34b4f84169), `ktp-federation`, 40 vectors | Updated 2026-10-29: distinct pure imported standing applies one receiver/class/lowering-bounded factor and independent receiver software ceilings; shared Core capacity keeps local Soul/R. Installed bilateral software evidence validates current directional agreement/admission bindings, one-link sender-earned exportable standing, receiver signature/class/lowering/sovereignty and current witness/registry/expiry facts from an authenticated source. The selected import-only standing/Core/claims/geometry/current-use route binds one reserved admission ceiling and refreshes current factor/frame/expiry; real signed native production exists under a named provisional profile. Exact source suite retained; not a full 40-case claim. | Current bond source, Root/whole-standing/genesis integration now exist under explicit provisional ceiling profiles; authenticated home metadata and receiving-scope selection prevent local fallback. Additional record/person/multilateral routes remain. Resolve FD27 earned-at-80 versus Identity intrinsic-80 closure semantics; complete deployment/API selection. Mixed local/imported accumulation and exportable extraction remain undefined by the draft. No propagation of foreign R as local authority. | Signed agreements/factors, registry/witness truth, reserves and bonds at home, record delivery, actual reached-zone history and revocations. |
| [Boundary declaration](https://github.com/nmcitra/ktp-rfc/tree/7cbcac84395dd8bcf84f8819ac63c28e36dbca44), deployment profile + `ktp-zones`, 5 vectors | Updated 2026-10-29: exact required declaration composed into native schema; `boundary.py` checks authenticated literal resources, actor class, authority-limit outcome, affected review routes and enclosing-resource subset. Core stops before other inputs on denial; claims preserve zone/expiry; native facade checks current boundary before geometry/readiness and matches nested ingress parent/epoch. Source vectors retained. | Final deployment/API cutover must validate the complete composite declaration; partial historical component fixtures do not establish conformance. Reconcile resource-resolution and authority-adapter contracts with the final tag. | Authenticate actual resource/principal class, authority/jurisdictions, affected outsiders, literal pattern resolution and real review routes; durably record/serve denials. |
| [Execution observation](https://github.com/nmcitra/ktp-rfc/tree/151cfe46e447be68794dfadf8bf11cfde79110d1), Core/execution observation, 3 vectors | Updated 2026-10-29: immutable semantic decision/observation model and selected installed Source wrapper classify the three retained EO cases. Exact actual operation, actor, zone/epoch, historical record digests, decision identity and time are bound; missing/misbound observations remain unverified. Denied dispatch and authenticated absent-decision/unenforced-route dispatch produce bypass and recording obligations. | Complete deployment/API selection and actual boundary adapters. Do not confuse observed dispatch with optional #139 downstream effect confirmation or record obligations with persistence. | Observe the real execution boundary, authenticate and durably bind receipts; record/open the breach and enforce the stop. |
| [Hand-back](https://github.com/nmcitra/ktp-rfc/tree/17f37b772eac8b2f84248c1912f3aeb3f5fa26d1), `hand-back.md` + `hand-back.json`, 73 vectors | Updated 2026-10-29: installed records/templates, leases and conditional duration Clear preserve return paths, native restrictions and expiry. Adjudicated pricing and grant reissue enforce historical profiles, actual audit order/issuance, corrected surviving bounds and current protected epoch; expunged history cannot impose delay. Selected relational reissue requires persistent stop barriers, current anchored reconciliation, actual registered route/clock and live nonce. A selected signed human-decision gate binds person/key/liability and declared endogenous refusal cases to explicit scoped non-dispatch evidence. Selected conditional relational Clear composes the exact native/template/reissue/decision graph with current authority/nonce/fence commit conditions and shortest validity. | Full exogenous meaningfulness review, actual Service single-use adapters, runtime resolution of new stops, broader source cases and complete capability selection. Resolve bootstrap/disclosure ambiguities before full adoption. | Actual signatures/custody/registration and complete historical policy/ledger authority, durable epoch continuity, append/expungement/sanctions, delivery/crash recovery, atomic commit/nonce consumption, review capacity/deadlines, regime truth/revocation. |
| [Person signed-act standing](https://github.com/nmcitra/ktp-rfc/tree/07b877ed1f8cdc532a1f92a07878be0cf77442f2), Core/Identity/Human, 12 vectors | Person proof/root shape is present, but no native person standing composition exists. Eligibility must remain separate. | Signed-act-only inputs and declared ceilings, person-specific lineage exclusions, root/terminator binding and separate capacity route; no software generation/default scores. | Authenticate signed acts, person/account/terminator authority and the selected standing/capacity profile. The source itself leaves the person trajectory-length ceiling unresolved. |
| [Charter amendment](https://github.com/nmcitra/ktp-rfc/tree/2573ca401997850a635e6bf48b9353ec14b5e1b2), Governance, 16 vectors | No native amendment evidence/declaration model was located. | Where exposed by SDK: immutable record validation and forward-effective/version binding; no alteration of previous decision evidence. Determine exact pure validation scope before implementing workflow. | Consent, authority, deliberation, clocks, publication and actual forward adoption. |
| [Recognition is not an imported term](https://github.com/nmcitra/ktp-rfc/tree/66778fad83659a32d52216baaaf4ae2951134cda), Federation, 3 recognition vectors | No native agreement/import validation enforces this boundary. | Include a non-widening recognition/import check in the selected federation/declaration contract; recognition alone supplies no new requirement. | Local-rule recognition, actual agreement/amendment authority and policy adoption. |
| [Claim names substrate](https://github.com/nmcitra/ktp-rfc/tree/b016dac2fe93e12c668b224dc5ef9e317026e359), Conformance, 3 vectors | Current docs avoid deployment claims, but no new native component/substrate claim model is adopted. | Update component-scoped claim metadata/validation and docs; distinguish supported SDK profiles from a deployment's claim. | Evidence supporting a real substrate/deployment claim and its accountable owner. |
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

Pre-tag readiness is unproven until every applicable Library-owned row is
implemented and evidenced, or the source itself leaves a precise unresolved
contract recorded as such. External ownership must be justified by actual I/O,
authority, factual assessment, persistence or workflow responsibility; it is
not a reason to omit deterministic SDK validation or a record model. Neither
the absence of the final tag nor passing the current suite closes these gaps.
