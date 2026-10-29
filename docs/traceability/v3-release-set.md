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
| [L11 adjudication direction](https://github.com/nmcitra/ktp-rfc/tree/c8f912e27108d1493672a5787d98d31f95d0659a), `ktp-core` L11, `adjudication-token.json`, 23 vectors | Updated 2026-10-29: `adjudication.py` covers current actor/action/possession/grant/evidence/zone/epoch/time/schema/key binding and declared-gate absence. `supervision_rails.py` verifies complete current signed holds and own-increment releases bounded by the environment and other rails; native geometry binds decision identity and preserves capacity/ceilings, carrier issuance caps expiry. No complete 23-case implementation claim. | Finish multi-source restriction-only composition and importance/supplied-input handling. Preserve measurement and whole-action scope; finalize the token wire/stronger-profile declaration. | External schema/issuer authority, current grants/evidence/session and complete hold inventory, token signatures/profile, accountable release process. |
| [Repair and re-entry](https://github.com/nmcitra/ktp-rfc/tree/e1f124b64de3234bc96f94fcd7c8ee612d965517), `ktp-repair`, 41 vectors | Root claim adjudication/lapse is distinct; it does not implement breach reconciliation or re-entry ceilings. | Deterministic record preconditions, independent-party checks, declared delta/re-entry ceiling, repeated breaches/descendants, current evidence and sponsorship/ambient restrictions; typed records and readiness integration. | Actual breach/party authority, anchors, independent verification, recourse/attendance, amendments, durable lineage and repair-capacity state. |
| [Federation rule and crossing](https://github.com/nmcitra/ktp-rfc/tree/8a733c4ab9e9063eb9cd64f92bc2cd34b4f84169), `ktp-federation`, 40 vectors | Request transport binding and egress are not directional standing admission. | Exact receiver-side factor/ceiling arithmetic, non-reciprocity, one-link/earned-within admissibility, reserve/bond limits and constraints on what records can count. No propagation of foreign R as local authority. | Signed agreements/factors, registry/witness truth, reserves and bonds at home, record delivery, actual reached-zone history and revocations. |
| [Boundary declaration](https://github.com/nmcitra/ktp-rfc/tree/7cbcac84395dd8bcf84f8819ac63c28e36dbca44), deployment profile + `ktp-zones`, 5 vectors | The current native deployment schema lacks this proposal's required `boundary` field; no native boundary evaluator was located. | Compose the declaration into the native profile; check exact resources/subject entitlements and affected-party review routes, nested resource containment, and early stop before further evaluation. | Authenticate actual resource/principal class, authority/jurisdictions, affected outsiders and real review routes. |
| [Execution observation](https://github.com/nmcitra/ktp-rfc/tree/151cfe46e447be68794dfadf8bf11cfde79110d1), Core/execution observation, 3 vectors | Pre-action geometry and trajectory signatures do not establish observed dispatch/non-dispatch. | Bound observation/decision model and deterministic outcome classification: absent observation is unverified; veto + observed dispatch is a bypass/conformance failure requiring breach handling. | Observe the real execution boundary, authenticate and durably bind receipts; record/open the breach and enforce the stop. |
| [Hand-back](https://github.com/nmcitra/ktp-rfc/tree/17f37b772eac8b2f84248c1912f3aeb3f5fa26d1), `hand-back.md` + `hand-back.json`, 73 vectors | A reason/silent-veto result alone is not a resolved or parked hand-back. | Closed immutable hand-back/clearance records, registered-template resolution, destination/recourse/repair/reissue-time/context checks and explicit non-Clear states; compose with adverse native results. Assess all applicable pure checks from the suite. | Template/recipient authority, actual delivery/parking, durable crash recovery, leases, review capacity/deadlines, voluntary vs managed regime truth and revocation. |
| [Person signed-act standing](https://github.com/nmcitra/ktp-rfc/tree/07b877ed1f8cdc532a1f92a07878be0cf77442f2), Core/Identity/Human, 12 vectors | Person proof/root shape is present, but no native person standing composition exists. Eligibility must remain separate. | Signed-act-only inputs and declared ceilings, person-specific lineage exclusions, root/terminator binding and separate capacity route; no software generation/default scores. | Authenticate signed acts, person/account/terminator authority and the selected standing/capacity profile. The source itself leaves the person trajectory-length ceiling unresolved. |
| [Charter amendment](https://github.com/nmcitra/ktp-rfc/tree/2573ca401997850a635e6bf48b9353ec14b5e1b2), Governance, 16 vectors | No native amendment evidence/declaration model was located. | Where exposed by SDK: immutable record validation and forward-effective/version binding; no alteration of previous decision evidence. Determine exact pure validation scope before implementing workflow. | Consent, authority, deliberation, clocks, publication and actual forward adoption. |
| [Recognition is not an imported term](https://github.com/nmcitra/ktp-rfc/tree/66778fad83659a32d52216baaaf4ae2951134cda), Federation, 3 recognition vectors | No native agreement/import validation enforces this boundary. | Include a non-widening recognition/import check in the selected federation/declaration contract; recognition alone supplies no new requirement. | Local-rule recognition, actual agreement/amendment authority and policy adoption. |
| [Claim names substrate](https://github.com/nmcitra/ktp-rfc/tree/b016dac2fe93e12c668b224dc5ef9e317026e359), Conformance, 3 vectors | Current docs avoid deployment claims, but no new native component/substrate claim model is adopted. | Update component-scoped claim metadata/validation and docs; distinguish supported SDK profiles from a deployment's claim. | Evidence supporting a real substrate/deployment claim and its accountable owner. |
| [L15 composition limit](https://github.com/nmcitra/ktp-rfc/tree/717751d9851eae14e59a18141e3a1c0aad361f50) and [v3 named limits](https://github.com/nmcitra/ktp-rfc/tree/25f55d15239f2bae6cba7112742a107885dd7ac2) | No claim should imply solved cross-request composition or settled contradictory crypto/control floors. | Explicit capability/limit statements and no invented universal precision/crypto/quarantine rule. Keep unresolved dependencies visible. | Any optional additional composition policy and the evidence for its own stronger claims. |

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
