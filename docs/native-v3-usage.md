# Candidate native 3.0 API and adoption

Use `kinetic_trust_library.v3.api` for the reviewed high-level entry points.
Detailed Source records and additional selected policies remain in their
component modules. Install the `v3-proofs` extra for canonical JSON, schema and
cryptographic operations. Importing the candidate API needs no optional
dependencies. Native modules have no direct legacy runtime dependencies and load
with those modules blocked under the tested future minimal package root. The
current released package root still initializes legacy models until the
deliberate root API cutover.

The package root, published version and RFC pin still identify the released
2.1.0 surface. This candidate namespace implements pinned untagged proposals;
importing it establishes no final 3.0 release or deployment conformance claim.
The final adoption will deliberately switch the root API/version/pin. Native
processing already rejects incompatible wire contracts and has no v2 fallback.

## Installed graph

All constructors receive independently installed policy and trusted provider
interfaces. Actual workloads do not select profiles, source expectations, key
roles, registries, authority mappings or freshness limits. A Source authenticates
its original facts/artifacts and actual scope; giving a requester-created record
an `Authenticated…` type does not authenticate it.

| Entry point | Result and responsibility |
| --- | --- |
| `InstalledProofVerifier` / `InstalledProofIssuer` | Complete pinned native proof verification or checked issuance through a separate signer. `TP_CLEAR` permits attempting remaining checks. |
| `InstalledLiveRootVerifier` / `InstalledRootVerifier` | Current complete inventory/lifecycle and exact instrument binding. `RootProofBinding` binds one evaluation snapshot and does not supply a long-lived current registry resolver. |
| `NativeCoreClaimsSource` | Derives software proof claims from bound installed Core/standing evidence. |
| `NativePersonClaimsSource` | Derives person standing claims from signed acts, institutional Root, Soul and exact five-factor evidence. Eligibility and operational human capacity remain separate. |
| `InstalledNativeEvaluationVerifier` | Actual invocation/proof association, geometry, readiness and selected current native gates. Keeps every constraint, veto and supporting deadline. |
| `InstalledClearanceVerifier` | Actual current managed relation, grant/intent, registered template and selected authority/formation/reissue gates. Returns typed conditional Clear or non-clearance. |
| `InstalledSoftwareConsumptionVerifier` | Optional selected duration software profile: independently signed current decision, complete original prerequisites, actual destination/workload/session/evidence and non-widening native/software restrictions. |
| `InstalledSoftwareCheckpointVerifier` | Pins the consumer/reservation graph; rechecks an existing continuing invocation through current native/software gates without reserving/reaccepting ordinary replay. |
| `InstalledSoftwareDecisionIssuer` | Validates unsigned installed-source inputs before signing and rechecks the completed artifact with retained continuity. |

`InstalledManagementVerifier`, `InstalledAuthoritySeparationVerifier`, registered
hand-back/template/non-clearance verifiers and actual provider interfaces are
installed before these composed paths. The software consumer requires current
management and structural authority checks. Its initial adapter explicitly
rejects relational/reissue, repair, ambient, federation and normative-demand
prerequisite combinations until their complete original-artifact bindings are
selected and implemented.
Protected native carriage includes its complete signed geometry carrier in the
required software prerequisite order; a local-only order cannot downgrade it.
Selected adjudication gates pin exact ordered policy identities and bind every
required signed token. Optional gates remain optional under their installed
policy. Checkpoints reverify retained tokens; replacements require a matching
new software decision and preserve original token deadlines.

Every returned `action_permitted` is false. Conditional Clear/consumption names
the conditions the Service must satisfy, including native constraints and all
software ceilings/supervision floors. The Service owns actual identity/transport,
current registry and key authenticity, measurements, complete durable state,
atomic fencing, scheduling/interruption and effects. No Library result alone
dispatches or confirms a target effect.

## Typed return paths

| Actual current failure | Installed resolver |
| --- | --- |
| Required adjudication gate | `InstalledNativeAdjudicationStopResolver` |
| Failed current readiness | `InstalledNativeReadinessStopResolver`, including fresh existing-invocation revalidation |
| Authenticated Soul veto | `InstalledNativeSoulStopResolver`; preserves the named sovereign's closed protocol |
| Native capacity excess/equality/uncertainty | `InstalledNativeCapacityStopResolver`; preserves measured-versus-unknown reason distinctions |
| Actual software availability/capacity/ceiling loss | `InstalledSoftwareStopResolver`; rechecks the pinned current-use graph |

Select a resolver from the actual verified failure family. A bad candidate is
not an authenticated Soul/capacity finding. Existing registered Revoked/Exceeded
records use typed current non-clearance; repeated preparation does not create a
new event. Preparation Sources genuinely seal/register the cause and hand-back;
the Library rereads current state and checks the exact record, original grant,
admission and registered recourse. Acknowledgment alone is insufficient.

Ordinary request IDs remain unique for their replay-domain lifetime. Repeating
ordinary acceptance yields `RB_REPLAY`. Continuing-use revalidation has the
separate `RB_CURRENT` prerequisite and never calls reserve. Original proof,
readiness, grant, observation and key deadlines remain binding; a fresh query
does not renew them. The next recheck can be earlier than signed-artifact expiry.

## Clean-break migration and final tag

| Existing 2.1 usage | Native candidate replacement |
| --- | --- |
| Root `DeploymentProfile` / `EvaluationRequest` objects | Explicit native canonical declarations, actual reconstructed complete operation and installed typed evidence graph. No conversion/default shim. |
| Legacy risk context/weights | The five declared native Risk Factors; missing measurement stays unknown/restrictive. Criticality belongs to demand. |
| Legacy proof claim/model/parser | Pinned closed native proof schema, explicit subject kind, current Root binding and exact complete proof/request association. |
| A single positive component result | Composed current prerequisites, actual grant/template, applicable conditional software checks and Service commit conditions. |
| Software-only standing/proof assumptions | Separate signed-act standing, person proof, eligibility and independently reviewed human measurements. |

Before adopting the final tag, compare its exact source/schema/vector set with
the retained [release inventory](traceability/v3-release-set.md), resolve the
listed normative conflicts, apply localized changes and run the full regression
and installed-package gates. Then switch the root exports to the candidate API,
change package/spec metadata together, update the adoption examples and verify
the consuming Service's independently owned source/fencing integration. Publish
only after deliberate release approval. This branch has no PR or merge.

Wire-number precision, final person trajectory/multiple-Root/import composition,
person-proof prose reconciliation and stronger named crypto/receipt profiles
remain exact source decisions. Optional emergency/Oracle-mesh/downstream-effect
profiles are explicitly unsupported by the ordinary native path. Local fixtures
and passing tests do not turn those limits into implemented deployment behavior.

Complete native evaluation installs only a declaration accepted by
`validate_deployment_declaration` from `v3.api`. This uses the bundled closed
schema and exact provisional catalog, checks the five weights without tolerance
or rescaling, required boundary/readiness binding, numeric controls, catalog
membership, aliases, normalization and known category dependencies. It performs
no network schema/catalog retrieval and does not approve a policy installation.

Environmental component validation checks the environmental declaration even
outside that complete graph. Its Source returns `AuthenticatedEnvironmentEvidence`
with `body_bytes` and a mandatory immutable `label_set_dependencies` tuple of
aggregated signal IDs. This is authenticated measurement metadata: the complete
actual category, denominator-predicate and bin dependencies of the measurements,
not a conformance flag. Every listed dependency requires installed labels; known
pinned enum/boolean, entropy and reviewed predicate dependencies cannot be omitted.
The Source must add all remaining actual dependencies, including derived numeric
classifiers. The SDK does not infer them from signal names or pretend the pinned
catalog encodes them all. The exact additional labels, measurement envelopes,
normalization execution and aggregation truth remain authenticated Source duties.
The Library-derived `catalog/label-requirements.json` is explicitly separate from
the unmodified source catalog and records its scope and the 15-vs-17 entropy
inventory discrepancy. Historical component fixtures are amended only inside tests.

`NativeCoreContext` and `NativePersonClaimsSource` apply the same complete
installation declaration check before proof production. A declaration alone
still cannot replace the separately authenticated, current boundary assessment.
The sealed environment assessment retains the exact checked dependency tuple
for subsequent audit composition.

The private relation-formation projection distinguishes a completed countersigned
witness from an authenticated `pending-objection`. In the latter, both
countersignature fields are absent together and an actual scoped objection is
required. Minting remains suspended pending human classification. Pre-mint callers
may supply no issued-grant time only for that pending state; it grants no direct
revocation authority. An issued grant's principal retains independent revocation,
while direct Relational counterparty revocation still needs the completed witness.
The Source authenticates identity, chronology and original objection evidence;
classification and actual mint suspension remain outside this calculation.

For a registered secondary endpoint, `InstalledCounterpartyHandBackVerifier`
checks a limited encrypted context alongside the separately valid full primary
hand-back. Its private `registered-counterparty-limited-context-v1` profile pins
the original hand-back profile and actual registry. The complete authenticated
redaction-policy bytes must hash to the original template's policy reference,
match its stable identity/subject/class and pre-grant registration, and preserve
the primary full tier. This avoids a template/policy digest cycle.

The selected rule carries exactly `action`, `reason_class` and
`attestation_references`. Reason class comes explicitly from `hand-back.reason`
(the pinned schema names that enum the reason class). The registered reference
rule is `all-primary-environment-attestations`, applied to the Source-authenticated
complete inventory from the exact original ciphertext. Future reference IDs are
not preselected at grant time. Secondary ciphertext, plaintext projection digest,
original hand-back, both profiles, original policy, operation and registered
principal/endpoint/key are independently matched. Distinct recipient principals,
endpoints and keys are a conservative restriction of this selected profile.

The Source must authenticate actual decryption/content, full original reference
inventory, current registry status and recipient custody, including that the
transporting agent cannot decrypt. The SDK never decrypts or delivers the bundle.
The result retains the opaque ciphertext, checked provenance and a secondary
delivery obligation; it contains no delivery-success assertion. Service must
perform and record delivery separately. Primary full context and the closed
hand-back wire remain unchanged. This profile requires an original registered
grant; it provides no bootstrap/fallback disclosure rule.

## Revised software profile declaration (2026-11-04)

The optional software adapter follows the pinned #131 proposal at
`652c06b68af7f6ee0785ab14399be68bc458843e`; it remains provisional.
It accepts only `ktp-software-substrate-decision-v1` and
`software-substrate-execution-v1`. Earlier unversioned artifacts are rejected.
A kinematic capacity veto requires `policyCode: KINETIC_CAPACITY_EXCEEDED`.
Issuance preflight and consumption use the same policy-code check.

The private installed evidence profile now requires:

- `observation_time_resolution_ms: 1000`: this adapter selects whole-second
  observation ticks and safe integer Unix seconds, including artifact deadlines.
  Other resolutions are explicitly unsupported; timestamps are never truncated.
- `operation_classes`: a literal operation-ID to class mapping;
  `repair_dependent_classes`: the declared subset requiring an exercised repair
  path; `novelty_domains`: validated domain IDs by operation class.
- `supervision_participants`: required participant declarations for `assisted`
  and `regulated`. Each participant names `id`, `kind` (`human` or `automated`)
  and level `capability` (`consensus` or `approval`, respectively). An empty
  declaration makes that level unavailable.

The authenticated current Source context must include `requesting_principal`.
The request binding's `actor_id` names that requester and must equal the
authenticated operation's `subject`; `workload_id` must equal its executing
`actor`. The grant's delegating principal remains a separate role, checked by
the installed native grant and authority paths.

The authenticated supervision observation includes `available_supervision_levels`,
a distinct list drawn from installed nonempty participant declarations. A false
availability observation requires an empty list; a true observation requires at
least one reachable level. The Source must establish every required participant's
actual identity, authority, capability and current reachability; these declarations
and lists are scoped facts, not proof of live participants.

An operation assessment includes `novelty_domain` alongside `irreversibility`
and `novelty`. A missing or unmatched installed domain records an undefined
assessment. A declared conservative estimate may proceed only with capacity
marked unknown; it does not invent zero novelty or a known capacity.

False repair availability withholds repair-dependent classes. Stable and
metacognitive operations can remain conditionally eligible with unavailable
external supervision; assisted and regulated require their corresponding
installed reachable participants. Unknown capacity still imposes an assisted
floor. Native restrictions, prior vetoes and magnitude ceilings continue to bind.
Actual current condition loss, rather than a generic false availability bit,
determines whether the continuing invocation requires the software stop path.
These outcomes never independently authorize effects.


## Optional consequential evidence #139

`InstalledConsequentialEvidenceVerifier` follows exact draft
`0e40c31305cc80779949c8a6fef5eb2cf3ca49f9`, with its retained schema and
29 contract/24 shape fixtures. It is a separate evidence assessment, never
ordinary authorization or target execution. Its installed private policy pins
zone, issuer/algorithm allowlists, source IDs and the states each may attest,
protected path, recovery boundary and maximum observation age.

`AuthenticatedConsequentialEvidenceContext` is an installed Source boundary.
It must supply independently authenticated actual request binding, original
observation/provenance bytes, scoped current signing keys, exact observed state
and marker, required protected interval, actual reservation correlation and
recorder evidence. The Source must authenticate the real observation and its
source; echoing a candidate into this context does not establish a fact.

The verifier binds the canonical complete signed consumption decision and actual
operation, requester/executor, parameters, destination and request fingerprint.
It checks safe integer Unix seconds, interval order, current Source validity,
observation freshness, exact canonical JWS payload/header and real ES256 or
Ed25519 signature under the installed evidence role. Historical correlation does
not claim the consumed authorization is still valid.

A verified `withheld` record covering the complete protected path and required
interval may produce `reservation_release_candidate`; this is a reconciliation
condition, not a completed release. `dispatched`, `effect_confirmed`, `no_effect`
and `unknown` retain reservations. Target evidence must come from the installed
trusted target observer, not HTTP status, timeout, denial or signature alone.
The Service owns durable recorder/ledger changes, observation authentication,
atomic reservation release and actual target effects.


## Optional cumulative effect budget and release checks

`InstalledEffectBudgetVerifier` installs the private
`cumulative-effect-budget-v1` policy. This selected adapter uses one shared
aggregate scope covering every actor, resource and replica declared by its
Source. Units and maximum consequences are independent from the #131 scale.
It has cumulative accounting, no automatic resets and no automatic charge
expiry. Other accounting policies need their own installed adapter; no expiry
or reset is inferred. Its declaration requires replay domain, retention covering
the longest queued/retry/reconciliation/recovery window, recovery boundary,
tested target contract digest, bounded checkpoints/safe transition, abandonment
bound, recorder requirement and the exact evidence-verifier profile.

`AuthenticatedEffectBudgetContext` must authenticate the complete live persistent
inventory and protected checkpoint, including each reservation attempt, original
fingerprint and decision history, original reservation digest, accountable
evidence/disposition and protected interval. It supplies independently established
maximum requested effects and a conservative reservation, actual target revision
and current recorder availability. A candidate or scoped subset is not a complete
inventory. Backends must authenticate every released entry's non-dispatch record;
a `released` flag or a copied evidence digest does not supply that proof.

The verifier checks the exact actual request/fingerprint, sums every held/charged
reservation, preserves unresolved entries across recovery and returns restrictive
atomic conditions. A duplicate unresolved identity cannot dispatch again; a new
transport identity or refreshed proof cannot clear it. Every attempt keeps the
same canonical fingerprint. A retry after withheld requires the actual fresh
sealed evidence assessment, complete path/interval coverage, original reservation
and a decision digest retained in that attempt's history. Prior attempts remain
in the inventory. A deadline, reset, restart, no-effect result or Trust Score never
replenishes this selected cumulative budget.

`InstalledConsequentialReleaseVerifier` pins the exact budget and software
checkpoint graph. Every evaluation refreshes the actual existing native
association, readiness/authority/prerequisites and signed software decision before
checking the current budget/target/recorder. It preserves the prior budget
assessment across an intervening native denial for later continuity checks.
Positive results contain the complete native/software conditions and budget
compare/reserve/commit conditions, including protected ledger head/digest,
identity, fingerprint, consumed decision, exact destination, target revision and
contract, next attempt, units and shortest deadline. They never change E or the
profile result.

The caller must atomically compare the protected head, reject duplicate identity,
append the durable reservation and enforce all target/version/authority conditions
within the declared tested commit boundary. The SDK performs none of those writes,
returns `action_permitted = false` and never claims commit-time authorization was
established. Targets without the selected conditional-commit capability are
withheld. Actual queueing, scoped shared-state completeness, idempotency windows,
replica atomicity, target effects, observation and abandonment/reconciliation
scheduling remain consuming Service responsibilities.


A release preflight's `evidence_state` is always `unknown`, with
`observation_record_required = true`: approval or denial supplies no execution
observation. A retry's earlier non-dispatch assessment cannot be reused as the
new attempt's observation. The independent evidence verifier determines an
observed state; the Service must retain that original evidence and perform the
required recording. An emitted recording obligation is not a completed write.
