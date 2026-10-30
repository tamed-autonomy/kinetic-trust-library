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
rejects relational/reissue and supplemental prerequisite combinations until
their complete original-artifact bindings are selected and implemented.
Protected native carriage includes its complete signed geometry carrier in the
required software prerequisite order; a local-only order cannot downgrade it.

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
