# Native v3 evaluation path (unreleased)

This branch implements a provisional software-agent path against pinned RFC
proposals. It is an API-only Library path. Source access, durable replay,
readiness, remaining authorization and execution belong to installed adapters
and the consuming product. The public package is still 2.1.0 pending cutover.

## Flow

1. Install immutable deployment and classifier profiles and the corresponding
   demand, Soul, standing, root and environmental verification adapters.
2. Derive `NativeClassifiedDemand` with `InstalledDemandClassifier`. Its separate
   classifier profile requires an absolute URI `id`, `version`, common-scale
   `unit: "ktp-action-risk-points"` and a nonempty `formula` description. The
   adapter receives those exact canonical profile bytes with each call. It owns
   actual implementation of that formula; the Library checks per-invocation
   restrictive ordering. The profile digest cannot substitute for that work.
3. Use `project_classified_native_core` to bind every assessment to one
   deployment, operation and evaluation time. Standing identifies the executing
   `actor`; the requester remains separately identified by operation `subject`.
4. Install `NativeCoreClaimsSource` with the Core snapshot, standing, Core
   context and immutable issuer metadata. Use `InstalledProofIssuer` to sign
   through a private-key adapter and check the completed proof with the installed
   full verifier. Veto proof details must come from authenticated Soul responses.
5. Install `NativeGeometrySource` with that claims source, classified demand,
   exact compact proof, proof verifier, geometry profile, authority adapter,
   decision ID and the trusted clock-health state. Its `request_bytes` property
   produces the canonical request using the classifier's exact ID/digest.
   `produce(evaluated_at=...)` derives the geometry body; `reproduce(...)`
   independently derives it without receiving any candidate record.
6. Use `InstalledGeometryVerifier` against a trusted native source, then
   `InstalledGeometryCarrierIssuer` with an installed signing adapter and carrier
   verifier. The issuer checks the body before signing and the complete carrier
   afterward. Expiry is the earliest supporting proof, signing-key, evaluation
   profile or other installed supporting expiry.
7. `AssociationGeometryCarrier` connects the signed record to
   `InstalledRequestAssociationVerifier`. The invocation adapter independently
   reconstructs actual identities, delegation, defaults, classification and
   replay domain. The replay adapter must reserve request and issuer/JTI maps
   atomically in authoritative durable state. `RB_BOUND` remains a prerequisite,
   not permission to execute.

## Native geometry profile

This is Library installation configuration, not a new RFC declaration. Supply
RFC 8785 canonical immutable bytes containing exactly:

```json
{
  "id": "urn:ktp:profile:native-geometry-example",
  "release": "unreleased-v3.0.0",
  "evaluator": "urn:ktp:evaluator:example",
  "core_deployment_digest": "sha256:<exact deployment payload digest>",
  "input_order": "layer-then-name-v1",
  "numeric_convention": "exact-decimal-boundaries-binary64-margin-v1",
  "constraint_policy": "retain-grant-and-prior-v1",
  "sources": {
    "soul": "urn:ktp:source:soul",
    "core": "urn:ktp:source:core",
    "environment": "urn:ktp:source:environment",
    "demand": "urn:ktp:source:demand",
    "authority": "urn:ktp:source:authority"
  },
  "magnitudes": {"max_calls": {"unit": "calls", "direction": "maximum"}},
  "thresholds": {
    "veto": 0,
    "assisted_floor": 0.05,
    "metacognitive_floor": 0.1,
    "allow": 0.2
  }
}
```

The digest placeholder must be replaced. The bands are an example, not universal
KTP thresholds: veto/allow must match the installed deployment declaration.
`thresholds: null` is accepted only when that declaration is absent. The named
constraint policy keeps the pointwise minimum of authenticated grants and prior
ceilings, including prior-only restrictions. It adds no product-specific shaping
formula. Magnitude units and maximum direction are declared in this installed
profile and authenticated by the source contract; undeclared names reject.

The authority adapter implements:

```python
verify(*, evaluation_profile_bytes, deployment_profile_bytes, operation_bytes,
       compact_proof, evaluated_at) -> AuthenticatedGeometryAuthority
```

It authenticates current, invocation-bound prior supervision, grants and their
complete evidence. Its response contains canonical `payload_bytes` and retained
`evidence_bytes`. The closed payload is `{prior, grant}`. An observed prior has
`{state: "observed", supervision, ceilings: {magnitude: maximum}}`; an observed
grant has `{state: "observed", ceilings: {...}}`. A missing branch has only
`{state: "absent"|"unanswered"|"stale"|"undefined"}`. A product that has no prior
restrictions must establish an observed baseline explicitly; absence is not
silently treated as stable. Source evidence must be resolvable and authenticated.

Binding is checked before Soul; Soul stops before the authority adapter is
queried. An inherited veto or unavailable prior stops later stages. Missing
required numeric inputs or grants do not acquire a fabricated measurement.
Capacity and equality use exact values; the profiled margin is binary64 display
from the exact ratio. Unknown software standing does not produce an authorizing
capacity record. Query inputs retain installed framework names, using a stable
digest alias when a name exceeds the record's 255-character bound. Inputs are
sorted by layer then name, with sorted evidence digests and matching undefined
entries in the same order.

## Current root verification

`InstalledLiveRootVerifier(instrument_verifier, inventory_source, context_bytes,
expected_zone)` can be installed as the full proof verifier's root predicate.
The context is immutable independently authenticated subject/class, deployment,
generation/lineage and hop-bound configuration. It does not come from the proof.
The inventory source implements `resolve(context_bytes=..., evaluated_at=...)`
without receiving the candidate and returns `AuthenticatedRootInventory` with
the complete instrument-byte tuple, retained inventory evidence, exact context,
current checked-at time and established no-credit reason. It must authenticate
inventory completeness and currentness; an outage cannot be called an empty set.

Every use reassesses instruments and current lifecycle through the installed
instrument verifier, selects the strongest eligible root and binds its exact
projection to the proof. Stale/mismatched inventory or unavailable source state
rejects. A changed lifecycle can require fresh proof issuance even within its
ten-second lifetime. `RootProofBinding` remains the exact-snapshot primitive;
it must not be reused as though its snapshot were a fresh current-state query.

The full proof result retains a sealed root result bound to the exact payload
bytes and current evaluation time. Request association and readiness-sidecar
results retain their full proof verification, including fresh root evidence.
Products can use the retained source evidence in their effect-fencing protocol;
the Library neither persists nor atomically fences external state by itself.

Tests verify actual RFC test instrument, Oracle-witness and lifecycle-event
signatures. Their envelope and unsafe public keys are test-only. They do not
define a production instrument format or establish actual exposure, chain truth,
current registries or inventory completeness.

## Current readiness prerequisite

`InstalledReadinessVerifier(deployment_profile_bytes, readiness_profile_bytes,
adapter, conformance_level, receiving_zone)` installs the separately approved
profile and trusted zone. Its `evaluate(attestation_bytes, actual_operation=...,
evaluated_at=..., clock_healthy=...)` returns a sealed prerequisite result.
It never increases standing, adds a component to E_base or permits execution.

The adapter's `resolve` receives those immutable profiles, canonical operation,
trusted evaluation time/level and receiving zone, without the candidate
attestation. It returns `AuthenticatedReadinessContext` with canonical bytes for
the independently reconstructed readiness request, authenticated current state
and trusted key registry projection. It must establish running artifact/configuration
bindings, actual scope/environment, registry competence/independence and evidence,
approved governance/profile relationships, current durable epoch/active digest,
challenge/check evidence and key revocation. A timestamp or digest label alone
does not establish any of those facts.

Current state contains exactly `profile_id`, `profile_digest`,
`deployment_profile_digest`, `assessor_registry_digest`,
`minimum_profile_version`, `readiness_epoch`, `active_attestation_digest`,
`challenge`, `checked_at` and `status`. Live status must be active and its
checked-at time equal the current evaluation second. Authenticated key entries
bind `kid`, `subject`, `zone_id`, `purpose`, `alg`, `kty`, `crv`, public JWK
coordinates, `not_before`, `not_after`, and `revoked: false`. Assessor and decision
purposes are respectively `ktp-readiness-attestation-v1` and
`ktp-readiness-decision-v1`.

`InstalledReadinessDecisionVerifier(readiness_verifier, proof_verifier).verify`
accepts complete canonical sidecar and attestation bytes, a derived
`RequestAssociationResult`, and current time/clock health. It requires
`RB_BOUND`, freshly queries readiness again, re-verifies the exact ordinary
proof, and verifies the sidecar's purpose-separated signature and complete
request/proof/epoch/evidence/expiry binding. Ordinary request replay reservation
therefore precedes this check; reservation is not permission or an effect.
Products must fence current state and complete remaining ordinary authorization
before protected effects, and apply their declared safe transition on lost
conditions. No cached positive readiness result can replace the live query.

The standalone assessment verifier supports the reference's classical strength
checks, including P-384/Ed448 for Level 3. Sidecar composition currently rejects
Level 3 because the ordinary proof verifier does not yet establish that
cryptographic profile. Threshold, hybrid, key-custody and broader conformance
requirements remain separate implementation gates.

## Combined native evaluation

`InstalledNativeEvaluationVerifier(association_verifier, readiness_verifier,
local_geometry_verifier=None, local_evaluated_at=None,
local_profile_expires_at=None)` composes the paths above. Association, readiness
and local geometry must use the same installed ordinary proof verifier. Local
use requires an independently installed geometry verifier, trusted evaluation
time and profile-expiry ceiling. Protected use consumes the exact signed carrier
retained by request association and rejects a supplied unsigned alternative.

`verify` takes the canonical request and association, exact compact proof,
readiness decision/attestation bytes, actual invocation evidence, current time
and clock health; local use additionally supplies the geometry body bytes.
The sealed `NativeEvaluationResult` retains association, current readiness/full
proof/root evidence, original canonical geometry, effective supervision and
immutable constraint bytes. Its expiry is the earliest record/profile, readiness
sidecar or ordinary-proof expiry. Consumer projections must preserve all producer
ceilings at the same or lower maxima and cannot lower supervision.

`NATIVE_PREREQUISITES_VALID` means these independently installed prerequisites
were verified for this invocation and snapshot. It is not execution permission.
Readiness failure returns `silent_veto` while retaining verified constraints;
record mismatch stops before readiness lookup. The service still establishes
remaining ordinary authorization, applicable human approval/supervision,
execution budgets and target semantics, and atomically fences source state with
protected effects. No positive cached result permits continuing after lost
conditions or expiry.

## Signed trajectory history

`InstalledTrajectoryVerifier(expected_context_bytes, adapter)` verifies native
`ktp-trajectory-v3` records against independently authenticated chain state.
The immutable expected context contains exactly `trusted_level`,
`trusted_profile_digest`, `expected_agent`, `expected_zone`, `expected_chain`
and `minimum_record_format: "ktp-trajectory-v3"`. The adapter's
`resolve(expected_context_bytes=..., checked_at=...)` receives no candidate.
It returns `AuthenticatedTrajectoryContext(state_bytes, trusted_keys_bytes,
evidence_bytes)` with canonical state and independently authenticated key data.

State contains exactly `checked_at`, `context`, `head`, `predecessor`,
`predecessor_context` and `migration`. The current context and check second must
match the installed expectation. `head` is the independently authenticated
complete final-head binding from the RFC, including final record hash and
commit intent. The resolver must verify the actual required commitment protocol,
unique durable head selection, current configuration/format floor and registry;
a mutable pointer or `committed` flag cannot establish those facts.

Genesis uses null predecessor and predecessor context. A continuation carries
the accepted complete predecessor and its independently approved historical
context, allowing authorized profile/key transitions without trusting the
predecessor's own assertions. The verifier checks both records' signatures,
complete hashes, exact sequence/hash/state continuity and strictly increasing
event timestamps. Key metadata uses the shared purpose-bound JWK projection
described above. Signing validity is checked at the event/Oracle times; history
does not expire simply because the signing key later reaches its validity end.
Current revocation and evidence admissibility remain resolver obligations.

For an activated migrated genesis, `migration` contains exactly `token`,
`checkpoint_digest`, `approved_state` and `activated_at`. The token is the full
signed migration JWS. The other facts must come from authenticated governance,
independent state revalidation and durable one-time lineage activation. The
verifier checks the checkpoint's exact new-genesis bindings and validity at
activation, including that the fully signed genesis precedes activation. It
does not require renewal when verifying an already activated history after the
checkpoint expiry. A record declaring migration without that external evidence
rejects. The Library does not implement the migration registry or approve state.

`verify(record_bytes, now=..., clock_healthy=...)` returns sealed integrity/head
evidence, retaining complete record, hashes and trusted state/evidence. It does
not establish an authorized transition, physical continuity, truthful sensors,
standing credit or permission. Inputs are bounded to 262,144 canonical record
bytes for this Library profile. Classical signature checks support the
reference's P-256/P-384 and Ed25519/Ed448 choices; a stronger trusted deployment
still needs its required threshold/hybrid/custody mechanisms.

The original trajectory schema and signed fixtures are byte-preserved. Native
validation explicitly changes the stale risk-schema reference to PR #164's v3
five-factor definition. Original six-factor fixtures are crypto diagnostics;
they are not a native compatibility mode. Fresh unsafe-test-key native records
exercise the composed profile. Final RFC reconciliation must update this
reference and regenerate canonical fixtures upstream.

## Remaining release gates

The source adapters in the integration tests are explicitly fixtures. Real
instrument/event source adapters and fencing, production source profiles,
person standing/eligibility/capacity, nested ingress and consuming-service
authorization still require their documented contracts and evidence.
Repeating root-score arithmetic and exact Decimal values that cannot survive
the JCS number wire remain precision dependencies. The final RFC tag, public
API cutover, migration and release verification remain outstanding. See the
[release-readiness audit](plans/2026-10-28-v3-release-readiness.md).
