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

## Remaining release gates

The source adapters in the integration tests are explicitly fixtures. Real
instrument/witness signatures, live lifecycle/root refresh, production source
profiles, person standing/eligibility/capacity, nested ingress, readiness and
full authorization still require their documented contracts and evidence.
Repeating root-score arithmetic and exact Decimal values that cannot survive
the JCS number wire remain precision dependencies. The final RFC tag, public
API cutover, migration and release verification remain outstanding. See the
[release-readiness audit](plans/2026-10-28-v3-release-readiness.md).
