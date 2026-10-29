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

## Human-origin eligibility

`InstalledHumanEligibilityVerifier(deployment_profile_bytes, human_profile_bytes,
adapter, conformance_level, receiving_zone, purpose_id)` installs an exact
`human_policy` binding to a separately approved profile. Missing binding rejects;
it does not select legacy human scoring. The resolver independently authenticates
the actual human/session, actor classification, approved criterion meaning and
registry, grants/delegation, current status and durable correction epoch/maps.
Candidate labels cannot select a human or software execution path.

`resolve` receives the immutable profiles and canonical operation, trusted check
time/level, receiving zone and purpose, without candidate evidence claims.
It returns `AuthenticatedHumanContext(actual_request_bytes, context_bytes,
evidence_bytes)`. The context is the RFC reference's complete `TrustedContext`:
principal/actor/type, authentication digest, profile/version floor and registry,
state epoch/check time/status and active evidence/grant/delegation ID-to-complete-
digest maps. Constructing those fields proves none of their real-world facts.

`evaluate(claims_bytes, actual_operation=..., evaluated_at=...,
clock_healthy=...)` consumes a closed canonical object with `evidence`, `grants`
and `delegations` arrays. It binds principal, actor, request, operation, exact
zone/resource/parameters/purpose and current state, then applies the RFC's
qualification and direct-delegation checks. An active but unsatisfied assessment
does not qualify. Corrected content remains unusable until its active digest
and epoch are updated. A delegation cannot outlive or widen its source grant.
Rejected claims remain untrusted review context, never authoritative evidence.

The result retains the complete unsigned decision body and trusted evidence.
It is personal information, not a human JWT, capacity value or permission.
Registry authentication, meaningful independent assessment and review,
correction propagation, lawful purpose/access and retention are source/product
responsibilities; a digest cannot detect forbidden ranking hidden in criteria.

`combine_human_origin(native_result, human_result, now=..., clock_healthy=...)`
joins an independently authenticated human-origin prerequisite to the software
executor's native evaluation. It requires the same current second, operation,
principal/actor, deployment, level and zone, preserves native supervision and
constraint bytes, and shortens expiry where needed. Failure only adds a veto;
qualifications never add standing or capacity, and the agent still needs its
own proof/readiness/grants. Selection of this composition must follow the
authenticated principal type in the service, never an applicant-provided flag.

Direct human execution still requires the RFC's separately reviewed human
authorization/capacity adapter. This Library does not synthesize software
generation, model, tier or E values for that route. An eligible unsigned body
alone cannot enable it; network use must authenticate the complete body and
bind the actual request/proof through that reviewed adapter. The existing
experimental person-subject proof-shape fixtures are not such an adapter.

## Remaining release gates

The source adapters in the integration tests are explicitly fixtures. Real
instrument/event source adapters and fencing, production source profiles,
reviewed direct-human execution/capacity, privacy storage/disposition, nested ingress and consuming-service
authorization still require their documented contracts and evidence.
Repeating root-score arithmetic and exact Decimal values that cannot survive
the JCS number wire remain precision dependencies. The final RFC tag, public
API cutover, migration and release verification remain outstanding. See the
[release-readiness audit](plans/2026-10-28-v3-release-readiness.md).

## Exact standing arithmetic

Installed standing passes the selected root's exact ratio into native base composition. `NativeBaseTrust.raw_base` is a `Fraction`; weighting and ceilings precede conversion of `base_trust` to a finite Decimal. The root's display score is diagnostic. A nonterminating effective standing is rejected until a wire precision profile is declared; a repeating raw value that becomes finite after a ceiling is supported.

## Erasure receipt accounting

`v3.privacy_erasure.InstalledErasureReceiptVerifier` checks the exact RFC erasure
receipt against an independently authenticated current inventory. Install a JCS
lookup context containing exactly `receipt_id`, `request_digest`,
`subject_scope_digest`, `privacy_policy_digest` and `conformance_level`.
This context is a Library adapter contract, not an additional RFC wire format.

The resolver receives only `expected_context_bytes` and `checked_at`. It returns
`AuthenticatedErasureContext(state_bytes, evidence_bytes)`. The closed state
contains `context` (the exact installed context), current `checked_at`,
`authenticated_receipt_digest` (the independently authenticated complete receipt)
and `inventory` (the RFC reference's `TrustedErasureInventory` fields).
The resolver must establish approved policy, actual request/scope, complete
copy/key/recipient discovery and concurrent-copy fencing, disposal evidence,
all usable key/wrapping/recovery paths, recipient acknowledgements and complete
retention authority. Constructing the return type does not establish those facts.
The candidate receipt is never passed to this lookup.

`verify(receipt_bytes, now=..., clock_healthy=True)` returns a sealed accounting
result. `ERASURE_ACCOUNTING_VERIFIED` preserves the receipt's verified `pending`,
`partial` or `complete` status and retains the exact receipt and authenticated
source evidence. `complete` is limited to that inventory, scope and cutoff;
it makes no claim about uncontrolled copies or a legal outcome. Approved retained
exceptions keep status partial; `overdue_retention_copy_ids` exposes elapsed
deadlines without granting continued retention. Invalid claims yield
`ERASURE_INVALID`; unavailable current context yields `ERASURE_UNAVAILABLE`.

This path does not delete storage, destroy keys, grant access, clear revocation,
change correction state or authorize an operation. A restored or newly discovered
copy requires current disposition/fencing evidence. Receipt and source metadata
remain purpose-limited personal data. The integration tests explicitly model
authenticated services and do not demonstrate deployed discovery or destruction.

## Encrypted evidence verification and recovery

`v3.privacy_evidence.InstalledPrivacyEvidenceVerifier` installs exact JCS lookup
fields `envelope_id`, `zone_id`, `chain_id`, `purpose_id`,
`privacy_policy_digest`, `issuer_id` and `conformance_level`.
Its archive resolver receives only `expected_context_bytes` and `checked_at`.
It returns `AuthenticatedPrivacyArchive(state_bytes, trusted_keys_bytes,
evidence_bytes)`. The closed state has the exact installed `context`, current
`checked_at` and independent `anchor` containing `sequence`, `previous_hash`
and `record_hash`. Registry keys use the shared native JWK contract, with the
`ktp-privacy-evidence-v1` purpose, issuer/zone, current revocation status and
creation-time key validity interval.

The source must establish current approved policy, actual archive position and
trustworthy key/role history. Candidate metadata cannot select the anchor.
The Library checks the unchanged RFC envelope schema, complete JCS signed body,
completed-envelope hash, predecessor/genesis shape, exact expected scope and
classical cryptographic floor. Success is explicitly
`PRIVACY_OUTER_INTEGRITY_ONLY`, retaining the original envelope and source
evidence. This can remain valid after a deletion deadline; it grants no right
to retain ciphertext or recover its content. Threshold/hybrid profiles and
archive consensus remain separate required deployment contracts.

`InstalledPrivacyEvidenceReader(verifier, access_adapter).open(...)` additionally
requires the complete actual operation descriptor and a healthy current clock.
It freshly verifies the archive, refuses recovery at or after `delete_after`,
then calls `authorize_and_resolve_key` with the installed archive context,
canonical operation bytes, verified envelope bytes/hash and current time.
The access service must authenticate and authorize the actual principal/actor,
purpose, operation and resource, enforce current correction/erasure state, and
resolve the exact surviving data key through approved custody and wrapping paths.
It returns `AuthenticatedPrivacyAccess(context_bytes, data_key, evidence_bytes)`.
Its closed context contains the exact installed `context`, actual `operation`,
`record_hash`, `key_ref`, current `checked_at` and an `expires_at` no later than
the signed deletion deadline. These are authenticated service outputs, not
candidate declarations or a Library authorization decision.

AES-256-GCM checks the original RFC associated data and recovers exact bytes.
The result is `PRIVACY_BYTES_RECOVERED_UNREVIEWED`; original evidence formats,
signatures, factual validity and current authority still require their own
checks. Wrong keys or tags return no plaintext. Data keys are not retained in
results, and key/plaintext fields are omitted from generated representations.
This is not secure memory zeroization. Key custody, authorized access, retention,
restoration and actual destruction remain source obligations. The issuer below
creates new envelopes separately from archive verification and authorized reads.

## Producing encrypted evidence

`v3.privacy_issuance.InstalledPrivacyEvidenceIssuer` installs the same archive
lookup context, an ingest source, a signing adapter and a key-storage adapter.
`issue(plaintext, actual_operation=..., now=..., clock_healthy=True)` accepts
1–65,536 exact bytes; the completed envelope is bounded to 262,144 bytes, matching
the verifier. These are Library resource limits, not universal RFC limits.

The ingest source receives only `expected_context_bytes`, canonical actual
`operation_bytes` and `checked_at`. It returns
`AuthenticatedPrivacyIngest(state_bytes, trusted_keys_bytes, evidence_bytes)`.
The closed state contains exact `context`, actual `operation`, current
`checked_at`, independently authenticated `plaintext_digest`, approved
`metadata`, `kid` and `algorithm`. The digest is SHA-256 at Levels 1/2 and
SHA-384 at Level 3, over the exact original bytes. Metadata has exactly the RFC
seal helper's ten fields: envelope/zone/chain/position/predecessor, purpose,
privacy-policy digest, creation/deletion times and issuer. Creation is current;
the approved policy must independently justify the retention deadline.

This source must authenticate permission to ingest these actual bytes, permitted
source/purpose/recipients and correction/retention state. It owns reservation,
predecessor selection and concurrent append fencing. The plaintext and its
candidate digest are not supplied to the source callback. Its output must
reflect the independently authenticated invocation, not echo candidate claims.

The Library generates a fresh 256-bit data key, 96-bit nonce and opaque key
reference per attempt, then applies the exact RFC AES-GCM associated data and
complete JCS signing body. The signing adapter's
`sign(signing_input, algorithm=..., kid=...)` returns raw JWS signature bytes;
private signing keys stay with that adapter. The Library verifies the completed
signature/hash and role/issuer/zone/strength before asking for key storage.

`key_storage.store(data_key, context_bytes=...)` must durably protect the exact
data key and return `AuthenticatedPrivacyKeyStorage(context_bytes,
evidence_bytes)`. The exact canonical custody context binds installed context,
operation, approved metadata, original-byte digest, completed `record_hash`,
`key_ref`, nonce, generated-key digest and current time. Acknowledging a different
key or binding fails issuance. Adapters must not log raw keys. Source and custody
evidence can identify personal data and must remain protected under the policy.

The sealed result is explicitly `PRIVACY_ENVELOPE_SIGNED_UNANCHORED`. It retains
the completed encrypted envelope and authenticated source/custody evidence,
without returning the raw key or original plaintext. Its local computed hash
does not establish an independent archive anchor. The consuming archive service
must durably append under its reservation, establish consensus/anchoring and
then use the installed verifier. Commit failures, uncertain storage outcomes,
orphan-key cleanup, retries, uniqueness, lawful retention and destruction remain
product responsibilities. No receipt, zeroization or original-evidence truth is
established by issuance.

## Nested ingress and current topology

`v3.ingress.InstalledIngressVerifier` installs exact JCS `context_bytes`,
`receipt_profile_bytes`, a topology/session source and receipt verifier.
The closed context binds `subject`, `issuing_zone`, `receiving_zone`, `receipt_profile_id`,
`receipt_profile_digest` and `conformance_level`. The named profile contains
`id`, positive integer `version`, and `link_digest_algorithm` (`sha256` or
`sha384`, with SHA-384 required at Level 3); its other fields describe the
installed receipt encoding, signing preimage, key requirements and link preimage.
The RFC proposal specifies the bindings, but does not yet supply interoperable
receipt signing/link encoding and crypto vectors. There is no default wire
profile here. The test adapter's JCS/Ed25519 format is explicitly unsafe test
material, not an additional standard or production profile.

The source receives only installed `context_bytes` and `evaluated_at`. It returns
`AuthenticatedIngressContext(state_bytes, evidence_bytes)`. The closed state
contains the exact installed `context`, current `checked_at`, `topology` and
`session`. Topology contains `epoch` and outermost-first `rings`; each ring has
`zone_id`, `enforcement_class` (`green`, `cyan`, `blue`, `deep_blue`),
`enclosure_reach`, `registry_enclosure_reach` and current authorized `oracle_kids`.
Session contains the actual authenticated `sub`, possession-verified `cnf_jkt`,
fresh `admission_id` and `expires_at`. These are Library adapter contracts, not
proposed RFC wire fields. The source must independently authenticate governance,
current topology/epoch, profile and registry declarations, Oracle roles/status,
the actual admission and possession of its key. Matching strings or constructing
the return type establishes none of those facts.

The Library requires one through six distinct rings, nondecreasing enforcement
class, positive declared and registry enclosure reach for every inner ring,
and a final ring matching the receiver. Depth comes from that topology. Depth
zero requires an absent path; positive depth requires exactly that many receipts.
Each closed receipt must bind its actual issuing Oracle, next inward audience,
subject, possession key, admission, current epoch, valid times and previous
complete receipt. An unavailable Oracle never shortens the required ancestry.

The receipt adapter's `verify(receipt_bytes, context_bytes=...,
authenticated_state_bytes=..., receipt_profile_bytes=..., evaluated_at=...)`
must authenticate the signature over every other receipt field, current key
role/revocation and selected profile strength. It returns
`AuthenticatedIngressReceipt(receipt_bytes, receipt_digest, evidence_bytes)`;
the exact receipt and profile-defined complete-receipt digest are retained.
The Library checks every next `prev` against that authenticated digest.

`InstalledProofVerifier(..., ingress_policy=...)` uses this current assessment at
stage 7. Its sealed `ProofVerificationResult.ingress_verification` retains the
exact proof payload, current topology/session evidence, receipt evidence and
earliest proof/session/receipt expiry. Authenticated depth must also match the
installed proof context; a topology change requires policy reconciliation,
never an implicit shortening. A bare boolean receipt callback is admitted only
in the explicitly selected fixture mode; native positive-depth use fails at
`TP_INGRESS` without the installed policy. Existing request/readiness results
retain the complete proof result for consuming-service fencing.

The proof's Oracle/`ktp.zone` belongs to `issuing_zone`; the receipt ancestry
and its final audience belong to `receiving_zone`. These can differ at ingress.
When installing `ingress_policy`, the proof verifier's installed context must
explicitly include `receiving_zone` as well as the existing issuing `zone`.
Both are compared with the ingress policy; neither is inferred from the path.
This does not change native wire claims or key/root issuing-zone checks.
`TP_CLEAR` remains a prerequisite result. In particular, the readiness sidecar's
local-proof scope requirement still applies before native protected evaluation.

Ingress remains a prerequisite. Physical/network containment, all route
enforcement, durable admission/replay state, current enclosure-risk aggregation,
degraded resident policy and outward confidential egress shaping remain distinct
requirements. The source snapshot has sixteen boundary cases; the crypto and
binding tests here do not execute the heat/egress cases or certify a gateway.

## Enclosure risk in the native Core

The selected `reference-floor-v1` enclosure profile implements PR #160's
informative form exactly: `H = max(a × P, G)` and
`R = L + w × max(0, H - L)`. `L` is the contemporaneous local five-factor
assessment, `P` the authenticated enclosure risk, `G` the receiving gateway's
own reading and `w` the declared reach. Across equal enforcement classes `a`
is exactly one; across a class step it is the selected attenuation parameter.
This is an explicit supported profile, not a universal normative formula.

The pure `EnclosureInputs`/`apply_enclosure_risk` API preserves the original
five-factor assessment through `risk.enclosure_projection.local` and exposes
`local_measured_risk`/`local_decision_risk`. It never adds a sixth weighted
factor, discounts Base Trust, or applies the domain twice. At depth zero the
domain is disabled and accepts no Wild enclosure reading. Missing required
enclosure or gateway readings preserve unknown measured risk and add undefined
term evidence, with a separate restrictive decision risk of one. Missing local
measurements also remain unknown. Measured calm never discounts local risk;
the surcharge can recede as current enclosure heat recedes.

`InstalledEnclosureVerifier(deployment_profile_bytes, profile_bytes, source,
algorithm)` selects an immutable Library profile with exactly `id`, `version`,
`formula`, `zone_id`, `depth`, `reach`, `attenuation_per_class_step` and
`overlap_policy_id`. This is an adapter configuration, not a new RFC wire field.
The source receives those installed bytes, canonical actual `operation_bytes`
and `evaluated_at`, never candidate risk scores. It returns
`AuthenticatedEnclosureEvidence(body_bytes, evidence_bytes)`. The closed body
binds `deployment_digest`, `operation_digest`, `profile_digest`, current
`checked_at`, `zone_id`, `depth`, `topology_epoch`, `zone_class`,
`enclosure_class`, `enclosure_zone`, `registry_reach`,
`signed_enclosure_risk`, `gateway_risk` and `expires_at`.

The source must authenticate current authorized topology and declared reach,
actual signed enclosure evidence/current issuer role, independently normalized
gateway observations, freshness, overlap handling and absence of protected-inner
telemetry feedback. A null reading declares missing evidence, not calm. An
unavailable source cannot supply a measurement or silently disable the profile.
Returned classes must be nondecreasing inward, and inner reach must be positive
in both profile and registry. The Library checks these bindings and retains
the full authenticated body/source evidence in a sealed assessment.

Select the same `enclosure_profile_bytes` in `NativeCoreContext`, then pass the
sealed assessment to `project_classified_native_core(..., enclosure=...)`.
After clear Soul, the Core requires exact deployment, invocation, time, profile
and current expiry, applies the domain before capacity, and retains the
assessment. Supplying an unselected assessment or omitting a selected one fails.
`NativeCoreClaimsSource` requires symmetric profile/evidence selection, preserves
the enclosure-adjusted R/E, checks the receiving zone and refuses proof expiry
beyond enclosure evidence. Removing the profile from a replacement claims
context cannot remove those requirements. Source/profile and final execution
fencing must remain current for every resident-agent evaluation, not just ingress.

## Fresh enclosure-measured egress

`v3.egress.InstalledEgressProjector` implements the selected
`fresh-enclosure-proof-v1` disclosure route. It takes an immutable disclosure
profile, current disclosure source, complete incoming proof verifier and a typed
`NativeCoreClaimsSource` for a freshly evaluated enclosure. At the outermost
ring, the new Core is measured in that same ring. This route creates a new
enclosure Oracle assertion; it does not rewrite an old signature or implement
the illustrative NZ12 object mutation as a new wire contract.

The profile binds exactly `id`, `version`, `mode`, `subject`, `source_zone`,
`measurement_zone`, `audience` and `digest_algorithm`. The last selects SHA-256
or SHA-384 for source-evidence bindings; it does not select or claim a stronger
signature/conformance profile. The incoming verifier must bind the actual
departing ring as its receiver; its Oracle issuing zone remains independently
configured. `evaluate(incoming_compact, evaluated_at=..., clock_healthy=True)`
first rechecks the complete input proof, including current roots and ingress.

The disclosure source receives only installed `profile_bytes` and
`evaluated_at`, and returns `AuthenticatedEgressEvidence(state_bytes,
evidence_bytes)`. The closed state binds `profile_digest`, exact complete
`incoming_proof_digest`, exact complete `outward_claims_digest`, current
`checked_at`, `topology_epoch`, outermost-first `ancestry` and `expires_at`.
The service must independently authenticate the actual departure/recipient,
current governance/topology and approval of the entire outward payload,
including standing/root and identity metadata. No candidate proof or payload
is passed to that resolver. Constructing the return type grants no authority.

The Library compares ancestry and epoch with current incoming ingress evidence,
requires the direct enclosure as measurement zone, and checks that a nested
measurement ring has its own current enclosure assessment at the same epoch,
depth and direct-parent relationship. An identically valued flat Core cannot
replace that assessment. The fresh Core supplies all R/E/context values, and
this route omits optional velocity, volatility, quorum and resilience telemetry
and extensions. Any outward receipts must be an outermost prefix of permitted
enclosures; the departing ring's own receipt and inner receipts cannot survive.
The output must have a fresh assertion identity, exact subject/recipient, and
expiry no later than incoming proof/ingress and disclosure evidence. A known
incoming veto cannot become clear.

The sealed `EgressClaims` retains incoming verification, outward Core and
authenticated disclosure evidence. Pass it as the claim source to the existing
`InstalledProofIssuer`, with the enclosure's signing adapter and complete
outward verifier. The issuer rechecks the completed new signature and current
root/ingress policy. The original compact proof remains untouched. This is
claim production, never movement permission or acceptance of foreign standing
for execution. Actual exit authorization, federation admission, recipient
access, audit/log exports, ongoing state fencing and disclosure side channels
remain product responsibilities. Other egress wire/profile routes still need
their own reviewed contracts.

`minimize_confidential_exit_summary` creates a new unsigned derivative containing
only present, safe integer `actions_total`, `actions_allowed`, `actions_vetoed`,
`soul_vetoes` and `attestations_earned`. It omits R/E statistics, tier history,
veto rates and unknown fields. It neither edits an original signed attestation
nor authenticates the retained counts. Those counts can still be personal or
sensitive data; disclosure approval and a newly authenticated attestation are
required before external use. No universal Exit Attestation wire format is
introduced by this helper.

## Declared adjudication gates

`v3.adjudication.InstalledAdjudicationVerifier` implements the token binding and
declared-gate portion of proposed Core L11. This checkpoint does not implement
per-rail supervision increments/releases or the complete importance/supplied-input
composition contract. Those remain explicit work in the release-set audit.

Install immutable deployment bytes, adjudication `profile_bytes`, approved
`external_schema_bytes`, a current-context source and a token verifier. The
closed profile binds `id`, `version`, `gate_id`, `gate_required`, `issuer`,
`zone_id`, `external_schema_id`, `external_schema_digest` and `token_profile_id`.
`gate_required` is authenticated installed policy, never a requester flag.
The external JSON Schema is checked and pinned, not evaluated for normative
adequacy. Its issuer/schema approval and the profile's applicability must be
established before installation and rechecked by the context source. Changing
this configuration requires the deployment's evaluation-policy/version process;
these fields are a Library adapter contract, not additional RFC wire claims.

The source receives installed deployment/profile/schema bytes, canonical actual
`operation_bytes` and `evaluated_at`, without the candidate token. It returns
`AuthenticatedAdjudicationContext(state_bytes, evidence_bytes)`. The closed
state contains `deployment_digest`, `operation_digest`, `profile_digest`, current
`checked_at`, actual `actor`, whole `action_digest`, possession-verified
`cnf_jkt`, current `grant_digest`, `evidence_digest`, `zone_id`,
`topology_epoch` and `expires_at`. It must authenticate actual whole-action and
possession scope, grant/evidence versions and current topology, not echo claims.

The adapter verifies the complete token JWS under the explicitly named installed
crypto/key-role profile and returns `AuthenticatedAdjudicationPayload` with
exact canonical `payload_bytes`, opaque `evidence_bytes`, actual verified
`key_id` and its authenticated `issuer`. The Library applies the unchanged
proposal schema and checks exact issuer, actor/action/possession/grant/evidence/
zone/epoch binding and integer `iat <= now < exp`. If payload `kid` is present,
it must match the verified key. Malformed, invalidly signed, expired, corrected
or misbound tokens are `ADJ_ABSENT`; unavailable current source state is
`ADJ_UNAVAILABLE`. Neither result invents a measurement or an additional gate.
Favorable and unfavorable assessments retain exact authenticated evidence,
original token bytes and the verified key ID/issuer for audit and current-key
fencing. They are bounded by token and source expiry and contain no capacity
or score. Retaining/exporting those records remains subject to the installed
data policy.

Select this verifier with `InstalledNativeEvaluationVerifier(...,
adjudication_verifier=...)`, then supply `adjudication_token` to `verify`.
Deployment and receiving-zone policies must agree. Existing proof, geometry,
veto and readiness failures stop before token use. After those prerequisites,
a declared unsatisfied gate yields `ADJ_GATE_UNSATISFIED`, retaining the original
measured geometry, supervision floor and constraints. A favorable verdict only
satisfies that gate and can shorten expiry; it does not improve the measured
result. With no required gate, an absent/unavailable token leaves the no-norm
result unchanged. Consumers must check the complete result reason; a supervision
floor alone is never execution permission. The assessment is retained in
`NativeEvaluationResult.adjudication`.

The source token schema retains its published draft `$id` (under `/v2/`) and
SHA-256 payload bindings unchanged. Stronger profiles and a final interoperable
token JOSE profile remain explicit reconciliation work. The test Ed25519/JWS
profile is unsafe fixture material, not a new wire standard. Unexpected provider
failures propagate without a successful evaluation. Complete coverage of all 23
source-vector semantics is not claimed.

Multiple declared gates use the explicit immutable `adjudication_verifiers`
tuple and `adjudication_tokens` gate-ID/token pairs. Gate IDs must be unique;
unknown or duplicate candidates and conflicting singular/plural policy forms
are rejected. Omitted tokens leave their required gates unsatisfied. Every
required gate must pass after baseline geometry/readiness checks, and the
result expires at the earliest required gate evidence expiry. The complete
tuple is retained as `NativeEvaluationResult.adjudications`; the singular
`adjudication` field is populated only for the singular policy form.

Token adapters must authenticate the exact declared gate/profile and return
its `profile_digest` in `AuthenticatedAdjudicationPayload`. An issuer match
alone is insufficient when that issuer answers multiple gates. The fixture
binds that digest in its signed protected header; this is an unsafe test
profile, not a new interoperable wire requirement. Deployments must supply
their declared domain separation and authority verification.

### Evaluation-scoped supervision rails

`InstalledSupervisionRailVerifier` verifies signed increments and accountable
own-increment releases through a selected external signature/schema adapter.
Its independent current-state source supplies the complete active hold inventory,
bound to exact signed-token digests, deployment, operation, geometry profile and
evaluation time. Omitting a hold fails verification. The semantic adapter record
is an internal Library contract, not a proposed universal RFC wire format.

Each act binds an evaluation ID, actor, whole-action digest, possession key,
grant/evidence digests, zone and topology epoch. Only the original rail and issuer
may release that increment. Invalid releases retain holds. Requested releases
below the environment or increment's original floor clamp to that floor; other
rails retain their holds. Multiple valid releases compose without order effects.
The installed source owns freshness, authority and actual action/session facts.

Native geometry selects the assessment with the internal
`supervision_rail_profile_digest` profile field. Selection requires matching sealed
evidence; evidence cannot be silently added to an unselected profile. The Core
instance, operation, profile, time and decision ID must match. Geometry retains
the underlying environment and non-releasable prior floor, capacity and grant/prior
ceilings. Providers must distinguish retained prior restrictions from the rail's
releasable increment; a previous aggregate supplied as prior remains conservatively
binding. Signed carrier issuance caps expiry to the rail assessment's earliest
supporting expiry. No result authorizes execution. Importance/supplied-input and
full mixed-shape normative composition remain separate implementation work.

### Declared zone boundaries

The composite native deployment schema requires the boundary proposal's exact
five-cell declaration: resources, entitled subject classes, affected outside
classes and review routes, jurisdictions, and authority limits. A profile with
no boundary cannot make a complete v3 conformance claim. Historical partial
component fixtures remain useful arithmetic tests; they do not establish that
claim or exercise a production deployment declaration.

`InstalledBoundaryVerifier` accepts only installed source-authenticated current
facts bound to the deployment and actual operation. The source authenticates
the executing actor's class, resource, affected parties, current zone/epoch,
literal resolution of every declared resource/pattern, and whether the act is
within the declared jurisdiction/authority limits. The Library does not infer
legal authority from prose or interpret an undeclared glob. An enclosing
deployment declaration additionally bounds the complete resolved inner resource
set. Missing or ambiguous affected-party review routes fail verification.

The sealed assessment records denials and every applicable declared review
route. Recording/serving those routes durably remains a Service responsibility.
`project_classified_native_core` requires current allowed boundary evidence when
the deployment declares a boundary, before Soul/standing/risk processing. It
raises with the boundary reason on denial; callers retain the assessment for
the denial record. Claims retain the assessment and cannot change its zone,
omit its declaration or outlive its support.

The native request facade requires the same installed boundary policy for a
declared deployment. After authenticating the actual request, it checks the
boundary before geometry/readiness, retains it as `NativeEvaluationResult.boundary`,
and caps successful result expiry. Positive-depth receivers require an enclosing
boundary and matching retained ingress parent/epoch. Passing the boundary
merely allows ordinary evaluation to continue; it grants no standing or execution
authority by itself. The authenticated source record is an internal adapter
projection, not a universal RFC transport format.

### Repair and re-entry records

`InstalledRepairVerifier` consumes an independently authenticated complete
current inventory of applicable actor/lineage breaches, including inherited
post-breach descendant obligations. Its source owns actual lineage and party
terminators, the required parties (including governing authority where only the
zone is affected), current anchor verification under the current cryptographic
profile, independence from every party at the record date, attendance and harm
declarations. A retired record signature does not invalidate a currently valid
anchor; a lawful disposition does not by itself reopen a reconciliation.
These facts are a typed internal projection, not a new Flight Recorder wire.

`project_reentry` validates the matching breach anchor, parties, terminator's
acknowledgment, explicit residual harm and verifier independence. A declined
party requires a published/followed route and an open right to attend/amend.
Missing or invalid records leave the inventory unreconciled. The selected
reference policy `fractional-reentry-with-additive-unrepaired-raise-v1` computes
the exact ceiling as standing-at-breach times one minus the declared delta,
with the previous lineage delta as a floor and the declared positive raise for
unrepaired harm. It caps delta at one. This is an explicitly selected additive
policy, not a universal RFC formula. Mandatory hard classes include acting
outside a signed decision, withdrawal for cause, misattestation, and seeking
reconciliation without attending; none may declare a delta below one tenth.
No grace period, new sponsor or favorable token substitutes for a record.

Select the installed repair verifier on `InstalledStandingVerifier` and its
exact `profile_bytes` as `NativeCoreContext.repair_profile_bytes`. Standing
rejects unreconciled re-entry and applies `repair_reentry` to E_base itself,
before risk multiplication. Callers cannot replace that reserved ceiling in
standing evidence. Core/claims reject asymmetric selection, foreign invocation,
zone mismatch or support that expires before the proof. The assessment remains
available at `NativeStandingAssessment.repair`.

The native request facade can select the same deployment's repair verifier.
It checks current re-entry status before geometry/readiness, requires both
numerical standing compliance and the declared applicable repair ceiling in
the accepted proof, and requires a fresh readiness assessment strictly after
the latest reconciliation anchor time. The result retains the assessment as
`NativeEvaluationResult.repair` and cannot outlive it. Final public composition
must install all applicable policies; omission of an optional component from a
partial fixture is not a complete repair conformance claim.

This path implements record closure, the re-entry cost and current
readiness/standing enforcement. Ambient breach/capacity/criticality and rule-repair
amendments remain separate work.
Neither an assessment nor a passing test
proves that a real ceremony, attendance, anchoring or durable breach closure
occurred; those are provider/Service responsibilities.

Earned ceiling recovery additionally requires a `ceiling_lift` identity/version/
digest binding in the selected internal repair profile, matching immutable
`ceiling_lift_profile_bytes` and an installed `ceiling_lift_adapter.project`.
The profile declares its standing-point unit and ordinary-rail formula; the
Library does not invent that formula. The current source supplies canonical
ordinary act records and their anchor, lineage, record time, profile digest,
current-anchor verification and ordinary admissibility. It owns those facts and
the ordinary-profile interpretation.

Only admissible, currently verified acts on the same lineage, recorded strictly
after the reconciliation and no later than the evaluation, enter the projector.
Earlier or foreign acts earn nothing; duplicate anchors fail validation. The
empty endpoint must equal the initial re-entry ceiling. Acts are ordered by
record time and anchor; checked prefixes cannot decrease the ceiling or exceed
100. These per-evaluation checks do not prove global formula calibration. The
sealed assessment retains the source records, lift profile and per-breach current
ceilings. Multiple breaches still impose the minimum applicable current ceiling.
The resulting ceiling flows through standing, Core, proof claims and native
request verification; ordinary grants, readiness, vetoes and environmental limits
still apply. A later residual-harm amendment or passage of time alone is not an
earned act. No adapter/profile may be silently selected or omitted.

### Sponsorship admission under unreconciled breach

`InstalledSponsorshipRepairVerifier` checks an independently authenticated bond
opening against the root's complete lineage-summed breach inventory at that
opening. The source authenticates the complete bond or its current anchor,
actual issuer/subject/opening time, the published policy, counts by entry class,
and prior blocking history. The Library checks exact deployment, internal policy,
context, complete-instrument/body digests, identity, zone and current snapshot.
Today’s counts are not substituted for the opening-time inventory.

The named internal profile declares an aggregate count limit and stricter
per-entry-class limits/capacities. Aggregate counts cannot exceed the aggregate
limit; hard breaches across all hard classes together cannot exceed one.
Per-class limits cannot exceed declared capacity and hard limits cannot exceed
one. A previously blocked threshold requires the count to fall strictly below
it. These are immutable current checks, not a durable lock manager. Actual
opening and protected reservation of sponsor capital remain Service work.

Select the verifier on `InstalledRootVerifier` and bind its exact profile digest
in the installed root context as `sponsorship_repair_profile_digest`. A selected
policy cannot be omitted. A void opening earns no root credit, and
`RootAssessment.sponsorship_repair` retains its reason/evidence. Proof binding
also enforces the assessment's zone and support expiry, while preserving the
instrument's real end time. Source operational failures propagate.

For native birth, `InstalledTrajectoryVerifier` selects the same profile digest
in its expected context and the installed sponsorship verifier. The independent
trajectory source supplies `AuthenticatedGenesisSponsorship`, binding the actual
signed genesis hash to its complete birth bond and installed identity context.
This must be the bond establishing that genesis, not an unrelated later bond.
The opening must be eligible and the bond must cover the exact birth instant:
`start_time <= birth < end_time`. The same check applies when genesis is the
accepted predecessor of the first ordinary record. The result retains the sealed
assessment as `TrajectoryVerificationResult.genesis_sponsorship`.

A bond valid at birth may have expired or closed today; that alone does not
erase genesis or retained intrinsic standing. Active root credit remains a
separate current-lifecycle check. An authorized migration genesis continues
through its explicit checkpoint/revalidated-state route, rather than opening
another birth bond. For later records, the installed registry/accepted-predecessor
source owns validation of the established genesis and its selected policy floor;
these pairwise checks do not re-walk the entire chain. No birth or root assessment
opens a real bond, mints an identity or authorizes an action.

Draft clarification remains useful for a zero count threshold after blocking:
the literal required recovery is below zero, which nonnegative counts cannot
reach. This implementation retains the block and does not invent an automatic
release; a valid policy amendment or clarified draft can supply that rule.

### Ambient repair accounting primitives

`project_ambient_window` keeps exact rational arrival, stock, utilization and
index values. Each distinct lineage contributes at most its declared share of
effective capacity to arrival; every breach still enters uncapped open stock.
Only authenticated anchored closure weight may reduce stock. Quiet windows,
restarts and a new sponsor have no stock-removal term. The reference bank policy
carries prior excess, adds positive local index excess and permits only explicit
retirement bounded by prior debt and anchored closure credit. A quiet window
alone does not retire anything. This is a declared reference policy, not a
universal bank formula prescribed by the RFC.

Unknown capacity remains unknown, with saturation and the existing assisted
supervision floor; known zero/no-accountable-root capacity forbids consequential
hosting while stock is open. A positive measured index does not independently
veto an action or manufacture a supervision outcome. Enclosing indices can raise
the heard index without changing local arrival, stock or bank. The pure helper's
caller must authenticate that these are enclosing zones; no outward relay or
topology authority is inferred from a tuple of numbers.

`project_repair_capacity` bounds declared capacity by demonstrated eligible
records per equal, contiguous backlogged window. A record inside a repairer's
declared interval remains anchored and may close stock/re-establish what it
re-establishes, but does not demonstrate durable throughput. Hard-record times
advance even for an interval-excluded record. Same-repairer records at the same
instant require distinct authenticated `anchor_order` values when the interval
matters; record hashes do not supply event order. Duplicate anchors and omitted
window intervals fail validation. No backlogged demonstration leaves a positive
declaration empirically unbounded/unknown in this reference policy; explicit
zero or no accountable roots still establishes zero.

`reference_criticality_valid` evaluates the informative reference condition
`K > 1/(1-sqrt(g))` by exact rational comparison, avoiding rounded square roots.
The deployment owns the normative K declaration and actual reproduction evidence.
These pure functions do not authenticate audit data or execute recovery tiers.
The installed reference composition below consumes them; arithmetic tests alone
do not establish ambient repair conformance or authorize hosting.

The draft's "above one, the stock necessarily grows" statement needs a precise
time-scale interpretation alongside repairer intervals and demonstrated capacity.
Four valid current closures can reduce observed stock even while durable capacity
is two and capped arrival is three. The helpers report actual `stock_change`
separately from `durable_capacity_exceeded`; they do not falsify anchored records
to make those meanings coincide. Both this distinction and the selected bank
policy must remain explicit when composing the final tagged requirements.

### Installed ambient evidence and current use

`InstalledAmbientRepairVerifier` binds an approved reference profile and a
separately pinned normalizer to exact deployment/operation/time/zone scope.
Its source authenticates complete zone-wide lineage counts and actual breach
classes, carried stock/bank, accountable roots, current anchors/order, sustained
backlog and repairer history, inward parent/epoch, reproduction evidence and the
actual operation's consequential classification. Those are Service/provider
facts, not caller-supplied assertions. Declared source signals refer to existing
catalogue inputs; the internal `ambient_repair` feed label adds no catalogue
signal or interoperable wire declaration.

Capacity windows must be complete, contiguous, equal to the declared period and
within their freshness bound. Their final `window_ledger_head` must match the
independently authenticated current `ledger_head`: a newer timestamp cannot hide
new audit entries outside an older stock window. Record classes fix hard/soft
weights; only currently valid anchors close stock, including records excluded
from demonstrated throughput by repairer intervals. The source owns completeness
and the catalogue/entry-class interpretation; this verifier does not implement
an audit chain or consensus.

The normalizer declares its formula, unit, identity/version and digest. Checked
corners require zero heat with no excess/debt, positive heat for positive excess
or bank, and a combined result no lower than either component. These checks do
not prove global calibration. The assessment retains exact capacity/metrics,
the raw authenticated frame, source evidence and a semantic frame digest. Only
`checked_at` and support expiry are omitted from that semantic digest; changed
ledger, counters, topology, profile or evidence still changes it. Exact ratios
may use the internal bounded `n`/`d` string form; there is no new public wire
precision rule.

Select the verifier on `InstalledEnvironmentVerifier` and its exact profile as
`NativeCoreContext.ambient_profile_bytes`. Known pressure can only raise the
adversarial-pressure factor; it cannot repair missing baseline measurements.
Unknown capacity, reproduction or enclosing pressure remains unobservable with
decision stress one, not a fabricated measured value. Core requires matching
policy/invocation/time and current enclosure zone/parent/epoch. Claims cannot
omit the selection, change zone or outlive its support.

Native geometry binds `ambient_repair_profile_digest`, records the current model
and semantic evidence, and respects the RFC's ordered gates and closed reason
vocabulary. Invalid reference criticality or known-zero capacity with open stock
for a consequential act stops at the input gate after the prior gate, using
`INPUT_UNAVAILABLE`; the model retains the detailed cause. A known zero with
proven empty stock contributes no new local heat while its 0/0 utilization stays
undefined; inherited heat and existing bank still apply. This does not grant an
action or erase a prior veto.

`InstalledNativeEvaluationVerifier.ambient_verifier` rechecks the current source,
receiver/topology, pressure and semantic evidence at use. Signed factors and
weighted local-risk bounds must support the current floor. Geometry must carry
the exact current model and profile/frame evidence digests, including an adequate
adversarial-pressure term. A frame match alone cannot excuse lower signed risk
or inflated capacity. The result retains `NativeEvaluationResult.ambient` and
its expiry cannot extend beyond ambient support. Internal `AMBIENT_*` reasons
give precise diagnoses without adding unsupported geometry wire enums.

The selected reference now composes pooled and per-entry-class capacity. Class
throughput partitions globally qualified anchors after the shared repairer
cooldown; changing classes cannot bypass that interval. Complete class capacity,
backlog, stock and debt declarations bind the current frame. Pressure takes the
maximum of the pool and active classes, so healthy pooled throughput cannot hide
a class shortage or outstanding class debt. Explicitly unknown declarations stay
unknown. Pooled and class debt are separate views, never additive stock counts.
This named reference composition is not a universal RFC formula or a claim that
all 41 source cases pass. Recovery tiers and rule-repair amendments remain
implementation work. The empty-backlog case also needs reconciliation:
this reference leaves a positive declaration without qualifying demonstration
unknown; it does not claim that the RFC universally requires startup denial or
that an unmeasured declaration is measured throughput. A final approved policy
can resolve that selection without changing the Core measurement boundary.

`repair_recovery.project_recovery` now provides a pure exact recovery-tier
projection. It requires the full declared trailing window to leave a tier, with
strict utilization margin and rate bounds, stock at target and zero bank. Crisis
requires utilization at least two throughout that window. Missing measurements
cannot establish recovery. The result carries the rule-repair obligation but
neither writes its record nor authorizes an emergency. A declared inability to
preserve the repair invariants in crisis prohibits consequential hosting even
outside crisis.

The installed ambient reference can select a closed `recovery` declaration with
margin, stock target, amendment/nonattendance rate limits, crisis capability and
an optional contingency. Its only permitted measures are published triage order,
independent federation verifier mutual aid and admission tightening. The sealed
assessment exposes which declared measures are available in debt growth/crisis;
it executes none and does not waive normal verifier independence.

Selection requires matching authenticated `recovery` state: persisted prior tier,
complete historical aggregate windows aligned with capacity periods, and current
amendment/nonattendance rates. The latest utilization and bank use the maximum
of pooled and active class views, and current stock comes from actual anchored
closure accounting. Unknown required class declarations cannot prove recovery.
Historical summaries cannot replace the latest computed measures. The semantic
frame and modeled geometry retain the selected tier and obligations; capability
hosting denial follows the existing ordered producer and current-use gates.

Recovery selection is optional for component assembly, not a claim that an
ambient-only component is a complete repair deployment. Full deployment policy
must select it.

An optional nested `rule_repair` declaration publishes the recurrence count.
Selection requires a complete authenticated inventory of applicable recurring
rule/profile/consequence-class patterns, including the profile cause associated
with the repair tier. `rule_repair.project_rule_repairs` checks the anchored
record and a ratified anchored amendment separately. An amendment must bind the
same pattern, responsible profile and prior definition, change that definition,
acknowledge the governing authority's breach, name all affected parties, retain
their rights, and carry independent verification distinct from the Oracle.

Each pattern has an independently authenticated exact set of reconciliation
records that drove it. The amendment must cite that nonempty set; a valid but
unrelated reconciliation is insufficient. Citations must retain current anchors
and precede or coincide with the amendment. Self-citation, a no-op amendment,
missing acknowledgment, an unratified amendment or invalid independence leaves
the pattern open. Persisted prior triggering remains binding when recent counts
fall, even before its first record exists. Time and recovery do not close it. The assessment and geometry
retain record completeness and open/closed pattern identifiers; the frame binds
the complete evidence. A new tier entry must name its current responsible profile.

The source owns complete historical applicability/counting, actual governing and
affected parties, independent-party facts at the record date, actual ratification
and changed definition, and the valid reconciliation records and their causal
relationship to each pattern. This is a closed semantic adapter projection,
not a new audit wire format or a mechanism for writing/ratifying amendments.
An open rule yields an obligation rather than an invented automatic action
veto. Full deployment policy must select both recovery and rule-repair evidence;
the component options alone do not establish complete repair conformance.

### Crossing-time imported standing

`imported_standing` provides a distinct pure software crossing route rather than
rebuilding local PoR/root/peer contributions and adding an import ceiling.
`derive_federation_factor` uses one factor bounded by the receiver-signed term,
applicable Enforcement Class ceiling and declared lowering result. An invalid
high floor is reported and ignored; an unsigned/unavailable direction provides
no factor, and a factor above one is a void clause. The agreement itself is not
voided and a missing import is not a universal ban on local evaluation.

`calculate_imported_standing` consumes the independently authenticated amount
earned within the sending zone, applies that factor once and then applies all
receiver software ceilings, including repair where selected and the missing-root
restriction. `NativeImportedStanding` retains origin, exportable amount, factor,
raw result and receiver ceilings without inventing local allocation shares.
Native Core/capacity accept the shared bounded-standing union and keep their
existing local Soul and risk calculation. No foreign R or E_trust is an operand.

The draft does not define how to extract exportable standing
from root/peer-containing E_base or combine an import with later locally earned
standing: require actual authenticated exportable evidence, and keep mixed
accumulation unsupported until a separately selected policy defines it.

`InstalledFederationVerifier` now authenticates current import evidence through
an installed source that receives only the actual operation and installed
profiles. Its closed state binds deployment/profile/operation, clock, subject,
sender/receiver and the actual admission identity/time. The source supplies the
actual signed agreement version applicable to that admission, current receiver
acceptance, actual subject/action/substrate and Enforcement Class, and separately
authenticated sender-earned exportable standing.

The initial reference supports bilateral software imports. The agreement
projection requires both parties' terminators/signing authorities, signatures,
effective/expiry times, directional terms, crossing/sovereignty declarations,
dispute/deadline, incident/notice and severance cells. Classified veto delegation,
foreign evaluation, coordinated evaluation inputs and foreign act-binding clauses
are void without voiding unrelated terms. Source clause classification is an
authenticated semantic fact, not natural-language legal interpretation by the SDK.

Only a receiver-signed matching direction supplies a factor. Action/substrate
overrides replace the default when present; if both match, the explicitly named
reference takes their minimum. A selected above-one override cannot hide behind
a valid matching override. Declared lowering results and class ceilings bound
the one factor. This selector policy is explicit rather than an asserted universal
rule for overlapping selectors in the draft.

An admitted attestation must match subject/profile/zones, cross one link, name the
sending zone as the zone in which its exportable standing was earned, have current
validity and registry-verified signatures, and have a witnessed sender signature.
Additional non-witness signatures add no credit. Exportable standing cannot
exceed total attested base standing; foreign risk/effective standing are not
accepted operands. Required sovereignty constraints must be enforced by the
receiver. Personal/reconciliation/veto/delta routes are not silently admitted by
this software standing profile.

Unavailable, expired, severed or unsupported import evidence yields an explicit
unavailable assessment, preserving the possibility of an independently installed
local route. Agreement/attestation expiry bounds the current source horizon;
cached evidence cannot extend it. A new agreement version effective after the
recorded ingress cannot be applied to that old admission. The source owns actual
forward-effective version/admission history and revocations. The sealed result
retains the raw current evidence, semantic frame, factor and void clauses and can
derive an imported standing value under independently supplied receiver ceilings.
Source fixtures model authority facts; actual signature, registry, admission and
export provenance need production adapters. Cross-zone bonds and additional
record/person/multilateral routes remain implementation work.

The installed software import route selects
`standing_binding: admission-digest-ceiling-v1` in its federation profile.
`InstalledStandingVerifier.federation_verifier` requires admissible current
evidence and derives the imported amount directly, retaining receiver identity,
root, generation/IAL/trajectory/adversity and repair ceiling checks. It never
adds local PoR/root/peer contributions to that amount. Unavailable import fails
this explicitly selected import-only route; an independently installed local
route remains a separate selection.

The profile uses the proof schema's existing further-declared-ceiling mechanism:
one `federation_ingress.<digest>` ceiling binds the resulting receiver-bounded
amount to the deployment/federation profiles, admission ID/time, subject/zones,
admission-time agreement body and attestation payload identity. This is a named
provisional Library interoperability profile, not a new RFC-standard wire claim.
The prefix is reserved against provider-supplied additional ceilings. Clock-only
refresh does not change its identity, while another admission or agreement cannot
reuse it. No imported allocation shares are fabricated; wire `peer_share` carries
the actual receiver deployment declaration.

`NativeCoreContext.federation_profile_bytes` requires symmetric current standing
evidence and consistent receiving topology. Claims retain the receiver zone and
cannot outlive federation support. Native geometry requires the matching
`federation_profile_digest` selection and carries the complete bound model and
evidence digests. A real Ed25519 fixture produces base standing 56 and effective
trust 33.6 under unchanged local R 0.4, without local contribution operands.

`InstalledNativeEvaluationVerifier.federation_verifier` refreshes the source after
boundary/repair checks, requires exactly one matching admission ceiling, rejects
proofs predating admission or exceeding the current imported bound, and checks
the exact current geometry model/profile/frame evidence. A still-sufficient
standing amount does not excuse a stale frame after lowering changes. A marked
proof without the selected policy is rejected. The result retains `.federation`
and expires no later than its support. Current invalidity, severance or a changed
admission cannot silently turn an old imported proof into local standing.

### Sponsorship capital before cross-zone bond admission

`sponsorship_capital` supplies exact pure Identity accounting for a complete
home-zone inventory. The input sponsor base is current base standing before
reserve deductions. Each active liability contributes the greater of its
depth-decayed ancestral floor and `stake * (1 - intrinsic_base / 80)`. Expiry,
maturity and previously established closure retain the floor. A later standing
loss does not reopen a closed bond's active capital charge.

Termination without cause does not release capital. A pending for-cause claim at
expiry remains visible as unresolved and retains the residual; only a sustained
finding discharges it. A transferred residual retains its authenticated current
amount rather than being recalculated at the receiving ancestor's depth. Complete
inventory subtraction includes active, residual and inherited liabilities and
rejects duplicate bond IDs. Overcommitment remains visible and available staking
capacity is bounded below by zero.

This taper is accounting, never an External Root or E_base composition input.
The projection neither verifies anchors/adjudication/ownership nor reserves funds,
creates genesis or grants root credit. An installed source must establish complete
ownership across zones, actual original stakes/intrinsic standing, prior closure,
transfer history and current adjudication. Cross-zone bond source/root/standing
composition remains next implementation work; bond or agreement end cannot be
implemented as release of permanent residual liability.

`InstalledFederatedSponsorshipVerifier` now binds the complete bond bytes/body,
identity context, deployment/receiver profiles, healthy current clock and separate
opening/current snapshots. It reuses the same directional federation projector
and the existing published root-lineage sponsorship count predicate. The Source
authenticates actual home ownership and complete capital inventories, actual
agreement/admission versions and registry/witness facts, ordinary sponsor
prerequisites, all opening breach zones and their published policies, bond anchors,
withdrawal and severance. This is a semantic adapter contract, not a new wire.

Opening eligibility requires the actual original home base, enough available
home capital before the new stake, receiving/home records, an agreement providing
for sponsorship and an admissible receiver-measured sponsor. The named exact
reference requires the original home base to be exportable; it does not infer or
re-export an imported portion of home standing. Every supplied breach-zone count
must pass its actual published policy, including prior blocking state.

Current credit requires the same origin agreement/admission, current records,
admissibility and sufficient backing, and ends at the earliest bond/origin
agreement/severance end. Its root sponsor basis cannot exceed either the actual
opening receiver measure or the current one. Both use the lesser of actual home
standing and attested exportable standing, preventing an older higher attestation
from increasing the bond's basis. The collateral half is accounting and is never
used as the subject's E_base. A derived end closes the active capital charge while
retaining the ancestral floor. An unrelated current agreement cannot rewrite
opening history or the original termination bound.

The sealed assessment distinguishes `.opening_valid` from `.active`, retains
independently earned intrinsic standing and current home capital, and binds the
derived state as well as source facts in its semantic frame. Crossing an end
changes that frame even if only the clock was refreshed. Ending current credit
does not invalidate a properly established opening, erase earned standing or
release residual liability. Actual root, total-standing and genesis composition
remain next integration work: genesis must match the bond and precede `ends_at`,
and active sponsorship must ceiling total receiver standing at sponsor measure.

Draft reconciliation remains at the maturity boundary: federation FD27 caps
`earnedInB: 80` at sponsor measure 72, while Identity Sections 6.4/8.2 close active
capital at intrinsic E_base 80. The vector does not define whether that earned
field is the same intrinsic quantity. This helper treats its explicitly named
intrinsic input according to Identity closure and does not claim FD27 is resolved.

Cross-zone sponsorship now composes through root credit, total standing and
genesis. `AuthenticatedRootInstrument.issuer_zone` is required for sponsorship:
the installed authority must bind the home responsible for this exact instrument
to its actual signing issuer/registry, never copy a candidate's zone claim.
Unknown home gives no sponsorship credit. A known foreign home requires the
selected `InstalledRootVerifier.federated_sponsorship_verifier`, matching policy,
home/receiver and complete authenticated body. The root retains raw signed inputs
while using the receiver-measured basis for its exact score and the earlier
effective end. The liability taper never becomes a root composition input.

Current root verification supplies the receiving zone from its independently
installed expected zone when absent and rejects a conflicting explicit context.
Inventory and candidate sources receive those normalized context bytes, so their
scope/digest/caching must use that exact context. Foreign candidates without the
applicable policy are ineligible before strongest-single selection; a stronger
unaccepted foreign bond cannot displace a valid local alternative.

The selected root profile declares `root_binding: credit-digest-ceiling-v1`.
Native standing adds the reserved `federated_sponsor` total-standing ceiling and
one `federated_sponsor_credit.<digest>` ceiling carrying the same bound. The digest
uses canonical exact root basis, deployment/profile, complete bond identity,
parties/zones and effective end. It binds current credit without inventing a
local contribution or double-applying a factor. These are further-declared
ceilings under a named provisional Library profile, not RFC-standard new wire
fields. Providers cannot replace either convention. Proof binding rejects stale,
duplicate or unselected markers, even if an unrelated tighter cap would conceal
a changed root contribution. Unrelated capital changes need not alter an unchanged
credit identity, but current eligibility and support still require revalidation.

Whole standing is bounded at the receiver's sponsor measure in addition to every
ordinary ceiling. An integration fixture makes sponsor measure 18 bind below the
generation ceiling of 25. A fresh Ed25519 proof passes all eight verification
stages with selected foreign support and fails current verification after that
support is withdrawn within the proof lifetime. Expiry remains bounded by the
supporting assessment and effective bond end.

`InstalledTrajectoryVerifier.federated_sponsorship_verifier` has a symmetric
`federated_sponsorship_profile_digest` selection and retains
`.genesis_federated_sponsorship`. Genesis or a first successor's genesis predecessor
must match the actual bond, historical opening, receiving zone and birth time
inside both the signed interval and `ends_at`. Current activity is not required
to establish an otherwise valid historical birth. Signed trajectory tests accept
an expired-today bond valid at birth, reject birth at its effective end and retain
the same restriction through the predecessor path. This creates no genesis record
and does not supply durable capital reservation or operational penalty enforcement.

### Federation record delivery

`InstalledFederationRecordVerifier` selects the private
`reached-subject-exposure-and-anchor-notification-v1` profile. Its installed Source
authenticates the exact record digest, subject, origin, current registry/witness
facts, signed bilateral agreements, complete reached-subject inventory and prior
breach deliveries. Coverage includes standing admitted under the agreement, a
bond held or previously opened there, or an admitted attestation. Breach and
for-cause withdrawal produce mandatory exposure destinations, never foreign
closure. An unenforced sovereignty constraint retains a blocked obligation.

Anchoring notifications instead use actual prior breach delivery, bound to the
subject, breach anchor, origin, signed agreement digest and delivery time. This
reference selects the exact same signed agreement terms; amended-term migration
is unsupported. Delayed delivery after local reconciliation still requires the
notification. Its generated `plan.notification_payload` contains exactly the
breach and reconciliation anchors. It is not a reconciliation record and never
closes receiver exposure, including for persons. Veto, delta and personal
reconciliation records have no route. Positive attestations remain a separate
selected import path; agent reconciliation-body delivery is not implemented.

The assessment retains raw record/Source evidence internally for verification;
these fields are not delivery payloads. Exposure routing does not invent or strip
an RFC exposure wire record: Service must deliver the authenticated exposure
record under the selected protocol, preserve constraints and perform local review.
No messages are sent, standing changed or delivery completion asserted. Complete
deployment composition and production authenticated delivery adapters remain.

### Execution observation

`InstalledExecutionObservationVerifier` selects the private
`decision-bound-boundary-observation-v1` profile and the zone's declared
enforcement level. Source authenticates the complete historical decision and
actual boundary observation records, their semantics and authority, actual route
enforcement and authoritative absence. A failed lookup must raise unavailability,
never manufacture `decision=None` or `observation=None` as authenticated absence.
Library checks exact original record digests, whole operation (including parameters,
request identity and replay domain), actor, zone, topology epoch, decision identity
and time. Wrong-scope/binding observations are retained as evidence but supply no
execution claim; missing observations remain `unverified`.

Bound dispatch after any denial, including an independent gate denial with stable
environmental supervision, returns a bypass with conformance-failure and breach
record obligations. Authenticated absent decision plus observed dispatch on a
route with no enforcement point is also a bypass, even if the observation
references a nonexistent decision. Bound `non_dispatch` means `not-executed`
even after a permit. Here `executed` is the EO contract's dispatch vocabulary;
it does not confirm the downstream effect in optional proposal #139.

All three retained EO source cases are exercised along with scope, substitution,
clock, historical-byte and independent-gate cases. The installed tests model
Source authority, not an actual production execution boundary. No failure or
breach is persisted by the library; Service must record/open and enforce it.
This post-decision classifier supplies no authorization and does not renew or
extend the original proof. Full deployment selection and production boundary
adapters remain separate release requirements.

### Importance and supplied normative demand

`InstalledNormativeDemandVerifier` selects a private
`maximum-whole-action-demand-v1` declaration naming each importance/supplied-input
authority and one pinned external Draft 2020-12 schema. Source authenticates a
complete current inventory of actual signed judgments, whole-action demand
calibration and actor/operation/grant/evidence/zone/topology scope. Library checks
declarations, schema, complete inventory, exact scope and validity, then takes
`max(pre_normative_demand, each supplied whole-action demand)`. Lower proposed
demands cannot lower the baseline. It neither sums judgments nor changes risk,
standing, effective trust, grants or executable ceilings. Missing required input
prevents classification instead of synthesizing a favorable default.

`InstalledDemandClassifier.normative_demand_verifier` requires a symmetric
`normative_input_profile_digest` in the classifier declaration, and an explicitly
healthy clock. `NativeCoreContext.normative_demand_profile_bytes` binds the policy
through Core; `.pre_normative_demand` and `.normative` retain the original demand
and assessment. Claims cannot outlive the supporting judgments. Geometry selects
`normative_demand_profile_digest` and records the modeled `normative_demand` term
with raw Source evidence, external schema, policy and semantic frame. Exact
enclosure/boundary topology must agree where selected. Prior/Soul vetoes and the
existing supervision own-increment/release rules continue to restrict independently.

The native current-use facade selects both `.normative_demand_verifier` and
`.normative_classifier_profile_bytes`. It refreshes actual Source evidence,
requires the exact current classifier/profile/frame/model and topology, rejects
increased demand and caps expiry. A carried normative term without an installed
policy is rejected. The trusted invocation adapter must still independently
reconstruct current demand under the declared classifier; requester-supplied A
is never that reconstruction. Complete deployment/API policy selection remains
pending, so this component selection is not a deployment conformance claim.

Schema resolution is closed to the pinned installed schema and its local
references. HTTP/file/uninstalled references cannot retrieve content and fail
with validation error. Content adequacy, judgment legitimacy, actual signatures
and calibration remain external responsibilities. Real signed producer/current-use
fixtures exercise the binding with modeled Source facts; the entire 23-case L11
suite and production normative-adapter interoperability are not claimed here.
