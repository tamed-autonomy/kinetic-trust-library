# Kinetic Trust Core: Clean-Room Architecture

> **Historical record — superseded for current integration (2026-10-09).**
> The current Library v2.1.0 architecture and
> [Library naming ADR](../adr/0002-library-service-naming.md) govern current
> names, specification scope, and interfaces. All text below preserves the
> historical v2.0.0 decisions, not maintained integration instructions.
> The old umbrella Core/package names and the single-result/derived-action
> assumptions below are historical only. Library `1.0.0` now profiles KTP
> `v2.1.0` at `15520035267546e1035aad7beea0cc3cf9ef8f2c`.
> One evaluation returns separate Core capacity and Envelope facts: equality is
> `AT_CAPACITY`/within and zero-margin `SILENT_VETO`; Soul short paths leave
> Core capacity unevaluated. Products own sensing, storage, keys, transport,
> failure handling, retries, human interaction, action, and enforcement.
>
> **Cancellation supersession (2026-10-17).** The current native-cancellation
> contract supersedes the historical `OperationCancelledError` contract below. Read-only
> async waits and cancellation before signer dispatch propagate native
> `asyncio.CancelledError`; cancellation during unresolved dispatched signing
> remains `OutcomeUnknownError`. The historical body is preserved unchanged.


Status: Approved design

Date: 2026-08-20

Initial target: KTP 2.0 Core and Basic-enabling application APIs

Current status (2026-09-15): The historical domain and interface decisions in
this document remain the KTP design record. Its former custom release-foundation
expectations are superseded by the simplified Library blueprint reflected in
the current [project terminology](../../CONTEXT.md).
Current release work is an ordinary single build and install smoke test; it does
not establish application conformance.

Current evidence/issuance boundary (2026-10-07): the maintained
[Library contract matrix](../traceability/library-contracts.md) supersedes
earlier record-writer orchestration and loose proof-time contracts.
Core supplies deterministic record data and proof semantics; Service supplies
replaceable synchronous composition; products own infrastructure and action.

## 1. Purpose

`kinetic-trust-core` is a production-useful Python library implementing the
deterministic Core of Kinetic Trust Protocol 2.0. It gives applications the
validated values, calculations, decision data, and implemented Trust Proof
operations needed to build a KTP system. Core is the RFC-faithful deterministic
reference library within its declared scope. Its focused `core.record` module
projects validated evaluations into immutable project-owned `DecisionRecord`
values; Service, not Core, owns evaluation-to-proof composition.

The library is not a product. It does not enforce decisions, intercept
requests, choose storage, operate a server, communicate with humans, or make
operational policy choices.

An application may become KTP Basic compliant by combining the library with
application-owned enforcement, durable recording, keys, evidence, and
operations, then demonstrating those behaviors through the conformance
harness. The library itself will not claim Basic application conformance.

## 2. Normative and Clean-Room Boundary

The sole normative source for the initial design and implementation is:

- Repository: <https://github.com/nmcitra/ktp-rfc>
- Tag: `v2.0.0`
- Resolved commit: `87474b759bbb0ec836330a889db6f6d88dfc35aa`

The initial design and implementation must not consult either:

- the previous Python implementation of KTP 1.x; or
- the Go implementation of KTP 2.0.

The older implementations are neither compatibility targets nor design
authorities. No KTP 1.x compatibility layer will be added.

After the Python architecture and initial implementation have been completed
and frozen for independent review, findings discovered during the Go project
may be used only as an adversarial audit checklist. That audit may reveal gaps
in the Python implementation, but it must not retroactively become the source
of the clean-room design.

Every normative requirement implemented by the library will be traceable to
the pinned RFC text, schema, or conformance artifact. Interpretive decisions
will be recorded explicitly rather than silently attributed to the RFC.

## 3. Product Boundary

### 3.1 Library responsibilities

The implemented Core and Trust Proof runtime own:

- strict validation of all KTP declarations;
- immutable, library-owned validated values and snapshots;
- full `E_base` composition, Proof-of-Resilience calculation, and applicable
  ceilings;
- Risk Factor normalization and aggregation;
- Node, Neighborhood, and Global risk-domain aggregation;
- the independent Soul veto;
- `E_trust` and trust-tier calculation;
- Zeroth Law and action-demand evaluation;
- Trust Proof construction, signing orchestration, parsing, and verification;
- typed results and typed operational failures;
- fail-closed behavior;
- proof timing and deterministic project-owned decision-record projection;
- bounded internal cleanup.

Service owns direct synchronous adapter invocation and evaluation-to-proof
composition. Its evidence seam carries complete `ObservationDeclaration` values
without semantic transformation. Direct adapter injection, fail-first calls,
and closed typed issuer outcomes are replaceable Service conventions, not RFC
semantics. Core remains usable directly without Service.

Any application conformance harness is product-owned and is not a future
responsibility of this Core library.

### 3.2 Application responsibilities

The consuming application owns:

- enforcement and every Policy Enforcement Point;
- identification of protected actions and complete interception coverage;
- databases, files, queues, retention jobs, and query infrastructure;
- sensor and evidence acquisition;
- key generation, custody, rotation, revocation, KMS, and HSM integration;
- networks, servers, endpoints, authentication, and transport;
- retry, fallback, reconciliation, compensation, and restart policies;
- observability, alerts, metrics, and operational response;
- configuration and deployment policy selection;
- credentials and source authenticity/completeness;
- protected-action execution; and
- every human or organizational workflow.

Human identity, accountability, exposure, consent, and sovereignty may appear
only as data supplied through application-owned APIs. The library has no
direct human interaction.

### 3.3 Explicit non-features

The runtime package will not contain:

- an `Enforcer` or PEP implementation;
- HTTP middleware or status-code mapping;
- a web server, daemon, sidecar, or background service;
- a database or persistence implementation;
- automatic retry, failover, replay, or restart;
- an approval queue, operator console, or UI;
- bundled product configuration; or
- a protected-action executor.

## 4. Architectural Shape

The supported public interface has four layers:

1. The eight-name package facade exports only `DeploymentProfile`,
   `EvaluationBundle`, `EvaluationRequest`, `KTPError`, `RejectedRequest`,
   `ValidatedActionDemand`, `ValidationError`, and `__version__`.
2. The deep Core and proof facades keep ordinary use small. The
   `kinetic_trust_core.core` aggregate exports only `evaluate`; the
   `kinetic_trust_core.proofs` facade exports only `AsyncTrustProofs` and
   `TrustProofs`.
3. Supported focused advanced modules own the larger value and stage surfaces.
   The supported focused model modules are `action`, `envelope`, `evidence`,
   `profile`, `proof`, `record`, `risk`, `soul`, `standing`, and `trust`.
   The supported focused Core modules are `evaluate`, `evidence`, `por`, `standing`, `soul`,
   `risk`, `trust`, `envelope`, and `record`. `kinetic_trust_core.protocols`,
   `kinetic_trust_core.errors`, and the optional
   `kinetic_trust_core.adapters.cryptography` module are also supported focused
   advanced interfaces. `kinetic_trust_core.models` and `kinetic_trust_core.adapters`
   are namespace-only aggregates; values are imported from focused modules.
4. Private implementation modules may change without public compatibility
   guarantees. In particular, `kinetic_trust_core.models._common` is private, as
   are the other underscore-prefixed implementation modules.

`models.proof.ProofIntent`, `models.record.DecisionRecord`, and
`core.record.build_decision_record` / `require_validated_decision_record` are
focused public interfaces, not root-facade exports. Service's synchronous
`Issuer` composes Core evaluation, record construction, and `TrustProofs` once
each on the eligible path. It is not a production runtime. The implemented
proof facades preserve native provider separation: `TrustProofs` is synchronous
and `AsyncTrustProofs` is natively asynchronous, with no hidden scheduling.

The proof authority has two distinct flows:

```text
complete non-vetoed EvaluationBundle
    -> TrustProofs / AsyncTrustProofs
    -> configured ProofSigner plus algorithm-bound SignatureVerifier
    -> ProofToken

raw token plus operation cutoff
    -> TrustProofs / AsyncTrustProofs
    -> VerificationKeySource plus algorithm-bound SignatureVerifier
    -> VerifiedTrustProof carrying authenticated claims only
```

The verification flow does not yield `EvaluationBundle`, `TrustSnapshot`, or
`KineticEnvelopeResult`. It authenticates only the claims carried in the
presented token. Enforcement begins only after the library returns and is
never a downstream library stage.

## 5. Full Core, Not a Basic Shortcut

The implementation will have one complete Core kernel. Basic, Standard, and
Full are not separate arithmetic implementations.

The initial release includes:

- the full published allocation of `E_base` terms;
- validated Proof-of-Resilience attestations and the published resilience
  calculation;
- an externally accountable root instrument;
- optional independent peer signals;
- all applicable declared ceilings;
- all six weighted Risk Factor inputs;
- all three risk domains;
- Soul as an independent veto;
- `E_trust` calculation;
- trust tiers;
- action demand and constraints; and
- Zeroth Law evaluation.

The RFC permits a simplified static `E_base` for Basic deployments. This
library intentionally does not implement that shortcut. Providers supply
validated declarations; they never inject a supposedly precomputed `E_base`,
`R`, or `E_trust`.

The initial release does not accept a caller-computed resilience contribution.
Applications supply attestations; the library validates their eligibility,
calculates the Resilience Score, and calculates the PoR contribution. External
acquisition, Oracle attestation issuance, and complete Agent trajectory-chain
verification remain application or later-level capabilities. They do not
transfer ownership of PoR arithmetic to the application.

The tagged specification requires a `standing_decay_rate` declaration in PoR
points per year but supplies no decay equation or inactivity anchor. The
library validates and preserves the declaration but does not apply decay to an
authoritative score until a normative formula is published or a separately
approved implementation profile defines one. It does not claim standing-decay
support.

The tagged PoR attestation has a timestamp but no validity horizon or expiry
field. The library rejects attestations dated after the operation cutoff but
does not invent age-based expiry or apply standing decay. Applications and
providers own historical retention and selection until a normative validity
profile is supplied. `calculate_por` accepts only a finite built-in list or
tuple so an unbounded producer cannot hold the pure calculation open; it places
no fixed library quota on that finite history. Root-instrument expiry remains
separate and is applied exactly from the instrument's declared end time.

Sponsored standing never accepts a sponsor trust scalar. A sponsorship root
owns a structurally revalidated Guarantor `StandingSnapshot` under the same
profile and exact operation cutoff. The library checks the sponsor's canonical
Agent identity, Guarantor phase, IAL sponsorship eligibility, subject/sponsor
identifier link, selected external-root chain, and stake limit, then derives
the sponsor term from that snapshot's `base_trust`. This reference is finite:
only a Sponsored subject consumes it, while the sponsor must already be a
Guarantor and therefore uses an external attestation rather than a further
sponsorship snapshot. Canonical standing data binds the sponsor by its guarded
snapshot digest, profile digest, exact cutoff, identity, lineage, and derived
base trust; it does not recursively serialize private profile internals.
For the Identity v2 colon-delimited form
`agent:sponsored:<sponsor_id>:<agent_name>:<unique_id>`, this implementation
defines `<sponsor_id>` as exactly the final `<unique_id>` segment of the
referenced canonical
`agent:guarantor:<N>gen:<name>:<unique_id>` identity. A full colon-containing
Agent identifier cannot be embedded unescaped in that segment, and the
human-readable Guarantor name is never accepted as an alias. The root attestor
still binds the complete canonical Guarantor Agent identifier.

The adversity ceiling is derived from eligible validated PoR facts, not a
consumer boolean. The PoR `friction` field is the environmental `R` recorded by
the Oracle, and the validated `friction_category` identifies Crisis. With
strict published thresholds, no eligible `R > 0.5` evidence caps at 60; no
eligible `R > 0.7` evidence caps at 80; no eligible Crisis evidence caps at 90;
and a qualifying Crisis attestation lifts this ceiling to 100. Other applicable
ceilings still compose by exact minimum.

External-root lifecycle status is derived as well. Consumers supply one typed
issuance, at most one typed withdrawal claim, and at most one typed
adjudication finding. The library checks ordering, declarant, the
profile-declared distinct adjudicator, and the exact cutoff. The declared end
time is the first expired instant. Without-cause withdrawal is non-renewable
until that instant; for-cause withdrawal is zero immediately; and an
unadjudicated for-cause claim becomes the preserved unresolved state only at
expiry. The application supplies and authenticates these facts but cannot
assert the resulting state label. A claim-less direct `MISATTESTATION` finding
may follow a separate without-cause withdrawal before expiry and immediately
zeros the instrument while preserving both facts. It cannot link that claim,
precede it, or accompany a for-cause withdrawal; a rejected for-cause claim
uses the distinct `FOR_CAUSE_REJECTED` finding outcome.

The accountability terminator is a typed legal-entity, named-human, or
physical-presence declaration and cannot use the Agent namespace. Peer standing
is a typed score/source/evidence declaration. Exact represented references are
set-compared against every PoR and root identifier, transaction, Oracle,
verification reference, chain hop, terminator, lifecycle provenance fact,
applicable built-in or additional ceiling name and provenance identifier, and
every represented fact reachable through a sponsor standing reference. The
reference closure includes the subject PoR digest and the sponsor Agent,
standing digest, PoR digest, profile digest, public applicable ceilings, and
raw represented declarations. It does not depend on the subject's not-yet-
available final standing digest. This proves represented non-overlap only;
semantic independence, authenticity, and completeness remain
provider/application responsibilities.

Peer evidence IDs and peer provenance references each have a 2,048-item
per-call implementation-safety maximum. These bounds stop hostile oversized
provenance inventories and are not product quotas, retention limits, or KTP
normative maxima. Validation uses linear set traversal. Root lifecycle has
fixed typed cardinality, and the accountability chain retains the normative
deployment hop bound, which cannot exceed 12. Standing validates the effective
high-fan-out profile exactly once per public prepare or require boundary and
passes that validated value through internal derivation and sponsor checks.
Sponsor snapshot traversal first checks exact type, Guarantor phase,
generation, canonical identity, and absence of further sponsorship before it
descends. Each public operation owns an active-path identity set plus a
completed-snapshot identity memo that retains strong object references; cycles
reject and duplicated public/private references structurally visit each
distinct snapshot once. There is no process-global registry. The normative
Guarantor base limits sponsorship to one referenced snapshot, and traversal is
linear in distinct represented snapshots and their represented facts.

## 6. Declaration and Validation Boundary

Every value originating outside the library is untrusted.

Consumer APIs return declaration types. The library validates those
declarations and creates immutable owned values. Validation includes, as
applicable:

- exact identifiers and version relationships;
- valid Unicode and rejection of invalid UTF-8 representations;
- finite, bounded numeric values;
- UTC and lossless timestamp handling;
- freshness, validity intervals, and cutoff ordering;
- complete provenance;
- duplicate and conflict detection;
- external-root chain termination and hop bounds;
- root status, exposure, capacity, and revocation facts;
- peer-share independence and bounds;
- complete, unique ceilings;
- factor normalization and direction;
- required inputs and undefined-input handling; and
- profile, evidence, standing, proof, and action coherence.

Each orchestration operation captures one clock value and uses that value as
its cutoff throughout the operation. Later stages consume validated snapshots
and do not call providers again for the same fact.

Generic dictionaries cannot carry authoritative KTP facts. Optional extension
metadata must be namespaced, bounded, canonicalizable, and explicitly
non-authoritative.

The validated deployment profile is also the complete deterministic evidence
contract. It binds each application source ID to exact `(domain, signal, unit)`
routes plus a positive feed weight, resolves each feed's refresh and stale
threshold, declares every populated duplicate-alias choice, and supplies
exactly one typed normalization or categorical label-to-stress mapping for
every aggregated signal. Numeric
normalization is limited to explicit identity-on-declared-0-1 and min/max
methods; unsupported methods fail closed rather than carrying an opaque
parameter bag. Weighted-average aggregation accepts only a complete positive
per-signal weight map; maximum and minimum accept no parameters. These are
implementation-profile constraints needed to make the RFC's declaration sites
executable, not additional product infrastructure. Both identity and min/max
normalizations declare whether the resulting scale is inverted so every output
has the required stress direction.

The identity declaration is a typed no-rescale marker, not a new formula. It
is valid for each catalogue-declared bare-`0-1` sort: ratio, synthetic, and
fully determined. In particular, a fully determined value such as HHI is not
subjected to a second invented min/max formula; the declaration records only
identity and the explicit stress-direction choice.

Feed durations are bounded as an implementation safety profile because the
tagged sensor schema supplies minimums but no maximums. A polled refresh
interval is at most 366 days, and a resolved stale threshold is at most five
times that value (1,830 days). The first bound admits annual published sources;
the second preserves the RFC's default `5 * refresh` relationship. These are
not normative KTP limits. They keep every accepted duration finite,
operationally bounded, and safely representable by ordinary UTC/timedelta
arithmetic.

Evidence declarations carry a typed observation class and the complete
class-specific measurement envelope. The five explicit envelope variants are
Direct, Enumerated, Adjudicated, Published, and Derived State; there is no
generic authoritative attributes mapping. The declaration is the immutable
library adapter value, not a transport-wire requirement. Validation exact-
matches its class to the pinned catalogue and checks every required or `n/a`
slot, including windows, population state, instrument/calibration or criteria
provenance, publication period/vintage/lag, and derived-state validity.

Raw readings also exact-match the catalogue scalar family. Integer signals
retain exact built-in integers and reject booleans, subclasses, fractional
Decimals, and conversions; float and duration signals normalize from exact
decimal inputs without accepting binary floating point; boolean signals retain
exact booleans; enum and string signals retain exact built-in strings. Scalar
families without a deterministic Core normalization fail closed. Observation
sequences are exact nonnegative built-in integers bounded to signed 64-bit
maximum, and every authoritative timestamp is an owned exact built-in UTC
`datetime` rather than a user-controlled subclass.

Evidence preparation has two deterministic implementation-safety bounds: at
most 2,048 declarations may be supplied in one call, and at most 64 validated,
non-future candidates may be retained for one source/domain/signal feed route.
The total admits one declaration for each of the pinned catalogue's 1,644
signals with roughly 24 percent headroom. Iteration is bounded while values are
pulled, so an infinite iterable terminates with a validation error at item
2,049; the per-route limit is enforced while declarations are validated.
Structural snapshot validation rechecks both inventories. These limits are not
normative KTP limits or product retry, rate, storage, or retention policy.

Configured profile scale is different from untrusted per-call evidence. The
library imposes no fixed maximum on validated feed routes or their corresponding
snapshot outcomes; products own configuration-scale and quota decisions,
including legitimate redundant feeds. At each preparation or structural-
validation boundary the library validates the effective profile once, then
builds one private immutable index keyed by `(domain, signal, source)` with an
ordered pair-to-routes view. Route resolution, normalization, weighting,
outcome construction, and structural revalidation use that index without
calling public profile accessors in inner loops. Authoritative profile mappings
require their permitted exact built-in string or enum key type and use
hash-based duplicate tracking. User-controlled string subclasses are rejected,
never coerced. Ordinary exceptions from external mapping iterator creation,
advancement, or lookup become controlled validation errors without intercepting
process-control signals or internal validation failures. The traversal portion
is `O(F + R + D)` for configured
feeds, configured routes, and bounded declarations. Deterministic key sorting,
canonical encoding, and cryptographic hashing add their ordinary input-
dependent costs, so the library does not claim that the complete operation is
mathematically linear. In particular, no pairwise `F²` duplicate-key scan or
route rescan remains.

Each evidence entry retains one ordered outcome for every configured feed.
Every outcome owns the complete canonical inventory represented by the
validated, non-future declarations supplied for that feed route in the current
bounded preparation call. The inventory uses a typed
`EvaluatedObservation` whose source/domain/signal/unit are inherited from the
containing profile-bound route rather than repeated. A selected outcome owns
its complete selected observation; an undefined outcome names its source and
distinguishes no eligible observation, expiry, staleness, source
unavailability, and an empty window. Each outcome digest binds its state,
route, candidate inventory, and selected result, and the snapshot digest binds
the complete ordered outcome inventory. Structural validation reruns expiry,
freshness, deterministic selection, and missingness from those facts instead
of trusting the state label. Invalid declarations, including malformed cached
declarations ingested after cutoff, reject snapshot preparation and never
become benign absence; only a fully valid future-cached declaration is excluded
before duplicate/conflict checks. Signal-level undefined reason is a
deterministic summary only; downstream calculations and records use the
complete feed outcomes to reconstruct active and undefined inputs exactly.
Missing-source identity occurs once in each canonical feed outcome.
When no feed is selected, the convenience signal summary uses the fixed order
stale, expired, unavailable, empty, then no eligible observation; this summary
never replaces the lossless per-feed outcomes.

`EvidenceSnapshot` retains its exact immutable validated profile binding in
addition to the public profile reference and digest. Its accessors structurally
revalidate the complete represented snapshot: exact nested types and
primitives, profile inventory and routes, feed outcomes,
class/envelope/unit/time/value/normalization invariants, observation provenance
digests, result arithmetic, safety bounds, and final canonical digest.
Constructor privacy or the class name alone never bypasses those coherence
checks; exact immutable copies may revalidate.

This boundary proves internal coherence of the represented inventory only.
`prepare_evidence` validates and derives from the complete bounded iterable
actually supplied in that call. It cannot prove that a provider supplied every
real-world observation or authenticate a source. Pure-Python private names,
constructor guards, and public self-hashes are not unforgeable against hostile
same-process code: a caller can omit or replace evidence and construct a
coherent new history with recomputed digests. That behavior is outside the
library guarantee. Provider/application APIs own evidence completeness and
source authenticity, just as they own on-demand liveness. Downstream Core uses
the in-process result of `prepare_evidence`; a reconstructed or coherently
resealed snapshot demonstrates coherence only, not transferable external
authority. The library adds no secret token, process-global registry,
authenticated external commitment, or storage mechanism to pretend otherwise.

Eligibility and currentness are determined per declaration before choosing the
deterministic maximum `(observed_at, sequence, observation_id)`. Therefore a
newer-acquired but stale Published declaration, or a newer expired Derived
State declaration, cannot suppress an older declaration that remains current.
When no current declaration remains, the complete retained inventory preserves
the facts used to derive stale or expired status.

Published freshness includes the normative publication lag. The declaration
must satisfy `publication_lag_ms == published_at - reference_period.end` in
exact milliseconds, and its age at an evaluation cutoff is
`cutoff - reference_period.end`. Publication, fetch, and ingestion never reset
that age.

An on-demand feed declaration binds the current evidence-preparation operation
ID and query cutoff. The library rejects a missing or mismatched binding and a
declaration routed as cached evidence. This checks declared coherence only:
because the provider/application supplies the response and binding, their
equality cannot prove that a live external query occurred or that a response
was not reused. The provider/application owns current acquisition and
non-reuse. The library adds no stateful registry, cache, retry, or product
workflow and makes no real-world freshness claim from caller-supplied IDs.

Validated capabilities are immutable snapshots bound to the exact profile and
cutoff. Every retained action class must exist in that profile and share the
complete declared constraint envelope. Envelope identity includes every
`(magnitude name, unit)` pair, not only magnitude names; applications that need
unlike envelopes provide separate capability declarations.

Constraint magnitudes and engineering units have distinct exact validators;
the generic lowercase KTP identifier grammar is not widened. Magnitudes retain
case and admit the published names and bounded colon namespaces such as
`joint:elbow:maxPositionRad`. Units retain their exact NFC spelling and admit
the published `m/s`, `N`, `N·m`, `m/s³`, `rad/s`, `m`, and `rad` forms under a
bounded engineering-unit grammar. Profile policy, capability ceiling, grant,
request, and derived-envelope revalidation all apply the same name semantics.

Each action policy also owns an ordered typed normative-gate inventory. Every
gate declares an identifier, exact bounded RFC 3986 absolute schema URI, and
whether absence is required-fail-closed or optional. A supplied token must
match that exact gate and schema and carries a typed clear/veto/undetermined
decision, absolute authority URI, exact current cutoff, and provenance ID.
Unknown and duplicate gates, schema mismatch, invalid authority, and noncurrent
tokens are invalid declarations. Missing required, veto, and undetermined
states constrain only the envelope after trust is derived; they never rewrite
`R`, `E_base`, or `E_trust`. Every declared gate has a typed carried outcome,
including explicit missing state. Required missing and undetermined outcomes
also enter the undefined-input inventory with provenance. A prior Soul veto
still stops all later authority, leaving gate outcomes, capacity, margin, and
tier explicitly unevaluated.

Soul assessment consumes one current, action-specific response for every
framework in the validated profile. Each supplied response exact-binds the
profile reference and digest, validated action identifier and digest, and the
operation cutoff. Its query cutoff and observed time must equal that cutoff;
an older clearance is invalid because Soul has no cache or staleness window.
These caller/provider-supplied values prove represented coherence only. They
cannot prove that a registry was actually queried, that the response is
authentic, or that the provider supplied every applicable framework.

The result retains one ordered outcome for every configured framework. A real
veto carries a typed schema constraint category, bounded constraint identifier,
strict bounded RFC 3986 absolute authority URI, and response provenance. The
URI boundary requires an exact built-in ASCII string, valid percent encoding,
and syntactically valid network authority, host, and port where present; raw
Unicode must be percent encoded. IPvFuture's version flag is validated
case-insensitively without changing the retained URI bytes or case. Legitimate
non-network absolute forms such as `urn:` and `did:` remain valid. A missing
response or an explicit unreachable, error, timeout, or empty response becomes
an `undetermined` outcome with no invented constraint or authority. All such
failure classes have identical decision force even though their disclosure-safe
class and provenance remain available for recording. A real veto takes result
state precedence over undetermined, while both yield
`SOVEREIGNTY_CONSTRAINT`; only an all-clear inventory is non-vetoed.

Response iteration is bounded by the validated configured-framework count and
pulls at most one additional item to detect overflow or an infinite producer.
Framework lookup and duplicate detection are linear. The library does not add
a hard configuration-size quota: products own profile scale, while an exact
one-response-per-configured-framework inventory bounds each assessment. The
immutable assessment is digest-bound and structurally rederived from its owned
profile, action, cutoff, and normalized represented responses. As with evidence
snapshots, this is same-process coherence rather than external authentication.
Profile, action, and Soul authoritative identifier collections require exact
built-in strings at initial construction and structural revalidation before
hashing, equality, lookup, or coercion. Profile-reference versions and the
external-root hop bound likewise require exact built-in integers before any
comparison or conversion. This prevents provider-defined primitive subclasses
from executing behavior inside the authority boundary.
The Core performs no registry call, retry, escalation, human interaction,
enforcement, storage, or operational recovery.

Risk and effective trust compose only already-validated values. Risk consumes
the exact profile, evidence snapshot, all-clear Soul assessment, action demand,
and operation cutoff. The action owns the typed external moment-criticality
value, supplier, unit, observation time, and provenance; risk has no second
moment argument that could disagree. The Deployment Profile owns one shared
declaration for the six Risk Factors. Each of the five signal-derived factors
declares one aggregation and one positive factor weight `beta_i`. Moment
Criticality declares one positive factor weight plus its action supplier and
unit contract and declares no Context Signals. Node, Neighborhood, and Global
scope observations and have separate positive domain weights `alpha_d`.

For signal factors, `c_i = sum_d(alpha_d * s[d,i])`; `c_m` is the single
action-owned Moment Criticality value. Authoritative Risk is calculated in
canonical factor order as `R = sum_i(beta_i * c_i)`. `R_d` values are retained
domain audit projections and are not reaggregated to produce `R`. All three
effective domain weights are explicit, positive, complete, exact-sum, and
digest-bound. Weighted averages renormalize over active declared inputs.
Maximum and minimum ignore undefined inputs while any remain active. An empty
active set is stress 1, never zero. Factor results retain ordered signal inputs,
selected observation digests, every feed-outcome digest, and undefined reasons;
the external factor retains the complete validated moment value.

Risk revalidation treats that retained moment as an untrusted nested boundary,
not as safe merely because its outer dataclass is exact. Before equality,
hashing, or canonical projection, it requires the exact built-in Decimal,
string, and datetime primitives, the fixed Decimal bounds, canonical UTC
timezone representation, valid supplier/unit/provenance identifiers, and exact
equality with the revalidated action-owned moment at the shared cutoff. Trust
and velocity inherit this revalidation, and their own represented timestamps
apply the same exact UTC boundary before timezone behavior can execute.
The same owned-UTC helper gates every action-side timestamp at both declaration
validation and represented-value revalidation: capability not-before,
not-after, and validation cutoff; the action cutoff; moment observation time;
and every normative-gate observation time. An exact datetime with a custom
zero-offset `tzinfo` is not library-owned UTC and is rejected without invoking
that object's timezone methods.

Effective trust consumes the standing snapshot that owns `E_base` and the risk
result that owns `R`; no public scalar arithmetic API accepts either term from
the caller. Profile, action, subject, Soul, and exact cutoff bindings must all
agree. The immutable trust snapshot derives `E_trust = E_base * (1-R)` and its
standard tier together. Optional velocity consumes two structurally validated
trust snapshots for the same subject, profile calibration, and action class,
with a strictly positive exact UTC interval. It is an informational derived
reading only and cannot change trust, supervision, or permission.

## 7. Provider Protocols

`kinetic_trust_core.protocols` is the one canonical declaration location for proof
provider contracts. Its proof families are exactly:

```python
ProofSigner
AsyncProofSigner
SignatureVerifier
AsyncSignatureVerifier
VerificationKeySource
AsyncVerificationKeySource
```

`ProofSigner` receives canonical signing bytes and exposes stable immutable
Oracle identity. `SignatureVerifier` is bound to one algorithm and performs
only primitive verification; it does not select algorithms or make KTP policy.
`VerificationKeySource` returns immutable backend-neutral key and lifecycle
facts rather than a trust decision. The three provider seams and their native
async peers carry only immutable neutral values and canonical bytes. PyCA key
objects do not cross them.

Each provider capability that an operation reaches is called exactly once;
validation that stops before a seam makes zero calls. The library does not
automatically retry, select a fallback, or restart a provider call. Protocol
implementations do not receive authority to replace Core calculations or proof
validation.

## 8. Results and Failures

The authoritative KTP evaluation value is an immutable Kinetic Envelope result
containing autonomy demand, environmental capacity, exact margin,
`capacity_known`, tighten-only constraints, supervision, rationale, tier, and
typed normative-gate outcomes plus undefined-input evidence. It is not an
Allowed/Denied enumeration. A decision verb and autonomous-permission predicate
are derived convenience readings and never replace the authoritative result.

`RejectedRequest` is a separate, non-authoritative result only for a
deterministic request-validation failure: for example, an invalid, expired,
revoked, malformed, or incoherent declaration represented in the request. It
contains a reason, failed stage, completed validation trace, and digest, but no
partial standing, evidence, risk, trust, tier, or envelope authority. An
operational or application exception is never converted into a
`RejectedRequest` or a fabricated KTP decision; it propagates to the product.

The pure evaluation request carries one already-validated action that owns its
capability. It does not repeat raw capability or action declarations. Soul
responses, and observations if evaluation reaches evidence, must be owned
replayable tuples so a returned bundle never depends on an exhausted one-shot
iterable; the underlying stage safety bounds still limit work. Evaluation
structurally revalidates that authority before Soul, then uses one cutoff and
operation identifier through the ordered stages. A Soul veto ends authority
evaluation before standing or observation facts are inspected and before risk,
trust, or tier. The returned envelope keeps capacity, margin, and tier explicitly
absent on that path rather than inventing zero or a default.

Every evaluated envelope remains authoritative decision data. Only a derived
ALLOW or SHAPE reading indicates autonomous permission; a rejection or
exception carries no evaluation authority. The consuming product still decides
how to enforce the data and handle every operational failure.

`ProofToken` represents successful Restricted Issuer Profile v1 issuance.
`VerifiedTrustProof` represents only the authenticated claims carried by a
successfully verified presented proof. Neither value is a product enforcement
decision.

Invalid, malformed, expired, untrusted, or cryptographically invalid presented
proofs are typed invalid-proof failures. They are distinct from operational
inability to obtain a key or invoke a provider, and neither category is
converted into an evaluation result. The broader exception taxonomy will
distinguish at least:

- invalid library configuration;
- provider unavailable or provider failed;
- operation cancelled;
- external effect outcome unknown, including a dispatched signer call that has
  not returned a definite signature or definite failure.

The signer is called exactly once and is never retried. Cancellation or loss of
acknowledgement while awaiting that dispatched call is outcome-unknown unless
the signer reports definite non-acceptance or definite failure. Once an exact
signature returns, signer outcome is known; cancellation during issuance self-
verification is `OperationCancelledError` and releases no token. Products
choose all retry, response, reconciliation, logging, alerting, compensation,
and enforcement behavior.

## 9. Decision Records and Service Composition

Pure Core functions perform no I/O. `core.record.build_decision_record` projects
any structurally validated `EvaluationBundle`, including a Soul-veto or
undetermined short path, into `DecisionRecord`.
`require_validated_decision_record` structurally revalidates the projection.
`RejectedRequest` is not an evaluation and cannot produce a record.

The `ktp-python-decision-record-v1` projection is a non-normative project-owned
representation of RFC-defined evaluation results, not a new decision semantic.
KTP v2.0.0 defines no canonical Decision Geometry JSON schema. This value is not
the RFC Trajectory Chain transaction record. It preserves absent downstream
values on Soul short paths and carries public evaluation facts, profile binding,
undefined inputs, and deterministic digests without private replay state or raw
evidence. Its timestamp conservatively floors the evaluation cutoff to UTC
milliseconds; its evaluation digest still binds the exact unrounded cutoff.

The record is returned data. It asserts no persistence, transport, proof
issuance, acceptance, action, or enforcement. Its digest proves represented
coherence, not source authenticity, completeness, storage, or execution.
`DecisionRecord` and `ProofToken` remain separate artifacts correlated by the
evaluation operation ID / proof `decision_id`. Products ensure operation-ID
global uniqueness where required and own storage, retention, transport,
retries/reconciliation, observability, deployment, execution, and enforcement.

Service's `EvidenceHost` directly invokes injected adapters synchronously in
registration order and stops at the first failure. Adapters return complete
`ObservationDeclaration` tuples without host repair or inference. Service's
`Issuer` evaluates once: rejection returns no record or proof; a valid Soul
short path returns an evaluation and record without inspecting proof intent or
signer; a complete Soul-clear evaluation returns a separate record and proof
after Core issuance. Operational errors propagate without an invented outcome,
retry, or persistence claim. These composition choices are non-normative and
replaceable. Product configuration, credentials, and source authenticity and
completeness remain outside both libraries.

Proof is not permission: a complete Soul-clear evaluation may receive a proof
even when its envelope does not permit autonomous action. A proof attests
evaluated claims, not acceptance, execution, enforcement, storage, or persistence.
Verification-side relying-party evaluation and any `Decider` remain deferred;
authenticated proof claims do not reconstruct local Core authority.

## 10. Numeric Model

All authoritative calculations use `decimal.Decimal` under a fixed,
documented context.

API boundaries may accept integers, decimal strings, `Decimal`, and finite
Python floats. Floats are converted through their shortest decimal
representation. Booleans, NaN, infinities, malformed numbers, and out-of-range
values are rejected.

Risk, effective-trust, tier, and velocity composition do not expose new raw
numeric inputs. They consume exact `Decimal` terms already owned by validated
profile, evidence, action, standing, Soul, risk, and trust snapshots. Elapsed
seconds are derived from integer datetime days, seconds, and microseconds, not
from binary `total_seconds()`.

The authoritative action-demand scale is bounded to `[0, 100]`. Caller-supplied
Decimals retain the shared adjusted-exponent range `[-6143, 6144]`; that input
boundary is not widened. The internally derived margin has a separate closed
canonical boundary because `1 - A/E` over valid inputs can reach adjusted
exponent 6145 when `A=100` and the smallest positive canonical capacity is
`1E-6143`. At precision 34 its smallest positive nonzero value is `1E-34`.
Only the internal margin projection admits this derived range, structural
revalidation verifies the range and exact recomputation, and no value is
clamped.

The final comparison is exact. The tagged Core statement `A <= E` conflicts
with the normative Kinetic Envelope margin rule, which vetoes when
`margin <= 0`. This implementation follows the fail-closed envelope rule:
`A == E_trust` produces `silent_veto`. No epsilon may convert a denial into an
allow. Clamping and rounding occur only where the RFC or the documented
implementation profile explicitly requires them.

Canonical JSON emits normalized decimal numbers without binary floating-point
artifacts. JWT NumericDate claims use integer UTC seconds.

The RFC does not prescribe a complete numeric representation. The fixed
decimal context is therefore an explicit implementation-profile decision, not
a claim about unstated RFC text.

## 11. Trust Proof Cryptography

The proof module supports both:

- ES256 using P-256 and SHA-256; and
- Ed25519 using the JWT `EdDSA` algorithm identifier.

KTP JWT framing and validation are library-owned so permissive generic JWT
defaults cannot weaken KTP requirements. The initial Trust Proof profile uses
the Core header type `ktp+jwt`, the canonical `schemas/trust-proof.json`
payload shape plus stricter semantic checks, and a maximum `exp - iat` of 10
seconds. Both ES256 and Ed25519 are supported. Parsing and verification reject
duplicate members, alternate token types, stale abbreviated examples,
unknown authoritative claims, malformed or non-canonical encodings, invalid
algorithms, invalid keys, invalid signatures, invalid lifetimes, and
inconsistent KTP claims. Full-Core proofs require generation and binding to the
resilience evidence even where the schema marks those members optional.

The authenticated `resource`, `context_hash`, `trajectory_id`, and
`decision_id` members are an implementation-profile extension to the
unchanged, pinned KTP v2.0.0 RFC. They bind a proof to the decision for which it
was issued without changing the immutable RFC or claiming exact schema
conformance. Verification requires every member, so proofs issued by the older
unbound profile are rejected.

Restricted Issuer Profile v1 accepts a complete, non-vetoed `EvaluationBundle`
directly. The issuer derives from the signer identity; the subject and
canonical action digest derive from the validated evaluation, as does
`decision_id` from its operation ID. The caller supplies one immutable
`ProofIntent` containing `proof_id`, `resource`, `context_hash`, `trajectory_id`,
and `lifetime_seconds` (an exact integer from one through ten); it cannot
construct evaluation-derived claims or supply absolute proof times.
Claim construction is constructor-guarded inside the library. VETO and
UNDETERMINED bundles are rejected before any
proof-provider call. Issuance copies `evaluation.risk.context` and
`evaluation.risk.risk` directly rather than recalculating or accepting
caller-supplied substitutes. It sets
`resilience_hash = f"sha256:{evaluation.standing.por.digest}"`, adding the
wire-required prefix without changing the Core's lowercase 64-hex digest.

The exact nine-to-three proof-root projection is `CURRENT -> current`,
`NON_RENEWABLE -> non_renewable`, and `EXPIRED`, `FOR_CAUSE_PENDING`,
`FOR_CAUSE_SUSTAINED`, `FOR_CAUSE_REJECTED`, `FOR_CAUSE_UNRESOLVED`,
`MISATTESTATION`, and `NONE` -> `none`. Anything outside the closed nine-state
Core enum is rejected, not projected. The `none` projection omits root detail
fields. Core derives `issued_at` from the exact built-in whole-second UTC
evaluation cutoff. Requested expiration is that cutoff plus the intent lifetime;
effective expiration is the minimum of requested expiration and the conservative
whole-second floor of a current or non-renewable root end. A `none` root uses the
requested expiration. These become JWT `iat` and `exp` through integer
UTC-epoch arithmetic, satisfying `0 < exp - iat <= 10 seconds`. A non-positive
effective lifetime is rejected before provider access. Verification, after
authenticating the signature, rejects an active-root proof when `exp` exceeds the authenticated root end or
the verification cutoff is at or after that end.

Successful issuance makes exactly one `ProofSigner` call followed by exactly
one self-verification call through the configured algorithm-bound
`SignatureVerifier`. Verification obtains neutral key lifecycle facts from
exactly one `VerificationKeySource` call and makes exactly one call to that
primitive verifier. Its result has authority only for authenticated carried
claims; it cannot reconstruct same-process Core authority. The consuming
application must compare the authenticated subject, action, resource, context
hash, issue and expiry times, trajectory ID, and decision ID with the decision
it intends to rely on before taking action.

The three provider seams carry only immutable backend-neutral values and
canonical bytes. The standard-library base does not implement cryptographic
primitives. Local PyCA-backed ES256 and Ed25519 support is isolated in the
optional `kinetic_trust_core.adapters.cryptography` module; KMS/HSM and remote
providers implement the same neutral contracts. Key custody and lifecycle
remain application responsibilities.

## 12. Python and Dependency Policy

The tested support set is CPython 3.11 through 3.15. The implementation does not use
CPython-specific APIs or extensions.

The base package is Python 3.11+ standard-library-only and has zero mandatory
third-party runtime dependencies. The distribution remains a pure-Python
`py3-none-any` wheel. The project advertises only CPython 3.11 through 3.15
versions exercised by its routine CI matrix.

The clone-and-test path is intentionally small:

- runtime: Python 3.11+ standard library;
- functional tests: standard-library `unittest`;
- no pytest requirement; and
- no mandatory formatter, type checker, documentation generator, or property
  testing framework.

The one crypto extra is exactly
`cryptography = ["cryptography>=50.0.0,<51"]`. It is optional and belongs only
to the adapter lane. Contributor tools may exist in an optional development
group, but a developer can clone the repository and run the authoritative
base suite without installing them.

## 13. Tagged-v2 Conflict Resolutions

The `v2.0.0` tag contains mutually incompatible requirements. These explicit
project rulings make the implementation deterministic without representing a
project choice as uncontested RFC text:

- `moment_criticality` follows Core L14. It is a separately validated external
  action-context input with supplier identity, unit convention, value, and
  provenance. It MUST NOT claim a Context Signal subset. Consequently, the
  project pins but does not claim exact conformance to the contradictory
  deployment-profile schema.
- The Deployment Profile owns one shared six-factor declaration. Each of the
  five signal-derived factors declares one aggregation and one positive factor
  weight `beta_i`; action-owned `moment_criticality` declares its positive
  factor weight, supplier, and unit contract and no Context Signals. Feed routes
  scope observations to Node, Neighborhood, and Global, whose explicit,
  positive, complete, exact-sum, digest-bound weights are `alpha_d`. Signal
  context values are `c_i = sum_d(alpha_d * s[d,i])`; the moment context value
  is the single action-owned value; and authoritative `R = sum_i(beta_i * c_i)`
  is calculated in canonical factor order. `R_d` values are retained domain
  audit projections and are never reaggregated to produce `R`.
- Missing, stale, unanswered, or unusable evidence never becomes measured zero.
  Remaining valid feeds may be renormalized only when their declared
  aggregation remains computable; otherwise the factor becomes stress 1.0.
  `default_on_failure` cannot manufacture an authoritative observation.
- A current Independent or Guarantor root instrument requires positive anchored
  capacity. A malformed instrument is rejected; an explicit absence contributes
  zero.
- PoR eligibility requires friction `R > 0.3`; equality earns no resilience
  credit.
- Undefined states and their provenance remain present in the evaluation and
  decision record.

These rulings and the requirements ledger travel with every implementation
plan. Upstream corrections may replace a ruling only through a reviewed design
change and versioned compatibility decision.

## 14. Conformance Position

The library will not claim Basic application conformance.

It will publish a requirement matrix distinguishing:

- RFC behavior implemented and tested by the library;
- behavior exposed through an application-owned protocol;
- behavior that only an assembled application can satisfy; and
- deferred Standard/Full behavior.

An adapter-driven Basic application conformance harness will live outside the
runtime package. It supplies tests, not storage or enforcement. Applications
provide their own adapters so the harness can test observable proof exchange,
denial, expiration, refresh, recording, retention queries, interoperability,
and failure behavior.

The harness cannot prove that an application intercepts every protected
operation. Enforcement coverage remains an application assertion backed by
application-specific tests.

## 15. Testing Strategy

Implementation will proceed test-first in separate dependency lanes. The
authoritative base lane installs no optional dependencies, uses only
standard-library `unittest`, and includes a guarded import check proving that
base imports do not attempt to import `cryptography`.

The optional-adapter lane installs the exact `cryptography` extra and
runs adapter, interoperability, and backend acceptance tests separately. An
authoritative optional-crypto job must fail if its extra or adapter cannot be
loaded; hidden skips are forbidden.

Coverage across the applicable lanes will include:

- RFC examples and pinned schemas;
- exact positive and negative Trust Proof vectors;
- all arithmetic boundaries and undefined states;
- immutable ownership and mutation attempts;
- duplicate, malformed, oversized, and non-canonical inputs;
- time, cancellation, provider failure, and outcome-unknown behavior;
- sync/async semantic equivalence;
- cryptographic interoperability;
- deterministic record projection and structural revalidation;
- consumer protocol contract tests;
- interpreter portability; and
- deterministic repeated execution.

Canonical Core and Trust Proof vectors remain protocol tests: they protect
behavior and exact protocol bytes, not distribution provenance. Package checks
are limited to one ordinary wheel/source-distribution build and one fresh-venv
public-import smoke test.

Base-lane tests must not require network access, a database, a server, Docker,
Go, Node.js, a particular Python implementation, or an optional crypto backend.

## 16. Deferred Backlog

The initial deferred backlog includes:

### Teaching and adoption

- minimal profile and evidence providers;
- example-only SQLite issuance/decision recorder;
- product-owned enforcement examples;
- sync and async Basic application assemblies;
- failure, cancellation, and reconciliation examples; and
- Agent proof lifecycle examples.

These examples are not part of the initial implementation and will not become
runtime package dependencies.

### Higher conformance capabilities

- complete Agent trajectory-chain acquisition and distributed verification;
- a normative standing-decay implementation after the missing formula is
  supplied or separately standardized;
- Oracle mesh consensus;
- threshold signatures;
- federation and cross-zone trust;
- cryptographically chained recording;
- emergency and circuit-breaker coordination;
- advanced Agent lineage behavior;
- Standard and Full proof formats;
- higher-level interoperability suites; and
- Standard and Full application conformance harnesses.

### Independent audit

- freeze the initial Python design and implementation;
- extract only issue classes and research findings from the Go project;
- test whether each issue independently exists in the Python implementation;
  and
- remediate verified issues without introducing Go compatibility or treating
  Go behavior as normative.

## 17. Delivery Status

The proof-runtime sequence is implemented:

1. The implemented Core and shared-risk topology are preserved.
2. Proof-crypto authority is synchronized with the Core boundary.
3. Neutral proof values and canonical provider protocols are present.
4. KTP JWT framing and parsing are strict and library-owned.
5. Verification returns authenticated carried claims only.
6. Restricted Issuer Profile v1 issuance accepts complete, non-vetoed bundles.
7. Native asynchronous parity uses no hidden scheduling.
8. The optional `kinetic_trust_core.adapters.cryptography` implementation has its
   separate optional-crypto evidence lane.

The project-owned decision-record projection and `ProofIntent`-based issuance
are implemented under the 2026-10-07 design. Service owns the separate evidence
seam and synchronous evaluation-to-proof composition. Relying-party evaluation,
`Decider`, product assemblies, and higher-level orchestration remain deferred;
neither library nor any application gains a conformance claim from these APIs.
