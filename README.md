# Kinetic Trust Library

Kinetic Trust Library implements selected deterministic KTP v2.1.0 protocol
primitives in Python. It returns immutable protocol values and factual results,
not product instructions.

| Concern | Library |
|---|---|
| GitHub repository | `tamed-autonomy/kinetic-trust-library` |
| Python distribution | `kinetic-trust-library` |
| Python import | `kinetic_trust_library` |
| Source root | `src/kinetic_trust_library` |
| Library version | `1.0.0` |

Kinetic Trust Library and Kinetic Trust Service share a `major.minor`
compatibility series; patch releases advance independently for each component.
The first paired series is `1.0`: Library `1.0.0` and Service `1.0.0` can
receive component-local patch releases without changing that shared series.

Package and protocol versions are independent. `kinetic-trust-library==1.0.0`
profiles the immutable release with `KTP_SPEC_TAG == "v2.1.0"` and
`KTP_SPEC_COMMIT == "15520035267546e1035aad7beea0cc3cf9ef8f2c"`.
The pinned source is [KTP v2.1.0](https://github.com/nmcitra/ktp-rfc/tree/v2.1.0),
not upstream `main` or informative website text.

## Choosing Library or Service

Kinetic Trust Library is the semantic layer. [Kinetic Trust
Service](https://github.com/tamed-autonomy/kinetic-trust-service) is an
optional Python package of synchronous composition helpers built on Library;
despite its name, it is not a server or daemon. There is no Service-only path:
Service depends on Library and delegates KTP semantics to it.

| Scenario | Use |
|---|---|
| You need deterministic KTP validation and evaluation, Decision Record projection, Trust Proof operations, Soul Constraint document parsing, or Trajectory parsing and adjacent-pair assessment. | **Library directly** |
| You want Service's ordered, fail-first `EvidenceHost` for product-supplied adapters and/or its `Issuer` to compose one evaluation with Decision Record projection and, when Soul-clear, proof issuance. | **Library plus Service** |
| You need networking, storage, retries, source authentication, key lifecycle, observability, human workflows, action execution, or enforcement. | **Product-owned code around Library or Library plus Service.** Neither package supplies these capabilities. |

If you are unsure, start with Library and add Service only when `EvidenceHost`
or `Issuer` removes composition code you would otherwise maintain. Service is
replaceable without changing KTP semantics. Neither package alone establishes
application or deployment conformance, and neither is an enforcement point. A
Trust Proof is not permission to perform an action.

## Building a conforming KTP application

Conformance applies to a named, versioned application and its deployment, not
to Library or Service by themselves. Neither package has a Basic, Standard, or
Full mode, and the levels are cumulative: Standard includes Basic, and Full
includes Standard. The [Library contract
matrix](docs/traceability/library-contracts.md) states what Library actually
implements; the immutable [KTP-Conformance
v2.1.0](https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md)
defines the controlling requirements. This table is orientation, not a
complete requirements, certification, or remaining-gap checklist.

| Target | Capabilities the assembled application and deployment must provide |
|---|---|
| **Basic** | An operational Oracle interface and product-owned evidence sources; secure key and Trust Proof lifecycle; a real PEP that intercepts every protected request, validates proofs, enforces the Zeroth Law before the protected effect, and logs the result; queryable decision records retained for at least 30 days; unique agent identities and proof obtain, present, refresh, and denial behavior; conservative failure handling; and published evidence for the required Basic tests. |
| **Standard** | Everything in Basic, plus a three-or-more-node Oracle mesh with 2-of-3 threshold signing; all six weighted Risk Factors and the independent Soul veto across three risk domains; velocity, lineage, Proof of Resilience, sponsorship, and federation behavior; five-tier and Soul enforcement with graceful degradation; tamper-evident Decision Geometry, audit queries, one-year decision retention, and seven-year Soul-veto retention; full trajectory behavior; automated key rotation; and published Standard test evidence. |
| **Full** | Everything in Standard, plus at least five Oracle nodes across at least three regions, 3-of-5 threshold signing, real-time consensus, and sub-second proof refresh; redundant failover sensing and Indigenous Data Sovereignty controls; all-zone layered enforcement within the required latency; externally anchored, multi-region records with seven-year retention and forensic reconstruction; HSM-backed keys and complete identity, attestation, and extended-proof behavior; formal security review, penetration testing, incident-response and recovery procedures; and third-party certification. |

Service can reduce synchronous composition code; it does not satisfy or waive
any conformance obligation. Package tests and released vectors establish only
the named package behaviors. An unqualified Basic, Standard, or Full claim
requires satisfying every applicable requirement and passing 100% of the
required tests for that level. Under v2.1.0, documented deviations support
only a clearly identified partial-compliance claim.

The tagged v2.1.0 corpus has cross-document inconsistencies affecting level
boundaries, including Basic inputs and Soul, recorder chaining, proof
lifetimes, Standard HSM requirements, Full post-quantum timing, and the
relationship between six weighted factors and the independent Soul veto.
Upstream issues [#154](https://github.com/nmcitra/ktp-rfc/issues/154) and
[#155](https://github.com/nmcitra/ktp-rfc/issues/155) propose a single Core
semantic contract and component-scoped conformance claims. Until those
proposals are adopted in an immutable specification, an application must
assess the complete v2.1.0 tag, document its interpretations, and avoid
representing this summary as certification evidence.

> **Looking ahead (non-normative):** Upstream issue
> [#182](https://github.com/nmcitra/ktp-rfc/issues/182) is an open proposal for
> KTP v3.0.0 ("Ostrom"), with a planned—not committed—tag date of December 10,
> 2026. Its proposed release set includes the still-open #154 and #155 work.
> The tag is intended to wait until applicable review floors clear, required
> pull requests are green, and required release evidence is complete. Until an
> immutable v3 tag exists and these projects separately review and adopt it,
> they remain pinned to KTP v2.1.0.

## Specification scope

| Official material | Library claim |
|---|---|
| KTP-Core v2.1.0 | Implements the deterministic trust calculation, Soul-first evaluation, exact Zeroth-Law capacity relation, Trust Proof model and operations, and Silent Veto data within the documented Library interface. It is not an operational Oracle, PDP deployment, or PEP. |
| Soul Constraint document v2.1.0 | Parses the official closed JSON document into an immutable value. Parsing validates shape only; it does not authenticate an authority, evaluate applicability, or enforce a veto. |
| Kinetic Envelope v2.1.0 | Implements the result model, exact margin, profile thresholds, supervision, tighten-only constraints, normative-gate effects, and released vectors within the declared implementation profile. |
| Deployment Profile v2.1.0 | Implements immutable validated declarations and deterministic profile binding; the consuming product supplies deployment-specific values. |
| KTP-Crypto v2.1.0 | Provides signer, verifier, and trusted-key-source interfaces plus an optional ES256/Ed25519 PyCA adapter. It does not claim the complete algorithm, key lifecycle, HSM, threshold, or post-quantum specification. |
| KTP-Oracle v2.1.0 | Supplies pure calculation and proof-issuance primitives only. It is not an Oracle node or Oracle Mesh. |
| KTP-Audit v2.1.0 | Supplies a project-owned deterministic Decision Record representation. It is not the RFC's Flight Recorder or a canonical KTP-Audit wire schema. |
| KTP-Identity Trajectory v2.1.0 | Supplies semantic parsing of official Trajectory Transactions and partial pairwise structural continuity findings. It does not authenticate records or operate a chain. |
| KTP-Conformance v2.1.0 | Lists exact released vectors exercised by the Library. Passing them is evidence about those primitives, not Basic, Standard, Full, deployment, or certification conformance. |

Exact released vectors exercised by the Library:

- `spec/v2.1.0/conformance/aggregation-empty-window-v1.json`
- `spec/v2.1.0/conformance/ros2-reference-v0.1.json`

> Informative Python reference library for selected KTP v2.1.0 protocol
> primitives. The Library is not an official KTP SDK, a complete KTP
> deployment, an enforcement point, or a certification claim.

Products own sensing, storage, keys, transport, failure handling, retries, human
interaction, action, and enforcement. Neither Library nor Service supplies
those operational responsibilities.

## Requirements and installation

The tested support set is CPython 3.11 through 3.15. The commands below use the
virtual-environment support included with Python, so they do not modify a
system or Homebrew-managed Python installation.

When a release appears on the
[PyPI project page](https://pypi.org/project/kinetic-trust-library/), create a
local virtual environment and install the latest available base library with:

```console
python3 -m venv .venv
.venv/bin/python -m pip install kinetic-trust-library
```

Install the optional cryptography extra only when the consuming application
wants the PyCA adapter supplied in the same wheel:

```console
.venv/bin/python -m pip install 'kinetic-trust-library[cryptography]'
```

On Windows PowerShell, use the corresponding environment-local interpreter:

```console
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install kinetic-trust-library
.\.venv\Scripts\python.exe -m pip install "kinetic-trust-library[cryptography]"
```

For unreleased changes—or until the first release appears on PyPI—change into
the `kinetic-trust-library` source-checkout root (the directory containing
`pyproject.toml`) and replace the package name above with `.` or
`'.[cryptography]'`. The dot identifies the package in the current directory,
so source installation fails when run elsewhere. Activating the virtual
environment is optional when invoking its interpreter directly as above.

The base installation has no third-party runtime dependencies.

`validate_absolute_uri(value, *, name)` exposes the bounded, value-preserving
generic RFC 3986 absolute-URI syntax used by Library's KTP fields. It is
scheme-neutral: it does not enforce registered URN or DID grammars, allowlist
schemes, or establish whether dereferencing a URI is safe. For example,
`urn://a` and `did://a` satisfy this generic syntax even if a scheme-specific
consumer rejects them. Products may layer scheme-specific policy; this
validator does not parse or normalize identifiers for them.

The Library returns facts and failures through Python APIs; the consuming
product decides how to enforce, retry, persist, or present them.

The optional PyCA adapter is present in the same wheel but is activated only
when a consumer installs the `cryptography` extra. The extra installs
`cryptography>=50.0.0,<51`; it is not a dependency of the base library. KMS,
HSM, and remote cryptographic services can instead implement the provider
protocols without using the supplied adapter.

### Run the examples

The runnable examples are available from a repository checkout or an unpacked
source distribution; they are intentionally not installed in the wheel. Run
them from that source root after completing the base installation above.

Examples 01–03 need only the dependency-free base installation. On macOS or
Linux, run:

```console
.venv/bin/python examples/01_core_and_envelope_evaluation.py
.venv/bin/python examples/02_fail_closed_evaluation_outcomes.py
.venv/bin/python examples/03_observations_from_application_apis.py
```

On Windows PowerShell, run:

```powershell
.\.venv\Scripts\python.exe examples\01_core_and_envelope_evaluation.py
.\.venv\Scripts\python.exe examples\02_fail_closed_evaluation_outcomes.py
.\.venv\Scripts\python.exe examples\03_observations_from_application_apis.py
```

After installing the optional `cryptography` extra shown above, run Example 04
with:

```console
.venv/bin/python examples/04_trust_proof_issue_and_verify.py
```

Or on Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe examples\04_trust_proof_issue_and_verify.py
```

See the
[KTP v2 examples catalogue](https://github.com/tamed-autonomy/kinetic-trust-library/blob/main/examples/README.md)
for the paired guides. These scripts stop after displaying values computed or
authenticated by the library. They do not provide application storage,
transport, enforcement, or evidence of deployment-level conformance.

## How the library fits into an application

```text
application-owned APIs and evidence sources
                 |
                 v
 immutable KTP declarations and EvaluationRequest
                 |
                 v
      kinetic_trust_library.core.evaluate(...)
                 |
        +--------+--------+
        |                 |
 RejectedRequest    EvaluationBundle
                          |
              Core Capacity Result + Kinetic Envelope Result
                          |
              +-----------+-----------+
              |                       |
     optional Trust Proof       application records and
        issue/verify             enforces the real action
```

Deterministic Library evaluation performs no provider I/O. It evaluates values
already supplied by the application. Trust Proof operations call only the
signer, verifier, and trusted key source injected by the application. After the library returns, the
application decides how to store results and how to enforce them.

## Evaluate an action

A complete evaluation starts from product-owned declarations. The application
obtains those declarations through its own APIs, then asks the library to
validate and evaluate them.

```python
from kinetic_trust_library import (
    DeploymentProfile,
    EvaluationBundle,
    EvaluationRequest,
    RejectedRequest,
    ValidatedActionDemand,
)
from kinetic_trust_library.core import evaluate

# These declarations and the UTC cutoff come from application-owned APIs.
profile = DeploymentProfile.validate(profile_declaration)
action = ValidatedActionDemand.validate(
    action_declaration,
    profile=profile,
    capability=capability_declaration,
    cutoff=cutoff,
)

# Standing, observations, and Soul responses are also application-owned facts.
request = EvaluationRequest(
    operation_id="operation:example",
    profile=profile,
    action=action,
    standing=standing_declaration,
    observations=tuple(observation_declarations),
    soul_responses=tuple(soul_response_declarations),
    cutoff=cutoff,
    previous_trust=None,  # Or the application's previous TrustSnapshot.
)

outcome = evaluate(request)

if isinstance(outcome, RejectedRequest):
    # Deterministic input validation failed. The application chooses how to
    # report, record, or otherwise handle the rejection.
    print(outcome.failed_stage, outcome.rationale)
else:
    bundle: EvaluationBundle = outcome
    if bundle.core_capacity is None:
        print("core_capacity=unevaluated")
    else:
        print(bundle.core_capacity.relation)
        print(bundle.core_capacity.within_capacity)
    envelope = bundle.envelope
    print(envelope.supervision)
    print(envelope.environmental_capacity)
    print(envelope.margin)
    print(envelope.tightened_constraints)
```

This is an integration skeleton rather than a toy policy. A real request must
contain a complete validated Deployment Profile and action, standing facts,
the observations required by that profile, and one current Soul response for
each configured framework. The library deliberately does not invent missing
product facts or silently turn missing evidence into measured zero.

One evaluation returns two bound facts: `bundle.core_capacity` is the exact
KTP-Core relation, and `bundle.envelope` is separate Kinetic Envelope
supervision and constraints. `within_capacity` is numerical, not permission.

Exact equality `A == E_trust` is `AT_CAPACITY` with
`within_capacity is True`. The released zero-veto-threshold Envelope has
`margin == 0` and `SILENT_VETO` at that same equality. The released Envelope
policy code `KINETIC_CAPACITY_EXCEEDED` is the Envelope's specified veto code,
not a claim that KTP-Core equality is above capacity. The Envelope may tighten
a within-capacity result but cannot weaken an above-capacity result.
Products decide the operational consequence of these facts.

A Soul veto still returns an `EvaluationBundle`, but downstream standing,
evidence, risk, trust, and velocity values are absent; `core_capacity is None`
means unevaluated, never invented zero trust. The Envelope still returns
Soul-constrained `SILENT_VETO`. A
`RejectedRequest` represents deterministic request-validation failure and is
not an exception. Operational exceptions from application code are allowed to
propagate back to the application.

## Issue and verify a Trust Proof

Trust Proof issuance requires a complete `EvaluationBundle` returned by
`evaluate()` whose Soul assessment is `CLEAR`. The caller supplies a
`ProofIntent` with a requested lifetime of one through ten seconds. The Library derives
issuance time from the evaluation's exact whole-second UTC cutoff and tightens
expiration to the whole-second end of a current or non-renewable root. A
non-positive effective lifetime is rejected before provider access.

The proof derives `subject` and the canonical `action` digest from the
validated evaluation, and `decision_id` from its operation ID. The caller
supplies `resource`, `context_hash`, and `trajectory_id` in `ProofIntent`. These
authenticated binding members are a Library implementation-profile extension
to the unchanged, pinned KTP v2.1.0 RFC. Verification requires them, so older
unbound proofs are rejected.

The following example uses an application-provided signer and trusted-key
source. They may be backed by a KMS, HSM, remote service, or the optional local
adapter.

```python
from datetime import timedelta
from hashlib import sha256

from kinetic_trust_library.adapters.cryptography import cryptography_proof_crypto
from kinetic_trust_library.models.proof import ProofIntent
from kinetic_trust_library.proofs import TrustProofs

# bundle is the complete, CLEAR EvaluationBundle returned above. signer and
# trusted_key_source are application-owned provider implementations.
proofs = TrustProofs(cryptography_proof_crypto())

resource = "urn:resource:example:document-42"
context_hash = "sha256:" + sha256(b'{"environment":"example"}').hexdigest()
trajectory_id = "trajectory:example:001"
proof_intent = ProofIntent(
    proof_id="proof:example",
    resource=resource,
    context_hash=context_hash,
    trajectory_id=trajectory_id,
    lifetime_seconds=10,
)

token = proofs.issue(
    bundle,
    proof=proof_intent,
    signer=signer,
)

verified = proofs.verify(
    token.raw,
    cutoff=bundle.cutoff + timedelta(seconds=1),
    keys=trusted_key_source,
)

expected_binding = (
    bundle.action.subject,
    bundle.action.digest,
    resource,
    context_hash,
    bundle.cutoff,
    token.expires_at,
    trajectory_id,
    bundle.operation_id,
)
actual_binding = (
    verified.claims.subject,
    verified.claims.action,
    verified.claims.resource,
    verified.claims.context_hash,
    verified.claims.issued_at,
    verified.claims.expires_at,
    verified.claims.trajectory_id,
    verified.claims.decision_id,
)
if actual_binding != expected_binding:
    raise ValueError("verified proof does not bind the intended decision")
assert token.expires_at <= bundle.cutoff + timedelta(seconds=10)

print(verified.claims.issuer)
print(verified.claims.subject)
print(verified.claims.effective_trust)
```

The optional adapter exports `ES256LocalSigner`, `Ed25519LocalSigner`, and their
native asynchronous counterparts. Applications remain responsible for loading
private keys, constructing the signer's `OracleSigningIdentity`, and supplying
trusted key lifecycle facts.

The issuer value parsed from a presented token is untrusted input. A
`VerificationKeySource` must independently anchor trust and return a key with
the correct issuer, key ID, algorithm, purpose, validity window, and revocation
facts.

A `VerifiedTrustProof` authenticates only the claims carried by the token. It
does not recreate an `EvaluationBundle` or `KineticEnvelopeResult`, and it does
not authorize or enforce an action. Before using it, the application must
compare the authenticated subject, action, resource, context hash, times,
trajectory ID, and decision ID with the decision it intends to rely on, as in
the example above.

Proof is not permission. It attests evaluated claims, including for a complete
Soul-clear evaluation whose Envelope supervision is non-autonomous. It
does not assert acceptance, action execution, enforcement, storage, or persistence.

For native asynchronous providers, use `AsyncTrustProofs` with
`async_cryptography_proof_crypto()`, `AsyncProofSigner`, and
`AsyncVerificationKeySource`. The asynchronous facade performs native awaits;
it does not create hidden threads or nested event loops.

## Provider interfaces and failures

Provider contracts live in `kinetic_trust_library.protocols`:

- `ProofSigner` and `AsyncProofSigner` sign canonical proof input;
- `SignatureVerifier` and `AsyncSignatureVerifier` verify one algorithm; and
- `VerificationKeySource` and `AsyncVerificationKeySource` resolve trusted key
  facts for one verification cutoff.

Providers use three explicit signals:

- `ProviderUnavailable`: the provider definitely did not accept the operation;
- `ProviderFailure`: the provider definitely produced no usable result; and
- `SigningOutcomeUnknown`: a signing operation may have completed externally.

The proof facade translates those signals into typed public errors. In
particular, `OutcomeUnknownError` carries the proof ID, signing-input digest,
and optional provider reference needed for application-owned reconciliation.
The library does not retry, select a fallback provider, or decide whether an
operation is safe to repeat.

Asynchronous read-only waits propagate native `asyncio.CancelledError`,
including verification-key resolution, incoming signature verification, and
issuance self-verification after the signer has returned an exact signature.
Cancellation before signer dispatch is also native. Cancellation while a
dispatched signer has no definite return raises `OutcomeUnknownError` instead:
the external signing effect may have completed. No cancelled or outcome-unknown
issuance releases a token. Native read-only cancellation lets application-owned
`asyncio.timeout()` contexts produce `TimeoutError` normally.

Presented proof failures derive from `InvalidProofError`. Configuration and
provider-operation failures derive from `ProofOperationError`. Invalid local
declarations raise `ValidationError`; deterministic evaluation rejection is
returned as `RejectedRequest`.

## Public API map

Focused record and proof imports are:

```python
from kinetic_trust_library.models.proof import ProofIntent
from kinetic_trust_library.models.record import DecisionRecord
from kinetic_trust_library.core.record import (
    build_decision_record,
    require_validated_decision_record,
)
from kinetic_trust_library.proofs import AsyncTrustProofs, TrustProofs
```

| Module | Purpose |
| --- | --- |
| `kinetic_trust_library` | `DeploymentProfile`, `EvaluationBundle`, `EvaluationRequest`, `KTPError`, `KTP_SPEC_TAG`, `KTP_SPEC_COMMIT`, `RejectedRequest`, `ValidatedActionDemand`, `ValidationError`, and `__version__` |
| `kinetic_trust_library.core` | The aggregate exports only `evaluate`; focused Core modules provide supported advanced calculations |
| `kinetic_trust_library.models` | Namespace-only; import public values from the focused model modules |
| `kinetic_trust_library.proofs` | `TrustProofs` and `AsyncTrustProofs` |
| `kinetic_trust_library.protocols` | Synchronous and asynchronous provider contracts and provider signals |
| `kinetic_trust_library.models.proof` | Backend-neutral proof values, key facts, algorithms, and crypto bindings |
| `kinetic_trust_library.models.capacity` | Exact `CapacityRelation` and immutable `CoreCapacityResult` |
| `kinetic_trust_library.models.record` | Immutable project-owned `DecisionRecord` |
| `kinetic_trust_library.core.record` | Deterministic record construction and structural revalidation |
| `kinetic_trust_library.soul_constraint` | Official Soul Constraint document parsing and immutable semantic values |
| `kinetic_trust_library.trajectory` | Official Trajectory Transaction semantic parsing, immutable values, and partial pairwise structural continuity findings |
| `kinetic_trust_library.adapters` | Namespace-only; optional implementations live in focused adapter modules |
| `kinetic_trust_library.adapters.cryptography` | Optional PyCA-backed ES256 and Ed25519 providers |
| `kinetic_trust_library.errors` | Complete typed validation, proof, configuration, and provider error hierarchy |

`kinetic_trust_library.models` and `kinetic_trust_library.adapters` are namespace-only
aggregates. Proof facades, provider protocols, and Trajectory names are
intentionally not exported from the package root. Import each value from its
owning module as shown above.

`build_decision_record(bundle)` returns deterministic data for any valid
evaluation, including a Soul short path; a `RejectedRequest` is not an
evaluation and cannot produce a record. `require_validated_decision_record`
structurally revalidates that representation. `DecisionRecord` uses the
project-owned `ktp-python-decision-record-v1` projection because KTP v2.1.0
defines no canonical Decision Geometry JSON schema. It is not the RFC Trajectory
Chain transaction record and introduces no new decision semantics.

The record carries `core_capacity_digest` and `capacity_relation`, both `None`
on a Soul short path, alongside the separate Envelope facts.
The record is returned data: it does not assert persistence, proof issuance,
acceptance, action, or enforcement. `DecisionRecord` and `ProofToken` remain
separate, correlated by evaluation operation ID / proof `decision_id`. Record
digests establish represented coherence, not source authenticity or completeness.

## Parse Soul Constraint documents

`kinetic_trust_library.soul_constraint` validates an already-decoded mapping
against the official KTP v2.1.0 Soul Constraint document shape:

```python
from kinetic_trust_library.soul_constraint import parse_soul_constraint

constraint = parse_soul_constraint(
    {
        "soul": 1,
        "constraint_type": "care",
        "authority": "https://example.org/sovereignty-framework",
        "community": "Example community",
    }
)

print(constraint.soul)
print(constraint.constraint_type)
print(constraint.authority)
```

The result is detached and immutable. Missing optional members and explicit
JSON null both project to `None`. Parsing does not establish that the source is
authentic, that the authority is trusted, that the constraint applies to an
action, or that a product must enforce it. It does not convert the document
into an evaluation declaration or proof claim. JSON decoding, duplicate-member
handling, transport, persistence, authority selection, and enforcement remain
product responsibilities.

Service does not wrap this independent parser; products call the focused
Library module directly.

## Parse and assess Trajectory Transactions

`kinetic_trust_library.trajectory` provides official v2.1.0 semantic parsing,
detached immutable values, and partial pairwise structural continuity.
Parsing is not authentication: the product supplies trusted release context
and owns record authentication, reporting, persistence, acceptance, recovery,
and enforcement.

The official post-action Trajectory Transaction records an action and its
execution outcome. It is distinct from the project-owned pre-action
`DecisionRecord`; neither evaluation nor a veto synthesizes a Trajectory
Transaction.

With two product-supplied mappings, the focused operations are:

```python
from kinetic_trust_library.trajectory import (
    assess_trajectory_link,
    parse_trajectory_transaction,
)

previous = parse_trajectory_transaction(previous_mapping)
current = parse_trajectory_transaction(current_mapping)
findings = assess_trajectory_link(previous, current)
finding_codes = tuple(finding.value for finding in findings)
```

The parser is the validation boundary and raises `ValidationError` for
malformed input. It preserves open-object extensions as owned immutable
semantic data, not original JSON bytes. Obtain validated values through the
parser; the ordinary frozen value constructors do not validate fields.
The module exposes `TrajectoryTransaction`, `TrajectoryAgentState`,
`TrajectoryAction`, `TrajectoryOracleAttestation`, and `TrajectoryLinkFinding`
alongside the two operations, only from this focused module.

The assessor trusts parsed values and returns an ordered tuple of
Library-local findings for chain identifier, sequence, supplied hash reference,
timestamp order, and typed semantic state continuity. Same-chain checking and
typed state equality are Library-local structural interpretations, not closed
RFC comparison rules. An empty tuple establishes only these supplied-pair
relations; it is not authenticity, acceptance, or deployment conformance.
Hashes and signatures remain opaque exact strings.

Strict RFC 3339 calendar/range checking of both timestamp fields is a
documented Library rule for safe pairwise ordering over the schema's
annotation-oriented `date-time` format, not a requirement imposed by the
schema alone. Ordinary root timestamps compare as exact UTC instants across
offsets and arbitrary fractional precision, including `-00:00`. Conservative
positive-leap syntax is accepted without an IERS occurrence table; when either
root timestamp uses it, assessment returns `TIMESTAMP_ORDER_UNDEFINED`
instead of a non-increasing-time finding.

This capability does not provide:

- genesis validation;
- canonical serialization or hash preimages;
- hash calculation or authentication;
- signature inputs or verification;
- chain persistence or append operation;
- whole-chain validation;
- record acceptance;
- retention, query, or investigation;
- Oracle/agent operation; or
- action execution or enforcement.

Physical continuity, violation response, and recovery policy also remain
outside this contract. Genesis-shaped records may be parsed, but genesis is
not assessed. See the
[frozen v2.1.0 coverage audit](docs/research/2026-10-10-ktp-v2.1.0-coverage-audit.md) and
[maintained Library-contract matrix](docs/traceability/library-contracts.md)
for provenance, focused evidence, and boundaries.

## Library, Service, and product responsibilities

| Owner | Responsibility |
| --- | --- |
| Library | RFC interpretation; deterministic evidence, evaluation, trust, and proof semantics; proof timing; canonical project-owned record projection |
| Service | Direct synchronous adapter invocation and evaluation-to-proof composition |
| Product | Configuration, credentials, source authenticity/completeness, evidence acquisition, key lifecycle, storage, retention, transport, retry/reconciliation, observability, deployment, action execution, enforcement, and human workflows |

Service's `EvidenceAdapter` returns complete Library-owned `ObservationDeclaration`
values through a direct synchronous evidence seam. Service's `Issuer` composes
evaluation, record projection, and proof issuance. These are replaceable,
non-normative conveniences; consumers may call Library directly without losing
KTP semantics. Neither library supplies product infrastructure.

The runtime package will not provide a database, HTTP middleware, web server,
daemon, background service, retry loop, approval queue, operator UI, or
enforcement implementation.

## Input and resource boundaries

Trust Proof parsing applies explicit protocol/profile safety caps. Evaluation
has selected implementation caps, but the Library imposes no universal quota
over every finite Proof of Resilience (PoR) or root history. Soul Constraint and
Trajectory parsers accept already-decoded mappings; they do not inherit Trust
Proof byte, nesting-depth, or string limits.

Products own ingress controls: serialized request/body size, decoder depth,
collection cardinality, concurrency, deadlines, and availability policy. The
Library's validation and typed failures do not replace these product controls.

## Current limitations

The scope matrix above is the public implementation contract. Operational
Oracle systems, key lifecycle, advanced cryptographic schemes, Flight Recorder
storage, trajectory-chain operations, and deployment-level verification are
outside the Library. Passing the released vectors does not certify a product.
Package publication and provenance are separate from protocol and product
conformance.

## Contributing and security

Kinetic Trust Library is an independent implementation. It is not an official
KTP SDK. NMCITRA does not certify, maintain, or endorse it.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change. Participation
is governed by the [Contributor Covenant](CODE_OF_CONDUCT.md), and suspected
vulnerabilities must follow the private route in [SECURITY.md](SECURITY.md).
Questions that would change the KTP specification belong in
[official KTP Discussions](https://github.com/nmcitra/ktp-rfc/discussions), not
in an implementation-only change.

## Verify a checkout

Run the authoritative base suite directly from the source tree with
CPython 3.11 through 3.15 and the standard library. The wrapper also runs Examples 01-03:

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python \
  tools/run_required_tests.py --start-dir tests/unit --top-level-dir .
```

Verify that the checked-in catalogue matches the pinned KTP v2.1.0 material:

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python tools/compile_catalog.py --check
```

After installing the optional cryptography extra, run its separate evidence
lane:

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python \
  tools/run_required_tests.py --start-dir tests_crypto --top-level-dir .
```

Run the reusable provider evidence lane separately:

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python \
  tools/run_required_tests.py --start-dir tests_provider --top-level-dir .
```

The canonical Core and Trust Proof vectors protect protocol behavior, including
exact bytes where the protocol requires them. They are not evidence of package
provenance.

## Project documentation

- [KTP v2.1.0 coverage audit](docs/research/2026-10-10-ktp-v2.1.0-coverage-audit.md)
- [Library and Service naming](https://github.com/tamed-autonomy/kinetic-trust-library/blob/main/docs/adr/0002-library-service-naming.md)
- [Ordinary release procedure](https://github.com/tamed-autonomy/kinetic-trust-library/blob/main/docs/releasing.md)
- [Project terminology](https://github.com/tamed-autonomy/kinetic-trust-library/blob/main/CONTEXT.md)
