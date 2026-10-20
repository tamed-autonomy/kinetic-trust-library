# Kinetic Trust Library

This context defines the project language for the deterministic Python Library
that profiles immutable KTP releases. Product infrastructure, operational
policy, and enforcement remain outside this context.

The current project boundary follows the lightweight Python Library model
defined below.
KTP remains a reusable Library: it owns deterministic evaluation, immutable
protocol values, Trust Proof operations, typed provider contracts, and the
optional local cryptography adapter. Products own sensing, evidence acquisition,
storage, keys and key lifecycle,
transport, failure handling, retries, human interaction, action, and enforcement.
Products also own ingress/body size, decoder depth, collection cardinality,
concurrency, deadlines, and availability controls. Library parser and selected
evaluation caps are not a universal resource quota; Soul and Trajectory parsers
consume already-decoded mappings rather than inheriting Trust Proof limits.
Library `1.0.0` profiles KTP `v2.1.0` at commit
`15520035267546e1035aad7beea0cc3cf9ef8f2c` independently of its package version.
Kinetic Trust Library and Kinetic Trust Service share a `major.minor`
compatibility series, beginning with `1.0`; patch versions advance
independently for each component. This package compatibility policy does not
change the independently pinned KTP specification tag or commit.

The tested support set is CPython 3.11 through 3.15. Canonical KTP-Core and Trust Proof
vectors protect protocol behavior, including exact protocol bytes; they do not
establish package provenance or application conformance.

## Language

**KTP Library**:
The reusable Python implementation artifact. It implements selected,
explicitly declared KTP specification semantics without becoming a deployed
Oracle, PDP, PEP, or complete product.
_Avoid_: Core, KTP deployment, official SDK

**KTP-Core**:
The official KTP Core Specification and the protocol semantics implemented by
the Library. It is not the umbrella software artifact.
_Avoid_: Library, Service

**KTP Service**:
The replaceable composition package that invokes Library operations with
caller-supplied adapters. It may make operational composition practical but
cannot weaken or reinterpret Library semantics.
_Avoid_: Product, Core, PEP

**Product**:
The consuming application or deployment that owns external facts, operational
policy, failure handling, storage, transport, enforcement, and human
interaction.
_Avoid_: Library, Service

**Core Capacity Result**:
The exact KTP-Core comparison of action demand with Effective Trust. Equality
is within Core capacity; this fact does not itself instruct a product to act.
_Avoid_: Envelope decision, product permission

**Kinetic Envelope Result**:
The separate supervision, tightening, constraint, and rationale result defined
by the Kinetic Envelope specification. It may constrain an action that remains
within Core capacity.
_Avoid_: Core Capacity Result, enforcement action

**Deployment Profile**:
The complete, versioned declaration that gives KTP calculations one exact and
reproducible meaning for a deployment.
_Avoid_: Runtime settings, product configuration

**Context Signal**:
A catalogue-defined observation that a Deployment Profile selects as evidence
for a Signal Risk Factor.
_Avoid_: Risk Factor, decision input

**Signal Risk Factor**:
One of the five risk factors derived from declared Context Signals using one
profile-bound aggregation and weight.
_Avoid_: Domain factor policy, sensor value

**Moment Criticality**:
The sixth risk factor, supplied and evidenced by the exact action context rather
than derived from Context Signals.
_Avoid_: Moment signal, domain observation

**Risk Domain**:
One of Node, Neighborhood, or Global, identifying the scope in which evidence
for a Signal Risk Factor is observed.
_Avoid_: Separate risk model

**Domain Factor Stress**:
The stress value for one Signal Risk Factor within one Risk Domain, including a
fail-closed value when its declared evidence is not computable.
_Avoid_: Context stress, raw observation

**Risk Context**:
The six factor stresses consumed by the authoritative risk calculation and
carried by a Trust Proof. Each signal-derived value combines the three Risk
Domains; Moment Criticality appears once.
_Avoid_: Eighteen-factor matrix, domain trace

**Domain Risk**:
The retained Node, Neighborhood, or Global risk projection used to explain how
domain-scoped evidence affected an evaluation.
_Avoid_: Authoritative final risk

**Authoritative Risk**:
The single environmental risk value calculated from the six values in the Risk
Context under one Deployment Profile.
_Avoid_: Reaggregated Domain Risk

**Soul Veto**:
The sovereignty result evaluated before risk aggregation and kept outside the
six weighted Risk Factors.
_Avoid_: Seventh risk factor

**Soul Constraint Document**:
The official KTP v2.1.0 schema-shaped assertion parsed by
`kinetic_trust_library.soul_constraint` into a detached immutable value. It is
not an evaluated `SoulConstraint`, a `SoulResponseDeclaration`, or an
authenticated proof claim. Parsing establishes shape only, not source
authenticity, authority trust, action applicability, permission, remediation,
or enforcement. Service does not wrap this independent Library parser.
_Avoid_: Evaluated veto, trusted authority result, enforcement instruction

**Enforcement Point**:
A product-owned mechanism that applies an evaluation result to a real action.
The Library and Service supply decision data but are not Enforcement Points.
_Avoid_: Library PEP, Service PEP

**ObservationDeclaration**:
The complete Library-owned evidence input, including source identity, sequence,
class-specific measurement facts, domain, times, and provenance. Structural
coherence does not prove source authenticity or completeness.
_Avoid_: Lightweight observation, repaired evidence

**ProofIntent**:
The immutable caller intent for proof ID, resource, context hash, trajectory ID,
and requested lifetime. The Library derives `issued_at` from the validated
evaluation cutoff and `decision_id` from its operation ID, tightening expiry to an active
root end.
_Avoid_: Caller-supplied proof time, permission request

**DecisionRecord**:
The deterministic project-owned pre-action `ktp-python-decision-record-v1`
projection of a validated evaluation, built and revalidated by `core.record`.
KTP v2.1.0 defines no canonical Decision Geometry JSON schema. This returned
data is separate from `ProofToken`, correlated by operation ID / `decision_id`,
and is not the RFC Trajectory Chain transaction record. It asserts no
persistence, proof issuance, acceptance, action, or enforcement.
_Avoid_: Canonical RFC record schema, storage receipt

**Trajectory Transaction**:
The official post-action KTP v2.1.0 record of an action and its execution
outcome, distinct from the project-owned pre-action `DecisionRecord`.
`kinetic_trust_library.trajectory` parses its semantic fields into detached
immutable values and assesses one supplied adjacent pair. Parsing is not
authentication, and pairwise findings do not establish genesis validity,
whole-chain validity, acceptance, persistence, or enforcement. Products supply
trusted release context and own record authentication and operation.
_Avoid_: DecisionRecord, authenticated record, append receipt

**EvidenceAdapter**:
A Service-owned, replaceable synchronous integration contract returning complete
`ObservationDeclaration` values. Service invokes adapters directly; products
own configuration, credentials, source authenticity/completeness, and operations.
_Avoid_: Core evidence semantics, product runtime

**Issuer**:
A Service-owned, replaceable evaluation-to-proof composition helper with typed
rejected, evaluated-without-proof, and issued-proof outcomes. It does not collect
evidence or perform storage, transport, retries, execution, or enforcement.
_Avoid_: RFC-mandated Python interface, permission service

**Proof is not permission**:
A Trust Proof attests evaluated claims. It does not assert acceptance, action
execution, enforcement, storage, or persistence; even a complete Soul-clear
evaluation with a non-autonomous envelope may receive one.
_Avoid_: Approval token, proof of execution
