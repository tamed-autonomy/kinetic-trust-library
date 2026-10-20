# ADR 0001: Core and Service Boundary

- Status: Accepted
- Date: 2026-09-15
- Updated: 2026-10-09 for Library naming and KTP v2.1.0

> Boundary remains accepted. [ADR 0002](0002-library-service-naming.md)
> supersedes this ADR's former umbrella **Core** name with **Library**;
> **KTP-Core** refers only to official specification semantics.
> The accepted v2.1.0 migration decision governs the separate Core capacity
> and Kinetic Envelope facts.

## Context

KTP needs a stable semantic kernel without turning the current experimental
phase into a production platform. The boundary must keep semantic behavior
portable and testable while allowing external systems to operate it.

## Decision

> `kinetic-trust-library` implements Kinetic Trust semantics;
> `kinetic-trust-service` composes injected adapters and Library operations;
> products own infrastructure and action.

| Owner | Responsibility |
| --- | --- |
| Library | RFC interpretation, deterministic evidence/evaluation/trust/proof semantics, proof timing, and canonical project-owned record projection |
| Service | Direct synchronous adapter invocation and evaluation-to-proof composition |
| Product | Configuration, credentials, source authenticity/completeness, storage, retention, transport, retry/reconciliation, observability, deployment, action execution, and enforcement |

Library is deterministic for identical explicit inputs. It performs no network,
database, environment, filesystem, scheduling, sleep, or ambient-clock I/O.
Callers inject time and all other runtime facts as explicit values or through
backend-neutral protocols.

Semantic Library code does not import Service, integration packages, or vendor
SDKs. The optional `adapters/cryptography.py` adapter is the sole current
exception: it may depend on PyCA cryptography, while semantic code depends only
on the Library's provider protocols. This exception does not permit ambient I/O.

Service's evidence seam returns complete Library-owned `ObservationDeclaration`
values; its `Issuer` composes evaluation, deterministic record projection, and
proof issuance. Direct injection, fail-first invocation, and the closed outcome union
are non-normative, replaceable conveniences, not RFC semantics. Product adapters
translate external facts into Library-owned declarations; vendor types do not
cross into Library semantics. Products own all operational concerns in the
table, including sensing, keys, failure handling, retries, human interaction,
and action.

Library is an informative reference library for selected RFC-defined primitives
within its declared scope. `DecisionRecord` is a project-owned representation,
not a canonical RFC Decision Geometry schema or Trajectory Chain transaction record. It is separate
returned data, correlated with a proof by operation ID / `decision_id`, not a
persistence or execution receipt. Proof is not permission: it attests evaluated
claims and asserts no acceptance, action, enforcement, storage, or persistence.
Neither Library nor Service claims deployment-level conformance.

A focused AST test enforces the obvious dependency and runtime-access
violations. It remains test-only and is intentionally a small denylist rather
than production architecture infrastructure.

## Consequences

Library stays dependency-light, deterministic, reusable, and independently
testable. Runtime capabilities must be passed in or placed outside Library.

This phase has high experimentation tolerance. We favor small, reversible
implementation and accept non-production operational limits. We explicitly
defer general dependency-policy machinery, plugin discovery, loaders,
lifecycle frameworks, schedulers, continuous loops, retries, health systems,
persistence, queues, network servers, CLIs, deployment packaging, vendor
integrations, enforcement adapters, federation, and legacy compatibility until
actual use and a lower risk tolerance justify them.
