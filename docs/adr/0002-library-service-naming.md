# ADR 0002: Library and Service Naming

- Status: Accepted
- Date: 2026-10-08

## Context

`KTP-Core` is the formal name of an official KTP specification. The Python
artifact previously used `kinetic-trust-core` as its repository,
distribution, and import identity even though it also contains Kinetic
Envelope behavior, Deployment Profile models, proof-provider seams, an
optional cryptography adapter, and project-owned record representations.

That overload makes the artifact appear to be either the complete KTP-Core
deployment architecture or a package restricted to only one RFC. Neither
reading describes the intended reusable Python library.

## Decision

The umbrella artifact is **Kinetic Trust Library**:

- repository and distribution: `kinetic-trust-library`;
- import namespace: `kinetic_trust_library`; and
- source root: `src/kinetic_trust_library`.

The internal `kinetic_trust_library.core` module retains `core` because it
implements KTP-Core semantics. The companion artifact remains **Kinetic Trust
Service**, with repository/distribution `kinetic-trust-service` and import
namespace `kinetic_trust_service`.

The migration is a clean pre-release break. No `kinetic_trust_core` alias,
compatibility distribution, re-export tree, or dual class family is provided.

Library releases use their own semantic version. Library `1.0.0` declares its
normative target separately as KTP `v2.1.0` at commit
`15520035267546e1035aad7beea0cc3cf9ef8f2c`.

The Library and Service package versions share a `major.minor` compatibility
series, beginning with Library `1.0.0` and Service `1.0.0`. Patch releases are
component-local and may advance independently. Package compatibility does not
identify or change the KTP specification version; the Library's exact KTP tag
and commit remain independent provenance.

The two facts returned by one evaluation are `bundle.core_capacity` and
`bundle.envelope`. At equality the first reports `AT_CAPACITY`/within and the
released zero-threshold Envelope reports zero-margin `SILENT_VETO`. Neither
fact determines product action or enforcement.

## Consequences

Artifact names no longer collide with the official KTP-Core document title.
Internal modules can still map directly to official specifications. The
Library may implement selected material from multiple KTP specifications
without another umbrella rename.

All Library imports, package metadata, build artifacts, examples, workflows,
and Service dependencies change together. Consumers cannot mix the old and new
class families. The absence of a compatibility layer is acceptable because no
public Library release exists under the old identity.

ADR 0001's deterministic-Library versus operational-Service separation
remains accepted. This ADR supersedes only its use of **Core** as the umbrella
software name.
