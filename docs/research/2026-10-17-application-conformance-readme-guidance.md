# Application Conformance README Guidance

## Purpose and scope

This note supports a short README section explaining what an application must
add around Kinetic Trust Library, with or without Kinetic Trust Service, before
the assembled deployment can make a KTP conformance claim. It is not a
conformance claim, certification, implementation plan, or substitute for
reviewing the complete tagged specification set.

The official conformance subject is a complete implementation made from a
Trust Oracle, Risk Factor sensors, a Policy Enforcement Point (PEP), a Flight
Recorder, and agents. The required claim syntax names a product and version.
Accordingly, a calculation or composition package can provide evidence for its
bounded responsibilities but cannot inherit the behavior of components it does
not operate. See [KTP-CONFORMANCE terminology][conformance-terminology] and
[claim format][conformance-claims].

## Immutable v2.1.0 authority

This guidance is pinned to official tag [`v2.1.0`][v210], dereferenced commit
`15520035267546e1035aad7beea0cc3cf9ef8f2c`. KTP versions the specification
series as one set, published tags do not move, and downstream work is instructed
to cite a tag rather than `main`; see [VERSIONING.md][versioning]. The official
site also says that the repository contains the normative artifacts and wins if
the site disagrees with them; see [Specifications][official-site].

KTP v2.1.0 names three conformance levels and says each builds on the previous:
Basic, Standard, and Full. The prose describing where a level is suitable is
guidance. Uppercase BCP 14 terms such as `MUST`, `MUST NOT`, and `REQUIRED` are
the formal normative requirements. See [KTP-CONFORMANCE, Conformance
Levels][conformance-levels].

## Application-owned responsibility matrix

This matrix summarizes what the application or deployment must provide. It is
not a claim that either package supplies the complete row.

| Level | Application or deployment responsibilities beyond reusable protocol code |
|---|---|
| **Basic** | Operate an Oracle that accepts Risk Factor input, computes `R` and `E_trust`, signs proofs, exposes health, and logs issuance; connect at least the Basic set of sensor inputs and health/failure handling stated by KTP-CONFORMANCE; place a PEP on every protected path to validate proofs and enforce the Zeroth Law; persist/query authorization decisions for at least 30 days; give agents identifiers and proof refresh/denial behavior; supply keys, transport, failure handling, and the Basic test and claim evidence. |
| **Standard** | Everything in Basic, plus at least a three-node Oracle mesh with threshold signing; all six weighted Risk Factors and the separate Soul veto; Node, Neighborhood, and Global risk domains; trust velocity, lineage, Proof of Resilience, sponsorship/federation behavior; all five trust tiers and graceful degradation; a cryptographically chained, tamper-detecting Flight Recorder with the stated one-year/seven-year retention and query/export behavior; production key custody and Standard test and claim evidence. |
| **Full** | Everything in Standard, plus at least five Oracle nodes with 3-of-5 signing, real-time consensus, sub-second refresh, and three-region distribution; redundant/failing-over critical sensors and Indigenous Data Sovereignty support; all-zone, defense-in-depth PEP operation with the stated latency and availability properties; externally anchored, multi-region, seven-year forensic records; cross-zone identity and extended-proof behavior; Level-3 key controls; formal security review, penetration testing, incident response, recovery procedures, and third-party conformance evidence as v2.1.0 describes it. |

The component-level `MUST` lists are the source for the matrix:

- [Basic and Standard Oracle requirements][oracle-requirements]
- [Risk Factor requirements][risk-requirements]
- [PEP requirements][pep-requirements]
- [Flight Recorder requirements][recorder-requirements]
- [Agent requirements][agent-requirements]
- [proof, Zeroth Law, Soul, tier, and cryptographic requirements][protocol-requirements]
- [Full additional requirements][full-additional]

The standalone normative specifications also require deployment-owned
declarations and enforcement. A deployment profile is the declaration surface
for factor mappings, Soul frameworks, feeds, aliases, normalization, labels,
peer share, External Root parameters, standing decay, and optional envelope
thresholds. Omitting a required declaration makes the deployment unassessable,
not a partial conformer; see [The Deployment Profile][deployment-profile]. The
Kinetic Envelope returns tighten-only constraints and supervision, while the
authorizing gateway consumes and enforces them; see [Kinetic Envelope
layering][envelope-layering].

## Package boundary

- **Library** owns its documented deterministic values, validation,
  calculation/evaluation, proof, and projection contracts.
- **Service** is an optional synchronous composition layer over Library. It is
  not a hosted service, independent protocol implementation, or enforcement
  point.
- **The consuming application or operator** owns sensing and source
  authentication, network endpoints, storage and retention, key custody and
  lifecycle, retries and availability, observability, agent runtime behavior,
  PEP interception and action enforcement, human or governance workflows,
  recovery, and the evidence supporting any deployment claim.

Neither package alone establishes Basic, Standard, or Full deployment
conformance. A Trust Proof is an input to authorization, not permission to act.
README wording should therefore use **supports** or **helps implement**, never
“install this package to become compliant.”

## Confirmed v2.1.0 contradictions relevant to wording

The immutable tag does not yield one conflict-free level checklist. The README
must not silently choose a side or imply that these conflicts are resolved:

1. **Basic inputs and Soul.** KTP-CONFORMANCE permits three weighted inputs and
   says Basic need not implement Soul, while the canonical deployment profile
   and schemas require all six factors and Soul. See [Basic][basic-summary],
   [profile shape][deployment-profile-shape], [Risk Factor schema][risk-schema],
   and [Trust Proof schema][proof-schema].
2. **Basic audit durability.** KTP-CONFORMANCE says Basic does not require
   recorder immutability or chaining, while KTP-AUDIT requires append-only
   storage and cryptographic chaining without a Basic exception. See [Basic
   limitations][basic-limitations] and [KTP-AUDIT immutability][audit-integrity].
3. **Proof lifetime and shape.** KTP-CONFORMANCE states 60 seconds for Basic,
   30 seconds for Standard, and 10 seconds for Full; the tagged Trust Proof
   schema documents a universal 10-second maximum and requires fields beyond
   the Basic claim set. See [level comparison][level-comparison] and [Trust
   Proof schema][proof-schema].
4. **Standard HSM custody.** KTP-CONFORMANCE calls an HSM recommended for
   Standard Oracle keys, while KTP-CRYPTO says Level 2+ Oracle signing keys
   `MUST` be stored in an HSM. See [conformance key management][conformance-key]
   and [crypto key custody][crypto-key].
5. **Six factors plus a veto.** Some conformance prose says “seven inputs,”
   while the canonical architecture says six weighted Risk Factors plus Soul as
   a separate pre-aggregation veto. See [Full summary][full-summary] and
   [Deployment Profile bridge][profile-bridge].
6. **Full post-quantum timing.** The Level-3 crypto table requires hybrid PQC,
   while the migration schedule calls it optional before 2027. See [Level-3
   crypto][crypto-full] and [PQC schedule][crypto-pqc].

These are specification conflicts, not gaps for Library or Service to resolve
by inventing policy.

## Evidence and certification limits

KTP-CONFORMANCE lists unit, integration, failure, interoperability, stress, and
chaos cases, and its self-certification section requires all required tests for
the claimed level, public results, execution-environment documentation, and
maintenance with each release. Basic and Standard may self-certify; v2.1.0
states that Full requires third-party certification. See [Test Suite][tests] and
[Certification Process][certification].

The tag supplies names for the broad certification cases, but not complete
executable inputs, expected outputs, or required-versus-optional metadata for
that suite. Its two machine-readable vector files cover the Kinetic Envelope
and empty-window aggregation only. Passing those vectors is evidence about
those bounded contracts, not evidence of whole-deployment conformance.

KTP-CONFORMANCE permits a partial claim, but deviations `MUST` be documented.
Until upstream defines component-scoped claims, the README should not turn
partial implementation evidence into a Basic, Standard, Full, certified, or
official-reference-implementation claim.

## v3 status

KTP v3 is not released. Upstream issue [#182][issue-182] is an open release-set
proposal for **v3.0.0 Ostrom**. It says the tag is planned for **2026-12-10**, but
also says the date is a plan and the proposed release set is the finish line.
The date is therefore not guaranteed, and neither proposed text nor current
`main` replaces the immutable v2.1.0 baseline.

Two proposed v3 changes directly address this README's boundary:

- [#154][issue-154] proposes one Core semantic contract across Basic,
  Standard, and Full, with levels tightening deployment assurance rather than
  redefining factors, Soul, proof semantics, or evaluation results.
- [#155][issue-155] proposes independently testable component/role profiles and
  claim syntax, while retaining Basic, Standard, and Full as whole-deployment
  claims.

Both are inputs to the proposed release set, not released requirements. Issue
#182 contains other proposed changes and explicitly names some conflicts as
post-v3 limits. Do not claim that v3 will fix every v2.1 inconsistency.

[v210]: https://github.com/nmcitra/ktp-rfc/tree/v2.1.0
[versioning]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/VERSIONING.md#L1-L73
[official-site]: https://kinetic-trust-protocol.net/specs/docs
[conformance-terminology]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L66-L82
[conformance-claims]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L1090-L1108
[conformance-levels]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L84-L301
[oracle-requirements]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L303-L370
[risk-requirements]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L372-L425
[pep-requirements]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L426-L481
[recorder-requirements]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L483-L536
[agent-requirements]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L538-L586
[protocol-requirements]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L588-L792
[full-additional]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L268-L277
[deployment-profile]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/specifications/deployment-profile.md#L21-L128
[envelope-layering]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/specifications/kinetic-envelope.md#L13-L24
[basic-summary]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L97-L147
[deployment-profile-shape]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/specifications/deployment-profile.md#L25-L57
[risk-schema]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/schemas/risk-factors.json#L1-L14
[proof-schema]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/schemas/trust-proof.json#L7-L56
[basic-limitations]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L137-L147
[audit-integrity]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-audit.md#L472-L542
[level-comparison]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L278-L298
[conformance-key]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L775-L792
[crypto-key]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-crypto.md#L624-L633
[full-summary]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L222-L267
[profile-bridge]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/specifications/deployment-profile.md#L38-L57
[crypto-full]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-crypto.md#L188-L237
[crypto-pqc]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-crypto.md#L1209-L1233
[tests]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L794-L979
[certification]: https://github.com/nmcitra/ktp-rfc/blob/v2.1.0/rfc-src/ktp-conformance.md#L980-L1050
[issue-182]: https://github.com/nmcitra/ktp-rfc/issues/182
[issue-154]: https://github.com/nmcitra/ktp-rfc/issues/154
[issue-155]: https://github.com/nmcitra/ktp-rfc/issues/155
