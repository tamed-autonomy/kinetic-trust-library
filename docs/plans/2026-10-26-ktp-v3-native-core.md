# Native KTP 3.0 Core Implementation Plan

> **For agentic workers:** Implement this plan task by task in the current v3 branch. Keep each task test first and preserve proposal source pins until the RFC tag replaces them.

**Goal:** Replace the coupled v2.1 Core implementation with a native five-factor, explicit-unknownness v3 path in the same Library package.

**Architecture:** Build immutable v3 values and pure calculations in `kinetic_trust_library.v3` while the RFC is unresolved. The current v2.1 public Core remains only as a development baseline on this branch. At the 3.0 cutover, make the accepted v3 path the primary public API and remove incompatible v2.1 models and evaluation behavior.

**Source:** [KTP v3 Library plan](2026-10-26-ktp-v3-library.md) and pinned RFC PRs #164, #203, #195, #196, #197 and #201 in [implementation findings](../research/2026-10-26-v3-first-implementation-findings.md).

## Constraints

- KTP 3.0 is a breaking release. No v2.1 runtime, wire, or API fallback is required.
- Library logic stays deterministic, immutable, and service independent. Providers authenticate and populate input evidence.
- `moment_criticality` is demand-side and is never a sixth weighted Risk Factor.
- An unobservable factor has no measured value; its decision stress is 1 while unknownness remains visible.
- The unresolved PR #164 R/E precision discrepancy and PR #195 schema conflict cannot be silently resolved by Library code.

## Tasks

1. **Compose the native risk boundary — implemented provisionally.** Add an immutable five-factor assessment that consumes sealed factor evidence states and exactly five weights. Preserve `measured_risk = None` when any factor is unobservable while calculating a separate restrictive `decision_risk`. Test complete, missing, duplicate and sixth-factor inputs against pinned proposal cases.
2. **Replace the Core input model — in progress.** Define v3 Soul, standing and demand inputs with authenticated-source contracts. Exclude the v2.1 request-supplied moment criticality and sponsor-reference inference. Test missing and veto states before connecting arithmetic. Soul query-state projection, the PR #202 preclassification operation digest, and deterministic demand value/declaration/time/provenance/binding prechecks are implemented. Framework response authenticity, supplier authentication, independent source/provenance verification, and the installed demand formula remain prerequisites.
3. **Assemble Core stage order — non-authorizing projection implemented.** Evaluate Soul first, then standing/evidence/risk, capacity and envelope. Early stops must leave later values uncomputed. The native projection returns no later stage after Soul veto or unknownness, requires a derived base-trust result before risk, and carries measured versus restrictive E separately. It does not authenticate the source contributions or classify A. Hold the authorizing result behind the RFC precision decision, demand/standing evidence verification and accepted proof schema.
4. **Replace native proof and record surfaces.** Compose the tested v3 proof stages with the corrected merged schema/root union, then bind the actual request and Decision Geometry. Reject v2 proof types and old record shapes on the native path.
5. **Cut over the package.** Move accepted v3 APIs to the primary public package, remove incompatible v2.1 exports/behavior, refresh migration and traceability docs, update version and RFC pin from the final tag, and run full package/Service compatibility checks.

## Immediate review focus

- Unknown factors must not become zero or a measured one.
- A known Soul veto must stop before risk or margin computation.
- A missing demand supplier must not be accepted as a caller-supplied scalar.
- Old proof bytes must not trigger a v2 fallback in the native verifier.
- Stage-6 proof schema mismatch must remain visible until the RFC fixes its five-factor reference.
