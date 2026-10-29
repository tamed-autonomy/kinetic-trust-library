# KTP Library 3.0 release-readiness gap audit

**Target:** Reach an implementation state where final RFC text normally changes a bounded module, schema, vector, or fixture rather than requiring a new Core architecture. This is an engineering target, not a present conformance claim. Reviewed against RFC `main` `9612f79` and the proposal heads in [implementation findings](../research/2026-10-26-v3-first-implementation-findings.md).

| Area | Current branch | Work needed before the final-tag reconciliation can be small |
| --- | --- | --- |
| Five-factor risk and missing evidence | Pure calculations, factor-state projection, Soul-first preflight, sensor configuration boundary, derived `E_base` arithmetic, exact E projection and non-authorizing ordered Core projection | Authenticate feed/signal population and every standing contribution/ceiling; classify A from the actual operation; define and test exact R/E precision before an authorization result. |
| Demand-side criticality | Canonical operation digest, deterministic precheck, installed verifier and classifier boundaries; all 42 published value cases exercised through a fixture ES256 adapter; classified values feed the native Core projection | Supply deployment-specific production adapters and calibrated monotonic A formulas. Per-invocation endpoint checks enforce restrictive direction but do not prove global calibration. |
| Standing and External Root | Identifier binding, PoR boundary, strongest-single eligible-root selection, closed root union schema validated against all 42 published shape cases | Replace v2 sponsor inference and standing model with authenticated bond/instrument and lifecycle projection. Person-subject handling needs the accepted proof shape. Schema acceptance supplies no lifecycle or exposure authentication. |
| Trust Proof | Ordered parser/signature/time precheck through stage 5, partial stage 7, pinned proposal schema | Resolve the five-factor schema reference across PRs, incorporate the closed External Root union, regenerate signed fixtures, implement stages 6–8 and a single accepting verifier. Level-specific cryptographic profiles remain explicit. |
| Request and Decision Geometry | Canonical request/proof and geometry digest primitives | Bind the actual invocation and accepted proof, replay reservation, gate/result, signed carriage and use-time checks. Preserve early-stop unknownness without fabricating fields. |
| Public package and Service | v2.1 public API/version/pin; v3 under a provisional namespace | Replace incompatible public Core/proof/record APIs, remove v2 fallback from native execution, write migration examples, coordinate Service 3.0, build and test a release candidate. |

## Current dependency order

1. Finish the native Core input and evaluator path with externally authenticated inputs and a conservative undefined-input result. The arithmetic projection exists, but its precomputed evidence values are not verified by it. Keep R/E precision as a named unresolved gate, not an implicit rounding choice.
2. Compose the proof stages only after the RFC supplies a coherent five-factor schema and External Root projection. Build signed positive and negative fixtures through the full accepting path.
3. Bind accepted proof, request, replay and Decision Geometry into one immutable result, then replace the public v2 APIs.
4. Run the Library and Service suites against the final RFC tag, update the RFC pin and package version, and exercise installed-wheel examples.

The refreshed full Library suite passed 839 tests with the v3 optional dependencies; the wheel build included the bundled demand schemas, precheck module and native Core projection modules.

Until steps 1–3 are implemented, an RFC freeze would still leave substantial Library work. The target is to finish those steps on this branch while treating proposal-specific edges as replaceable. The final tag should then require a source diff review, localized changes, fixture refresh, and release verification.
