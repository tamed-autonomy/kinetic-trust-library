# Consequential-action evidence implementation plan

Authority: continuous implementation and verified pushes on the existing
codex/ktp-v3-library-planning branch. No PR/merge/release or root version cutover.
Goal: close deterministic #139 gaps against exact proposal
0e40c31305cc80779949c8a6fef5eb2cf3ca49f9, after revised #131.

Architecture: additive optional installed adapters; ordinary execution does not
silently enable them. Existing current software checkpoint remains the release
prerequisite. Source authenticates complete persistent replay/budget inventories,
coverage and target observations; Library verifies signatures, exact binding,
continuity and restrictive arithmetic, returning conditions, never executing.
Python/JCS/JSON Schema and existing ES256/Ed25519 primitives only.

1. Pin exact specification/schema/29 contract and 24 shape cases; implement
   bounded canonical evidence parsing and installed evidence signature/semantic
   verification. Five states remain distinct; signed unknown/no_effect/dispatch
   never proves non-dispatch. Actual scope/source/interval/provenance/coverage
   must bind independently authenticated facts and original artifacts. Test
   all shape cases, real signatures, substitutions and release-only-on-withheld.
   Full/wheel verification then checkpoint push; continue.
2. Add exact conservative shared-budget/replay source and release composition.
   Private policy declares units/scopes/maxima/retention/recovery/idempotency/
   accounting/abandonment/checkpoint/conditional-commit and observer contracts.
   Source supplies complete current durable inventory with explicit epochs and
   heads, actual target revision and protected recovery checkpoint. An existing
   identity cannot release again, changed fingerprint is a collision, uncertainty
   retains reservations. Resets cannot erase unresolved inventory. Budget is an
   additional restriction, never E. Fresh software/native revalidation runs for
   every proposed release. Return atomic compare/reserve/commit obligations,
   not claims that they happened. Test retries/renewal/recovery/remainder/time/
   identity/target/version/recorder loss; integrate real installed graph.
3. Readonly review, exact requirement/code/test documentation, source-case
   qualification with explicit limits, full and installed wheel tests; push
   checkpoint and verify remote match. Reassess remaining chosen 3.0 gaps and
   continue settled Library work. Precise source decisions alone block affected
   slices; production Service adapters and final adoption are separate.

Review focus: forged/mis-scoped signed evidence; unsupported observation claims;
held vs charged effects and no_effect retention; changed identity/body/replica
replay; stale/incomplete restored ledger and atomic race conditions.

Checkpoint fa07a67 pushed after 1,396 full-suite tests and 13 wheel checks.
Task 2 implemented the declared cumulative-only budget and release composition.
Ruling: no reset/charge expiry adapter is invented; the selected policy declares
cumulative accounting with neither automatic operation. Cost: deployments needing
other policies require an explicit additional adapter, not an inferred formula.
Ruling: each retry appends a new attempt and retains all prior reservations;
only genuine sealed non-dispatch evidence admits a retry candidate. A positive
budget/release result carries atomic obligations, never executed authority.
Readonly review found evidence result lifetime beyond signing-key validity;
fixed after genuine red/green regression, plus transitive non-dispatch deadline
coverage. Final readonly follow-up: 18 focused tests passed, no remaining
important defect demonstrated in the reviewed scope.

Final code gate: 1,407 required tests passed without skips (103.437 seconds),
42 final wheel tests passed, 36 cryptography and eight provider tests passed.
Catalog reproduction, exact proposal/package hashes, isolated native imports and
git diff --check passed. Native API exports all six new verifiers/assessment
classes. Preflight explicitly returns unknown observation plus recording obligation.
Final qualification report will pin this code checkpoint and suite immutably;
no conformance or actual Service enforcement claim is inferred.
