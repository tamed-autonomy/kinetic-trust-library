# KTP v3.0.0 Library planning

**Status:** Working plan, 2026-10-26. The proposed v3 slices listed below are under implementation; no v3 conformance claim is made here.

**Research:** [RFC v3 Library impact](../research/2026-10-26-ktp-v3-rfc-library-impact.md), with source links and status for each proposal. Baseline on this branch: `PYTHONPATH=src python3 -m unittest discover -s tests -q` passed 766 tests on 2026-10-26.

**Implementation started:** PR #193 friction boundaries, PR #194 Agent URI/binding, PR #164 five-factor arithmetic, PR #203 missing-evidence factor projections, PR #195 Trust Proof stages 1–5 and selected stage-7 invariants, PR #196 canonical-request and complete-proof digests, PR #197 Decision Geometry body digest, and PR #201 strongest-single eligible-root selection are pinned and exercised provisionally. See [implementation findings](../research/2026-10-26-v3-first-implementation-findings.md). These are parts of slices B–E, not completion of those slices. The provisional v3 primitives live separately from the released v2.1 evaluation path. Stage 6 is blocked by PR #195's schema reference to the six-factor v2 risk shape while its clear vector uses the five-factor v3 shape.

## Goal and source of authority

Advance Kinetic Trust Library from its pinned KTP RFC v2.1.0 semantics to a separately released 3.0.0 series after the RFC's v3.0.0 contract is approved and tagged. Keep the Library generic, deterministic, immutable, and free of storage, transport, enforcement, and product workflows. The published RFC tag and its exact commit, schemas, and conformance vectors will be the normative baseline. Open PRs and `main` are planning inputs only.

RFC release proposal: [issue #182](https://github.com/nmcitra/ktp-rfc/issues/182). It proposes the “Ostrom” release, a merge order, and a December 10, 2026 tag target; the tag waits for the release criteria. The current Library pin remains RFC `v2.1.0` at `15520035267546e1035aad7beea0cc3cf9ef8f2c` until a reviewed v3 release is adopted.

RFC `main` at `6035a2fe929d5d0546961cd084a8b0719eb7ab79` already contains unreleased readiness, trajectory-signature, human-eligibility, and privacy-evidence drafts. No `release/v3.0.0` remote branch or v3 tag was present on 2026-10-26. These drafts require gap analysis alongside the open PRs; they are not v2.1.0 semantics.

## Workstreams in dependency order

1. **Source control and gap ledger.** Record the final v3 tag and commit; inventory its normative source, schemas, migration entries, and vectors against `docs/traceability/library-contracts.md`. For every new requirement, mark Library-owned behavior, product-owned behavior, or unsupported behavior, with source and test references. Resolve conflicting draft branches against the merged tag, never by stacking arbitrary PR heads.
2. **Core and input semantics.** Update the five weighted Risk Factor contract and declared demand-side `moment_criticality` input (#161/#164, #147/#202); missing-evidence propagation (#148/#203); one Core contract across conformance levels (#154/#198); and person/External Root standing and lifecycle projection (#162/#165, #157/#201). Likely owners: `core/risk.py`, `core/evidence.py`, `core/evaluate.py`, `core/standing.py`, and focused immutable models. Preserve Soul as an independent veto and explicit missing/unknown states.
3. **Identity, proof, and decision records.** Implement the canonical v3 Trust Proof (#151/#195), ordinary request association (#152/#196), Decision Geometry and signed carriage (#153/#197), sponsored identifier meaning (#149/#194), and Proof of Resilience boundary corrections (#150/#193). Review `models/proof.py`, `proofs/`, `models/record.py`, `core/record.py`, `trajectory/`, and public APIs together. Historical v2 signed bytes retain v2 meaning; do not silently reinterpret them as v3.
4. **Profiles and bounded pure primitives.** Review nested-zone and federation proposals (#159/#160, #173/#174, #177/#178), repair (#171/#172), zone boundary (#189/#190), execution observation (#187/#188 and #129/#139), and software-substrate profile (#124/#131) for deterministic Library contracts. Add only pure value, parsing, and calculation surfaces justified by the final specification. Leave durable state, network crossing, execution receipts, operational reconciliation, and authority enforcement to products.
5. **Conformance and release.** Apply component-scoped claim rules (#155/#199) and the final KTP-CONFORMANCE text. Pin official v3 vectors and test each implemented behavior, including negative and boundary cases. Update the public contract matrix, migration notes, package metadata, `KTP_SPEC_TAG`/`KTP_SPEC_COMMIT`, and release procedure only after the normative pin is immutable. Coordinate the shared 3.0 compatibility series with Kinetic Trust Service; do not claim Basic/Standard/Full or certification for a package.

## Proposed implementation slices and acceptance checks

| Slice | Main files and contracts | Done when |
|---|---|---|
| A. Source delta and public migration design | `docs/traceability/library-contracts.md`, a new v3 source ledger, public API inventory; compare v2.1 tag with accepted v3 source | Every changed clause/schema/vector has an owner and status; v2 historical bytes and the Service migration path are explicitly documented; no code silently reads draft text as released. |
| B. Five-factor Core and evidence | `models/risk.py`, `models/evidence.py`, `models/profile.py`, `core/risk.py`, `core/evidence.py`, `core/evaluate.py` | Official demand and missing-evidence vectors pass; absent evidence never becomes a fabricated zero; Soul veto and unknown Soul stay distinct; Core stage ordering and immutable outputs are preserved. |
| C. Standing and identity | `models/standing.py`, `models/_uri.py`, `core/por.py`, `core/standing.py`, relevant proof identity projections | Official friction, identifier, and External Root lifecycle vectors pass; person standing is modeled only to the accepted protocol extent; product-owned eligibility remains separate. |
| D. Proof and request association | `models/proof.py`, `proofs/_jwt.py`, `_issue.py`, `_verify.py`, a focused request-binding module if accepted | Canonical v3 proof positive and negative vectors pass, including signed bytes, outcome, bounds, malformed input, and request mismatch. API and migration tests demonstrate that v2 proofs retain v2 meaning. |
| E. Decision Geometry | `models/record.py`, `core/record.py`, separate signed-carriage primitive if accepted | Official geometry vectors pass for full evaluation and early stop; no unevaluated field is fabricated; the project-owned v2 Decision Record and canonical v3 record are unambiguously named and migrated. |
| F. Other pure v3 contracts | Profile, trajectory, zone/federation declaration, observation, and repair modules only where the final RFC supplies a deterministic Library-owned contract | Each included surface has a source clause, vector or focused test, and a contract-matrix row. Operational workflows remain consumer responsibilities. |
| G. Release adoption | `spec/v3.0.0/`, `docs/traceability/library-contracts.md`, `README.md`, `docs/releasing.md`, `pyproject.toml`, `src/kinetic_trust_library/__init__.py` | Final RFC tag and commit are pinned; all Library tests and included official vectors pass; package version and metadata agree; Service 3.0 compatibility is checked; public claims name only demonstrated component behavior. |

Slices B–E can be designed from pinned proposal heads but remain provisional until their owning PRs merge. Slice F is deliberately selected by the final source delta: a whole-protocol obligation does not automatically become a Library API. Each slice should be one or more focused PRs if its public interface cannot be reviewed as a unit.

## First executable planning tasks

- Build a source-to-code matrix from the *merged* RFC v3 release branch, listing each changed normative clause, schema field, and vector with its owning Library module and current behavior. Record pending PRs separately from accepted text.
- Start the provisional matrix now from the source-linked research note, including the unreleased RFC `main` drafts. Record the exact head commit for each candidate PR and refresh it when the PR changes.
- Identify public API breaks before implementation: factor input shape, request/proof association, subject types, proof and record models, and claim wording. Draft the v2.1-to-v3 migration contract for consumers and Service.
- Split implementation into reviewable PRs in the dependency order above. Each PR pins its exact RFC source commit, adds focused tests from the official vectors where available, and updates its traceability row.
- Run the existing Library suite as a baseline, then verify each changed contract with focused tests and the complete suite. Recheck against the final RFC tag before release.

## Decision gates and limits

- RFC issue #182 and its component proposals remain open as of this plan. Proposed wording is not normative, and review floors, merge order, and the target tag date may change.
- Do not publish a v3 package or change the released v2.1 pin based on draft text. Development can proceed on this branch against explicitly provisional source snapshots, with those tests and claims labelled provisional.
- The Library's scope remains selected primitives. A v3 release number denotes the adopted RFC series, not complete protocol or deployment conformance.

## Current readiness checkpoint

The branch contains provisional, vector-backed primitives for slices B–E. The completed proof precheck covers ordered stages 1–5, but it returns only the first prerequisite failure; passing it is never proof acceptance. The stage-7 predicate is isolated and requires authenticated expected state. Request and geometry digests reproduce the proposal's known answers but do not establish authentic inputs, replay protection, or signed carriage. CI has a separate `v3-proofs` dependency path so the JCS and schema checks run when a PR is eventually opened.

Before a v3 package can ship, resolve the PR #195 five-factor schema conflict and compose PR #201's new External Root union into the proof schema and regenerated signed fixtures, as documented in the [implementation findings](../research/2026-10-26-v3-first-implementation-findings.md). Then finish the ordered Trust Proof stage-6/8 contract and ingress verification, bind actual requests and replay state, implement Decision Geometry gate/result and carrier semantics, reconcile all other selected v3 Library clauses against the final tag, and update the public API, migration notes, version, pin and package checks. These are implementation gates, not tasks to defer automatically until after tagging; the final tag supplies the immutable source for the last reconciliation.
