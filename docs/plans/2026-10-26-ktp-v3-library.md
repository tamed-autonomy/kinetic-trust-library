# KTP v3.0.0 Library planning

**Status:** Working plan, 2026-10-26. No v3 implementation or conformance claim is made here.

## Goal and source of authority

Advance Kinetic Trust Library from its pinned KTP RFC v2.1.0 semantics to a separately released 3.0.0 series after the RFC's v3.0.0 contract is approved and tagged. Keep the Library generic, deterministic, immutable, and free of storage, transport, enforcement, and product workflows. The published RFC tag and its exact commit, schemas, and conformance vectors will be the normative baseline. Open PRs and `main` are planning inputs only.

RFC release proposal: [issue #182](https://github.com/nmcitra/ktp-rfc/issues/182). It proposes the “Ostrom” release, a merge order, and a December 10, 2026 tag target; the tag waits for the release criteria. The current Library pin remains RFC `v2.1.0` at `15520035267546e1035aad7beea0cc3cf9ef8f2c` until a reviewed v3 release is adopted.

## Workstreams in dependency order

1. **Source control and gap ledger.** Record the final v3 tag and commit; inventory its normative source, schemas, migration entries, and vectors against `docs/traceability/library-contracts.md`. For every new requirement, mark Library-owned behavior, product-owned behavior, or unsupported behavior, with source and test references. Resolve conflicting draft branches against the merged tag, never by stacking arbitrary PR heads.
2. **Core and input semantics.** Update the five weighted Risk Factor contract and declared demand-side `moment_criticality` input (#161/#164, #147/#202); missing-evidence propagation (#148/#203); one Core contract across conformance levels (#154/#198); and person/External Root standing and lifecycle projection (#162/#165, #157/#201). Likely owners: `core/risk.py`, `core/evidence.py`, `core/evaluate.py`, `core/standing.py`, and focused immutable models. Preserve Soul as an independent veto and explicit missing/unknown states.
3. **Identity, proof, and decision records.** Implement the canonical v3 Trust Proof (#151/#195), ordinary request association (#152/#196), Decision Geometry and signed carriage (#153/#197), sponsored identifier meaning (#149/#194), and Proof of Resilience boundary corrections (#150/#193). Review `models/proof.py`, `proofs/`, `models/record.py`, `core/record.py`, `trajectory/`, and public APIs together. Historical v2 signed bytes retain v2 meaning; do not silently reinterpret them as v3.
4. **Profiles and bounded pure primitives.** Review nested-zone and federation proposals (#159/#160, #173/#174, #177/#178), repair (#171/#172), zone boundary (#189/#190), execution observation (#187/#188 and #129/#139), and software-substrate profile (#124/#131) for deterministic Library contracts. Add only pure value, parsing, and calculation surfaces justified by the final specification. Leave durable state, network crossing, execution receipts, operational reconciliation, and authority enforcement to products.
5. **Conformance and release.** Apply component-scoped claim rules (#155/#199) and the final KTP-CONFORMANCE text. Pin official v3 vectors and test each implemented behavior, including negative and boundary cases. Update the public contract matrix, migration notes, package metadata, `KTP_SPEC_TAG`/`KTP_SPEC_COMMIT`, and release procedure only after the normative pin is immutable. Coordinate the shared 3.0 compatibility series with Kinetic Trust Service; do not claim Basic/Standard/Full or certification for a package.

## First executable planning tasks

- Build a source-to-code matrix from the *merged* RFC v3 release branch, listing each changed normative clause, schema field, and vector with its owning Library module and current behavior. Record pending PRs separately from accepted text.
- Identify public API breaks before implementation: factor input shape, request/proof association, subject types, proof and record models, and claim wording. Draft the v2.1-to-v3 migration contract for consumers and Service.
- Split implementation into reviewable PRs in the dependency order above. Each PR pins its exact RFC source commit, adds focused tests from the official vectors where available, and updates its traceability row.
- Run the existing Library suite as a baseline, then verify each changed contract with focused tests and the complete suite. Recheck against the final RFC tag before release.

## Decision gates and limits

- RFC issue #182 and its component proposals remain open as of this plan. Proposed wording is not normative, and review floors, merge order, and the target tag date may change.
- Do not publish a v3 package or change the released v2.1 pin based on draft text. Development can proceed on this branch against explicitly provisional source snapshots, with those tests and claims labelled provisional.
- The Library's scope remains selected primitives. A v3 release number denotes the adopted RFC series, not complete protocol or deployment conformance.
