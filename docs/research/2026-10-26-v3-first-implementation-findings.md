# Provisional v3 implementation findings

**Status:** Development evidence only, 2026-10-26. Library remains released and pinned as v2.1.0. The RFC PRs below are open and have not been approved or tagged.

## Pinned proposal inputs

| Proposal | Exact reviewed head | Local test fixture | Scope |
|---|---|---|---|
| [RFC PR #193](https://github.com/nmcitra/ktp-rfc/pull/193), issue #150 | `b698f82e02c435974bc828eb34616b2db1dc603d` | `spec/proposals/por-friction-boundaries-v3.json` (SHA-256 `91ad1952b4f6abb51d275c4f10aa494b8a39521ff352090f833eaccb3fa846d4`) | 18 modeled friction boundary decisions |
| [RFC PR #194](https://github.com/nmcitra/ktp-rfc/pull/194), issue #149 | `9889cabcf4ebf7e79771bf606db8c752e4e4a03d` | `spec/proposals/agent-identifiers-v3.json` (SHA-256 `0ba112e06bc58fcd995cc1444ef45024b1affc665c83c57a4100af7d9ab39594`) | 26 Agent URI parse and 9 binding cases |

The fixtures are proposal snapshots under `spec/proposals/`, not released normative vectors. Refresh them with the exact approved RFC commit before any v3 release.

The provisional implementation and proposal checks ran with `PYTHONPATH=src python3 -m unittest discover -s tests -q`: 771 tests passed on 2026-10-26. This is Library test evidence for the pinned proposal snapshots, not an RFC or deployment conformance claim.

## Findings from implementing the vectors

1. **Friction at exactly 0.3 is a real migration boundary.** The current v2.1 Library accepted an `ELEVATED` PoR declaration at `0.3` and awarded zero credit. PR #193 classifies `0.3` as `CALM`. The provisional v3 path now classifies it as CALM and rejects a conflicting ELEVATED category. The Library still has no signed-record release provenance in `PoRAttestationDeclaration`, so it cannot grant the proposal's optional tagged-v2 grandfathered credit. This implementation uses zero v3 credit for correctly classified CALM input and rejects a mislabeled declaration. Historical signed bytes must stay intact; a later versioned migration path must decide how historical declarations are admitted without rewriting them.
2. **The embedded sponsor reference cannot establish sponsorship.** The v2.1 standing code compares the sponsored identifier's third segment with the sponsor identifier's final segment. PR #194 explicitly makes that segment opaque and requires an authenticated Sponsorship Bond's full `sponsor_id` URI to bind subject, bond and proof. The new pure binding validator passes the proposal's cases, including an unrelated opaque reference. It assumes the bond and proof have already been authenticated, as the vector preconditions require. Existing `StandingDeclaration` does not carry a validated bond, so its v2.1 inference remains isolated until the v3 standing/proof model can accept one. Removing that inference alone would weaken the standing check.
3. **Proposal vectors cover pure decisions, not runtime proof.** The friction vectors do not test attestation authenticity or historical admission. The identifier binding vectors assume an applicable authenticated bond and proof. Passing them does not demonstrate signature verification, replay control, authority, or deployment conformance.

## Next integration gate

Design a versioned v3 standing input that carries a validated Sponsorship Bond (or an immutable verified bond value) and separates historical v2 PoR records from native v3 declarations. Then connect the pure identifier binding check to proof verification and standing preparation, using the accepted #149/#151/#157 contracts and their final vectors. Keep v2.1 signed bytes and their release interpretation available through an explicit migration path.
