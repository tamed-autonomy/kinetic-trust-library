# RFC revision refresh — 2026-11-07

Authority: update the existing codex/ktp-v3-library-planning branch, push verified
checkpoints, no PR/merge/tag/version promotion. Retain unrelated docs/security.
The default working directory is now kinetic-trust-library.

1. Compare latest main and proposal heads against active retained contracts,
   read maintainer replies #213–#218 and current PR discussions. Exact #131 and
   #139 spec/schema/vector bytes are unchanged despite rebases; metadata follows
   new heads. Source contracts remain provisional, official baseline is 2.1.0.
2. Correct demonstrated person Root gap under #165/#201: the installed Root
   authenticator supplies current institution standing bound independently to
   complete instrument digest, subject, terminator, time and source anchor.
   Score eligible person instruments by that standing; never exposure/capacity.
   Reuse exact maximum and complete-digest tie break, preserve lifecycle/zero
   exposure/chain/identity gates and keep software scoring unchanged. Remove
   the old zero/single-only person limitation; bind the selected institution
   again at standing composition and cap proof/standing by all scoring facts'
   validity. No configurable ranking policy or credit addition is introduced.
3. Archive superseded exact vectors and retain current PS13, corrected geometry
   and federation vectors, immutable recurrence AM17/18 and demand-input fixtures.
   Add genuine failing regressions first; preserve exact original bytes and hashes.
   Reconcile reader docs/status with maintainer responses; mixed standing stays
   unsupported and the separate MAJOR decision is deferred beyond v3.0.
4. Run focused, complete required no-skips, crypto/provider, import/catalog and
   installed-wheel gates. Request readonly review, close findings, push checkpoints
   and confirm remote/HEAD and tracked clean state. Never change RFC files or holds.

Real Source authentication, complete Root inventories, institution standing,
ledger provenance, cryptographic custody and execution remain Service obligations.

Verification outcome: 1,413 required tests passed without skips (100.439 seconds),
50 selected tests passed against the built wheel, 36 cryptography and eight
provider tests passed. Native import isolation, catalog reproduction, exact
upstream snapshot hashes and git diff --check passed. The first full gate found
only two outdated active manifest hashes; the old ledger was archived, current
commits/hashes were recorded, and the full no-skips gate was rerun successfully.

Readonly review found valid person instruments with zero institution standing
were discarded by the generic selector. A regression reproduced this; person
zero scores now retain the current attestation with zero contribution and digest
ties, while invalid/zero-exposure and software zero behavior stay unchanged.
Final review passed 21 focused tests with no further important defect found.
New real signed person-proof coverage verifies concurrent strongest selection,
base69 and preserved subject-specific wire fields. Upstream holds remain intact.
