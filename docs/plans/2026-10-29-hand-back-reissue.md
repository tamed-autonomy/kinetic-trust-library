# Grant-time reissue enforcement

Continue the hand-back plan inline with TDD/supplier review against §7 at
`17f37b772eac8b2f84248c1912f3aeb3f5fa26d1`.

Add an installed current reissue verifier using the selected hysteresis policy.
Source authenticates actual full signed grant digest/subject/class/time/audit
position, current protected grant epoch, complete retained audit history and
each surviving applicable stop's historically governing profile. Validate historical profile
digests; never substitute today's curve for an earlier stop's bound.

Use existing pure timeline pricing. Ignore expired and logically expunged stops;
for surviving applicable same-class stops, a grant must follow the stop in real
audit order and be issued no earlier than its corrected bound. Fully elapsed
historical caps can prove eligibility without unavailable older pricing windows;
otherwise the complete historical window is required. The protected epoch
preserves invalidation across bounded retention and cannot roll back on restart.
Current time passing never repairs an early or pre-stop issuance.

Compose exact policy/source/epoch/lease bindings and shortest evidence validity
into Clear. Remove the temporary selected-hysteresis rejection only when this
gate is installed symmetrically. Keep relational Clear unsupported pending its
reconciliation/human gate and atomic consumption composition. Source owns actual
registry, append proofs, minting and durable fencing; Library grants no execution.

Tests: declared bounds, historical versions, expungement, same-tick order, stale
epochs, backdated/early grants, missing windows/policies, and signed native Clear.
Run review/full/installed checks and push; no PR/merge/release.

Implemented selected duration-grant enforcement and Clear composition. Historical
versions, early/backdated and same-tick grants, epoch disagreement, expungement,
elapsed caps, missing windows/policies and signed native integration are tested.
Selected hysteresis now requires its reissue gate; relational remains disabled.
Continue anchored relational repair/human decision and remaining hand-back/runtime
families under the broader goal.

Checkpoint validation: supplier review cleared the implementation; 1,094 full
regressions and 44 installed-package related checks passed. Imports remain lazy
without optional dependencies. Push the checkpoint on the existing branch and
continue relational reconciliation and accountable decision gates.
