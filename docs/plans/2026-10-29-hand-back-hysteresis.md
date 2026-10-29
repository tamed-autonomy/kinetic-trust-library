# Adjudicated hand-back hysteresis

Continue the approved hand-back implementation inline with TDD/supplier review.
Source: `17f37b772eac8b2f84248c1912f3aeb3f5fa26d1`, hand-back §7, HB-09 family.

Implement a named capped-linear reference policy, not a universal RFC formula.
Declarations specify owner/append protocol, retention/window, per-class minimum,
increment/cap and repeated-overturn threshold for per-revoker accounting.
Only authenticated adjudication-confirmed, unexpunged prior adverse events count.
Expiry/pending/overturned/false-causing-attestation entries never inflate subject
delay. Missing mandatory expungements remain correction obligations while being
excluded immediately. Revoker accounting spans the complete zone inventory and
never becomes a subject penalty or invented personal standing formula.

Use actual audit sequence for same-tick ordering and bind each stop and later
finding/expungement to actual anchors/records/times. Later expungement removes
wrongful history; later confirmation cannot retroactively increase an old price.
Source authenticates complete history and current head; Library owns arithmetic.

First checkpoint: pure projection plus installed current stop pricing, then
selected hand-back issue/reissue bound integration. Follow with grant reissue and
relational reconciliation/human-gate composition; do not leave those off the goal.
Run supplier review, full/installed tests and push. No PR/merge/release. Service
owns actual append/correction, revoker sanctions, durable state and commit fencing.

Implemented pure and installed current stop pricing plus selected hand-back
binding. Timelines preserve the original issued quote and current corrected
price; the priced stop itself is included and its expungement is visible.
Actual variant/anchor/profile/scope and original bound must agree. Grant-time
integration now exists in `2026-10-29-hand-back-reissue.md` and is required when
hysteresis is selected. Continue relational gates; no full HB-09/capability claim.

Checkpoint validation: supplier review cleared the implementation; 1,085 full
regressions and 35 installed-package related checks passed. Six pure tests also
pass without optional dependencies. Push on the existing development branch,
then continue the grant/reissue and relational work.
