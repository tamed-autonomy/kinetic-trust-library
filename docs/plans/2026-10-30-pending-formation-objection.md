# Pending formation objection

Exact retained Hand-back case HB-02-004: a counterparty declines to countersign a
Logistics formation and objects that the effect mutates relation state. Minting
must suspend pending human classification; no mid-flight protocol is invented.

The existing private formation projection required a countersignature before it
could return that suspension. A failing source-backed regression reproduces it.
Allow both countersignature fields absent together only with a current,
authenticated, scoped objection and original registration/formation witness.
The derived pending-objection state is distinct from completed countersigning.
An absent grant time is allowed only for this pre-mint pending state; it creates
no direct revocation authority. Existing issued grant principals retain their
independent revocation power. Counterparty direct revocation still requires a
completed, unobjectioned Relational witness.

Source owns genuine counterparty identity, original objection/signature evidence,
complete history, human classification and actual mint suspension. No automatic
objection resolution flag, new public wire field, mint or revocation is added.
Verify pure boundary/chronology tests plus current installed clearance and
revocation integration, complete suite and installed wheel; review then push.
