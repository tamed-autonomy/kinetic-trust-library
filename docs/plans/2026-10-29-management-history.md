# Management history, demotion and unmanaged responses

Draft source: hand-back §§2.1/2.2 and HB-13/HB-14 at
`17f37b772eac8b2f84248c1912f3aeb3f5fa26d1`.

The pure history projection requires a complete ordered admission/demotion
inventory with distinct anchors and explicit final hand-back digests. Demotion
changes classification immediately. A contest is not an admission event; it
cannot restore managed classification. Actual later admission is a separate
attested event, and old demotions/final hand-backs remain in history.

The installed wrapper binds registry, append protocol, ledger head, subject,
zone, actual operation, current time, actual ingress surface and credential
digest. Source must authenticate actual identity and the complete registry
history; this wrapper does not authenticate raw proof bytes. Managed status
never supplies Clear or action permission. The complete native proof and
clearance gates remain mandatory for every managed action.

A retained sealed assessment can be supplied as a prior checkpoint. The same
installed verifier rejects history truncation, altered prior events, ledger
rollback or equal-position changed heads. Source must provide complete history
on first observation, and Service must persist prior checkpoints/ledger state;
the SDK cannot detect a history never shown to it from counts alone. Policy
migration requires an explicit historical-checkpoint adapter; replacing the
verifier does not silently reauthorize an old checkpoint.

Every demotion retains the original operation and immutable final hand-back.
The installed hand-back validator must accept the same subject, demotion reason
and occurrence time. Missing/invalid final hand-backs leave explicit debt;
classification remains unmanaged and no action permission is produced.

Unmanaged responses never parse or echo raw credentials. Absent, expired,
malformed and nearly valid inputs receive the same 401/code/body; the body names
only the public admission endpoint. The single denial code is separate response
metadata. Declared
hostile-facing wire silence omits status and body. The admission channel always
returns only the public admission endpoint with the same denial code. Surface
and timing-uniformity limitations are explicit selected declarations. Actual
network timing and no-counteraction behavior require Service integration.

Demotion cannot prematurely hide its exit obligations behind wire silence. An
optional delivery verifier must be the exact installed hand-back graph and
match the selected digest. Without it, demoted identities retain generic denial.
With it, all retained final hand-backs need current, delivered, acknowledged and
effort-current lifecycle assessments before silence. This selected adapter
waits for acknowledgment as well as delivery; it does not infer completion from
an old wire delivery annotation. Missing facts/errors never become completion.

Selected resource bounds: 4096 classification events, 262144-byte state, and
1 MiB aggregate retained operation/hand-back input per call. Exceeding these
bounds requires a future authenticated archival adapter, never silent history
truncation. Actual registry durability, identities, signatures, ciphertext,
delivery receipts and protected commit fences remain Service/Source evidence.
