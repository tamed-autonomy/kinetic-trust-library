# Current management history in conditional clearance

Extends draft hand-back §§2.1/2.2 at
`17f37b772eac8b2f84248c1912f3aeb3f5fa26d1`.

The clearance policy supports a symmetric `management_profile_digest` selection
with the exact installed hand-back graph and zone. The selected management
verifier receives the actual native proof bytes, encoded from the immutable
association input, not a caller-supplied substitute credential. Its current
authenticated ingress classification runs before the managed-relation registry
is queried. Unmanaged results cannot become conditional Clear; they preserve
the uniform admission-route response and any final-demotion hand-back debt.

For managed requests, the actual grant registry must bind the current admission
anchor, and the grant must have been issued after that admission. Readmission
does not retroactively validate a prior relation's grant. Parent Clear retains
the complete management assessment and earliest validity limit, alongside all
ordinary native, formation, template, reissue, human and authority restrictions.

History continuity now rejects both prefix rewriting and events inserted at or
before an already observed ledger head. A prior sealed in-memory assessment can
be supplied explicitly. For restart continuity, the authenticated Source context
can carry `retained_checkpoint_bytes`: actual prior canonical state restored
from protected storage. The SDK checks the same scope, valid historical
inventory, temporal/head order and append-only extension. The old checkpoint
may have expired as a current decision; expiration does not erase history.

Only Source-authenticated restored bytes are accepted. Arbitrary wire bytes are
not a checkpoint and no Python object deserialization is required. The result
retains the exact restored checkpoint and current Source evidence for audit.
Source must establish the real persisted checkpoint and completeness; Service
must durably persist it and protect it against rollback. These obligations
cannot be proven from a self-declared history/count or a digest alone.

Actual request identity, membership authority, storage, protected currentness,
full current-Clear authorization and atomic effect/nonce fencing remain
Source/Service work. The selected Library path grants no action permission.
Policy migration of historical checkpoints still needs an explicit scoped
adapter; this path handles unchanged installed policy only.
