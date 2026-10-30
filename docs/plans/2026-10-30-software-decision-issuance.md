# Installed software-decision producer

Extend the verified duration consumer with an installed claim authority and
separate private-key signing adapter. The claim authority returns a bounded
canonical unsigned payload for the exact operation, current time and installed
consumer profile. The same deterministic consumer checks establish all scope,
evidence, prerequisite, current grant, epoch, restriction and numeric conditions
before any signing call. The selected current public key must match the installed
issuer, zone, purpose, algorithm, profile, policy and validity interval.

Unsigned preparation has a separate `issuance_prepared` indication. Its
`verified`, `conditional_consumption` and `action_permitted` are false; it carries
no signed decision or commit conditions. A temporary local signature-shaped
placeholder permits reuse of the closed published shape validator only. It is
never authenticated or exposed as a usable artifact. No private key enters the
Library or an executing workload through this API.

After the signing adapter returns bounded raw signature bytes, the Library
builds the canonical complete artifact and independently verifies it against
fresh current software/clearance Source facts, retaining the preparation's
software and management checkpoints. Changed grant status, invalid signatures,
wrong keys and lost continuity withhold the artifact. A restrictive valid result
may be issued, but remains non-consumable. A completed artifact is not a release
receipt, and the caller still supplies the current native assessment and must
revalidate/fence the full native graph before actual effects.

The signed integration exercises real Ed25519 issuance plus incorrect input,
issuer/time/algorithm selection, invalid raw signatures, no-sign-on-invalid and
a grant revocation during signing. These use modeled authenticated operational
Sources, not a deployed key-custody or measurement service.
