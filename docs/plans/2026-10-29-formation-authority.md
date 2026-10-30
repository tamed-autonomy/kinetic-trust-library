# Relation formation and direct revocation authority

Implemented against draft hand-back §§6.2 and 6.5 at
`17f37b772eac8b2f84248c1912f3aeb3f5fa26d1`, not a final 3.0 claim.

The pure formation projection binds subject, managed relation, signed consequence
class, immutable registered-template digest, counterparty, registration time,
formation time, countersignature time and actual witness/signature anchors.
Registration precedes formation/countersigning and the grant. This adapter uses
explicit integer-second times; it does not prescribe a new RFC wire format.

Installed non-clearance requires actual claimant authority for principal and
counterparty revocation. A counterparty obtains direct authority only for the
matching Relational formation witness. An unwitnessed claimant produces explicit
contest/suspension and identity-siting obligations, never direct `Revoked`.
Principal revocation remains independent. No revocation is classified as actor
breach or automatically countable adversity. Existing hand-back validation still
checks the original stop and sealed delivery destination.

Conditional clearance now requires countersigned formation, bound to the actual
registered template and original grant. Missing/malformed formation and an
unresolved formation objection block conditional Clear. An objection cannot be
cleared by a generic resolution boolean: this selected adapter requires an
actual newly classified formation record. Source owns complete history and
whether that new record lawfully replaces the prior record.

Source remains responsible for authenticating signatures, actual identity,
formation presence and complete objection history; the Library checks their
typed relationships. It performs no minting, revocation, suspension, identity
assurance, human classification or persistence itself. The pure projection and
all installed results grant no action permission. Actual operational Service
adapters and atomic revocation/commit integration remain unproven.

The subsequent `2026-10-29-mint-authority-stops.md` checkpoint adds installed
refusal and nonresponse-record checks. Remaining authority gaps include the
missing-template bootstrap route, full successful mint-request integration,
structural key/measurer separation and broader unmanaged-relation/demotion
history. These are not closed by the formation slice.
