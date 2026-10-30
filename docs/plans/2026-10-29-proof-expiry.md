# Ordinary proof expiry and independent lease lifetime

Hand-back §2.1 treats an expired ordinary proof for a managed identity as
routine reissue rather than a new adverse stop. The installed expiry adapter
authenticates the original signature with the ordinary verifier at the actual
current time, requires its stage-five time failure, and checks native schema,
subject, audience, static invariants, installed extensions and the originally
valid bounded lifetime. It never evaluates live Root at a historical time.
The result contains refresh metadata only and never grants permission.

Conditional clearance selects this adapter by an exact profile digest and the
same proof-verifier instance, with current installed management required. Its
proof refresh endpoint must differ from lease reissue. Current adverse stops,
revocation, epoch changes, consumed grants, inactive grants and independent
lease expiry take precedence. An active grant remains unchanged when proof
expiry produces `Expired`; no new hand-back or hysteresis event is fabricated.
The resulting assessment retains the original signature and expiry metadata.

The composed path also accepts authenticated absence of a current grant when
current management/admission and relation facts are valid, no retained intent
contradicts that absence, and no current adverse stop exists. A template need
not be invented to refresh a proof. Missing or malformed credentials still
cannot claim expiry; absence never produces clearance or a replacement grant.
Service owns actual management/stop/lease truth, authenticated time and atomic
effect fences. A registry must not erase a known revoked grant by reporting
absence; the authenticated source contract requires complete current state.

Tests use real signed ordinary proofs, reject bad signatures, subject mismatch,
malformed lifetime and unhealthy clocks, and exercise managed expiry with actual
native association and independent current lease state. Regression and installed
wheel checks are required before committing this checkpoint.
