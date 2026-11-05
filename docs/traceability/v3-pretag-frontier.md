# Current pre-tag frontier — 2026-11-04

Existing branch: `codex/ktp-v3-library-planning`. The released root/package/spec
pin remains 2.1.0; native v3 stays separate with no old wire/API/runtime fallback.
No PR, merge, tag, version cutover or release is authorized by this work.

## New settled Library work completed

- Revised #131 wire and semantics: versioned artifact/profile/JWS, requester and
  executing-workload binding, repair classes, per-level available supervision,
  novelty domains, installed time resolution and capacity-veto policy code.
- Revised #139: canonical signed five-state evidence, complete protected-path
  non-dispatch, scoped current signing keys and shortest validity; cumulative
  shared-budget/replay inventory, per-attempt history, uncertain-state retention,
  authenticated non-dispatch retry, protected recovery continuity and atomic terms.
- Real native/software current-use graph composed immediately before a release
  candidate; current authorization/evidence, target and recorder loss withhold.
  Preflight observation stays unknown and returns a recording obligation.
- Native API exports, packaged schemas, isolated imports, source hashes, exact
  E08/E27 numeric and all 24 evidence-schema outcomes have been verified.

The reviewed implementation checkpoint is `05cfd9f9dfff2f2163d5553b86c4a33ba24fc7a5`.
Its required suite passed 1,407 tests without skips; the wheel passed 42 checks,
with separate cryptography/provider lanes passing 36/8. Review found and closed
signing-key and transitive non-dispatch validity bugs. The immutable component
coverage record is [consequential-action-v1-coverage.json](consequential-action-v1-coverage.json).
The 27 remaining source contract cases are explicitly not reported as a complete
runtime qualification. Related unit/integration tests are recorded in the main
gap map; a source integrity runner or flag-driven simulation is not substituted
for an actual implementation run.

## Upstream decisions and corrections still required

Live GitHub check: all six issues remain open without comments.

| Gate | Required source answer | Current safe boundary |
|---|---|---|
| [#213](https://github.com/nmcitra/ktp-rfc/issues/213) | Correct the two geometry fixture request preimages/digests | Original fixtures remain intact; corrected isolated semantic checks do not qualify broken originals |
| [#214](https://github.com/nmcitra/ktp-rfc/issues/214) | Reconcile person-proof introduction with its coordinated person branch | Subject-specific implementation remains explicitly provisional |
| [#215](https://github.com/nmcitra/ktp-rfc/issues/215) | Concurrent person Root selection/ranking | Zero/single-current-Root route; no invented additive credit or software ranking |
| [#216](https://github.com/nmcitra/ktp-rfc/issues/216) | Local/imported person-standing composition and re-export boundary | Distinct scoped routes; no implicit mixed accumulation |
| [#217](https://github.com/nmcitra/ktp-rfc/issues/217) | FD27 earned-at-80 versus intrinsic-at-80 sponsorship closure | Declared provisional ceiling and historical birth bounds; no interpretation promoted to normative |
| [#218](https://github.com/nmcitra/ktp-rfc/issues/218) | Protected amendment-route recurrence interpretation | Reject unsupported changes rather than infer new amendment permissions |

Exact derived-number wire/rounding policy and stronger named crypto/receipt
profiles also await the source decision/adoption boundary. Writers reject
unrepresentable values; unsupported profiles remain withheld. Do not reopen the
explicitly deferred decisions by supplying a local default.

RFC main is still `9612f7955d88e25d193dab2a17d51d0c9d9075d0`; no 3.x tag was
advertised. #131 remains open at `652c06b68af7f6ee0785ab14399be68bc458843e`;
#139 remains open at `0e40c31305cc80779949c8a6fef5eb2cf3ca49f9`.

## Independent consuming-Service qualification

Real deployed Sources must establish measurements and original artifact/key
truth, actual participants/consent/liability, complete current registries and
protected audit/replay inventories. The Service must demonstrate full-scope
atomic compare/reserve and target/version/authority enforcement, durable
idempotency/recovery, recording, bounded safe transitions and authentic target
and protected non-dispatch observations. Library tests do not supply this evidence.

The cumulative budget has no automatic reset/charge expiry. Other accounting,
target and stronger signing profiles are outside the selected adapter, with no
fallback. Emergency and Byzantine-consensus declarations are explicitly rejected
by the ordinary native profile. These scoped choices are not claims that every
optional KTP deployment capability has been implemented.

At final adoption: compare every exact retained proposal/schema/catalog to the
adopted tag, reconcile the gates above, run the applicable chosen capability and
source-case qualification, then perform the separately authorized root/API/version/
pin cutover and consuming-Service validation. A final tag alone does not perform
those steps or supply operational evidence.
