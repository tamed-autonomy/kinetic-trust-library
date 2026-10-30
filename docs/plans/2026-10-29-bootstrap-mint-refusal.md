# Missing-template sealed mint-refusal path

Source: hand-back §6.3 and HB-02-002 at
`5ea926338cb69a80fa9cf6a816334891acf9bed5`. The updated vector confirms the
requesting-principal channel, or failing that the deployment's declared default
endpoint. This routing rule does not require a final RFC decision.

## Distinct construction origin

`InstalledBootstrapHandBackVerifier` validates a sealed `mint_refused` message
without fabricating a registered template or a lease. Its assessment explicitly
names `mint-request-fallback`, is not clearance-capable, and never grants action
permission. Its Source context has no `template` field. Ordinary registered
template validation and all Clear prerequisites remain separate.

The installed private policy declares the authority, actual template registry,
default endpoint, class-scaled SLA/reissue floors, independent recourse and
same-subject repair references, and redaction policy. An actual anchored policy
declaration must predate the request. Source authenticates the complete signed
request and the historical absence lookup as of its acceptance time; both must
name the same immutable request/anchor and no template digest. The original
request's consequence class and whole actual operation are bound. An actual
relation mutation cannot use a lower class.

The request's named channel wins; mere unreachability never selects another
recipient. Only channel absence uses the declared default endpoint. Both paths
still seal to the same authenticated requesting principal's key; a default relay
does not acquire plaintext. Recipient accountability, class SLA ceiling,
independent contest ownership (excluding actor/operator/affiliates/measurers),
same-subject repair, full sealed sections, ciphertext digest/key/endpoint,
agent unreadability and capacity-aware resolved/parked delivery are shared
checks, without granting the bootstrap path template-registration semantics.

## Authority monitor and pricing

`InstalledMintStopVerifier` can symmetrically select the bootstrap profile. The
selected request record must explicitly supply the actual template digest or
absence. A present template uses the original installed verifier and must match
that digest. Absence uses the distinct bootstrap verifier and cross-checks the
whole authenticated request record. Missing selection facts cannot downgrade.
Deployment, authority, zone, algorithm, default/defect endpoints and class limits
must match. Actual Source errors propagate rather than becoming hostile wire.

When adjudicated hysteresis is selected, bootstrap and normal hand-back must
use the exact same installed verifier. The actual stop anchor, subject, class,
issuance, Exceeded variant and original quote must bind; a base-only reissue
time cannot replace the actual adjudicated price. Expungement remains a pricing
correction, never an invented breach or action permission.

## Delivery without a fictional grant

The explicit `anchored-retry-and-escalation-v2` lifecycle binds one of three
actual origins: granted lease, registered template without a lease, or the
authenticated mint request without a template. Origin kind, exact relevant
template/lease/request references and declaration time are checked. Bootstrap
requires actual request references on evaluation; it cannot select the older
grant-only lifecycle profile. A registered no-lease refusal can use the actual
template's registration as its origin instead of inventing a lease.

Routes, recipient/key and capacity binding must have been declared at that
origin. The same complete anchored queue/attempt/escalation/capacity/receipt/ack
validator and pure schedule accounting apply. A new receipt advances delivery
without rewriting the original parked wire. No lifecycle result authorizes an
action or claims actual transport/storage from a boolean.

These are selected private SDK records, not new RFC wire formats. Source owns
actual signatures, identity, lookup completeness, approved governing defaults,
route/key/custody truth, sealed contents, durable escrow, audit and receipts.
Actual minting/refusal dispatch, retries, crash recovery and protected effects
remain Service work. This slice does not decide the broader registered-template
absence case for a managed demotion outside a mint request.
