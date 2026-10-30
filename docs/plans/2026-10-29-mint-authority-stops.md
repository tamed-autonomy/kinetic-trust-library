# Lease-authority refusal and silence

Installed monitor implements the Library checks for draft hand-back §6.3,
HB-01-003 and HB-01-004 at
`17f37b772eac8b2f84248c1912f3aeb3f5fa26d1`.

The selected `mint-refusal-and-silence-v1` adapter binds the complete actual
authority request/response history to deployment, operation, subject, zone,
selected profile and current time. It supports pending requests and refusals.
Successful `Minted` assertions explicitly return `MINT_SUCCESS_REQUIRES_CLEARANCE`;
lease/formation/native/current-clearance validation remains mandatory elsewhere.
No result authorizes an action, mints a grant or treats authority silence as
subject breach.

The declared positive response SLA runs from the authenticated request time.
An anchored authority declaration must bind this exact selected profile and
predate the request; changing the SLA after receiving the request cannot erase
the original deadline under this installed selection. Source must authenticate
the actual governing declaration, not merely any older profile registration.
Before its deadline a pending assessment expires at the deadline. Still pending
at the deadline requires a recorded and routed event attributable to the lease
authority. A response received by the deadline is timely; a later refusal
retains this earlier obligation. This adapter uses explicit integer-second
times and a closed deadline convention; the RFC does not prescribe this wire.

Silence routing selects the requesting principal's declared channel, falling
back to the installed profile's declared default endpoint. These are authority
event routes, separate from the refusal's registered hand-back destination.
An actual silence record must name this authority, request and route, occur
after the deadline and before evaluation, and have a distinct audit anchor.
Recording does not establish routing: only a separate authenticated receipt
with matching endpoint, actual event anchor/request ID, distinct receipt anchor
and acceptance after recording clears
the routing obligation. The Source authenticates the actual receipt and its
association with this event; strings alone establish no transport fact.

Refusal requires the original hand-back bytes and actual digest, matching refusal
time, `mint_refused` reason, system-origin stop, no existing lease, and the same
requesting principal and consequence class. The existing installed hand-back
verifier checks registered routes, sealed content and resolved/parked delivery.
Missing/invalid hand-back remains explicit debt. Source and child-Source contract
failures propagate; they cannot silently become empty/pending history.

The missing-template bootstrap still cannot pass ordinary template validation.
The adapter exposes the requesting-principal/default routing obligation, but
does not invent a replacement template or claim that unresolved bootstrap
contract is implemented. Real authority requests, signatures, complete histories,
storage, routing receipts and transport remain Service-owned evidence. This is
not production integration or a final 3.0 conformance claim.
