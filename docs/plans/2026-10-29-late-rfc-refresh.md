# Reconciliation of the later October 29 proposal update

RFC main remains `9612f7955d88e25d193dab2a17d51d0c9d9075d0`; no final
`v3.0.0` tag was found. Newly fetched heads include:

- one-Core coalesced stack: `4ea1b6774dbe823659d305a4e5be4fa1af0e69ba`
- canonical proof: `bee83b9fadd503b3b73c63f05e5cc226000c4027`
- request association: `d67d3cca77ad00d00971dd87e96ec7ca4184ccf2`
- Decision Geometry: `4e37b72ab3bb82ba7770daaa1bd38d75a72567c2`
- hand-back: `5ea926338cb69a80fa9cf6a816334891acf9bed5`
- repair: `6892c709ecdb175523e4f9d435eb5f2fce742580`
- L11: `5e3b9344780225153552fc0381faa0c8f5ac74f8`
- person-root: `484414459f4e2ce2797f649845bd910331a0f3fa`
- explicit numeric-writing limit L23: `23417923576d89270d1cd5e407eba1f94e812941`

The schema/vector manifest now records 18 exact current snapshots, including
the complete proof/root/person schema supplied directly by the coalesced source.
The active base/composed proof resources are byte-identical. Prior exact bytes
and the former manifest remain in
`spec/proposals/archive/2026-10-29-before-late-refresh/`; the earlier archive and
the immutable released v2 registry are preserved. No schema alias or legacy
runtime fallback was added.

## Implemented changes

The common request/geometry/classifier unit is now exactly
`urn:ktp:unit:action-risk-points`. The former unit is rejected, not aliased.
Updated source vectors carry the corresponding canonical hashes/signatures.
All local fixture schema registries now include the actual Root dependency.
Canonical fixture proofs already carry subject kind and the missing-root ceiling;
fixtures no longer append duplicate ceilings or assume absent subject kind.
Person fixtures pass their independently installed expected subject class.

Sponsorship becomes eligible at or below the published count, even after earlier
blocking. In particular, a zero-count policy reopens after all breaches reconcile.
Historical blocked markers remain authenticated evidence but impose no extra
below-limit latch. Aggregate, class, capacity and hard-entry bounds remain.
The existing ambient projection already reports both utilization above capacity
and the actual stock change; its negative-stock-change test matches new BR27b.

Decision Geometry's unavailable/prohibited A/E input branches now use the updated
`TRUST_INSUFFICIENT` reason. Unavailable prior restriction state remains separately
undefined; no unknown input becomes measured zero. Fractional/integral-float
`evaluated_at` control tokens reject at encoding, matching the refreshed corpus.
Adjudication's schema ID adopts the new standalone namespace. The human-eligibility
clarification preserves the existing separation of operation eligibility from
zone-specific standing; no general human score or software fallback is enabled.

## Two verified upstream fixture defects

In exact Decision Geometry vectors from the coalesced source, `over-capacity`
and `equality` name the new unit in their actual request but retain the SHA-256
request association digest computed with the previous unit. The Library rejects
both original records as `DG_BINDING`. Tests prove the old preimage and separately
exercise locally corrected unsigned bodies as `DG_VALID`. The retained source
bytes and manifest hashes are unchanged; these two original cases are not
reported as passing published fixtures. An upstream fixture correction is owed,
not a relaxation of binding or a new normative interpretation.

## Precise remaining RFC dependencies

L23 now explicitly states that a normative written form for compared/digested
numbers is unresolved, including repeating allocation values and precision
beyond binary64. Existing exact rational computation and refusal of unsupported
wire representations remain; no rounding rule is invented. Person trajectory
ceiling and mixed local/imported standing questions also remain source decisions.
They do not stop independent implementation work.

The hand-back vector update removes its earlier bootstrap-question wording and
confirms §6.3's requesting-principal/default-endpoint route. That routing rule
is settled. The existing registered-template verifier cannot validate a missing
template; a separately scoped, sealed mint-refusal fallback adapter remains
implementable work rather than a reason to wait for a final tag.
