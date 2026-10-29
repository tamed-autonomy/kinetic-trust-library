# Refreshed native RFC schema references

Observed primary-source heads:

- canonical Trust Proof: `223f4259f7441ca97a916d26476a71b6114005a6`
- request association: `1ea01e4d0454d51583bd2eb7bf1e898c9252d722`
- decision geometry: `5878df1fcbb50f5f45672ddaf2a13c98d666e3d7`
- one Core contract: `40f00a02be58f8b43c31485c9ffcb021758372f6`

These are untagged proposals, not released authority. RFC main remains
`9612f7955d88e25d193dab2a17d51d0c9d9075d0`; the released baseline and package
version remain 2.1.0. This work neither merges proposals nor publishes a release.

## Implemented reconciliation

The refreshed Trust Proof and transaction-record schemas directly reference
`https://kinetic-trust-protocol.net/specs/schemas/v3/risk-factors.json`. The
Library now uses that exact native five-factor schema in its stage-6 validator,
native proof schema bundle, trajectory validator and test registries. The
published clear proof passes schema validation; a sixth `moment_criticality`
member is rejected. The function is still a shape check, never authorization.

Native proof and trajectory validators no longer rewrite a v2 reference into a
v3 reference in memory. The explicit native root/person composition remains;
only its risk reference was reconciled. No assumption is made that a single
upstream branch already includes every proposed root/person contract. The Soul
constraint's unchanged source reference remains shared; no v2 Risk Factor
schema or wire/runtime fallback is selected by the native path.

The obsolete six-factor risk resource and five-factor resource with a v2 alias
were removed from the native package and archived with prior proof/record
snapshots under `spec/proposals/archive/2026-10-29-pre-refresh/`. The frozen
`spec/v2.1.0` registry is unchanged. Prior snapshots remain evidence of the
earlier reference conflict, not active native validation policy.

`spec/proposals/rfc-refresh-2026-10-29.json` records 12 exact byte hashes against
their observed RFC commit/path. It includes the adopted proof/record schemas
and verified native Risk Factor, proof/vector, request/association, geometry
and demand-vector files. Request/association and geometry contract files did
not change in these refreshed trees. The five-factor schema and exact demand
vectors already matched. Manifest tests also check installed package resources,
so a source-tree-only change cannot hide stale packaged schemas.

Core's exact kickoff arithmetic remains `R=0.53975`, `E_trust=43.72375` at base
95. The corrected maintenance example is exercised at `R=0.0559825` and
`E_trust=89.6816625`, without intermediate rounding. Native code has one
five-factor risk aggregate and imposes no Node/Neighborhood/Global requirement;
the refreshed RFC makes those sensing scopes informative feed configuration.
This does not change the separately preserved released v2 implementation.

## Limits and continuation

This closes the observed risk-schema reference gap and checks the corresponding
contract snapshots and arithmetic. It does not prove every changed sentence in
all refreshed proposal trees or a complete 3.0 release. Root/person composition,
stronger cryptographic profiles, complete capability selection and final-tag
adoption remain explicitly scoped in the release-set inventory.

Next return to the production-review Full decision gate and protected commit
fences, then continue remaining implementable release-set paths. Actual Source
authenticity, durable replay/nonce consumption, protected effects and complete
ordinary authorization remain Service/provider responsibilities.

Verification: supplier review found no actionable defects and independently
matched all 12 recorded snapshots to their RFC Git bytes. All 1,170 regression
tests passed; the built package passed 19 focused schema/proof/native-readiness/
geometry tests. Eight pure arithmetic/snapshot checks passed without optional
dependencies. The frozen `spec/v2.1.0` tree has no diff from the prior checkpoint.
