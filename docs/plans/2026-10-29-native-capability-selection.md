# Explicit ordinary native capability scope

The installed profile is named `ordinary-native-v3`. It is a private SDK
selection, not a new normative RFC profile or a complete release-set claim.

Native Core contexts and the installed native evaluation facade now explicitly
reject `emergency_policy` and `oracle_consensus` declaration presence. The
selected SDK scope is disabled-only for these optional capabilities; omission
is required. Null, false, malformed and shape-valid bindings do not silently
enable them. This intentionally rejects an ordinary installation with such a
binding even if an external component might implement that optional capability;
that integration needs a future explicit supported-profile selection.

The evidence comes from emergency-capability's default-disabled/separate-policy
contract and the optional Oracle mesh contract at RFC main
`9612f7955d88e25d193dab2a17d51d0c9d9075d0`. Their declaration schemas alone do not
establish policy approval, quorum, independence, runtime consensus or execution.

The explicit execution selector rejects every profile except
`ordinary-native-v3`, including `software-substrate-decision`,
`consequential-action-evidence`, `emergency` and `oracle-consensus`. Generic
geometry, readiness or dispatch observations do not implement the separately
signed #131 software-substrate decision or #139 downstream-effect evidence.
Those contracts remain unsupported, rather than falling back to ordinary
semantics. Passing these selectors is not evidence of complete ordinary
authorization; all existing native restrictions and hand-back/commit gates
remain necessary.

This is an intentional scoped alternative allowed by the release-set work map,
not an unresolved RFC question. Supporting those optional capabilities remains
future implementation work; the current branch cannot claim them. Released
v2 code, public version and normative pin are unchanged.
