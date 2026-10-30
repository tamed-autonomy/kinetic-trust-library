# Complete signed carrier binding in protected software consumption

Software proposal `8dda717a51818a5e9ef00e36898ddae6af890230`, signed
consumption decision, requires complete required signed prerequisites in the
independently installed order. A protected native path requires the signed
geometry carrier, not merely its decoded geometry body or expiration.

The software consumer now derives the required order from its installed native
graph: readiness, geometry carrier where protected carriage is required, grant,
principal intent. A protected graph cannot install the weaker local-only order.
The carrier digest covers the complete unchanged ASCII compact JWS, including
its signature, taken from the independently verified typed native carrier.
Omission, substitution and reordering are rejected even under a valid software
decision signature. Existing proof/geometry/expiry checks remain in force.

Real signed protected-native integration traverses the same software consumer,
producer, continuing checkpoints and current-condition hand-back checks as the
local path. No alternate unsigned record or candidate-supplied carrier lookup is
introduced. Original carrier expiration remains an artifact lifetime bound.
