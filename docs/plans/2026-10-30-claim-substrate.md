# Claim metadata names its RFC-carried substrate

Implement the claim-substrate boundary from proposal
`b016dac2fe93e12c668b224dc5ef9e317026e359`, its Claim Format text and three
`claims-substrate-v1` vectors. The installed RFC-set profile inventory is trusted
configuration, never supplied by a candidate claim. Exact identifier and version
must match; a missing or vendor-private profile cannot claim this specification.

The helper checks only this metadata boundary. Preserve the claim's level and
identify the profile under which its specified tests must run. Do not label
repository fixtures as runtime evidence, verify the stated test count, publish
a claim, or enable an otherwise unsupported execution profile. Format acceptance
does not establish conformance; evidence remains explicitly unverified.

Retain exact source vectors, exercise all three plus malformed/duplicate local
inventory and exact version boundaries, review, full regression, installed wheel
and checkpoint push. No Library/deployment conformance claim is made by this work.

Exact retained source SHA-256:
`694cdc069c69ffb748f2eb0d2d62688afdeaaba4667cfc527b96c609278ab892`.
