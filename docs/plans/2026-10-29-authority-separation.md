# Structural authority and measurer separation

Draft source: hand-back §5 and conformance §10.5 / HB-05 at
`17f37b772eac8b2f84248c1912f3aeb3f5fa26d1`.

The pure validator checks actual enumerated agent/boundary processes, lease
constructor capabilities, authority/measurer accepted keys, key access/custody,
operator boundaries, measurer processes, declared quorum and actually used
measurers. Accepted keys must have explicit custody entries; absence is not
assumed separation. A capability or accepted-key access inside the agent trust
boundary fails. A process both measuring and carrying action fails.

The outside-operator measurer must actually participate in the current decision,
not just appear as an unused roster entry. Blue/Deep Blue require declared k-of-n
with k>=2. Green/Cyan selecting k=1 require an explicit limitation declaration;
this records the Cyan SHOULD deviation rather than silently calling it redundant.
Two measurer identities accepting one shared signing key, or counted measurers
sharing an execution process, cannot count as an independent quorum in this
selected profile. Audit inventories must cover actual access/control paths,
including shared supervisory processes; separate labels are not independence.

The installed verifier binds the audit to its exact profile and static inventory
digest, trusted named auditor, current audit-age ceiling and actual current
operation/zone/decision/lease authority. Actually counted attestation records
must name the correct measurer/key, distinct actual audit references and this
decision. Source authenticates the original signatures and the association
between actual environment evidence and the native decision; these records do
not pretend that measurers directly signed the entire Decision Geometry.

Custody inventories describe actual capabilities and access, including remote
signing access, not just which filesystem/HSM physically holds a key. The Source
must establish complete current facts and the governing zone class/authority
key registries. Counts, names and digests cannot prove physical independence.
The projection explicitly labels evidence `architectural-audit`. It makes no
cryptographic custody proof, deployment certification or Full conformance claim.

Conditional clearance supports a symmetric `authority_profile_digest` selection
with the exact installed deployment, zone, algorithm and lease authority. A
selected failed audit blocks conditional Clear; the parent retains the actual
assessment and takes the earliest expiry. Existing Native/Soul/envelope/reissue/
formation/template/relational restrictions remain necessary. Omitting this
selection does not establish a hand-back architectural-audit claim.

Actual audit collection, key/process discovery, audited completeness, signature
verification, revocation, protected currentness and atomic effect fencing remain
Source/Service work. Service must revalidate current complete Clear and fence
the governing protected state at commit. This slice does not itself revoke,
mint, dispatch, write audit records or authorize an effect.
