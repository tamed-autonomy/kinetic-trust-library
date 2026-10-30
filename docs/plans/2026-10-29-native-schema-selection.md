# Native proof policy cannot select legacy or fixture semantics

Canonical Trust Proof source at `bee83b9fadd503b3b73c63f05e5cc226000c4027`
requires native v3 artifacts to satisfy the native contract without selecting a
legacy schema or semantic fallback. Candidate proofs never select their policy.

Close the configuration boundary too: the v3 installed proof verifier requires
the native schema root identity. Schema bundles remain reusable generic local
utilities; using an arbitrary/legacy root in the native verifier is rejected.
Native evaluation and proof issuance reject the explicit test-only software
default flag, even if its caller has supplied an otherwise well-shaped graph.
Published fixture tests may still use that explicitly marked verifier helper.

This does not prove that trusted installed schema content or Source policy is
correct merely because an identifier matches. Exact bundled-source/hash checks,
local reference closure, signature/semantic validation and Source provenance
remain necessary. No root API/version/released v2 implementation changes.
