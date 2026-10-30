# Registered counterparty hand-back context

HB-11-003 and Hand-back §4.4 require a populated registered counterparty endpoint
to receive action, reason class and attestation references, never drafts. Keep
primary full context and the closed public hand-back wire unchanged.

Add an installed companion over a separately valid original primary hand-back.
Authenticate the actual complete registered redaction-policy bytes, bound by the
original template digest reference and original pre-grant registration. Bind the
policy to stable template ID/version/subject/class rather than its digest to avoid
a hash cycle. Bind the exact primary ciphertext and original reference inventory,
then enforce the complete policy-permitted subset in the limited projection.

This private selected policy explicitly takes reason class from hand-back.reason
(the pinned wire schema calls that enum the reason class). No numeric diagnostics
or alternative inferred mapping. Distinct primary/counterparty principals,
endpoints and keys are conservative profile restrictions, not universal RFC rules.

Source authenticates registry/current original policy, ciphertext decryption and
actual content, complete primary references, recipient identity/key custody and
agent inability to decrypt. SDK independently checks exact limited field set,
actual original action/reason, selected reference subset and all artifact/policy/
operation/template/route/key/time digest bindings. No signature wire, transport,
delivery receipt or permission is invented. Construction cannot establish actual
secondary delivery; Service retains that separate obligation.

Verify real AES-GCM fixture contents, missing/extra/redacted fields, substituted
primary/limited ciphertext, policies registered after grant, endpoint/key changes,
wrong action/reason/references and Source contract failures. Review, full suite,
installed package, push, continue.
