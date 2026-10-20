# Trust Proof issuance and verification

## Problem

Issue and authenticate a short-lived Trust Proof for one complete Soul-clear Library
evaluation.

## Application supplies

The example supplies an ephemeral Ed25519 signing key, an
`OracleSigningIdentity`, and an application-owned trusted-key resolver. A real
product owns secure key storage, rotation, trust anchoring, and key retrieval.

## Library call

The script uses `TrustProofs.issue()` to create a `ProofToken`, then
`TrustProofs.verify()` with the optional cryptography adapter and trusted-key
source.

The caller supplies a `ProofIntent` containing proof ID, resource, context hash,
trajectory ID, and a requested lifetime of one through ten seconds. The Library derives
`decision_id` from the validated evaluation's operation ID and `issued_at` from
its exact whole-second UTC cutoff. Expiration is no later than the requested
lifetime and is tightened to the whole-second end of a current or non-renewable
root. The script asserts those bindings after real cryptographic verification.

## Library returns

Successful verification returns `VerifiedTrustProof` with authenticated claims
and the verification key. The example prints stable claim fields, never key or
token material. It also prints the original evaluation's distinct capacity
relation/within fact and Envelope margin/supervision. Verification does not
reconstruct those local results.

## Application decides

The product decides operational consequences. Verification authenticates the proof claims. It does not reconstruct the
original evaluation, authorize an action, enforce a decision, or establish
application conformance.

Proof is not permission: it attests evaluated facts, not acceptance, action
execution, enforcement, storage, or persistence.

## Run and dependencies

This requires `.[cryptography]`.

```console
.venv/bin/python examples/04_trust_proof_issue_and_verify.py
```
