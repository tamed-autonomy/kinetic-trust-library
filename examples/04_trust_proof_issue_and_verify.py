from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric import ed25519

from kinetic_trust_library import EvaluationBundle
from kinetic_trust_library.adapters.cryptography import (
    Ed25519LocalSigner,
    cryptography_proof_crypto,
    ed25519_public_key_bytes,
)
from kinetic_trust_library.models.proof import (
    KeyLookup,
    KeyPurpose,
    KeyResolution,
    OracleSigningIdentity,
    ProofAlgorithm,
    ProofIntent,
    TrustedVerificationKey,
    UnknownVerificationKey,
)
from kinetic_trust_library.proofs import TrustProofs

from _support import evaluate_clear_request


class LocalTrustedKeySource:
    def __init__(self, trusted_key: TrustedVerificationKey) -> None:
        self._keys = {
            (
                trusted_key.issuer,
                trusted_key.key_id,
                trusted_key.algorithm,
                trusted_key.purpose,
            ): trusted_key
        }

    def resolve(self, lookup: KeyLookup, /) -> KeyResolution:
        key = (
            lookup.untrusted_issuer,
            lookup.key_id,
            lookup.algorithm,
            lookup.purpose,
        )
        try:
            return self._keys[key]
        except KeyError:
            return UnknownVerificationKey(lookup.key_id)


def main() -> None:
    bundle = evaluate_clear_request()
    if (
        type(bundle) is not EvaluationBundle
        or bundle.standing is None
        or bundle.risk is None
        or bundle.trust is None
        or bundle.core_capacity is None
    ):
        raise RuntimeError("the shared model did not produce a complete evaluation")

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = ed25519_public_key_bytes(private_key.public_key())
    identity = OracleSigningIdentity(
        issuer="https://oracle.example",
        key_id="example-ed25519-key",
        algorithm=ProofAlgorithm.ED25519,
        purpose=KeyPurpose.ORACLE_TRUST_PROOF,
        public_key=public_key,
        signing_not_before=bundle.cutoff - timedelta(minutes=1),
        signing_not_after=bundle.cutoff + timedelta(minutes=1),
        revoked_at=None,
    )
    signer = Ed25519LocalSigner(identity, private_key)
    trusted_key = TrustedVerificationKey(
        issuer=identity.issuer,
        key_id=identity.key_id,
        algorithm=identity.algorithm,
        purpose=identity.purpose,
        public_key=identity.public_key,
        signing_not_before=identity.signing_not_before,
        signing_not_after=identity.signing_not_after,
        verification_not_after=identity.signing_not_after,
        revoked_at=None,
    )

    proofs = TrustProofs(cryptography_proof_crypto())
    proof_intent = ProofIntent(
        proof_id="proof-example-1",
        resource="urn:resource:example",
        context_hash="sha256:" + ("b" * 64),
        trajectory_id="trajectory-example-1",
        lifetime_seconds=10,
    )
    token = proofs.issue(
        bundle,
        proof=proof_intent,
        signer=signer,
    )
    verified = proofs.verify(
        token.raw,
        cutoff=bundle.cutoff + timedelta(seconds=1),
        keys=LocalTrustedKeySource(trusted_key),
    )
    if verified.claims.decision_id != bundle.operation_id:
        raise RuntimeError("verified proof decision ID does not match the evaluation")
    if verified.claims.issued_at != bundle.cutoff:
        raise RuntimeError("verified proof issued-at does not match the evaluation cutoff")
    if token.expires_at > bundle.cutoff + timedelta(seconds=10):
        raise RuntimeError("issued proof exceeds the requested lifetime")

    print("verified=true")
    print(f"proof_id={verified.claims.proof_id}")
    print(f"issuer={verified.claims.issuer}")
    print(f"subject={verified.claims.subject}")
    print(f"key_id={verified.verification_key.key_id}")
    print(f"E_base={verified.claims.base_trust}")
    print(f"risk={verified.claims.risk}")
    print(f"E_trust={verified.claims.effective_trust}")
    print(f"capacity_relation={bundle.core_capacity.relation.value}")
    print(f"within_capacity={bundle.core_capacity.within_capacity}")
    print(f"envelope_margin={bundle.envelope.margin}")
    print(f"envelope_supervision={bundle.envelope.supervision.value}")
    print("authorization_performed=false")


if __name__ == "__main__":
    main()
