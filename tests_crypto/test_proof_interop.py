"""End-to-end interoperation evidence for the official optional adapter."""

from __future__ import annotations

import asyncio
from base64 import urlsafe_b64decode
from dataclasses import replace
from datetime import timedelta
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from kinetic_trust_library.adapters.cryptography import (
    AsyncES256LocalSigner,
    AsyncEd25519LocalSigner,
    ES256LocalSigner,
    Ed25519LocalSigner,
    async_cryptography_proof_crypto,
    cryptography_proof_crypto,
    ed25519_public_key_bytes,
    es256_public_key_bytes,
)
from kinetic_trust_library.errors import VerificationKeySourceContractError
from kinetic_trust_library.models.proof import (
    KeyPurpose,
    OracleSigningIdentity,
    ProofAlgorithm,
    ProofIntent,
    TrustedVerificationKey,
    VerifiedTrustProof,
)
from kinetic_trust_library.proofs import AsyncTrustProofs, TrustProofs
from tests.unit.proofs._fixtures import complete_bundle


_COMPLETE_BUNDLE = complete_bundle()
_ED25519_NON_POINT_Y_TWO = bytes.fromhex("02" + ("00" * 31))


def _decode_segment(segment: str) -> bytes:
    return urlsafe_b64decode(segment + ("=" * (-len(segment) % 4)))


def _private_key(algorithm: ProofAlgorithm):
    if algorithm is ProofAlgorithm.ES256:
        return ec.derive_private_key(1, ec.SECP256R1())
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _public_key_bytes(algorithm: ProofAlgorithm, private_key) -> bytes:
    if algorithm is ProofAlgorithm.ES256:
        return es256_public_key_bytes(private_key.public_key())
    return ed25519_public_key_bytes(private_key.public_key())


def _identity(algorithm: ProofAlgorithm, private_key, cutoff) -> OracleSigningIdentity:
    return OracleSigningIdentity(
        issuer="https://oracle.example",
        key_id=f"interop-{algorithm.name.lower()}-key",
        algorithm=algorithm,
        purpose=KeyPurpose.ORACLE_TRUST_PROOF,
        public_key=_public_key_bytes(algorithm, private_key),
        signing_not_before=cutoff - timedelta(minutes=1),
        signing_not_after=cutoff + timedelta(minutes=1),
        revoked_at=None,
    )


def _trusted_key(identity: OracleSigningIdentity) -> TrustedVerificationKey:
    return TrustedVerificationKey(
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


class _KeySource:
    def __init__(self, trusted: TrustedVerificationKey) -> None:
        self.trusted = trusted
        self.calls = 0

    def resolve(self, lookup, /):
        self.calls += 1
        return self.trusted


class _AsyncKeySource(_KeySource):
    async def resolve(self, lookup, /):
        self.calls += 1
        return self.trusted


def _sync_signer(
    algorithm: ProofAlgorithm,
    identity: OracleSigningIdentity,
    private_key,
):
    if algorithm is ProofAlgorithm.ES256:
        return ES256LocalSigner(identity, private_key)
    return Ed25519LocalSigner(identity, private_key)


def _async_signer(
    algorithm: ProofAlgorithm,
    identity: OracleSigningIdentity,
    private_key,
):
    if algorithm is ProofAlgorithm.ES256:
        return AsyncES256LocalSigner(identity, private_key)
    return AsyncEd25519LocalSigner(identity, private_key)


def _verify_independently(raw: str, algorithm: ProofAlgorithm, private_key) -> None:
    header, payload, encoded_signature = raw.split(".")
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = _decode_segment(encoded_signature)
    if algorithm is ProofAlgorithm.ES256:
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        private_key.public_key().verify(
            utils.encode_dss_signature(r, s),
            signing_input,
            ec.ECDSA(hashes.SHA256()),
        )
        return
    private_key.public_key().verify(signature, signing_input)


class ProofInteropTests(unittest.TestCase):
    def test_one_fixed_complete_bundle_issues_self_verifies_and_independently_verifies(
        self,
    ):
        bundle = _COMPLETE_BUNDLE
        for algorithm in (ProofAlgorithm.ES256, ProofAlgorithm.ED25519):
            private_key = _private_key(algorithm)
            identity = _identity(algorithm, private_key, bundle.cutoff)
            keys = _KeySource(_trusted_key(identity))
            facade = TrustProofs(cryptography_proof_crypto())

            token = facade.issue(
                bundle,
                proof=ProofIntent(
                    proof_id=f"proof-interop-{algorithm.name.lower()}",
                    resource="urn:resource:interop",
                    context_hash="sha256:" + ("b" * 64),
                    trajectory_id="trajectory-interop-1",
                    lifetime_seconds=10,
                ),
                signer=_sync_signer(algorithm, identity, private_key),
            )
            verified = facade.verify(
                token.raw,
                cutoff=bundle.cutoff + timedelta(seconds=1),
                keys=keys,
            )

            with self.subTest(algorithm=algorithm):
                self.assertIs(type(verified), VerifiedTrustProof)
                self.assertEqual(verified.raw, token.raw)
                self.assertEqual(verified.claims.proof_id, token.proof_id)
                self.assertEqual(verified.claims.issuer, identity.issuer)
                self.assertEqual(verified.claims.subject, bundle.action.subject)
                self.assertEqual(verified.claims.action, bundle.action.digest)
                self.assertEqual(verified.claims.issued_at, bundle.cutoff)
                self.assertEqual(
                    verified.claims.expires_at, bundle.cutoff + timedelta(seconds=10)
                )
                self.assertEqual(verified.claims.decision_id, bundle.operation_id)
                self.assertEqual(verified.claims.resource, "urn:resource:interop")
                self.assertEqual(verified.claims.context_hash, "sha256:" + "b" * 64)
                self.assertEqual(verified.claims.trajectory_id, "trajectory-interop-1")
                self.assertEqual(verified.verification_key, keys.trusted)
                self.assertEqual(keys.calls, 1)
                _verify_independently(token.raw, algorithm, private_key)

    def test_non_point_trusted_ed25519_key_is_key_source_contract_failure(self):
        bundle = _COMPLETE_BUNDLE
        private_key = _private_key(ProofAlgorithm.ED25519)
        identity = _identity(ProofAlgorithm.ED25519, private_key, bundle.cutoff)
        facade = TrustProofs(cryptography_proof_crypto())
        token = facade.issue(
            bundle,
            proof=ProofIntent(
                proof_id="proof-non-point-trusted-key",
                resource="urn:resource:interop",
                context_hash="sha256:" + ("b" * 64),
                trajectory_id="trajectory-interop-1",
                lifetime_seconds=10,
            ),
            signer=_sync_signer(ProofAlgorithm.ED25519, identity, private_key),
        )
        malformed = replace(
            _trusted_key(identity),
            public_key=_ED25519_NON_POINT_Y_TWO,
        )

        with self.assertRaises(VerificationKeySourceContractError):
            facade.verify(
                token.raw,
                cutoff=bundle.cutoff + timedelta(seconds=1),
                keys=_KeySource(malformed),
            )


class AsyncProofInteropTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_async_and_sync_paths_emit_identical_canonical_tokens(self):
        asyncio.get_running_loop().slow_callback_duration = 2.0
        bundle = _COMPLETE_BUNDLE
        for algorithm in (ProofAlgorithm.ES256, ProofAlgorithm.ED25519):
            private_key = _private_key(algorithm)
            identity = _identity(algorithm, private_key, bundle.cutoff)
            sync_token = TrustProofs(cryptography_proof_crypto()).issue(
                bundle,
                proof=ProofIntent(
                    proof_id=f"proof-parity-{algorithm.name.lower()}",
                    resource="urn:resource:interop",
                    context_hash="sha256:" + ("b" * 64),
                    trajectory_id="trajectory-interop-1",
                    lifetime_seconds=10,
                ),
                signer=_sync_signer(algorithm, identity, private_key),
            )
            asynchronous = AsyncTrustProofs(async_cryptography_proof_crypto())
            async_token = await asynchronous.issue(
                bundle,
                proof=ProofIntent(
                    proof_id=f"proof-parity-{algorithm.name.lower()}",
                    resource="urn:resource:interop",
                    context_hash="sha256:" + ("b" * 64),
                    trajectory_id="trajectory-interop-1",
                    lifetime_seconds=10,
                ),
                signer=_async_signer(algorithm, identity, private_key),
            )
            keys = _AsyncKeySource(_trusted_key(identity))
            verified = await asynchronous.verify(
                async_token.raw,
                cutoff=bundle.cutoff + timedelta(seconds=1),
                keys=keys,
            )

            with self.subTest(algorithm=algorithm):
                self.assertEqual(async_token, sync_token)
                self.assertEqual(verified.raw, sync_token.raw)
                self.assertEqual(verified.claims.action, bundle.action.digest)
                self.assertEqual(verified.claims.issued_at, bundle.cutoff)
                self.assertEqual(
                    verified.claims.expires_at, bundle.cutoff + timedelta(seconds=10)
                )
                self.assertEqual(verified.claims.decision_id, bundle.operation_id)
                self.assertEqual(verified.claims.resource, "urn:resource:interop")
                self.assertEqual(verified.claims.context_hash, "sha256:" + "b" * 64)
                self.assertEqual(verified.claims.trajectory_id, "trajectory-interop-1")
                self.assertEqual(keys.calls, 1)
                _verify_independently(async_token.raw, algorithm, private_key)

    async def test_async_non_point_trusted_key_is_key_source_contract_failure(self):
        asyncio.get_running_loop().slow_callback_duration = 2.0
        bundle = _COMPLETE_BUNDLE
        private_key = _private_key(ProofAlgorithm.ED25519)
        identity = _identity(ProofAlgorithm.ED25519, private_key, bundle.cutoff)
        facade = AsyncTrustProofs(async_cryptography_proof_crypto())
        token = await facade.issue(
            bundle,
            proof=ProofIntent(
                proof_id="proof-async-non-point-trusted-key",
                resource="urn:resource:interop",
                context_hash="sha256:" + ("b" * 64),
                trajectory_id="trajectory-interop-1",
                lifetime_seconds=10,
            ),
            signer=_async_signer(ProofAlgorithm.ED25519, identity, private_key),
        )
        malformed = replace(
            _trusted_key(identity),
            public_key=_ED25519_NON_POINT_Y_TWO,
        )

        with self.assertRaises(VerificationKeySourceContractError):
            await facade.verify(
                token.raw,
                cutoff=bundle.cutoff + timedelta(seconds=1),
                keys=_AsyncKeySource(malformed),
            )


if __name__ == "__main__":
    unittest.main()
