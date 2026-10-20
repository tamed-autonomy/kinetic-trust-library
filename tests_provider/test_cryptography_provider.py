"""Run the reusable provider contract against the official optional adapter."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha512
from inspect import isawaitable
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.exceptions import (
    InternalError,
    InvalidSignature,
    UnsupportedAlgorithm,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from kinetic_trust_library.adapters import cryptography as adapter
from kinetic_trust_library.adapters.cryptography import (
    AsyncES256LocalSigner,
    AsyncEd25519LocalSigner,
    ES256LocalSigner,
    Ed25519LocalSigner,
    async_cryptography_proof_crypto,
    cryptography_proof_crypto,
)
from kinetic_trust_library.models.proof import (
    KeyPurpose,
    OracleSigningIdentity,
    ProofAlgorithm,
    SignatureVerificationOutcome,
)
from kinetic_trust_library.protocols import ProviderFailure, ProviderUnavailable
from tests_provider.conformance import (
    CancellationMode,
    ExecutionMode,
    FaultRequest,
    InjectedFault,
    Observation,
    ObservedCase,
    OperationRequest,
    PinnedVector,
    ProviderAttempt,
    ProviderEvidence,
    ProviderFactories,
    ProviderOperation,
    ReachedCancellationCase,
    TrustProofProviderContract,
)


_NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
_P256_ORDER = int(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    16,
)
_ED25519_ORDER = int(
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
    16,
)
_ED25519_NON_POINT_Y_TWO = bytes.fromhex("02" + ("00" * 31))

# RFC 6979 Appendix A.2.5, P-256/SHA-256, message "sample". RFC 6979's
# high-S response is pinned below as a rejection vector; KTP output is low-S.
_ES256_PRIVATE_KEY = ec.derive_private_key(
    int("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", 16),
    ec.SECP256R1(),
)
_ES256_PUBLIC_KEY = bytes.fromhex(
    "04"
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
)
_ES256_SIGNATURE = bytes.fromhex(
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
    "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9"
)
_ES256_HIGH_S_SIGNATURE = bytes.fromhex(
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
)
_ES256_DER_SIGNATURE = bytes.fromhex(
    "3045022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0e"
    "a84eaf371602200834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5"
    "f51f93782857a9"
)
_ES256_OTHER_PUBLIC_KEY = bytes.fromhex(
    "04"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
_ES256_OTHER_SIGNATURE = bytes.fromhex(
    "019cdb1385a6cf8575a83b0b710495916e92a3075495496d52b59108e39dfaf7"
    "16a2eb065cb9ad1507aa68dad5b4d37cbc4a83d66d2f02b273b383e7d81e87c9"
)

# RFC 8032 section 7.1, TEST 2.
_ED25519_PRIVATE_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
)
_ED25519_PUBLIC_KEY = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)
_ED25519_SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)
_ED25519_OTHER_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
_ED25519_OTHER_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)

_VECTORS = (
    PinnedVector(
        algorithm=ProofAlgorithm.ES256,
        signing_input=b"sample",
        public_key=_ES256_PUBLIC_KEY,
        signature=_ES256_SIGNATURE,
        other_public_key=_ES256_OTHER_PUBLIC_KEY,
        other_signature=_ES256_OTHER_SIGNATURE,
        invalid_public_keys=(b"", b"\x04" + (b"\x00" * 64)),
        invalid_signatures=(
            b"",
            _ES256_HIGH_S_SIGNATURE,
            _ES256_DER_SIGNATURE,
        ),
    ),
    PinnedVector(
        algorithm=ProofAlgorithm.ED25519,
        signing_input=b"\x72",
        public_key=_ED25519_PUBLIC_KEY,
        signature=_ED25519_SIGNATURE,
        other_public_key=_ED25519_OTHER_PUBLIC_KEY,
        other_signature=_ED25519_OTHER_SIGNATURE,
        invalid_public_keys=(b"", _ED25519_NON_POINT_Y_TWO),
        invalid_signatures=(
            b"",
            _ED25519_NON_POINT_Y_TWO + _ED25519_SIGNATURE[32:],
            _ED25519_SIGNATURE[:32] + _ED25519_ORDER.to_bytes(32, "little"),
        ),
    ),
)
_VECTOR_BY_ALGORITHM = {vector.algorithm: vector for vector in _VECTORS}


def _identity(algorithm: ProofAlgorithm) -> OracleSigningIdentity:
    vector = _VECTOR_BY_ALGORITHM[algorithm]
    return OracleSigningIdentity(
        issuer="https://provider-contract.example",
        key_id=f"contract-{algorithm.name.lower()}-key",
        algorithm=algorithm,
        purpose=KeyPurpose.ORACLE_TRUST_PROOF,
        public_key=vector.public_key,
        signing_not_before=_NOW - timedelta(minutes=1),
        signing_not_after=_NOW + timedelta(minutes=1),
        revoked_at=None,
    )


def _verifier(algorithm: ProofAlgorithm):
    return next(
        binding.verifier
        for binding in cryptography_proof_crypto().bindings
        if binding.algorithm is algorithm
    )


def _async_verifier(algorithm: ProofAlgorithm):
    return next(
        binding.verifier
        for binding in async_cryptography_proof_crypto().bindings
        if binding.algorithm is algorithm
    )


def _reference_verify(
    algorithm: ProofAlgorithm,
    public_key: bytes,
    signing_input: bytes,
    signature: bytes,
) -> SignatureVerificationOutcome:
    try:
        if algorithm is ProofAlgorithm.ES256:
            if len(signature) != 64:
                return SignatureVerificationOutcome.INVALID_SIGNATURE
            key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                public_key,
            )
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            key.verify(
                utils.encode_dss_signature(r, s),
                signing_input,
                ec.ECDSA(hashes.SHA256()),
            )
        else:
            key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(signature, signing_input)
    except ValueError:
        return SignatureVerificationOutcome.INVALID_PUBLIC_KEY
    except InvalidSignature:
        return SignatureVerificationOutcome.INVALID_SIGNATURE
    return SignatureVerificationOutcome.VALID


@dataclass(slots=True)
class _Trace:
    attempts: list[ProviderAttempt] = field(default_factory=list)
    fallback_used: bool = False
    usable_result_produced: bool = False

    def snapshot(self) -> Observation:
        return Observation(
            attempts=tuple(self.attempts),
            fallback_used=self.fallback_used,
            usable_result_produced=self.usable_result_produced,
        )


def _effect(fault: InjectedFault | None) -> BaseException | None:
    if fault is InjectedFault.UNAVAILABLE:
        return UnsupportedAlgorithm("injected provider capability failure")
    if fault is InjectedFault.FAILURE:
        return InternalError("injected provider operational failure", [])
    return None


def _finish_observed(result, trace: _Trace):
    if not isawaitable(result):
        trace.usable_result_produced = True
        return result

    async def finish():
        value = await result
        trace.usable_result_produced = True
        return value

    return finish()


def _observed_signer_case(
    request: OperationRequest,
    fault: InjectedFault | None,
) -> ObservedCase:
    vector = _VECTOR_BY_ALGORITHM[request.algorithm]
    trace = _Trace()
    effect = _effect(fault)
    modules = adapter._load_cryptography()

    if request.algorithm is ProofAlgorithm.ES256:

        class ObservedPrivateKey:
            def public_key(self):
                return _ES256_PRIVATE_KEY.public_key()

            def sign(self, signing_input, signature_algorithm):
                trace.attempts.append(
                    ProviderAttempt(
                        ProviderOperation.SIGN,
                        request.algorithm,
                        signing_input,
                        None,
                        None,
                        False,
                    )
                )
                if effect is not None:
                    raise effect
                return _ES256_PRIVATE_KEY.sign(signing_input, signature_algorithm)

        observed_key = ObservedPrivateKey()
        observed_ec = SimpleNamespace(
            ECDSA=modules.ec.ECDSA,
            EllipticCurvePrivateKey=ObservedPrivateKey,
            EllipticCurvePublicKey=modules.ec.EllipticCurvePublicKey,
            SECP256R1=modules.ec.SECP256R1,
        )
        observed_modules = replace(modules, ec=observed_ec)
        signer_type = (
            ES256LocalSigner
            if request.mode is ExecutionMode.SYNC
            else AsyncES256LocalSigner
        )
    else:

        class ObservedPrivateKey:
            def public_key(self):
                return _ED25519_PRIVATE_KEY.public_key()

            def sign(self, signing_input):
                trace.attempts.append(
                    ProviderAttempt(
                        ProviderOperation.SIGN,
                        request.algorithm,
                        signing_input,
                        None,
                        None,
                        False,
                    )
                )
                if effect is not None:
                    raise effect
                return _ED25519_PRIVATE_KEY.sign(signing_input)

        observed_key = ObservedPrivateKey()
        observed_ed25519 = SimpleNamespace(
            Ed25519PrivateKey=ObservedPrivateKey,
            Ed25519PublicKey=modules.ed25519.Ed25519PublicKey,
        )
        observed_modules = replace(modules, ed25519=observed_ed25519)
        signer_type = (
            Ed25519LocalSigner
            if request.mode is ExecutionMode.SYNC
            else AsyncEd25519LocalSigner
        )

    with patch.object(
        adapter,
        "_load_cryptography",
        return_value=observed_modules,
    ):
        signer = signer_type(_identity(request.algorithm), observed_key)

    def invoke():
        return _finish_observed(signer.sign(vector.signing_input), trace)

    return ObservedCase(invoke=invoke, snapshot=trace.snapshot)


def _observed_verifier_case(
    request: OperationRequest,
    fault: InjectedFault | None,
) -> ObservedCase:
    vector = _VECTOR_BY_ALGORITHM[request.algorithm]
    trace = _Trace()
    effect = _effect(fault)
    modules = adapter._load_cryptography()

    if request.algorithm is ProofAlgorithm.ES256:

        class ObservedPublicKey:
            def __init__(self, key, encoded) -> None:
                self._key = key
                self._encoded = encoded

            @classmethod
            def from_encoded_point(cls, curve, encoded):
                key = ec.EllipticCurvePublicKey.from_encoded_point(curve, encoded)
                return cls(key, encoded)

            def verify(self, encoded_signature, signing_input, signature_algorithm):
                r, s = utils.decode_dss_signature(encoded_signature)
                raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
                trace.attempts.append(
                    ProviderAttempt(
                        ProviderOperation.VERIFY,
                        request.algorithm,
                        signing_input,
                        self._encoded,
                        raw_signature,
                        False,
                    )
                )
                if effect is not None:
                    raise effect
                return self._key.verify(
                    encoded_signature,
                    signing_input,
                    signature_algorithm,
                )

        observed_ec = SimpleNamespace(
            ECDSA=modules.ec.ECDSA,
            EllipticCurvePrivateKey=modules.ec.EllipticCurvePrivateKey,
            EllipticCurvePublicKey=ObservedPublicKey,
            SECP256R1=modules.ec.SECP256R1,
        )
        observed_modules = replace(modules, ec=observed_ec)
        verifier_type = (
            adapter._ES256Verifier
            if request.mode is ExecutionMode.SYNC
            else adapter._AsyncES256Verifier
        )
    else:

        class ObservedPublicKey:
            def __init__(self, key, encoded) -> None:
                self._key = key
                self._encoded = encoded

            @classmethod
            def from_public_bytes(cls, encoded):
                key = ed25519.Ed25519PublicKey.from_public_bytes(encoded)
                return cls(key, encoded)

            def verify(self, signature, signing_input):
                trace.attempts.append(
                    ProviderAttempt(
                        ProviderOperation.VERIFY,
                        request.algorithm,
                        signing_input,
                        self._encoded,
                        signature,
                        False,
                    )
                )
                if effect is not None:
                    raise effect
                return self._key.verify(signature, signing_input)

        observed_ed25519 = SimpleNamespace(
            Ed25519PrivateKey=modules.ed25519.Ed25519PrivateKey,
            Ed25519PublicKey=ObservedPublicKey,
        )
        observed_modules = replace(modules, ed25519=observed_ed25519)
        verifier_type = (
            adapter._Ed25519Verifier
            if request.mode is ExecutionMode.SYNC
            else adapter._AsyncEd25519Verifier
        )

    verifier = verifier_type(observed_modules)

    def invoke():
        result = verifier.verify(
            public_key=vector.public_key,
            signing_input=vector.signing_input,
            signature=vector.signature,
        )
        return _finish_observed(result, trace)

    return ObservedCase(invoke=invoke, snapshot=trace.snapshot)


def _observed_success(request: OperationRequest) -> ObservedCase:
    if request.operation is ProviderOperation.SIGN:
        return _observed_signer_case(request, None)
    return _observed_verifier_case(request, None)


def _observed_fault(request: FaultRequest) -> ObservedCase:
    if request.operation.operation is ProviderOperation.SIGN:
        return _observed_signer_case(request.operation, request.fault)
    return _observed_verifier_case(request.operation, request.fault)


def _bounded_local_cancellation(
    algorithm: ProofAlgorithm,
    operation: ProviderOperation,
) -> CancellationMode:
    return CancellationMode.BOUNDED_NO_AWAIT


def _unreachable_reached_cancellation(
    algorithm: ProofAlgorithm,
    operation: ProviderOperation,
) -> ReachedCancellationCase:
    raise AssertionError("bounded local provider has no reached await boundary")


_OFFICIAL_EVIDENCE = ProviderEvidence(
    vectors=_VECTORS,
    reference_verify=_reference_verify,
    observed_success=_observed_success,
    observed_fault=_observed_fault,
    cancellation_mode=_bounded_local_cancellation,
    reached_cancellation=_unreachable_reached_cancellation,
)


def _official_factories() -> ProviderFactories:
    return ProviderFactories(
        es256_signer=lambda: ES256LocalSigner(
            _identity(ProofAlgorithm.ES256),
            _ES256_PRIVATE_KEY,
        ),
        async_es256_signer=lambda: AsyncES256LocalSigner(
            _identity(ProofAlgorithm.ES256),
            _ES256_PRIVATE_KEY,
        ),
        ed25519_signer=lambda: Ed25519LocalSigner(
            _identity(ProofAlgorithm.ED25519),
            _ED25519_PRIVATE_KEY,
        ),
        async_ed25519_signer=lambda: AsyncEd25519LocalSigner(
            _identity(ProofAlgorithm.ED25519),
            _ED25519_PRIVATE_KEY,
        ),
        verifier=_verifier,
        async_verifier=_async_verifier,
        evidence=_OFFICIAL_EVIDENCE,
    )


class CryptographyProviderContractTests(
    TrustProofProviderContract,
    unittest.IsolatedAsyncioTestCase,
):
    factories = _official_factories()


class ProviderObservationIntegrityTests(unittest.TestCase):
    def test_es256_trace_records_actual_der_scalars_reaching_backend(self):
        real_modules = adapter._load_cryptography()
        mutated_raw = (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
        mutated_utils = SimpleNamespace(
            decode_dss_signature=real_modules.asymmetric_utils.decode_dss_signature,
            encode_dss_signature=lambda r, s: utils.encode_dss_signature(1, 1),
        )
        modules = replace(real_modules, asymmetric_utils=mutated_utils)
        request = OperationRequest(
            ProofAlgorithm.ES256,
            ProviderOperation.VERIFY,
            ExecutionMode.SYNC,
        )

        with patch.object(adapter, "_load_cryptography", return_value=modules):
            case = _observed_verifier_case(request, None)
        case.invoke()

        self.assertEqual(case.snapshot().attempts[0].signature, mutated_raw)


class ProviderKitAdversarialRegressionTests(unittest.TestCase):
    def test_self_consistent_noncryptographic_provider_fails_the_contract(self):
        class ToySigner:
            def __init__(self, algorithm: ProofAlgorithm) -> None:
                self.algorithm = algorithm
                self.identity = _identity(algorithm)

            def sign(self, signing_input: bytes, /) -> bytes:
                if type(signing_input) is not bytes:
                    raise ProviderFailure("toy input failure")
                digest = sha512(b"silently-prefixed:" + signing_input).digest()
                if self.algorithm is ProofAlgorithm.ES256:
                    r = digest[:32]
                    s = int.from_bytes(digest[32:], "big") % (_P256_ORDER // 2) + 1
                    return r + s.to_bytes(32, "big")
                return digest

        class AsyncToySigner(ToySigner):
            async def sign(self, signing_input: bytes, /) -> bytes:
                return super().sign(signing_input)

        class ToyVerifier:
            def __init__(self, algorithm: ProofAlgorithm) -> None:
                self.algorithm = algorithm

            def verify(self, *, public_key, signing_input, signature):
                if type(signing_input) is not bytes:
                    raise ProviderFailure("toy input failure")
                if public_key == b"":
                    return SignatureVerificationOutcome.INVALID_PUBLIC_KEY
                if signature == b"":
                    return SignatureVerificationOutcome.INVALID_SIGNATURE
                expected = ToySigner(self.algorithm).sign(signing_input)
                if signature == expected:
                    return SignatureVerificationOutcome.VALID
                return SignatureVerificationOutcome.INVALID_SIGNATURE

        class AsyncToyVerifier(ToyVerifier):
            async def verify(self, *, public_key, signing_input, signature):
                return super().verify(
                    public_key=public_key,
                    signing_input=signing_input,
                    signature=signature,
                )

        def toy_observed(request: OperationRequest) -> ObservedCase:
            vector = _VECTOR_BY_ALGORITHM[request.algorithm]
            trace = _Trace()

            def perform():
                prefixed = b"silently-prefixed:" + vector.signing_input
                for fallback in (False, True):
                    trace.attempts.append(
                        ProviderAttempt(
                            request.operation,
                            request.algorithm,
                            prefixed,
                            vector.public_key
                            if request.operation is ProviderOperation.VERIFY
                            else None,
                            vector.signature
                            if request.operation is ProviderOperation.VERIFY
                            else None,
                            fallback,
                        )
                    )
                trace.fallback_used = True
                trace.usable_result_produced = True
                if request.operation is ProviderOperation.SIGN:
                    return ToySigner(request.algorithm).sign(vector.signing_input)
                return ToyVerifier(request.algorithm).verify(
                    public_key=vector.public_key,
                    signing_input=vector.signing_input,
                    signature=vector.signature,
                )

            if request.mode is ExecutionMode.SYNC:
                invoke = perform
            else:

                async def invoke():
                    return perform()

            return ObservedCase(invoke=invoke, snapshot=trace.snapshot)

        def toy_fault(request: FaultRequest) -> ObservedCase:
            vector = _VECTOR_BY_ALGORITHM[request.operation.algorithm]
            trace = _Trace()

            def perform():
                trace.attempts.extend(
                    ProviderAttempt(
                        request.operation.operation,
                        request.operation.algorithm,
                        vector.signing_input,
                        vector.public_key
                        if request.operation.operation is ProviderOperation.VERIFY
                        else None,
                        vector.signature
                        if request.operation.operation is ProviderOperation.VERIFY
                        else None,
                        fallback,
                    )
                    for fallback in (False, True)
                )
                trace.fallback_used = True
                if request.fault is InjectedFault.UNAVAILABLE:
                    raise ProviderUnavailable("toy unavailable")
                raise ProviderFailure("toy failure")

            if request.operation.mode is ExecutionMode.SYNC:
                invoke = perform
            else:

                async def invoke():
                    return perform()

            return ObservedCase(invoke=invoke, snapshot=trace.snapshot)

        def toy_reached(
            algorithm: ProofAlgorithm,
            operation: ProviderOperation,
        ) -> ReachedCancellationCase:
            vector = _VECTOR_BY_ALGORITHM[algorithm]
            trace = _Trace()
            reached = asyncio.Event()

            async def invoke():
                trace.attempts.append(
                    ProviderAttempt(
                        operation,
                        algorithm,
                        vector.signing_input,
                        vector.public_key
                        if operation is ProviderOperation.VERIFY
                        else None,
                        vector.signature
                        if operation is ProviderOperation.VERIFY
                        else None,
                        False,
                    )
                )
                reached.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    trace.attempts.append(
                        ProviderAttempt(
                            operation,
                            algorithm,
                            vector.signing_input,
                            vector.public_key
                            if operation is ProviderOperation.VERIFY
                            else None,
                            vector.signature
                            if operation is ProviderOperation.VERIFY
                            else None,
                            True,
                        )
                    )
                    trace.fallback_used = True
                    trace.usable_result_produced = True
                    if operation is ProviderOperation.SIGN:
                        return ToySigner(algorithm).sign(vector.signing_input)
                    return SignatureVerificationOutcome.VALID

            return ReachedCancellationCase(
                invoke=invoke,
                wait_until_reached=reached.wait,
                snapshot=trace.snapshot,
            )

        toy_evidence = ProviderEvidence(
            vectors=_VECTORS,
            reference_verify=_reference_verify,
            observed_success=toy_observed,
            observed_fault=toy_fault,
            cancellation_mode=lambda algorithm, operation: (
                CancellationMode.REACHED_SUPPORTED
            ),
            reached_cancellation=toy_reached,
        )

        class ToyContractTests(
            TrustProofProviderContract,
            unittest.IsolatedAsyncioTestCase,
        ):
            factories = ProviderFactories(
                es256_signer=lambda: ToySigner(ProofAlgorithm.ES256),
                async_es256_signer=lambda: AsyncToySigner(ProofAlgorithm.ES256),
                ed25519_signer=lambda: ToySigner(ProofAlgorithm.ED25519),
                async_ed25519_signer=lambda: AsyncToySigner(ProofAlgorithm.ED25519),
                verifier=ToyVerifier,
                async_verifier=AsyncToyVerifier,
                evidence=toy_evidence,
            )

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ToyContractTests)
        output = io.StringIO()
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
        failed_names = {
            getattr(test, "test_case", test)._testMethodName
            for test, _ in (*result.failures, *result.errors)
        }

        self.assertEqual(result.testsRun, 6)
        self.assertFalse(result.wasSuccessful(), output.getvalue())
        self.assertIn(
            "test_pinned_known_answers_and_independent_interoperation",
            failed_names,
        )
        self.assertIn(
            "test_exact_backend_attempts_and_zero_fallback",
            failed_names,
        )
        self.assertIn(
            "test_reached_async_cancellation_or_explicit_bounded_local_n_a",
            failed_names,
        )


if __name__ == "__main__":
    unittest.main()
