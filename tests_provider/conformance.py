"""Reusable Trust Proof provider evidence contract.

Passing this contract is compatibility evidence only. It is not certification,
proof of operational key custody, or a KTP, FIPS, or export-control claim.
All vectors, references, and provider-specific observation hooks are supplied by
the concrete runner; this module remains backend-neutral and test-only.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum, auto
from inspect import isawaitable
from typing import Awaitable, Callable

from kinetic_trust_library.models.proof import (
    OracleSigningIdentity,
    ProofAlgorithm,
    SignatureVerificationOutcome,
)
from kinetic_trust_library.protocols import ProviderFailure, ProviderUnavailable


class ProviderOperation(Enum):
    SIGN = auto()
    VERIFY = auto()


class ExecutionMode(Enum):
    SYNC = auto()
    ASYNC = auto()


class InjectedFault(Enum):
    UNAVAILABLE = auto()
    FAILURE = auto()


class CancellationMode(Enum):
    REACHED_SUPPORTED = auto()
    BOUNDED_NO_AWAIT = auto()


@dataclass(frozen=True, slots=True)
class PinnedVector:
    algorithm: ProofAlgorithm
    signing_input: bytes
    public_key: bytes
    signature: bytes
    other_public_key: bytes
    other_signature: bytes
    invalid_public_keys: tuple[bytes, ...]
    invalid_signatures: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class OperationRequest:
    algorithm: ProofAlgorithm
    operation: ProviderOperation
    mode: ExecutionMode


@dataclass(frozen=True, slots=True)
class FaultRequest:
    operation: OperationRequest
    fault: InjectedFault


@dataclass(frozen=True, slots=True)
class ProviderAttempt:
    operation: ProviderOperation
    algorithm: ProofAlgorithm
    signing_input: bytes
    public_key: bytes | None
    signature: bytes | None
    fallback: bool


@dataclass(frozen=True, slots=True)
class Observation:
    attempts: tuple[ProviderAttempt, ...]
    fallback_used: bool
    usable_result_produced: bool


@dataclass(frozen=True, slots=True)
class ObservedCase:
    invoke: Callable[[], object | Awaitable[object]]
    snapshot: Callable[[], Observation]


@dataclass(frozen=True, slots=True)
class ReachedCancellationCase:
    invoke: Callable[[], Awaitable[object]]
    wait_until_reached: Callable[[], Awaitable[None]]
    snapshot: Callable[[], Observation]


ReferenceVerify = Callable[
    [ProofAlgorithm, bytes, bytes, bytes],
    SignatureVerificationOutcome,
]


@dataclass(frozen=True, slots=True)
class ProviderEvidence:
    vectors: tuple[PinnedVector, ...]
    reference_verify: ReferenceVerify
    observed_success: Callable[[OperationRequest], ObservedCase]
    observed_fault: Callable[[FaultRequest], ObservedCase]
    cancellation_mode: Callable[[ProofAlgorithm, ProviderOperation], CancellationMode]
    reached_cancellation: Callable[
        [ProofAlgorithm, ProviderOperation], ReachedCancellationCase
    ]


@dataclass(frozen=True, slots=True)
class ProviderFactories:
    es256_signer: Callable[[], object]
    async_es256_signer: Callable[[], object]
    ed25519_signer: Callable[[], object]
    async_ed25519_signer: Callable[[], object]
    verifier: Callable[[ProofAlgorithm], object]
    async_verifier: Callable[[ProofAlgorithm], object]
    evidence: ProviderEvidence


class TrustProofProviderContract:
    """Mixin run only by a concrete provider runner with explicit factories."""

    factories: ProviderFactories

    def _sync_signer(self, algorithm: ProofAlgorithm):
        if algorithm is ProofAlgorithm.ES256:
            return self.factories.es256_signer()
        return self.factories.ed25519_signer()

    def _async_signer(self, algorithm: ProofAlgorithm):
        if algorithm is ProofAlgorithm.ES256:
            return self.factories.async_es256_signer()
        return self.factories.async_ed25519_signer()

    def _vectors(self) -> tuple[PinnedVector, ...]:
        vectors = self.factories.evidence.vectors
        self.assertEqual(
            tuple(vector.algorithm for vector in vectors),
            (ProofAlgorithm.ES256, ProofAlgorithm.ED25519),
        )
        return vectors

    async def test_pinned_known_answers_and_independent_interoperation(self):
        for vector in self._vectors():
            sync_signer = self._sync_signer(vector.algorithm)
            async_signer = self._async_signer(vector.algorithm)
            identity = sync_signer.identity
            first_signature = sync_signer.sign(vector.signing_input)
            second_signature = sync_signer.sign(vector.signing_input)
            async_signature = await async_signer.sign(vector.signing_input)
            sync_verifier = self.factories.verifier(vector.algorithm)
            async_verifier = self.factories.async_verifier(vector.algorithm)

            with self.subTest(algorithm=vector.algorithm):
                self.assertIs(type(identity), OracleSigningIdentity)
                self.assertEqual(sync_signer.identity, identity)
                self.assertEqual(identity.public_key, vector.public_key)
                self.assertIs(type(async_signer.identity), OracleSigningIdentity)
                self.assertEqual(async_signer.identity.public_key, vector.public_key)
                self.assertIs(type(first_signature), bytes)
                self.assertEqual(first_signature, vector.signature)
                self.assertEqual(second_signature, vector.signature)
                self.assertEqual(async_signature, vector.signature)
                self.assertIs(
                    self.factories.evidence.reference_verify(
                        vector.algorithm,
                        vector.public_key,
                        vector.signing_input,
                        first_signature,
                    ),
                    SignatureVerificationOutcome.VALID,
                )
                self.assertIs(
                    self.factories.evidence.reference_verify(
                        vector.algorithm,
                        vector.public_key,
                        vector.signing_input,
                        async_signature,
                    ),
                    SignatureVerificationOutcome.VALID,
                )
                self.assertIs(
                    sync_verifier.verify(
                        public_key=vector.public_key,
                        signing_input=vector.signing_input,
                        signature=async_signature,
                    ),
                    SignatureVerificationOutcome.VALID,
                )
                self.assertIs(
                    await async_verifier.verify(
                        public_key=vector.public_key,
                        signing_input=vector.signing_input,
                        signature=first_signature,
                    ),
                    SignatureVerificationOutcome.VALID,
                )

    async def test_positive_and_negative_vectors_are_exact_in_both_modes(self):
        for vector in self._vectors():
            for mode in (ExecutionMode.SYNC, ExecutionMode.ASYNC):
                verifier = (
                    self.factories.verifier(vector.algorithm)
                    if mode is ExecutionMode.SYNC
                    else self.factories.async_verifier(vector.algorithm)
                )

                async def verify(*, public_key, signing_input, signature):
                    result = verifier.verify(
                        public_key=public_key,
                        signing_input=signing_input,
                        signature=signature,
                    )
                    return await result if isawaitable(result) else result

                cases = (
                    (
                        "positive",
                        vector.public_key,
                        vector.signing_input,
                        vector.signature,
                        SignatureVerificationOutcome.VALID,
                    ),
                    (
                        "changed-input",
                        vector.public_key,
                        vector.signing_input + b"!",
                        vector.signature,
                        SignatureVerificationOutcome.INVALID_SIGNATURE,
                    ),
                    (
                        "other-key",
                        vector.other_public_key,
                        vector.signing_input,
                        vector.signature,
                        SignatureVerificationOutcome.INVALID_SIGNATURE,
                    ),
                    (
                        "other-signature",
                        vector.public_key,
                        vector.signing_input,
                        vector.other_signature,
                        SignatureVerificationOutcome.INVALID_SIGNATURE,
                    ),
                )
                for name, public_key, signing_input, signature, expected in cases:
                    with self.subTest(
                        algorithm=vector.algorithm,
                        mode=mode,
                        case=name,
                    ):
                        self.assertIs(
                            await verify(
                                public_key=public_key,
                                signing_input=signing_input,
                                signature=signature,
                            ),
                            expected,
                        )
                for public_key in vector.invalid_public_keys:
                    with self.subTest(
                        algorithm=vector.algorithm,
                        mode=mode,
                        case="invalid-public-key",
                        value=public_key.hex()[:16],
                    ):
                        self.assertIs(
                            await verify(
                                public_key=public_key,
                                signing_input=vector.signing_input,
                                signature=vector.signature,
                            ),
                            SignatureVerificationOutcome.INVALID_PUBLIC_KEY,
                        )
                for signature in vector.invalid_signatures:
                    with self.subTest(
                        algorithm=vector.algorithm,
                        mode=mode,
                        case="invalid-signature",
                        value=signature.hex()[:16],
                    ):
                        self.assertIs(
                            await verify(
                                public_key=vector.public_key,
                                signing_input=vector.signing_input,
                                signature=signature,
                            ),
                            SignatureVerificationOutcome.INVALID_SIGNATURE,
                        )

    async def test_exact_backend_attempts_and_zero_fallback(self):
        vectors = {vector.algorithm: vector for vector in self._vectors()}
        for algorithm in (ProofAlgorithm.ES256, ProofAlgorithm.ED25519):
            vector = vectors[algorithm]
            for operation in (ProviderOperation.SIGN, ProviderOperation.VERIFY):
                for mode in (ExecutionMode.SYNC, ExecutionMode.ASYNC):
                    request = OperationRequest(algorithm, operation, mode)
                    case = self.factories.evidence.observed_success(request)
                    result = case.invoke()
                    if isawaitable(result):
                        result = await result
                    observation = case.snapshot()

                    with self.subTest(
                        algorithm=algorithm,
                        operation=operation,
                        mode=mode,
                    ):
                        if operation is ProviderOperation.SIGN:
                            self.assertEqual(result, vector.signature)
                        else:
                            self.assertIs(
                                result,
                                SignatureVerificationOutcome.VALID,
                            )
                        self.assertEqual(len(observation.attempts), 1)
                        attempt = observation.attempts[0]
                        self.assertIs(attempt.operation, operation)
                        self.assertIs(attempt.algorithm, algorithm)
                        self.assertEqual(attempt.signing_input, vector.signing_input)
                        self.assertEqual(
                            attempt.public_key,
                            vector.public_key
                            if operation is ProviderOperation.VERIFY
                            else None,
                        )
                        self.assertEqual(
                            attempt.signature,
                            vector.signature
                            if operation is ProviderOperation.VERIFY
                            else None,
                        )
                        self.assertFalse(attempt.fallback)
                        self.assertFalse(observation.fallback_used)
                        self.assertTrue(observation.usable_result_produced)

    async def test_typed_faults_are_single_attempt_without_fallback(self):
        expected_errors = {
            InjectedFault.UNAVAILABLE: ProviderUnavailable,
            InjectedFault.FAILURE: ProviderFailure,
        }
        for algorithm in (ProofAlgorithm.ES256, ProofAlgorithm.ED25519):
            for operation in (ProviderOperation.SIGN, ProviderOperation.VERIFY):
                for mode in (ExecutionMode.SYNC, ExecutionMode.ASYNC):
                    for fault, expected_error in expected_errors.items():
                        request = FaultRequest(
                            OperationRequest(algorithm, operation, mode),
                            fault,
                        )
                        case = self.factories.evidence.observed_fault(request)
                        try:
                            result = case.invoke()
                            if isawaitable(result):
                                await result
                        except expected_error as error:
                            self.assertIs(type(error), expected_error)
                        except Exception as error:
                            self.fail(
                                "provider fault had wrong classification: "
                                f"{type(error).__name__}"
                            )
                        else:
                            self.fail("provider fault produced a usable result")

                        observation = case.snapshot()
                        with self.subTest(
                            algorithm=algorithm,
                            operation=operation,
                            mode=mode,
                            fault=fault,
                        ):
                            self.assertEqual(len(observation.attempts), 1)
                            self.assertFalse(observation.attempts[0].fallback)
                            self.assertFalse(observation.fallback_used)
                            self.assertFalse(observation.usable_result_produced)

    async def test_pre_entry_async_cancellation_is_native(self):
        vectors = {vector.algorithm: vector for vector in self._vectors()}
        for algorithm in (ProofAlgorithm.ES256, ProofAlgorithm.ED25519):
            vector = vectors[algorithm]
            signer = self._async_signer(algorithm)
            operation = asyncio.create_task(signer.sign(vector.signing_input))
            self.assertTrue(operation.cancel())
            with (
                self.subTest(algorithm=algorithm, stage="sign"),
                self.assertRaises(asyncio.CancelledError),
            ):
                await operation

            verifier = self.factories.async_verifier(algorithm)
            operation = asyncio.create_task(
                verifier.verify(
                    public_key=vector.public_key,
                    signing_input=vector.signing_input,
                    signature=vector.signature,
                )
            )
            self.assertTrue(operation.cancel())
            with (
                self.subTest(algorithm=algorithm, stage="verify"),
                self.assertRaises(asyncio.CancelledError),
            ):
                await operation

    async def test_reached_async_cancellation_or_explicit_bounded_local_n_a(self):
        for algorithm in (ProofAlgorithm.ES256, ProofAlgorithm.ED25519):
            for operation in (ProviderOperation.SIGN, ProviderOperation.VERIFY):
                mode = self.factories.evidence.cancellation_mode(
                    algorithm,
                    operation,
                )
                with self.subTest(algorithm=algorithm, operation=operation):
                    self.assertIs(type(mode), CancellationMode)
                if mode is CancellationMode.BOUNDED_NO_AWAIT:
                    continue
                self.assertIs(mode, CancellationMode.REACHED_SUPPORTED)
                case = self.factories.evidence.reached_cancellation(
                    algorithm,
                    operation,
                )
                task = asyncio.create_task(case.invoke())
                await asyncio.wait_for(case.wait_until_reached(), timeout=1.0)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                observation = case.snapshot()
                self.assertEqual(len(observation.attempts), 1)
                self.assertFalse(observation.attempts[0].fallback)
                self.assertFalse(observation.fallback_used)
                self.assertFalse(observation.usable_result_produced)


__all__ = [
    "CancellationMode",
    "ExecutionMode",
    "FaultRequest",
    "InjectedFault",
    "Observation",
    "ObservedCase",
    "OperationRequest",
    "PinnedVector",
    "ProviderAttempt",
    "ProviderEvidence",
    "ProviderFactories",
    "ProviderOperation",
    "ReachedCancellationCase",
    "TrustProofProviderContract",
]
