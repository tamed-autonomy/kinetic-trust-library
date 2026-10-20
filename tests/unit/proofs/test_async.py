"""Native asynchronous Trust Proof parity tests."""

import asyncio
from datetime import timedelta
import gc
from hashlib import sha256
import inspect
import unittest
from unittest.mock import patch
import warnings

import kinetic_trust_library
import kinetic_trust_library.proofs as proofs
from kinetic_trust_library.errors import (
    CryptoConfigurationError,
    CryptoProviderContractError,
    CryptoProviderFailureError,
    CryptoProviderUnavailableError,
    InvalidSignatureError,
    OutcomeUnknownError,
    ProofClaimsError,
    ProofIssuanceInputError,
    SignerContractError,
    SigningProviderFailureError,
    SigningProviderUnavailableError,
    VerificationKeySourceContractError,
    VerificationKeySourceFailureError,
    VerificationKeySourceUnavailableError,
)
from kinetic_trust_library.models.proof import (
    AsyncProofCrypto,
    AsyncVerifierBinding,
    KeyPurpose,
    OracleSigningIdentity,
    ProofAlgorithm,
    ProofCrypto,
    SignatureVerificationOutcome,
    TrustedVerificationKey,
    VerifierBinding,
)
from kinetic_trust_library.models.standing import RootInstrumentStatus
from kinetic_trust_library.proofs import AsyncTrustProofs, TrustProofs
from kinetic_trust_library.protocols import (
    ProviderFailure,
    ProviderUnavailable,
    SigningOutcomeUnknown,
)

from ._fakes import (
    AsyncMutatingKeySource,
    AsyncSpyKeySource,
    AsyncSpySigner,
    AsyncSpyVerifier,
    SpyKeySource,
    SpySigner,
    SpyVerifier,
)
from ._fixtures import (
    proof_intent,
    root_bundle,
    complete_bundle,
    es256_signature,
    oracle_signing_identity,
)
from .test_verify import CUTOFF, proof_token, trusted_key, valid_payload


def async_crypto(verifier: object) -> AsyncProofCrypto:
    return AsyncProofCrypto((AsyncVerifierBinding(ProofAlgorithm.ES256, verifier),))


def sync_crypto(verifier: object) -> ProofCrypto:
    return ProofCrypto((VerifierBinding(ProofAlgorithm.ES256, verifier),))


class BlockingAsyncKeySource(AsyncSpyKeySource):
    def __init__(self, effect: object, *, events: list[str] | None = None) -> None:
        super().__init__(effect, events=events)
        self.reached = asyncio.Event()
        self._never = asyncio.Event()

    async def resolve(self, lookup, /):
        self.body_entries += 1
        self.arguments.append(lookup)
        self.events.append("keys.resolve")
        self.reached.set()
        await self._never.wait()
        return self.effect


class BlockingAsyncVerifier(AsyncSpyVerifier):
    def __init__(self, effect: object, *, events: list[str] | None = None) -> None:
        super().__init__(effect, events=events)
        self.reached = asyncio.Event()
        self._never = asyncio.Event()

    async def verify(
        self,
        *,
        public_key: bytes,
        signing_input: bytes,
        signature: bytes,
    ):
        self.body_entries += 1
        self.arguments.append(
            {
                "public_key": public_key,
                "signing_input": signing_input,
                "signature": signature,
            }
        )
        self.events.append("verifier.verify")
        self.reached.set()
        await self._never.wait()
        return self.effect


class BlockingAsyncSigner(AsyncSpySigner):
    def __init__(
        self,
        identity: object,
        effect: object,
        *,
        events: list[str] | None = None,
    ) -> None:
        super().__init__(identity, effect, events=events)
        self.reached = asyncio.Event()
        self._never = asyncio.Event()

    async def sign(self, signing_input: bytes, /) -> bytes:
        self.body_entries += 1
        self.arguments.append(signing_input)
        self.events.append("signer.sign")
        self.reached.set()
        await self._never.wait()
        return self.effect  # type: ignore[return-value]


class AsyncTrustProofsFacadeTests(unittest.IsolatedAsyncioTestCase):
    async def test_mutated_intent_stops_before_async_providers(self) -> None:
        events: list[str] = []
        signer = AsyncSpySigner(
            oracle_signing_identity(),
            es256_signature(r=1, s=1),
            events=events,
        )
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID, events=events)
        intent = proof_intent()
        object.__setattr__(intent, "lifetime_seconds", True)
        with self.assertRaises(ProofIssuanceInputError):
            await AsyncTrustProofs(async_crypto(verifier)).issue(
                complete_bundle(),
                proof=intent,
                signer=signer,
            )
        self.assertEqual(
            (signer.identity_reads, signer.calls, verifier.calls, events),
            (0, 0, 0, []),
        )

    async def test_non_positive_root_bound_stops_before_async_providers(self) -> None:
        cutoff = complete_bundle().cutoff
        bundle = root_bundle(
            RootInstrumentStatus.NON_RENEWABLE,
            end_time=cutoff + timedelta(microseconds=900_000),
        )
        events: list[str] = []
        signer = AsyncSpySigner(
            oracle_signing_identity(),
            es256_signature(r=1, s=1),
            events=events,
        )
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID, events=events)
        with self.assertRaises(ProofIssuanceInputError):
            await AsyncTrustProofs(async_crypto(verifier)).issue(
                bundle,
                proof=proof_intent(),
                signer=signer,
            )
        self.assertEqual(
            (signer.identity_reads, signer.calls, verifier.calls, events),
            (0, 0, 0, []),
        )

    async def test_binding_semantics_never_preempt_signature_verification(self):
        for field in (
            "sub",
            "iat",
            "exp",
            "action",
            "resource",
            "context_hash",
            "trajectory_id",
            "decision_id",
        ):
            for outcome, error in (
                (SignatureVerificationOutcome.INVALID_SIGNATURE, InvalidSignatureError),
                (SignatureVerificationOutcome.VALID, ProofClaimsError),
            ):
                with self.subTest(field=field, outcome=outcome):
                    payload = valid_payload()
                    target = (
                        payload if field in {"sub", "iat", "exp"} else payload["ktp"]
                    )
                    target[field] = None
                    events = []
                    keys = AsyncSpyKeySource(trusted_key(), events=events)
                    verifier = AsyncSpyVerifier(outcome, events=events)
                    with self.assertRaises(error):
                        await AsyncTrustProofs(async_crypto(verifier)).verify(
                            proof_token(payload=payload), cutoff=CUTOFF, keys=keys
                        )
                    self.assertEqual(events, ["keys.resolve", "verifier.verify"])

    async def test_async_facade_is_public_from_proofs_only(self):
        self.assertEqual(AsyncTrustProofs.__module__, "kinetic_trust_library.proofs")
        self.assertEqual(proofs.__all__, ["AsyncTrustProofs", "TrustProofs"])
        self.assertFalse(hasattr(kinetic_trust_library, "AsyncTrustProofs"))

    async def test_async_facade_signatures_are_exact_coroutines(self):
        constructor = inspect.signature(AsyncTrustProofs.__init__)
        self.assertEqual(tuple(constructor.parameters), ("self", "crypto"))
        issue = inspect.signature(AsyncTrustProofs.issue)
        self.assertEqual(
            tuple(issue.parameters),
            ("self", "evaluation", "proof", "signer"),
        )
        verify = inspect.signature(AsyncTrustProofs.verify)
        self.assertEqual(tuple(verify.parameters), ("self", "raw", "cutoff", "keys"))
        self.assertTrue(inspect.iscoroutinefunction(AsyncTrustProofs.issue))
        self.assertTrue(inspect.iscoroutinefunction(AsyncTrustProofs.verify))


class AsyncVerificationParityTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_verify_matches_sync_value_arguments_order_and_calls(self):
        sync_events: list[str] = []
        sync_verifier = SpyVerifier(
            SignatureVerificationOutcome.VALID,
            events=sync_events,
        )
        sync_keys = SpyKeySource(trusted_key(), events=sync_events)
        async_events: list[str] = []
        async_verifier = AsyncSpyVerifier(
            SignatureVerificationOutcome.VALID,
            events=async_events,
        )
        async_keys = AsyncSpyKeySource(trusted_key(), events=async_events)
        raw = proof_token()

        sync_result = TrustProofs(sync_crypto(sync_verifier)).verify(
            raw,
            cutoff=CUTOFF,
            keys=sync_keys,
        )
        async_result = await AsyncTrustProofs(async_crypto(async_verifier)).verify(
            raw,
            cutoff=CUTOFF,
            keys=async_keys,
        )

        self.assertEqual(async_result, sync_result)
        self.assertEqual(async_keys.arguments, sync_keys.arguments)
        self.assertEqual(async_verifier.arguments, sync_verifier.arguments)
        self.assertEqual(
            (async_keys.calls, async_verifier.calls),
            (sync_keys.calls, sync_verifier.calls),
        )
        self.assertEqual(
            async_events,
            ["keys.resolve", "verifier.verify"],
        )
        self.assertEqual(async_events, sync_events)

    async def test_async_verify_rejects_sync_crypto_before_all_effects_and_warnings(
        self,
    ):
        sync_verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
        keys = AsyncSpyKeySource(trusted_key())

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertRaises(CryptoConfigurationError):
                await AsyncTrustProofs(sync_crypto(sync_verifier)).verify(  # type: ignore[arg-type]
                    "not-a-token",
                    cutoff=CUTOFF,
                    keys=keys,
                )

        self.assertEqual(
            (keys.calls, keys.body_entries, sync_verifier.calls), (0, 0, 0)
        )
        self.assertFalse(
            any(
                item.category is RuntimeWarning
                and "was never awaited" in str(item.message)
                for item in caught
            )
        )

    async def test_async_verify_preserves_authenticated_active_soul(self):
        payload = valid_payload()
        payload["ktp"]["soul"] = {  # type: ignore[index]
            "soul": 1,
            "constraint_type": "care",
            "constraint_id": "CARE-1",
            "constraint_name": "Care authority",
            "authority": "https://authority.example/care",
            "community": "Example Community",
            "remediation": "Ask first",
        }
        keys = AsyncSpyKeySource(trusted_key())
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

        result = await AsyncTrustProofs(async_crypto(verifier)).verify(
            proof_token(payload=payload),
            cutoff=CUTOFF,
            keys=keys,
        )

        self.assertEqual(result.claims.soul.soul, 1)
        self.assertEqual(result.claims.soul.constraint_id, "CARE-1")
        self.assertEqual(result.claims.effective_trust, 63)
        self.assertEqual((keys.calls, verifier.calls), (1, 1))

    async def test_async_key_source_cannot_mutate_private_header_authority(self):
        changed_key_id = "provider-changed-key"
        keys = AsyncMutatingKeySource(
            trusted_key(key_id=changed_key_id),
            changed_key_id=changed_key_id,
        )
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

        with self.assertRaises(VerificationKeySourceContractError):
            await AsyncTrustProofs(async_crypto(verifier)).verify(
                proof_token(),
                cutoff=CUTOFF,
                keys=keys,
            )

        self.assertEqual(keys.calls, 1)
        self.assertEqual(keys.arguments[0].key_id, changed_key_id)
        self.assertEqual(verifier.calls, 0)


class AsyncVerificationFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_key_source_failures_match_sync_errors_and_effect_counts(self):
        cases = (
            (ProviderUnavailable, VerificationKeySourceUnavailableError),
            (ProviderFailure, VerificationKeySourceFailureError),
            (SigningOutcomeUnknown, VerificationKeySourceFailureError),
            (TimeoutError, VerificationKeySourceFailureError),
            (RuntimeError, VerificationKeySourceFailureError),
        )
        for signal_type, outward in cases:
            sync_signal = signal_type("sync")
            sync_keys = SpyKeySource(sync_signal)
            sync_verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(signal=signal_type.__name__, mode="sync"),
                self.assertRaises(outward) as sync_raised,
            ):
                TrustProofs(sync_crypto(sync_verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=sync_keys
                )

            async_signal = signal_type("async")
            async_keys = AsyncSpyKeySource(async_signal)
            async_verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(signal=signal_type.__name__, mode="async"),
                self.assertRaises(type(sync_raised.exception)) as async_raised,
            ):
                await AsyncTrustProofs(async_crypto(async_verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=async_keys
                )

            self.assertIs(sync_raised.exception.__cause__, sync_signal)
            self.assertIs(async_raised.exception.__cause__, async_signal)
            self.assertEqual(
                (async_keys.calls, async_verifier.calls),
                (sync_keys.calls, sync_verifier.calls),
            )

    async def test_verifier_failures_match_sync_errors_and_effect_counts(self):
        cases = (
            (ProviderUnavailable, CryptoProviderUnavailableError),
            (ProviderFailure, CryptoProviderFailureError),
            (SigningOutcomeUnknown, CryptoProviderFailureError),
            (TimeoutError, CryptoProviderFailureError),
            (RuntimeError, CryptoProviderFailureError),
        )
        for signal_type, outward in cases:
            sync_signal = signal_type("sync")
            sync_keys = SpyKeySource(trusted_key())
            sync_verifier = SpyVerifier(sync_signal)
            with (
                self.subTest(signal=signal_type.__name__, mode="sync"),
                self.assertRaises(outward) as sync_raised,
            ):
                TrustProofs(sync_crypto(sync_verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=sync_keys
                )

            async_signal = signal_type("async")
            async_keys = AsyncSpyKeySource(trusted_key())
            async_verifier = AsyncSpyVerifier(async_signal)
            with (
                self.subTest(signal=signal_type.__name__, mode="async"),
                self.assertRaises(type(sync_raised.exception)) as async_raised,
            ):
                await AsyncTrustProofs(async_crypto(async_verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=async_keys
                )

            self.assertIs(sync_raised.exception.__cause__, sync_signal)
            self.assertIs(async_raised.exception.__cause__, async_signal)
            self.assertEqual(
                (async_keys.calls, async_verifier.calls),
                (sync_keys.calls, sync_verifier.calls),
            )

    async def test_nonawaitable_provider_returns_are_contract_failures(self):
        class NonawaitableKeySource:
            def __init__(self) -> None:
                self.calls = 0

            def resolve(self, lookup, /):
                del lookup
                self.calls += 1
                return trusted_key()

        keys = NonawaitableKeySource()
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)
        with self.assertRaises(VerificationKeySourceContractError):
            await AsyncTrustProofs(async_crypto(verifier)).verify(
                proof_token(),
                cutoff=CUTOFF,
                keys=keys,  # type: ignore[arg-type]
            )
        self.assertEqual((keys.calls, verifier.calls), (1, 0))

        class NonawaitableVerifier:
            def __init__(self) -> None:
                self.calls = 0

            def verify(self, **arguments):
                del arguments
                self.calls += 1
                return SignatureVerificationOutcome.VALID

        nonawaitable = NonawaitableVerifier()
        keys = AsyncSpyKeySource(trusted_key())
        with self.assertRaises(CryptoProviderContractError):
            await AsyncTrustProofs(async_crypto(nonawaitable)).verify(
                proof_token(), cutoff=CUTOFF, keys=keys
            )
        self.assertEqual((keys.calls, nonawaitable.calls), (1, 1))

    async def test_key_source_nested_coroutine_is_disposed_without_second_await(self):
        class NestedCoroutineKeySource:
            def __init__(self) -> None:
                self.arguments = []
                self.nested_body_entries = 0

            @property
            def calls(self) -> int:
                return len(self.arguments)

            async def resolve(self, lookup, /):
                self.arguments.append(lookup)

                async def nested_result():
                    self.nested_body_entries += 1
                    return trusted_key()

                return nested_result()

        keys = NestedCoroutineKeySource()
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(VerificationKeySourceContractError):
                await AsyncTrustProofs(async_crypto(verifier)).verify(
                    proof_token(),
                    cutoff=CUTOFF,
                    keys=keys,  # type: ignore[arg-type]
                )
            gc.collect()

        self.assertEqual((keys.calls, verifier.calls), (1, 0))
        self.assertEqual(keys.nested_body_entries, 0)
        self.assertEqual(caught, [])

    async def test_nested_coroutine_cleanup_failure_preserves_contract_error(self):
        cleanup_failure = RuntimeError("nested cleanup failed")

        class CleanupFailingKeySource:
            def __init__(self) -> None:
                self.calls = 0
                self.cleanup_entries = 0

            async def resolve(self, lookup, /):
                del lookup
                self.calls += 1

                class Suspend:
                    def __await__(self):
                        yield None

                async def nested_result():
                    try:
                        await Suspend()
                    finally:
                        self.cleanup_entries += 1
                        raise cleanup_failure

                result = nested_result()
                result.send(None)
                return result

        keys = CleanupFailingKeySource()
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(VerificationKeySourceContractError):
                await AsyncTrustProofs(async_crypto(verifier)).verify(
                    proof_token(),
                    cutoff=CUTOFF,
                    keys=keys,  # type: ignore[arg-type]
                )
            gc.collect()

        self.assertEqual((keys.calls, keys.cleanup_entries, verifier.calls), (1, 1, 0))
        self.assertEqual(caught, [])

    async def test_nested_coroutine_cleanup_process_controls_propagate(self):
        for signal in (KeyboardInterrupt(), SystemExit(19), GeneratorExit()):

            class ProcessControlKeySource:
                def __init__(self) -> None:
                    self.calls = 0
                    self.cleanup_entries = 0

                async def resolve(self, lookup, /):
                    del lookup
                    self.calls += 1

                    class Suspend:
                        def __await__(self):
                            yield None

                    async def nested_result():
                        try:
                            await Suspend()
                        finally:
                            self.cleanup_entries += 1
                            raise signal

                    result = nested_result()
                    result.send(None)
                    return result

            keys = ProcessControlKeySource()
            verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

            with (
                self.subTest(signal=type(signal).__name__),
                warnings.catch_warnings(record=True) as caught,
            ):
                warnings.simplefilter("always", RuntimeWarning)
                with self.assertRaises(type(signal)) as raised:
                    await AsyncTrustProofs(async_crypto(verifier)).verify(
                        proof_token(),
                        cutoff=CUTOFF,
                        keys=keys,  # type: ignore[arg-type]
                    )
                gc.collect()

            self.assertIs(raised.exception, signal)
            self.assertEqual(
                (keys.calls, keys.cleanup_entries, verifier.calls),
                (1, 1, 0),
            )
            self.assertEqual(caught, [])

    async def test_verifier_nested_coroutine_is_disposed_without_second_await(self):
        class NestedCoroutineVerifier:
            def __init__(self) -> None:
                self.arguments = []
                self.nested_body_entries = 0

            @property
            def calls(self) -> int:
                return len(self.arguments)

            async def verify(self, **arguments):
                self.arguments.append(arguments)

                async def nested_result():
                    self.nested_body_entries += 1
                    return SignatureVerificationOutcome.VALID

                return nested_result()

        keys = AsyncSpyKeySource(trusted_key())
        verifier = NestedCoroutineVerifier()

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(CryptoProviderContractError):
                await AsyncTrustProofs(async_crypto(verifier)).verify(
                    proof_token(),
                    cutoff=CUTOFF,
                    keys=keys,
                )
            gc.collect()

        self.assertEqual((keys.calls, verifier.calls), (1, 1))
        self.assertEqual(verifier.nested_body_entries, 0)
        self.assertEqual(caught, [])

    async def test_contract_and_invalid_outcomes_match_sync_exact_errors(self):
        cases = (
            (object(), CryptoProviderContractError),
            (True, CryptoProviderContractError),
            (SignatureVerificationOutcome.INVALID_SIGNATURE, InvalidSignatureError),
            (
                SignatureVerificationOutcome.INVALID_PUBLIC_KEY,
                VerificationKeySourceContractError,
            ),
        )
        for outcome, outward in cases:
            sync_keys = SpyKeySource(trusted_key())
            sync_verifier = SpyVerifier(outcome)
            with (
                self.subTest(outcome=repr(outcome), mode="sync"),
                self.assertRaises(outward) as sync_raised,
            ):
                TrustProofs(sync_crypto(sync_verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=sync_keys
                )

            async_keys = AsyncSpyKeySource(trusted_key())
            async_verifier = AsyncSpyVerifier(outcome)
            with (
                self.subTest(outcome=repr(outcome), mode="async"),
                self.assertRaises(type(sync_raised.exception)),
            ):
                await AsyncTrustProofs(async_crypto(async_verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=async_keys
                )

            self.assertEqual(
                (async_keys.calls, async_verifier.calls),
                (sync_keys.calls, sync_verifier.calls),
            )

    async def test_process_control_signals_other_than_cancellation_propagate(self):
        for stage in ("keys", "verifier"):
            for signal in (KeyboardInterrupt(), SystemExit(8), GeneratorExit()):
                keys = AsyncSpyKeySource(signal if stage == "keys" else trusted_key())
                verifier = AsyncSpyVerifier(
                    signal
                    if stage == "verifier"
                    else SignatureVerificationOutcome.VALID
                )
                with (
                    self.subTest(stage=stage, signal=type(signal).__name__),
                    self.assertRaises(type(signal)) as raised,
                ):
                    await AsyncTrustProofs(async_crypto(verifier)).verify(
                        proof_token(), cutoff=CUTOFF, keys=keys
                    )
                self.assertIs(raised.exception, signal)
                self.assertEqual(
                    (keys.calls, verifier.calls),
                    (1, 0 if stage == "keys" else 1),
                )


class AsyncVerificationCancellationTests(unittest.IsolatedAsyncioTestCase):
    async def test_pre_entry_cancellation_is_native_and_has_zero_effects(self):
        keys = AsyncSpyKeySource(trusted_key())
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)
        operation = asyncio.create_task(
            AsyncTrustProofs(async_crypto(verifier)).verify(
                proof_token(), cutoff=CUTOFF, keys=keys
            )
        )

        self.assertTrue(operation.cancel())
        with self.assertRaises(asyncio.CancelledError):
            await operation

        self.assertEqual(
            (keys.calls, keys.body_entries, verifier.calls, verifier.body_entries),
            (0, 0, 0, 0),
        )

    async def test_reached_key_source_cancellation_is_native(self):
        events: list[str] = []
        keys = BlockingAsyncKeySource(trusted_key(), events=events)
        verifier = AsyncSpyVerifier(
            SignatureVerificationOutcome.VALID,
            events=events,
        )
        operation = asyncio.create_task(
            AsyncTrustProofs(async_crypto(verifier)).verify(
                proof_token(), cutoff=CUTOFF, keys=keys
            )
        )
        await keys.reached.wait()

        operation.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await operation

        self.assertEqual((keys.calls, verifier.calls), (1, 0))
        self.assertEqual(events, ["keys.resolve"])

    async def test_asyncio_timeout_remains_a_timeout(self):
        events: list[str] = []
        keys = BlockingAsyncKeySource(trusted_key(), events=events)
        verifier = AsyncSpyVerifier(
            SignatureVerificationOutcome.VALID,
            events=events,
        )

        with self.assertRaises(TimeoutError):
            async with asyncio.timeout(0):
                await AsyncTrustProofs(async_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )

        self.assertTrue(keys.reached.is_set())
        self.assertEqual((keys.calls, verifier.calls), (1, 0))
        self.assertEqual(events, ["keys.resolve"])

    async def test_reached_incoming_verifier_cancellation_is_native(self):
        events: list[str] = []
        keys = AsyncSpyKeySource(trusted_key(), events=events)
        verifier = BlockingAsyncVerifier(
            SignatureVerificationOutcome.VALID,
            events=events,
        )
        operation = asyncio.create_task(
            AsyncTrustProofs(async_crypto(verifier)).verify(
                proof_token(), cutoff=CUTOFF, keys=keys
            )
        )
        await verifier.reached.wait()

        operation.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await operation

        self.assertEqual((keys.calls, verifier.calls), (1, 1))
        self.assertEqual(events, ["keys.resolve", "verifier.verify"])

    async def test_cancellation_before_key_source_await_remains_native(self):
        class CancelledResolveLookup:
            def __init__(self) -> None:
                self.lookups = 0

            @property
            def resolve(self):
                self.lookups += 1
                raise asyncio.CancelledError

        keys = CancelledResolveLookup()
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

        with self.assertRaises(asyncio.CancelledError):
            await AsyncTrustProofs(async_crypto(verifier)).verify(
                proof_token(),
                cutoff=CUTOFF,
                keys=keys,  # type: ignore[arg-type]
            )

        self.assertEqual((keys.lookups, verifier.calls), (1, 0))

    async def test_cancellation_before_incoming_verifier_await_remains_native(self):
        class CancelledVerifyLookup:
            def __init__(self) -> None:
                self.lookups = 0

            @property
            def verify(self):
                self.lookups += 1
                raise asyncio.CancelledError

        keys = AsyncSpyKeySource(trusted_key())
        verifier = CancelledVerifyLookup()

        with self.assertRaises(asyncio.CancelledError):
            await AsyncTrustProofs(async_crypto(verifier)).verify(
                proof_token(),
                cutoff=CUTOFF,
                keys=keys,
            )

        self.assertEqual((keys.calls, verifier.lookups), (1, 1))


class AsyncIssuanceParityTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_issue_matches_sync_bytes_values_arguments_order_and_calls(
        self,
    ):
        signature = es256_signature(r=1, s=2)
        sync_events: list[str] = []
        sync_signer = SpySigner(
            oracle_signing_identity(),
            signature,
            events=sync_events,
        )
        sync_verifier = SpyVerifier(
            SignatureVerificationOutcome.VALID,
            events=sync_events,
        )
        async_events: list[str] = []
        async_signer = AsyncSpySigner(
            oracle_signing_identity(),
            signature,
            events=async_events,
        )
        async_verifier = AsyncSpyVerifier(
            SignatureVerificationOutcome.VALID,
            events=async_events,
        )
        bundle = complete_bundle()

        sync_token = TrustProofs(sync_crypto(sync_verifier)).issue(
            bundle,
            proof=proof_intent(proof_id="proof-async-parity"),
            signer=sync_signer,
        )
        async_token = await AsyncTrustProofs(async_crypto(async_verifier)).issue(
            bundle,
            proof=proof_intent(proof_id="proof-async-parity"),
            signer=async_signer,
        )

        self.assertEqual(async_token, sync_token)
        self.assertEqual(async_token.raw, sync_token.raw)
        self.assertEqual(async_signer.arguments, sync_signer.arguments)
        self.assertEqual(async_verifier.arguments, sync_verifier.arguments)
        self.assertEqual(
            (async_signer.identity_reads, async_signer.calls, async_verifier.calls),
            (sync_signer.identity_reads, sync_signer.calls, sync_verifier.calls),
        )
        self.assertEqual(
            async_events,
            ["signer.identity", "signer.sign", "verifier.verify"],
        )
        self.assertEqual(async_events, sync_events)

    async def test_ed25519_issue_and_verify_select_only_matching_async_binding(self):
        bundle = complete_bundle()
        cutoff = bundle.cutoff
        public_key = b"\x02" + (b"\x00" * 31)
        signature = public_key + (1).to_bytes(32, "little")
        identity = OracleSigningIdentity(
            issuer="https://oracle.example",
            key_id="ed-key-1",
            algorithm=ProofAlgorithm.ED25519,
            purpose=KeyPurpose.ORACLE_TRUST_PROOF,
            public_key=public_key,
            signing_not_before=cutoff - timedelta(seconds=1),
            signing_not_after=cutoff + timedelta(seconds=2),
            revoked_at=None,
        )
        key = TrustedVerificationKey(
            issuer=identity.issuer,
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            purpose=identity.purpose,
            public_key=identity.public_key,
            signing_not_before=identity.signing_not_before,
            signing_not_after=identity.signing_not_after,
            verification_not_after=cutoff + timedelta(seconds=2),
            revoked_at=None,
        )
        sync_es256 = SpyVerifier(AssertionError("ES256 verifier must stay unused"))
        sync_ed25519 = SpyVerifier(SignatureVerificationOutcome.VALID)
        sync_configuration = ProofCrypto(
            (
                VerifierBinding(ProofAlgorithm.ES256, sync_es256),
                VerifierBinding(ProofAlgorithm.ED25519, sync_ed25519),
            )
        )
        async_es256 = AsyncSpyVerifier(
            AssertionError("ES256 verifier must stay unused")
        )
        async_ed25519 = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)
        async_configuration = AsyncProofCrypto(
            (
                AsyncVerifierBinding(ProofAlgorithm.ES256, async_es256),
                AsyncVerifierBinding(ProofAlgorithm.ED25519, async_ed25519),
            )
        )
        sync_signer = SpySigner(identity, signature)
        async_signer = AsyncSpySigner(identity, signature)

        sync_token = TrustProofs(sync_configuration).issue(
            bundle,
            proof=proof_intent(proof_id="proof-ed-async-parity", lifetime_seconds=1),
            signer=sync_signer,
        )
        async_token = await AsyncTrustProofs(async_configuration).issue(
            bundle,
            proof=proof_intent(proof_id="proof-ed-async-parity", lifetime_seconds=1),
            signer=async_signer,
        )
        sync_keys = SpyKeySource(key)
        async_keys = AsyncSpyKeySource(key)
        sync_result = TrustProofs(sync_configuration).verify(
            sync_token.raw,
            cutoff=cutoff,
            keys=sync_keys,
        )
        async_result = await AsyncTrustProofs(async_configuration).verify(
            async_token.raw,
            cutoff=cutoff,
            keys=async_keys,
        )

        self.assertEqual(async_token, sync_token)
        self.assertEqual(async_result, sync_result)
        self.assertEqual(async_signer.arguments, sync_signer.arguments)
        self.assertEqual(async_keys.arguments, sync_keys.arguments)
        self.assertEqual(async_ed25519.arguments, sync_ed25519.arguments)
        self.assertEqual((sync_es256.calls, async_es256.calls), (0, 0))
        self.assertEqual((sync_ed25519.calls, async_ed25519.calls), (2, 2))
        self.assertEqual(
            (async_signer.identity_reads, async_signer.calls, async_keys.calls),
            (1, 1, 1),
        )

    async def test_async_issue_rejects_sync_crypto_before_bundle_effects_and_warnings(
        self,
    ):
        sync_verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
        signer = AsyncSpySigner(
            oracle_signing_identity(),
            es256_signature(r=1, s=1),
        )

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertRaises(CryptoConfigurationError):
                await AsyncTrustProofs(sync_crypto(sync_verifier)).issue(  # type: ignore[arg-type]
                    object(),  # type: ignore[arg-type]
                    proof=proof_intent(proof_id="proof-1"),
                    signer=signer,
                )

        self.assertEqual(
            (
                signer.identity_reads,
                signer.calls,
                signer.body_entries,
                sync_verifier.calls,
            ),
            (0, 0, 0, 0),
        )
        self.assertFalse(
            any(
                item.category is RuntimeWarning
                and "was never awaited" in str(item.message)
                for item in caught
            )
        )


class AsyncIssuanceFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_identity_failures_match_sync_errors_before_sign_dispatch(self):
        cases = (
            (ProviderUnavailable, SigningProviderUnavailableError),
            (ProviderFailure, SigningProviderFailureError),
            (SigningOutcomeUnknown, SignerContractError),
            (RuntimeError, SignerContractError),
        )
        for signal_type, outward in cases:
            sync_effect = (
                signal_type("sync-ref")
                if signal_type is SigningOutcomeUnknown
                else signal_type("sync")
            )
            sync_signer = SpySigner(
                sync_effect,
                es256_signature(r=1, s=1),
            )
            sync_verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(signal=signal_type.__name__, mode="sync"),
                self.assertRaises(outward) as sync_raised,
            ):
                TrustProofs(sync_crypto(sync_verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=sync_signer,
                )

            async_effect = (
                signal_type("async-ref")
                if signal_type is SigningOutcomeUnknown
                else signal_type("async")
            )
            async_signer = AsyncSpySigner(
                async_effect,
                es256_signature(r=1, s=1),
            )
            async_verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(signal=signal_type.__name__, mode="async"),
                self.assertRaises(type(sync_raised.exception)) as async_raised,
            ):
                await AsyncTrustProofs(async_crypto(async_verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=async_signer,
                )

            self.assertIs(sync_raised.exception.__cause__, sync_effect)
            self.assertIs(async_raised.exception.__cause__, async_effect)
            self.assertEqual(
                (
                    async_signer.identity_reads,
                    async_signer.calls,
                    async_signer.body_entries,
                    async_verifier.calls,
                ),
                (
                    sync_signer.identity_reads,
                    sync_signer.calls,
                    0,
                    sync_verifier.calls,
                ),
            )

    async def test_sync_identity_native_coroutine_is_closed_by_async_facade(self):
        body_entries = 0
        scheduling_calls = 0

        class CoroutineIdentitySigner:
            def __init__(self, identity: object) -> None:
                self.identity_result = identity
                self.identity_reads = 0
                self.sign_lookups = 0
                self.sign_dispatches = 0

            @property
            def identity(self):
                self.identity_reads += 1
                return self.identity_result

            @property
            def sign(self):
                self.sign_lookups += 1
                return self._sign

            async def _sign(self, signing_input: bytes, /):
                del signing_input
                self.sign_dispatches += 1
                return es256_signature(r=1, s=1)

        async def nested_identity():
            nonlocal body_entries
            body_entries += 1
            return oracle_signing_identity()

        result = nested_identity()
        signer = CoroutineIdentitySigner(result)
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

        def record_scheduling(*args, **kwargs):
            nonlocal scheduling_calls
            del args, kwargs
            scheduling_calls += 1
            raise AssertionError("nested identity coroutine must not be scheduled")

        with (
            patch("asyncio.create_task", side_effect=record_scheduling),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(SignerContractError):
                await AsyncTrustProofs(async_crypto(verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=signer,  # type: ignore[arg-type]
                )
            state = inspect.getcoroutinestate(result)
            signer.identity_result = None
            del result
            gc.collect()

        self.assertEqual(
            (
                signer.identity_reads,
                signer.sign_lookups,
                signer.sign_dispatches,
                verifier.calls,
                body_entries,
                scheduling_calls,
            ),
            (1, 0, 0, 0, 0, 0),
        )
        self.assertEqual(state, inspect.CORO_CLOSED)
        self.assertEqual(caught, [])

    async def test_sign_method_lookup_failures_match_sync_before_dispatch(self):
        class SignMethodEffect:
            def __init__(self, effect: object) -> None:
                self.effect = effect
                self.identity_reads = 0
                self.sign_lookups = 0

            @property
            def identity(self):
                self.identity_reads += 1
                return oracle_signing_identity()

            @property
            def sign(self):
                self.sign_lookups += 1
                if isinstance(self.effect, BaseException):
                    raise self.effect
                return self.effect

        cases = (
            (
                lambda: ProviderUnavailable("unavailable"),
                SigningProviderUnavailableError,
            ),
            (lambda: ProviderFailure("failed"), SigningProviderFailureError),
            (lambda: SigningOutcomeUnknown("lookup-ref"), SignerContractError),
            (lambda: TimeoutError("timeout"), SignerContractError),
            (lambda: RuntimeError("undeclared"), SignerContractError),
            (object, SignerContractError),
        )
        for effect_factory, outward in cases:
            sync_effect = effect_factory()
            sync_signer = SignMethodEffect(sync_effect)
            sync_verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(effect=type(sync_effect).__name__, mode="sync"),
                self.assertRaises(outward) as sync_raised,
            ):
                TrustProofs(sync_crypto(sync_verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=sync_signer,  # type: ignore[arg-type]
                )

            async_effect = effect_factory()
            async_signer = SignMethodEffect(async_effect)
            async_verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(effect=type(async_effect).__name__, mode="async"),
                self.assertRaises(type(sync_raised.exception)) as async_raised,
            ):
                await AsyncTrustProofs(async_crypto(async_verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=async_signer,  # type: ignore[arg-type]
                )

            if isinstance(sync_effect, BaseException):
                self.assertIs(sync_raised.exception.__cause__, sync_effect)
                self.assertIs(async_raised.exception.__cause__, async_effect)
            else:
                self.assertIsNone(sync_raised.exception.__cause__)
                self.assertIsNone(async_raised.exception.__cause__)
            self.assertEqual(
                (
                    async_signer.identity_reads,
                    async_signer.sign_lookups,
                    async_verifier.calls,
                ),
                (
                    sync_signer.identity_reads,
                    sync_signer.sign_lookups,
                    sync_verifier.calls,
                ),
            )

    async def test_definite_signer_failures_match_sync_errors_and_counts(self):
        cases = (
            (ProviderUnavailable, SigningProviderUnavailableError),
            (ProviderFailure, SigningProviderFailureError),
        )
        for signal_type, outward in cases:
            sync_effect = signal_type("sync")
            sync_signer = SpySigner(oracle_signing_identity(), sync_effect)
            sync_verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(signal=signal_type.__name__, mode="sync"),
                self.assertRaises(outward) as sync_raised,
            ):
                TrustProofs(sync_crypto(sync_verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=sync_signer,
                )

            async_effect = signal_type("async")
            async_signer = AsyncSpySigner(
                oracle_signing_identity(),
                async_effect,
            )
            async_verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(signal=signal_type.__name__, mode="async"),
                self.assertRaises(type(sync_raised.exception)) as async_raised,
            ):
                await AsyncTrustProofs(async_crypto(async_verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=async_signer,
                )

            self.assertIs(sync_raised.exception.__cause__, sync_effect)
            self.assertIs(async_raised.exception.__cause__, async_effect)
            self.assertEqual(
                (async_signer.calls, async_signer.body_entries, async_verifier.calls),
                (sync_signer.calls, 1, sync_verifier.calls),
            )

    async def test_unknown_signer_outcomes_match_exact_sync_correlation(self):
        cases = [
            ("valid", SigningOutcomeUnknown("remote:42"), "remote:42"),
            ("timeout", TimeoutError("timeout"), None),
            ("undeclared", RuntimeError("undeclared"), None),
        ]
        for name, reference in (
            ("deleted", None),
            ("non-string", 42),
            ("overlong UTF-8", "é" * 129),
            ("invalid Unicode", "\ud800"),
        ):
            signal = SigningOutcomeUnknown()
            if name == "deleted":
                del signal.provider_reference
            else:
                signal.provider_reference = reference
            cases.append((name, signal, None))
        for name, effect, provider_reference in cases:
            digests = []
            for mode in ("sync", "async"):
                with self.subTest(effect=name, mode=mode):
                    if mode == "sync":
                        signer = SpySigner(oracle_signing_identity(), effect)
                        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
                        facade = TrustProofs(sync_crypto(verifier))
                    else:
                        signer = AsyncSpySigner(oracle_signing_identity(), effect)
                        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)
                        facade = AsyncTrustProofs(async_crypto(verifier))
                    with self.assertRaises(OutcomeUnknownError) as caught:
                        operation = facade.issue(
                            complete_bundle(),
                            proof=proof_intent(proof_id="proof-exact"),
                            signer=signer,
                        )
                        if mode == "async":
                            await operation
                    error = caught.exception
                    self.assertEqual(error.stage, "signing")
                    self.assertEqual(error.proof_id, "proof-exact")
                    self.assertEqual(error.provider_reference, provider_reference)
                    self.assertEqual(
                        error.signing_input_digest,
                        "sha256:" + sha256(signer.arguments[0]).hexdigest(),
                    )
                    self.assertIs(error.__cause__, effect)
                    self.assertEqual((signer.calls, verifier.calls), (1, 0))
                    if mode == "async":
                        self.assertEqual(signer.body_entries, 1)
                    digests.append(error.signing_input_digest)
            if len(digests) == 2:
                self.assertEqual(digests[0], digests[1])

    async def test_dispatch_time_unknown_signer_with_invalid_reference_preserves_correlation(self):
        for name, reference, expected_reference in (
            ("valid", "remote:42", "remote:42"),
            ("deleted", None, None),
            ("non-string", 42, None),
            ("overlong UTF-8", "é" * 129, None),
            ("invalid Unicode", "\ud800", None),
        ):
            with self.subTest(reference=name):
                signal = SigningOutcomeUnknown()
                if name == "deleted":
                    del signal.provider_reference
                else:
                    signal.provider_reference = reference
                signer = SpySigner(oracle_signing_identity(), signal)
                verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)
                with self.assertRaises(OutcomeUnknownError) as caught:
                    await AsyncTrustProofs(async_crypto(verifier)).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-exact"),
                        signer=signer,
                    )
                error = caught.exception
                self.assertEqual(error.stage, "signing")
                self.assertEqual(error.proof_id, "proof-exact")
                self.assertEqual(error.provider_reference, expected_reference)
                self.assertEqual(
                    error.signing_input_digest,
                    "sha256:" + sha256(signer.arguments[0]).hexdigest(),
                )
                self.assertIs(error.__cause__, signal)
                self.assertEqual((signer.calls, verifier.calls), (1, 0))

    async def test_malformed_signature_and_self_verifier_failures_match_sync(self):
        signer_cases = (
            bytearray(es256_signature(r=1, s=1)),
            b"short",
            es256_signature(r=0, s=1),
        )
        for signature in signer_cases:
            sync_signer = SpySigner(oracle_signing_identity(), signature)
            sync_verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with self.assertRaises(SignerContractError) as sync_raised:
                TrustProofs(sync_crypto(sync_verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=sync_signer,
                )
            async_signer = AsyncSpySigner(oracle_signing_identity(), signature)
            async_verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)
            with self.assertRaises(type(sync_raised.exception)):
                await AsyncTrustProofs(async_crypto(async_verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=async_signer,
                )
            self.assertEqual(
                (async_signer.calls, async_verifier.calls),
                (sync_signer.calls, sync_verifier.calls),
            )

        verifier_cases = (
            (ProviderUnavailable, CryptoProviderUnavailableError),
            (ProviderFailure, CryptoProviderFailureError),
            (SigningOutcomeUnknown, CryptoProviderFailureError),
            (TimeoutError, CryptoProviderFailureError),
            (RuntimeError, CryptoProviderFailureError),
        )
        for signal_type, outward in verifier_cases:
            sync_effect = signal_type("sync")
            sync_signer = SpySigner(
                oracle_signing_identity(),
                es256_signature(r=1, s=1),
            )
            sync_verifier = SpyVerifier(sync_effect)
            with self.assertRaises(outward) as sync_raised:
                TrustProofs(sync_crypto(sync_verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=sync_signer,
                )
            async_effect = signal_type("async")
            async_signer = AsyncSpySigner(
                oracle_signing_identity(),
                es256_signature(r=1, s=1),
            )
            async_verifier = AsyncSpyVerifier(async_effect)
            with self.assertRaises(type(sync_raised.exception)) as async_raised:
                await AsyncTrustProofs(async_crypto(async_verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=async_signer,
                )
            self.assertIs(async_raised.exception.__cause__, async_effect)
            self.assertEqual(
                (async_signer.calls, async_verifier.calls),
                (sync_signer.calls, sync_verifier.calls),
            )

    async def test_nonawaitable_signer_return_is_contract_failure_with_known_result(
        self,
    ):
        class NonawaitableSigner:
            def __init__(self) -> None:
                self.identity_reads = 0
                self.arguments: list[bytes] = []

            @property
            def identity(self):
                self.identity_reads += 1
                return oracle_signing_identity()

            def sign(self, signing_input: bytes, /):
                self.arguments.append(signing_input)
                return es256_signature(r=1, s=1)

        signer = NonawaitableSigner()
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

        with self.assertRaises(SignerContractError):
            await AsyncTrustProofs(async_crypto(verifier)).issue(
                complete_bundle(),
                proof=proof_intent(proof_id="proof-1"),
                signer=signer,  # type: ignore[arg-type]
            )

        self.assertEqual(
            (signer.identity_reads, len(signer.arguments), verifier.calls),
            (1, 1, 0),
        )

    async def test_signer_nested_coroutine_is_disposed_without_second_await(self):
        class NestedCoroutineSigner:
            def __init__(self) -> None:
                self.identity_reads = 0
                self.arguments: list[bytes] = []
                self.nested_body_entries = 0

            @property
            def identity(self):
                self.identity_reads += 1
                return oracle_signing_identity()

            @property
            def calls(self) -> int:
                return len(self.arguments)

            async def sign(self, signing_input: bytes, /):
                self.arguments.append(signing_input)

                async def nested_result():
                    self.nested_body_entries += 1
                    return es256_signature(r=1, s=1)

                return nested_result()

        signer = NestedCoroutineSigner()
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(SignerContractError):
                await AsyncTrustProofs(async_crypto(verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=signer,  # type: ignore[arg-type]
                )
            gc.collect()

        self.assertEqual(
            (signer.identity_reads, signer.calls, verifier.calls),
            (1, 1, 0),
        )
        self.assertEqual(signer.nested_body_entries, 0)
        self.assertEqual(caught, [])

    async def test_self_verifier_outcomes_match_sync_errors_and_release_no_token(self):
        undeclared = object.__new__(SignatureVerificationOutcome)
        object.__setattr__(undeclared, "_name_", "UNDECLARED")
        object.__setattr__(undeclared, "_value_", 999)
        cases = (
            (SignatureVerificationOutcome.INVALID_SIGNATURE, SignerContractError),
            (SignatureVerificationOutcome.INVALID_PUBLIC_KEY, SignerContractError),
            (True, CryptoProviderContractError),
            (undeclared, CryptoProviderContractError),
        )
        for outcome, outward in cases:
            signer = AsyncSpySigner(
                oracle_signing_identity(),
                es256_signature(r=1, s=1),
            )
            verifier = AsyncSpyVerifier(outcome)
            token = None
            with (
                self.subTest(outcome=repr(outcome)),
                self.assertRaises(outward),
            ):
                token = await AsyncTrustProofs(async_crypto(verifier)).issue(
                    complete_bundle(),
                    proof=proof_intent(proof_id="proof-1"),
                    signer=signer,
                )
            self.assertIsNone(token)
            self.assertEqual((signer.calls, verifier.calls), (1, 1))

    async def test_process_control_signals_other_than_cancellation_propagate(self):
        for stage in ("identity", "signer", "verifier"):
            for signal in (KeyboardInterrupt(), SystemExit(11), GeneratorExit()):
                signer = AsyncSpySigner(
                    signal if stage == "identity" else oracle_signing_identity(),
                    signal if stage == "signer" else es256_signature(r=1, s=1),
                )
                verifier = AsyncSpyVerifier(
                    signal
                    if stage == "verifier"
                    else SignatureVerificationOutcome.VALID
                )
                with (
                    self.subTest(stage=stage, signal=type(signal).__name__),
                    self.assertRaises(type(signal)) as raised,
                ):
                    await AsyncTrustProofs(async_crypto(verifier)).issue(
                        complete_bundle(),
                        proof=proof_intent(proof_id="proof-1"),
                        signer=signer,
                    )
                self.assertIs(raised.exception, signal)
                self.assertEqual(
                    (signer.calls, verifier.calls),
                    (
                        0 if stage == "identity" else 1,
                        1 if stage == "verifier" else 0,
                    ),
                )


class AsyncIssuanceCancellationTests(unittest.IsolatedAsyncioTestCase):
    async def test_pre_entry_cancellation_is_native_and_has_zero_effects(self):
        signer = AsyncSpySigner(
            oracle_signing_identity(),
            es256_signature(r=1, s=1),
        )
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)
        operation = asyncio.create_task(
            AsyncTrustProofs(async_crypto(verifier)).issue(
                complete_bundle(),
                proof=proof_intent(proof_id="proof-1"),
                signer=signer,
            )
        )

        self.assertTrue(operation.cancel())
        with self.assertRaises(asyncio.CancelledError):
            await operation

        self.assertEqual(
            (
                signer.identity_reads,
                signer.calls,
                signer.body_entries,
                verifier.calls,
                verifier.body_entries,
            ),
            (0, 0, 0, 0, 0),
        )

    async def test_reached_signer_cancellation_is_outcome_unknown(self):
        events: list[str] = []
        signer = BlockingAsyncSigner(
            oracle_signing_identity(),
            es256_signature(r=1, s=1),
            events=events,
        )
        verifier = AsyncSpyVerifier(
            SignatureVerificationOutcome.VALID,
            events=events,
        )
        operation = asyncio.create_task(
            AsyncTrustProofs(async_crypto(verifier)).issue(
                complete_bundle(),
                proof=proof_intent(proof_id="proof-cancelled"),
                signer=signer,
            )
        )
        await signer.reached.wait()

        operation.cancel()
        with self.assertRaises(OutcomeUnknownError) as raised:
            await operation

        self.assertEqual(raised.exception.proof_id, "proof-cancelled")
        self.assertEqual(
            raised.exception.signing_input_digest,
            "sha256:" + sha256(signer.arguments[0]).hexdigest(),
        )
        self.assertIsInstance(raised.exception.__cause__, asyncio.CancelledError)
        self.assertEqual(
            (signer.identity_reads, signer.calls, verifier.calls), (1, 1, 0)
        )
        self.assertEqual(events, ["signer.identity", "signer.sign"])

    async def test_post_signature_self_verifier_cancellation_is_native(self):
        events: list[str] = []
        signer = AsyncSpySigner(
            oracle_signing_identity(),
            es256_signature(r=1, s=1),
            events=events,
        )
        verifier = BlockingAsyncVerifier(
            SignatureVerificationOutcome.VALID,
            events=events,
        )
        token = None
        operation = asyncio.create_task(
            AsyncTrustProofs(async_crypto(verifier)).issue(
                complete_bundle(),
                proof=proof_intent(proof_id="proof-1"),
                signer=signer,
            )
        )
        await verifier.reached.wait()

        operation.cancel()
        with self.assertRaises(asyncio.CancelledError):
            token = await operation

        self.assertIsNone(token)
        self.assertEqual(
            (signer.identity_reads, signer.calls, verifier.calls), (1, 1, 1)
        )
        self.assertEqual(
            events,
            ["signer.identity", "signer.sign", "verifier.verify"],
        )

    async def test_cancellation_during_identity_read_remains_native(self):
        class CancelledIdentity:
            def __init__(self) -> None:
                self.identity_reads = 0
                self.sign_lookups = 0

            @property
            def identity(self):
                self.identity_reads += 1
                raise asyncio.CancelledError

            @property
            def sign(self):
                self.sign_lookups += 1
                raise AssertionError("sign method must stay unreachable")

        signer = CancelledIdentity()
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

        with self.assertRaises(asyncio.CancelledError):
            await AsyncTrustProofs(async_crypto(verifier)).issue(
                complete_bundle(),
                proof=proof_intent(proof_id="proof-1"),
                signer=signer,  # type: ignore[arg-type]
            )

        self.assertEqual(
            (signer.identity_reads, signer.sign_lookups, verifier.calls),
            (1, 0, 0),
        )

    async def test_cancellation_before_sign_method_dispatch_remains_native(self):
        class CancelledSignLookup:
            def __init__(self) -> None:
                self.identity_reads = 0
                self.sign_lookups = 0

            @property
            def identity(self):
                self.identity_reads += 1
                return oracle_signing_identity()

            @property
            def sign(self):
                self.sign_lookups += 1
                raise asyncio.CancelledError

        signer = CancelledSignLookup()
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

        with self.assertRaises(asyncio.CancelledError):
            await AsyncTrustProofs(async_crypto(verifier)).issue(
                complete_bundle(),
                proof=proof_intent(proof_id="proof-1"),
                signer=signer,  # type: ignore[arg-type]
            )

        self.assertEqual(
            (signer.identity_reads, signer.sign_lookups, verifier.calls),
            (1, 1, 0),
        )

    async def test_cancellation_during_sign_dispatch_is_outcome_unknown(self):
        class DispatchCancellingSigner:
            def __init__(self) -> None:
                self.identity_reads = 0
                self.arguments: list[bytes] = []

            @property
            def identity(self):
                self.identity_reads += 1
                return oracle_signing_identity()

            def sign(self, signing_input: bytes, /):
                self.arguments.append(signing_input)
                raise asyncio.CancelledError

        signer = DispatchCancellingSigner()
        verifier = AsyncSpyVerifier(SignatureVerificationOutcome.VALID)

        with self.assertRaises(OutcomeUnknownError) as raised:
            await AsyncTrustProofs(async_crypto(verifier)).issue(
                complete_bundle(),
                proof=proof_intent(proof_id="proof-dispatch"),
                signer=signer,  # type: ignore[arg-type]
            )

        self.assertEqual(raised.exception.proof_id, "proof-dispatch")
        self.assertEqual(
            raised.exception.signing_input_digest,
            "sha256:" + sha256(signer.arguments[0]).hexdigest(),
        )
        self.assertEqual(
            (signer.identity_reads, len(signer.arguments), verifier.calls), (1, 1, 0)
        )

    async def test_cancellation_before_self_verifier_await_remains_native(self):
        class CancelledVerifyLookup:
            def __init__(self) -> None:
                self.lookups = 0

            @property
            def verify(self):
                self.lookups += 1
                raise asyncio.CancelledError

        verifier = CancelledVerifyLookup()
        signer = AsyncSpySigner(
            oracle_signing_identity(),
            es256_signature(r=1, s=1),
        )

        with self.assertRaises(asyncio.CancelledError):
            await AsyncTrustProofs(async_crypto(verifier)).issue(
                complete_bundle(),
                proof=proof_intent(proof_id="proof-1"),
                signer=signer,
            )

        self.assertEqual((signer.calls, verifier.lookups), (1, 1))


if __name__ == "__main__":
    unittest.main()
