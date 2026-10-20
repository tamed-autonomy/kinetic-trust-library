"""Synchronous authenticated Trust Proof verification tests."""

import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone, tzinfo
from decimal import Decimal, localcontext
import gc
from hashlib import sha256
import inspect
import json
import unittest
import warnings
from unittest.mock import patch

import kinetic_trust_library
import kinetic_trust_library.proofs as proofs
import kinetic_trust_library.proofs._verify as verification_kernel
from kinetic_trust_library.errors import (
    CryptoConfigurationError,
    CryptoProviderContractError,
    CryptoProviderFailureError,
    CryptoProviderUnavailableError,
    DisabledProofAlgorithmError,
    InactiveVerificationKeyError,
    InvalidSignatureError,
    ProofClaimsError,
    ProofFormatError,
    ProofLifetimeError,
    RevokedVerificationKeyError,
    UnsupportedProofAlgorithmError,
    UnknownVerificationKeyError,
    UntrustedVerificationKeyError,
    ValidationError,
    VerificationKeySourceContractError,
    VerificationKeySourceFailureError,
    VerificationKeySourceUnavailableError,
)
from kinetic_trust_library.models.proof import (
    AsyncProofCrypto,
    AsyncVerifierBinding,
    KeyLookup,
    KeyPurpose,
    ProofAlgorithm,
    ProofCrypto,
    SignatureVerificationOutcome,
    TrustedVerificationKey,
    UnknownVerificationKey,
    UntrustedVerificationKey,
    VerifiedTrustProof,
    VerifierBinding,
)
from kinetic_trust_library.models.envelope import EvaluationBundle, KineticEnvelopeResult
from kinetic_trust_library.models.trust import TrustSnapshot
from kinetic_trust_library.protocols import ProviderFailure, ProviderUnavailable
from kinetic_trust_library.proofs import TrustProofs
from kinetic_trust_library.proofs._jwt import parse_payload as parse_test_payload

from ._fakes import MutatingKeySource, SpyKeySource, SpyVerifier
from ._fixtures import compact_token, es256_signature


ISSUED_AT = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
CUTOFF = ISSUED_AT + timedelta(seconds=5)
ISSUED_AT_SECONDS = 1_787_572_800
KEY_ID = "oracle-key-1"
ISSUER = "https://oracle.example"
SUBJECT = "urn:agent:test"
ES256_PUBLIC_KEY = bytes.fromhex(
    "04"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
VALID_SIGNATURE = es256_signature(r=1, s=1)
RFC8032_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
RFC8032_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def valid_payload() -> dict[str, object]:
    return {
        "iss": ISSUER,
        "sub": SUBJECT,
        "iat": ISSUED_AT_SECONDS,
        "exp": ISSUED_AT_SECONDS + 10,
        "jti": "proof-1",
        "ktp": {
            "action": "c" * 64,
            "resource": "urn:resource:document:42",
            "context_hash": "sha256:" + "b" * 64,
            "trajectory_id": "trajectory-1",
            "decision_id": "decision-1",
            "e_base": 70,
            "e_trust": 63,
            "r": 0.1,
            "context": {
                "evidence_density": 0.1,
                "trust_trend": 0.2,
                "adversarial_pressure": 0.3,
                "update_resistance": 0.4,
                "attestation_coverage": 0.5,
                "moment_criticality": 0.6,
            },
            "soul": {"soul": 0},
            "lineage": "guarantor",
            "generation": 7,
            "resilience_hash": "sha256:" + ("a" * 64),
            "peer_share": 0,
            "applicable_ceilings": [
                {"ceiling": "adversity", "value": 100},
                {"ceiling": "generation", "value": 100},
                {"ceiling": "ial", "value": 95},
                {"ceiling": "trajectory", "value": 100},
            ],
            "advancement_floor": 0,
            "root_instrument": {"status": "none"},
        },
    }


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def proof_token(
    *,
    payload: dict[str, object] | None = None,
    algorithm: str = "ES256",
    key_id: str = KEY_ID,
    proof_type: str = "ktp+jwt",
    signature: bytes = VALID_SIGNATURE,
) -> str:
    header = {"alg": algorithm, "kid": key_id, "typ": proof_type}
    return compact_token(
        canonical_json(header),
        canonical_json(payload if payload is not None else valid_payload()),
        signature,
    )


def proof_token_with_ktp_decimal(member: str, lexeme: str) -> str:
    payload = valid_payload()
    payload["ktp"][member] = "decimal-lexeme"  # type: ignore[index]
    payload_bytes = canonical_json(payload).replace(
        b'"decimal-lexeme"', lexeme.encode("ascii")
    )
    return compact_token(
        canonical_json({"alg": "ES256", "kid": KEY_ID, "typ": "ktp+jwt"}),
        payload_bytes,
        VALID_SIGNATURE,
    )


def trusted_key(**overrides: object) -> TrustedVerificationKey:
    values: dict[str, object] = {
        "issuer": ISSUER,
        "key_id": KEY_ID,
        "algorithm": ProofAlgorithm.ES256,
        "purpose": KeyPurpose.ORACLE_TRUST_PROOF,
        "public_key": ES256_PUBLIC_KEY,
        "signing_not_before": ISSUED_AT - timedelta(days=1),
        "signing_not_after": ISSUED_AT + timedelta(days=1),
        "verification_not_after": ISSUED_AT + timedelta(days=2),
        "revoked_at": None,
    }
    values.update(overrides)
    return TrustedVerificationKey(**values)  # type: ignore[arg-type]


def proof_crypto(verifier: object, *, include_ed25519: bool = False) -> ProofCrypto:
    bindings = [VerifierBinding(ProofAlgorithm.ES256, verifier)]
    if include_ed25519:
        bindings.append(VerifierBinding(ProofAlgorithm.ED25519, verifier))
    return ProofCrypto(tuple(bindings))


def provider_spies() -> tuple[SpyKeySource, SpyVerifier]:
    events: list[str] = []
    verifier = SpyVerifier(SignatureVerificationOutcome.VALID, events=events)
    keys = SpyKeySource(trusted_key(), events=events)
    return keys, verifier


class TrustProofsFacadeTests(unittest.TestCase):
    def test_synchronous_facade_is_public_from_proofs_only(self):
        self.assertEqual(TrustProofs.__module__, "kinetic_trust_library.proofs")
        self.assertEqual(proofs.__all__, ["AsyncTrustProofs", "TrustProofs"])
        self.assertFalse(hasattr(kinetic_trust_library, "TrustProofs"))
        for name in (
            "prepare_verification",
            "accept_key_resolution",
            "complete_verification",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(proofs, name))

    def test_facade_signatures_are_exact(self):
        constructor = inspect.signature(TrustProofs.__init__)
        self.assertEqual(tuple(constructor.parameters), ("self", "crypto"))
        verify = inspect.signature(TrustProofs.verify)
        self.assertEqual(tuple(verify.parameters), ("self", "raw", "cutoff", "keys"))
        self.assertEqual(
            verify.parameters["cutoff"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertEqual(
            verify.parameters["keys"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )


class VerificationPreparationTests(unittest.TestCase):
    def test_undeclared_exact_algorithm_configuration_fails_before_effects(self):
        undeclared = str.__new__(ProofAlgorithm, ProofAlgorithm.ES256.value)
        object.__setattr__(undeclared, "_name_", "UNDECLARED_ES256_ALIAS")
        object.__setattr__(undeclared, "_value_", ProofAlgorithm.ES256.value)
        keys, verifier = provider_spies()
        binding = object.__new__(VerifierBinding)
        object.__setattr__(binding, "algorithm", undeclared)
        object.__setattr__(binding, "verifier", verifier)
        crypto = object.__new__(ProofCrypto)
        object.__setattr__(crypto, "bindings", (binding,))

        with self.assertRaises(CryptoConfigurationError):
            TrustProofs(crypto).verify(proof_token(), cutoff=CUTOFF, keys=keys)

        self.assertEqual((keys.calls, verifier.calls), (0, 0))

    def test_invalid_facade_configuration_precedes_framing_and_all_effects(self):
        forged = object.__new__(ProofCrypto)
        object.__setattr__(forged, "bindings", ())
        keys, _ = provider_spies()

        with self.assertRaises(CryptoConfigurationError):
            TrustProofs(forged).verify("not-a-token", cutoff=CUTOFF, keys=keys)

        self.assertEqual(keys.calls, 0)

    def test_cutoff_requires_exact_builtin_utc_before_framing_and_effects(self):
        class HostileDateTime(datetime):
            @property
            def tzinfo(self):  # type: ignore[override]
                raise AssertionError("datetime hook must not run")

        class ZeroOffset(tzinfo):
            def utcoffset(self, dt: datetime | None) -> timedelta:
                return timedelta(0)

            def dst(self, dt: datetime | None) -> timedelta:
                return timedelta(0)

        invalid_cutoffs = (
            CUTOFF.replace(tzinfo=None),
            CUTOFF.replace(tzinfo=ZeroOffset()),
            HostileDateTime(2026, 8, 24),
        )
        for cutoff in invalid_cutoffs:
            keys, verifier = provider_spies()
            with (
                self.subTest(cutoff_type=type(cutoff).__name__),
                self.assertRaises(ValidationError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    "not-a-token",
                    cutoff=cutoff,
                    keys=keys,
                )
            self.assertEqual((keys.calls, verifier.calls), (0, 0))

    def test_sync_facade_rejects_exact_async_configuration_before_effects(self):
        keys, verifier = provider_spies()
        crypto = AsyncProofCrypto(
            (AsyncVerifierBinding(ProofAlgorithm.ES256, verifier),)
        )

        with self.assertRaises(CryptoConfigurationError):
            TrustProofs(crypto).verify(  # type: ignore[arg-type]
                "not-a-token",
                cutoff=CUTOFF,
                keys=keys,
            )

        self.assertEqual((keys.calls, verifier.calls), (0, 0))


class VerificationKeySourceTests(unittest.TestCase):
    def test_provider_cannot_mutate_private_signed_header_lookup_facts(self):
        changed_key_id = "provider-changed-key"
        keys = MutatingKeySource(
            trusted_key(key_id=changed_key_id),
            changed_key_id=changed_key_id,
        )
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        with self.assertRaises(VerificationKeySourceContractError):
            TrustProofs(proof_crypto(verifier)).verify(
                proof_token(), cutoff=CUTOFF, keys=keys
            )

        self.assertEqual(keys.calls, 1)
        self.assertEqual(keys.arguments[0].key_id, changed_key_id)
        self.assertEqual(verifier.calls, 0)

    def test_unknown_key_receives_one_exact_owned_lookup_and_stops(self):
        events: list[str] = []
        keys = SpyKeySource(UnknownVerificationKey(KEY_ID), events=events)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID, events=events)

        with self.assertRaises(UnknownVerificationKeyError):
            TrustProofs(proof_crypto(verifier)).verify(
                proof_token(), cutoff=CUTOFF, keys=keys
            )

        self.assertEqual(keys.calls, 1)
        self.assertEqual(
            keys.arguments,
            [
                KeyLookup(
                    untrusted_issuer=ISSUER,
                    key_id=KEY_ID,
                    algorithm=ProofAlgorithm.ES256,
                    purpose=KeyPurpose.ORACLE_TRUST_PROOF,
                    cutoff=CUTOFF,
                )
            ],
        )
        self.assertEqual(verifier.calls, 0)
        self.assertEqual(events, ["keys.resolve"])

    def test_untrusted_key_is_distinct_and_stops_before_verifier(self):
        keys = SpyKeySource(UntrustedVerificationKey(KEY_ID))
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        with self.assertRaises(UntrustedVerificationKeyError):
            TrustProofs(proof_crypto(verifier)).verify(
                proof_token(), cutoff=CUTOFF, keys=keys
            )

        self.assertEqual((keys.calls, verifier.calls), (1, 0))

    def test_declared_and_ordinary_source_failures_map_with_cause(self):
        cases = (
            (ProviderUnavailable("offline"), VerificationKeySourceUnavailableError),
            (ProviderFailure("failed"), VerificationKeySourceFailureError),
            (RuntimeError("undeclared"), VerificationKeySourceFailureError),
        )
        for signal, outward in cases:
            keys = SpyKeySource(signal)
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with self.subTest(signal=type(signal).__name__):
                with self.assertRaises(outward) as raised:
                    TrustProofs(proof_crypto(verifier)).verify(
                        proof_token(), cutoff=CUTOFF, keys=keys
                    )
                self.assertIs(raised.exception.__cause__, signal)
                self.assertEqual((keys.calls, verifier.calls), (1, 0))

    def test_source_process_control_signals_propagate_unchanged(self):
        for signal in (KeyboardInterrupt(), SystemExit(7), GeneratorExit()):
            keys = SpyKeySource(signal)
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with self.subTest(signal=type(signal).__name__):
                with self.assertRaises(type(signal)) as raised:
                    TrustProofs(proof_crypto(verifier)).verify(
                        proof_token(), cutoff=CUTOFF, keys=keys
                    )
                self.assertIs(raised.exception, signal)
                self.assertEqual((keys.calls, verifier.calls), (1, 0))

    def test_sync_source_native_coroutine_result_is_closed_before_contract_error(self):
        body_entries = 0
        scheduling_calls = 0

        async def nested_resolution():
            nonlocal body_entries
            body_entries += 1
            return trusted_key()

        result = nested_resolution()
        keys = SpyKeySource(result)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        def record_scheduling(*args, **kwargs):
            nonlocal scheduling_calls
            del args, kwargs
            scheduling_calls += 1
            raise AssertionError("native coroutine must not be scheduled")

        with (
            patch("asyncio.create_task", side_effect=record_scheduling),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(VerificationKeySourceContractError):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )
            state = inspect.getcoroutinestate(result)
            keys.effect = None
            del result
            gc.collect()

        self.assertEqual(
            (keys.calls, verifier.calls, body_entries, scheduling_calls),
            (1, 0, 0, 0),
        )
        self.assertEqual(state, inspect.CORO_CLOSED)
        self.assertEqual(caught, [])

    def test_sync_source_coroutine_cleanup_failure_preserves_contract_error(self):
        cleanup_failure = RuntimeError("nested cleanup failed")
        cleanup_entries = 0

        class Suspend:
            def __await__(self):
                yield None

        async def nested_resolution():
            nonlocal cleanup_entries
            try:
                await Suspend()
            finally:
                cleanup_entries += 1
                raise cleanup_failure

        result = nested_resolution()
        result.send(None)
        keys = SpyKeySource(result)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(VerificationKeySourceContractError):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )
            state = inspect.getcoroutinestate(result)
            keys.effect = None
            del result
            gc.collect()

        self.assertEqual((keys.calls, cleanup_entries, verifier.calls), (1, 1, 0))
        self.assertEqual(state, inspect.CORO_CLOSED)
        self.assertEqual(caught, [])

    def test_sync_source_coroutine_cleanup_process_controls_propagate(self):
        for signal in (
            KeyboardInterrupt(),
            SystemExit(19),
            GeneratorExit(),
            asyncio.CancelledError(),
        ):
            cleanup_entries = 0

            class Suspend:
                def __await__(self):
                    yield None

            async def nested_resolution():
                nonlocal cleanup_entries
                try:
                    await Suspend()
                finally:
                    cleanup_entries += 1
                    raise signal

            result = nested_resolution()
            result.send(None)
            keys = SpyKeySource(result)
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

            with (
                self.subTest(signal=type(signal).__name__),
                warnings.catch_warnings(record=True) as caught,
            ):
                warnings.simplefilter("always", RuntimeWarning)
                with self.assertRaises(type(signal)) as raised:
                    TrustProofs(proof_crypto(verifier)).verify(
                        proof_token(), cutoff=CUTOFF, keys=keys
                    )
                state = inspect.getcoroutinestate(result)
                keys.effect = None
                del result
                gc.collect()

            self.assertIs(raised.exception, signal)
            self.assertEqual(
                (keys.calls, cleanup_entries, verifier.calls),
                (1, 1, 0),
            )
            self.assertEqual(state, inspect.CORO_CLOSED)
            self.assertEqual(caught, [])

    def test_sync_source_coroutine_resisting_once_is_closed_before_contract_error(
        self,
    ):
        cleanup_entries = 0
        scheduling_calls = 0

        class Suspend:
            def __await__(self):
                yield None

        async def nested_resolution():
            nonlocal cleanup_entries
            try:
                await Suspend()
            except GeneratorExit:
                cleanup_entries += 1
                await Suspend()

        result = nested_resolution()
        result.send(None)
        keys = SpyKeySource(result)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        def record_scheduling(*args, **kwargs):
            nonlocal scheduling_calls
            del args, kwargs
            scheduling_calls += 1
            raise AssertionError("native coroutine must not be scheduled")

        with (
            patch("asyncio.create_task", side_effect=record_scheduling),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(VerificationKeySourceContractError):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )
            state = inspect.getcoroutinestate(result)
            keys.effect = None
            del result
            gc.collect()

        self.assertEqual(
            (keys.calls, verifier.calls, cleanup_entries, scheduling_calls),
            (1, 0, 1, 0),
        )
        self.assertEqual(state, inspect.CORO_CLOSED)
        self.assertEqual(caught, [])

    def test_sync_source_coroutine_second_cleanup_failure_preserves_contract_error(
        self,
    ):
        cleanup_failure = RuntimeError("second cleanup failed")
        cleanup_entries = 0

        class Suspend:
            def __await__(self):
                yield None

        async def nested_resolution():
            nonlocal cleanup_entries
            try:
                try:
                    await Suspend()
                except GeneratorExit:
                    cleanup_entries += 1
                    await Suspend()
            finally:
                cleanup_entries += 1
                raise cleanup_failure

        result = nested_resolution()
        result.send(None)
        keys = SpyKeySource(result)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(VerificationKeySourceContractError):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )
            state = inspect.getcoroutinestate(result)
            keys.effect = None
            del result
            gc.collect()

        self.assertEqual((keys.calls, cleanup_entries, verifier.calls), (1, 2, 0))
        self.assertEqual(state, inspect.CORO_CLOSED)
        self.assertEqual(caught, [])

    def test_sync_source_coroutine_second_cleanup_process_controls_propagate(self):
        for signal in (
            KeyboardInterrupt(),
            SystemExit(23),
            GeneratorExit(),
            asyncio.CancelledError(),
        ):
            cleanup_entries = 0

            class Suspend:
                def __await__(self):
                    yield None

            async def nested_resolution():
                nonlocal cleanup_entries
                try:
                    try:
                        await Suspend()
                    except GeneratorExit:
                        cleanup_entries += 1
                        await Suspend()
                finally:
                    cleanup_entries += 1
                    raise signal

            result = nested_resolution()
            result.send(None)
            keys = SpyKeySource(result)
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

            with (
                self.subTest(signal=type(signal).__name__),
                warnings.catch_warnings(record=True) as caught,
            ):
                warnings.simplefilter("always", RuntimeWarning)
                with self.assertRaises(type(signal)) as raised:
                    TrustProofs(proof_crypto(verifier)).verify(
                        proof_token(), cutoff=CUTOFF, keys=keys
                    )
                state = inspect.getcoroutinestate(result)
                keys.effect = None
                del result
                gc.collect()

            self.assertIs(raised.exception, signal)
            self.assertEqual(
                (keys.calls, cleanup_entries, verifier.calls),
                (1, 2, 0),
            )
            self.assertEqual(state, inspect.CORO_CLOSED)
            self.assertEqual(caught, [])

    def test_sync_source_coroutine_cleanup_is_bounded_to_two_attempts(self):
        injected_exits = 0
        permit_close = False

        class Suspend:
            def __await__(self):
                yield None

        async def nested_resolution():
            nonlocal injected_exits
            while True:
                try:
                    await Suspend()
                except GeneratorExit:
                    if permit_close:
                        raise
                    injected_exits += 1

        result = nested_resolution()
        result.send(None)
        keys = SpyKeySource(result)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(VerificationKeySourceContractError):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )
            state_after_production = inspect.getcoroutinestate(result)
            result.throw(GeneratorExit())
            state_after_third = inspect.getcoroutinestate(result)
            permit_close = True
            result.close()
            closed_state = inspect.getcoroutinestate(result)
            keys.effect = None
            del result
            gc.collect()

        self.assertEqual((keys.calls, verifier.calls), (1, 0))
        self.assertEqual(injected_exits, 3)
        self.assertEqual(state_after_production, inspect.CORO_SUSPENDED)
        self.assertEqual(state_after_third, inspect.CORO_SUSPENDED)
        self.assertEqual(closed_state, inspect.CORO_CLOSED)
        self.assertEqual(caught, [])

    def test_sync_source_generic_custom_awaitable_is_untouched(self):
        class CustomAwaitable:
            def __init__(self) -> None:
                self.await_entries = 0
                self.close_calls = 0
                self.throw_calls = 0
                self.cancel_calls = 0

            def __await__(self):
                self.await_entries += 1
                yield None

            def close(self) -> None:
                self.close_calls += 1

            def throw(self, *args: object) -> None:
                del args
                self.throw_calls += 1

            def cancel(self) -> None:
                self.cancel_calls += 1

        result = CustomAwaitable()
        keys = SpyKeySource(result)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
        scheduling_calls = 0

        def record_scheduling(*args, **kwargs):
            nonlocal scheduling_calls
            del args, kwargs
            scheduling_calls += 1
            raise AssertionError("custom awaitable must not be scheduled")

        with (
            patch("asyncio.create_task", side_effect=record_scheduling),
            self.assertRaises(VerificationKeySourceContractError),
        ):
            TrustProofs(proof_crypto(verifier)).verify(
                proof_token(), cutoff=CUTOFF, keys=keys
            )

        self.assertEqual(
            (
                keys.calls,
                result.await_entries,
                result.close_calls,
                result.throw_calls,
                result.cancel_calls,
                scheduling_calls,
                verifier.calls,
            ),
            (1, 0, 0, 0, 0, 0, 0),
        )

    def test_malformed_resolution_and_key_id_mismatches_are_contract_failures(self):
        class UnknownSubclass(UnknownVerificationKey):
            pass

        malformed = object.__new__(TrustedVerificationKey)
        object.__setattr__(malformed, "issuer", ISSUER)
        effects = (
            object(),
            UnknownSubclass(KEY_ID),
            UnknownVerificationKey("another-key"),
            UntrustedVerificationKey("another-key"),
            malformed,
        )
        for effect in effects:
            keys = SpyKeySource(effect)
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(effect_type=type(effect).__name__),
                self.assertRaises(VerificationKeySourceContractError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 0))

    def test_trusted_key_must_exactly_match_lookup_facts(self):
        mismatches = (
            trusted_key(issuer="https://another-oracle.example"),
            trusted_key(key_id="another-key"),
            trusted_key(algorithm=ProofAlgorithm.ED25519),
        )
        wrong_purpose = trusted_key()
        object.__setattr__(wrong_purpose, "purpose", "oracle-general")
        mismatches += (wrong_purpose,)

        for resolution in mismatches:
            keys = SpyKeySource(resolution)
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(field=repr(resolution)),
                self.assertRaises(VerificationKeySourceContractError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 0))

    def test_revocation_at_or_before_cutoff_invalidates_the_key(self):
        for revoked_at in (CUTOFF - timedelta(microseconds=1), CUTOFF):
            keys = SpyKeySource(trusted_key(revoked_at=revoked_at))
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(revoked_at=revoked_at),
                self.assertRaises(RevokedVerificationKeyError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 0))

    def test_cutoff_must_be_inside_the_key_verification_window(self):
        inactive = (
            trusted_key(signing_not_before=CUTOFF + timedelta(microseconds=1)),
            trusted_key(
                signing_not_after=CUTOFF,
                verification_not_after=CUTOFF,
            ),
        )
        for resolution in inactive:
            keys = SpyKeySource(resolution)
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with self.subTest(resolution=resolution):
                with self.assertRaises(InactiveVerificationKeyError):
                    TrustProofs(proof_crypto(verifier)).verify(
                        proof_token(), cutoff=CUTOFF, keys=keys
                    )
                self.assertEqual((keys.calls, verifier.calls), (1, 0))

    def test_malformed_trusted_window_and_public_key_are_contract_failures(self):
        malformed_window = trusted_key()
        object.__setattr__(malformed_window, "signing_not_after", "tomorrow")
        invalid_es256_key = trusted_key(public_key=b"not-a-p256-key")
        invalid_ed25519_key = trusted_key(
            algorithm=ProofAlgorithm.ED25519,
            public_key=b"\x00" * 32,
        )
        cases = (
            (malformed_window, proof_token(), False),
            (invalid_es256_key, proof_token(), False),
            (
                invalid_ed25519_key,
                proof_token(algorithm="EdDSA", signature=b"x" * 64),
                True,
            ),
        )
        for resolution, raw, include_ed25519 in cases:
            keys = SpyKeySource(resolution)
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(resolution=resolution),
                self.assertRaises(VerificationKeySourceContractError),
            ):
                TrustProofs(
                    proof_crypto(verifier, include_ed25519=include_ed25519)
                ).verify(raw, cutoff=CUTOFF, keys=keys)
            self.assertEqual((keys.calls, verifier.calls), (1, 0))

    def test_framing_header_algorithm_and_issuer_failures_have_no_effect(self):
        bad_issuer = valid_payload()
        bad_issuer["iss"] = "relative/path"
        cases = (
            (ProofFormatError, "not-a-token", False),
            (
                ProofFormatError,
                proof_token(proof_type="ktp-trust-proof+jwt"),
                False,
            ),
            (
                UnsupportedProofAlgorithmError,
                proof_token(algorithm="RS256"),
                False,
            ),
            (
                DisabledProofAlgorithmError,
                proof_token(algorithm="EdDSA", signature=b"x" * 64),
                False,
            ),
            (ProofFormatError, proof_token(payload=bad_issuer), False),
        )
        for error, raw, include_ed25519 in cases:
            keys, verifier = provider_spies()
            with (
                self.subTest(error=error.__name__),
                self.assertRaises(error),
            ):
                TrustProofs(
                    proof_crypto(verifier, include_ed25519=include_ed25519)
                ).verify(raw, cutoff=CUTOFF, keys=keys)
            self.assertEqual((keys.calls, verifier.calls), (0, 0))


class VerificationSignatureAndVerifierTests(unittest.TestCase):
    def test_malformed_signature_stops_after_source_and_before_verifier(self):
        cases = (
            (
                proof_token(signature=b"\x00" * 64),
                trusted_key(),
                False,
            ),
            (
                proof_token(algorithm="EdDSA", signature=b"\x00" * 64),
                trusted_key(
                    algorithm=ProofAlgorithm.ED25519,
                    public_key=RFC8032_PUBLIC_KEY,
                ),
                True,
            ),
        )
        for raw, resolution, include_ed25519 in cases:
            events: list[str] = []
            keys = SpyKeySource(resolution, events=events)
            verifier = SpyVerifier(
                SignatureVerificationOutcome.VALID,
                events=events,
            )
            with (
                self.subTest(algorithm=resolution.algorithm.value),
                self.assertRaises(InvalidSignatureError),
            ):
                TrustProofs(
                    proof_crypto(verifier, include_ed25519=include_ed25519)
                ).verify(raw, cutoff=CUTOFF, keys=keys)
            self.assertEqual((keys.calls, verifier.calls), (1, 0))
            self.assertEqual(events, ["keys.resolve"])

    def test_invalid_signature_calls_providers_once_with_exact_owned_arguments(self):
        events: list[str] = []
        resolution = trusted_key()
        keys = SpyKeySource(resolution, events=events)
        verifier = SpyVerifier(
            SignatureVerificationOutcome.INVALID_SIGNATURE,
            events=events,
        )
        raw = proof_token()

        with self.assertRaises(InvalidSignatureError):
            TrustProofs(proof_crypto(verifier)).verify(
                raw,
                cutoff=CUTOFF,
                keys=keys,
            )

        self.assertEqual((keys.calls, verifier.calls), (1, 1))
        self.assertEqual(events, ["keys.resolve", "verifier.verify"])
        header_segment, payload_segment, _ = raw.split(".")
        self.assertEqual(
            verifier.arguments,
            [
                {
                    "public_key": ES256_PUBLIC_KEY,
                    "signing_input": f"{header_segment}.{payload_segment}".encode(
                        "ascii"
                    ),
                    "signature": VALID_SIGNATURE,
                }
            ],
        )

    def test_verifier_declared_and_ordinary_failures_map_with_cause(self):
        cases = (
            (ProviderUnavailable("offline"), CryptoProviderUnavailableError),
            (ProviderFailure("failed"), CryptoProviderFailureError),
            (RuntimeError("undeclared"), CryptoProviderFailureError),
        )
        for signal, outward in cases:
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(signal)
            with self.subTest(signal=type(signal).__name__):
                with self.assertRaises(outward) as raised:
                    TrustProofs(proof_crypto(verifier)).verify(
                        proof_token(), cutoff=CUTOFF, keys=keys
                    )
                self.assertIs(raised.exception.__cause__, signal)
                self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_verifier_process_control_signals_propagate_unchanged(self):
        for signal in (KeyboardInterrupt(), SystemExit(9), GeneratorExit()):
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(signal)
            with self.subTest(signal=type(signal).__name__):
                with self.assertRaises(type(signal)) as raised:
                    TrustProofs(proof_crypto(verifier)).verify(
                        proof_token(), cutoff=CUTOFF, keys=keys
                    )
                self.assertIs(raised.exception, signal)
                self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_sync_verifier_native_coroutine_result_is_closed_before_contract_error(
        self,
    ):
        body_entries = 0
        scheduling_calls = 0

        async def nested_outcome():
            nonlocal body_entries
            body_entries += 1
            return SignatureVerificationOutcome.VALID

        result = nested_outcome()
        keys = SpyKeySource(trusted_key())
        verifier = SpyVerifier(result)

        def record_scheduling(*args, **kwargs):
            nonlocal scheduling_calls
            del args, kwargs
            scheduling_calls += 1
            raise AssertionError("native coroutine must not be scheduled")

        with (
            patch("asyncio.create_task", side_effect=record_scheduling),
            patch.object(
                verification_kernel,
                "parse_payload",
                side_effect=AssertionError("claim decoding must remain unreachable"),
            ),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always", RuntimeWarning)
            with self.assertRaises(CryptoProviderContractError):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )
            state = inspect.getcoroutinestate(result)
            verifier.effect = None
            del result
            gc.collect()

        self.assertEqual(
            (keys.calls, verifier.calls, body_entries, scheduling_calls),
            (1, 1, 0, 0),
        )
        self.assertEqual(state, inspect.CORO_CLOSED)
        self.assertEqual(caught, [])

    def test_verifier_outcomes_are_exact_and_closed(self):
        cases = (
            (object(), CryptoProviderContractError),
            (True, CryptoProviderContractError),
            (
                SignatureVerificationOutcome.INVALID_PUBLIC_KEY,
                VerificationKeySourceContractError,
            ),
        )
        for outcome, outward in cases:
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(outcome)
            with (
                self.subTest(outcome=repr(outcome)),
                self.assertRaises(outward),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_undeclared_exact_verifier_outcome_stops_before_claim_authority(self):
        undeclared = object.__new__(SignatureVerificationOutcome)
        object.__setattr__(undeclared, "_name_", "UNDECLARED")
        object.__setattr__(undeclared, "_value_", 999)
        keys = SpyKeySource(trusted_key())
        verifier = SpyVerifier(undeclared)

        with (
            patch.object(
                verification_kernel,
                "parse_payload",
                side_effect=AssertionError("claim decoding must remain unreachable"),
            ),
            self.assertRaises(CryptoProviderContractError),
        ):
            TrustProofs(proof_crypto(verifier)).verify(
                proof_token(), cutoff=CUTOFF, keys=keys
            )

        self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_header_algorithm_selects_only_its_bound_verifier(self):
        events: list[str] = []
        es256 = SpyVerifier(SignatureVerificationOutcome.VALID, events=events)
        ed25519 = SpyVerifier(
            SignatureVerificationOutcome.INVALID_SIGNATURE,
            events=events,
        )
        crypto = ProofCrypto(
            (
                VerifierBinding(ProofAlgorithm.ES256, es256),
                VerifierBinding(ProofAlgorithm.ED25519, ed25519),
            )
        )
        keys = SpyKeySource(
            trusted_key(
                algorithm=ProofAlgorithm.ED25519,
                public_key=RFC8032_PUBLIC_KEY,
            ),
            events=events,
        )

        with self.assertRaises(InvalidSignatureError):
            TrustProofs(crypto).verify(
                proof_token(algorithm="EdDSA", signature=RFC8032_SIGNATURE),
                cutoff=CUTOFF,
                keys=keys,
            )

        self.assertEqual((keys.calls, es256.calls, ed25519.calls), (1, 0, 1))
        self.assertEqual(events, ["keys.resolve", "verifier.verify"])
        self.assertEqual(
            ed25519.arguments[0]["public_key"],
            RFC8032_PUBLIC_KEY,
        )


class AuthenticatedClaimsConstructionTests(unittest.TestCase):
    def test_required_decision_binding_round_trips_to_immutable_claims(self):
        keys, verifier = provider_spies()
        claims = (
            TrustProofs(proof_crypto(verifier))
            .verify(proof_token(), cutoff=CUTOFF, keys=keys)
            .claims
        )
        for name in (
            "action",
            "resource",
            "context_hash",
            "trajectory_id",
            "decision_id",
        ):
            self.assertEqual(getattr(claims, name), valid_payload()["ktp"][name])
            with self.assertRaises(AttributeError):
                setattr(claims, name, "changed")

    def test_missing_or_invalid_binding_is_rejected_after_authentication(self):
        invalid = {
            "action": (None, "", "sha256:" + "c" * 64, "C" * 64, "c" * 63),
            "resource": (None, "", "relative", "urn:" + "r" * 2045),
            "context_hash": (
                None,
                "",
                "b" * 64,
                "sha256:" + "B" * 64,
                "sha256:" + "b" * 64 + "\n",
            ),
            "trajectory_id": (None, "", "a" * 257, "bad id", "bad\x00id"),
            "decision_id": (None, "", "a" * 257, "bad id", "bad\x00id"),
        }
        for field, values in invalid.items():
            for value in (*values, "MISSING"):
                with self.subTest(field=field, value=value):
                    payload = valid_payload()
                    if value == "MISSING":
                        del payload["ktp"][field]
                    else:
                        payload["ktp"][field] = value
                    keys, verifier = provider_spies()
                    with self.assertRaises(ProofClaimsError):
                        TrustProofs(proof_crypto(verifier)).verify(
                            proof_token(payload=payload), cutoff=CUTOFF, keys=keys
                        )
                    self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_valid_outcome_returns_owned_immutable_authenticated_evidence(self):
        events: list[str] = []
        resolution = trusted_key()
        keys = SpyKeySource(resolution, events=events)
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID, events=events)
        raw = proof_token()

        result = TrustProofs(proof_crypto(verifier)).verify(
            raw,
            cutoff=CUTOFF,
            keys=keys,
        )

        self.assertIs(type(result), VerifiedTrustProof)
        self.assertEqual((keys.calls, verifier.calls), (1, 1))
        self.assertEqual(events, ["keys.resolve", "verifier.verify"])
        self.assertEqual(result.raw, raw)
        self.assertEqual(
            result.token_digest,
            "sha256:" + sha256(raw.encode("ascii")).hexdigest(),
        )
        self.assertEqual(result.claims.issuer, ISSUER)
        self.assertEqual(result.claims.subject, SUBJECT)
        self.assertEqual(result.claims.issued_at, ISSUED_AT)
        self.assertEqual(result.claims.expires_at, ISSUED_AT + timedelta(seconds=10))
        self.assertEqual(result.claims.base_trust, Decimal(70))
        self.assertEqual(result.claims.effective_trust, Decimal(63))
        self.assertEqual(result.claims.risk, Decimal("0.1"))
        self.assertEqual(result.claims.generation, 7)
        self.assertEqual(result.verification_key, resolution)
        with self.assertRaises((AttributeError, TypeError)):
            result.claims.subject = "urn:agent:forged"  # type: ignore[misc]
        with self.assertRaises((AttributeError, TypeError)):
            result.verification_key.public_key = b"forged"  # type: ignore[misc]

    def test_authenticated_issuer_is_rebound_to_verified_key(self):
        authenticated_payload = valid_payload()
        authenticated_payload["iss"] = "https://different-oracle.example"
        decoded = parse_test_payload(canonical_json(authenticated_payload))
        keys = SpyKeySource(trusted_key())
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        with (
            patch.object(verification_kernel, "parse_payload", return_value=decoded),
            self.assertRaisesRegex(ProofClaimsError, "issuer"),
        ):
            TrustProofs(proof_crypto(verifier)).verify(
                proof_token(), cutoff=CUTOFF, keys=keys
            )

        self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_verified_evidence_does_not_reconstruct_core_authority(self):
        keys = SpyKeySource(trusted_key())
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
        result = TrustProofs(proof_crypto(verifier)).verify(
            proof_token(), cutoff=CUTOFF, keys=keys
        )

        core_authority = (EvaluationBundle, TrustSnapshot, KineticEnvelopeResult)
        self.assertNotIsInstance(result, core_authority)
        self.assertNotIsInstance(result.claims, core_authority)
        for name in ("decision", "allowed", "outcome", "evaluation", "trust"):
            self.assertFalse(hasattr(result, name))
        source = inspect.getsource(verification_kernel)
        for name in ("EvaluationBundle", "TrustSnapshot", "KineticEnvelopeResult"):
            self.assertNotIn(name, source)
        self.assertEqual(source.count("object.__new__(TrustProofClaims)"), 1)


class AuthenticatedTimeBindingTests(unittest.TestCase):
    def test_cutoff_and_ten_second_lifetime_boundaries_are_exact(self):
        valid_cases = (
            (ISSUED_AT_SECONDS + 1, ISSUED_AT),
            (ISSUED_AT_SECONDS + 10, ISSUED_AT),
            (
                ISSUED_AT_SECONDS + 10,
                ISSUED_AT + timedelta(seconds=9, microseconds=999_999),
            ),
        )
        for expiration, cutoff in valid_cases:
            payload = valid_payload()
            payload["exp"] = expiration
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with self.subTest(expiration=expiration, cutoff=cutoff):
                result = TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=payload), cutoff=cutoff, keys=keys
                )
                self.assertEqual(result.claims.issued_at, ISSUED_AT)
                self.assertEqual((keys.calls, verifier.calls), (1, 1))

        invalid_cases = (
            (ISSUED_AT_SECONDS, ISSUED_AT),
            (ISSUED_AT_SECONDS - 1, ISSUED_AT),
            (ISSUED_AT_SECONDS + 11, ISSUED_AT),
            (ISSUED_AT_SECONDS + 10, ISSUED_AT - timedelta(microseconds=1)),
            (ISSUED_AT_SECONDS + 10, ISSUED_AT + timedelta(seconds=10)),
        )
        for expiration, cutoff in invalid_cases:
            payload = valid_payload()
            payload["exp"] = expiration
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(expiration=expiration, cutoff=cutoff),
                self.assertRaises(ProofLifetimeError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=payload), cutoff=cutoff, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_numeric_dates_require_exact_integers_after_crypto_success(self):
        for member, value in (("iat", True), ("iat", "1787572800"), ("exp", 1.5)):
            payload = valid_payload()
            payload[member] = value
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(member=member, value=value),
                self.assertRaises(ProofClaimsError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=payload), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_authenticated_iat_must_be_inside_key_signing_window(self):
        inactive = (
            trusted_key(signing_not_before=ISSUED_AT + timedelta(microseconds=1)),
            trusted_key(signing_not_after=ISSUED_AT),
        )
        for resolution in inactive:
            keys = SpyKeySource(resolution)
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(resolution=resolution),
                self.assertRaises(InactiveVerificationKeyError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))


class AuthenticatedClaimsValidationTests(unittest.TestCase):
    def test_decimal_core_edges_are_accepted_after_authentication(self):
        cases = (
            ("1e6144", Decimal("1e6144")),
            ("1e-6143", Decimal("1e-6143")),
            (
                "9999999999999999999999999999999999",
                Decimal("9999999999999999999999999999999999"),
            ),
            (
                "0.1234567890123456789012345678901234",
                Decimal("0.1234567890123456789012345678901234"),
            ),
        )
        for lexeme, expected in cases:
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

            with self.subTest(lexeme=lexeme):
                verified = TrustProofs(proof_crypto(verifier)).verify(
                    proof_token_with_ktp_decimal("de_dt", lexeme),
                    cutoff=CUTOFF,
                    keys=keys,
                )

            self.assertEqual(verified.claims.velocity, expected)
            self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_decimal_values_outside_core_bounds_fail_only_after_authentication(self):
        lexemes = (
            "1e6145",
            "1e-6144",
            "10000000000000000000000000000000000",
            "0.12345678901234567890123456789012345",
            "1e999999",
        )
        for lexeme in lexemes:
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

            with (
                self.subTest(lexeme=lexeme),
                self.assertRaises(ProofClaimsError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token_with_ktp_decimal("de_dt", lexeme),
                    cutoff=CUTOFF,
                    keys=keys,
                )

            self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_active_root_extreme_decimal_is_a_claim_error_not_decimal_overflow(self):
        payload = valid_payload()
        payload["ktp"]["root_instrument"] = {  # type: ignore[index]
            "status": "current",
            "end_time": ISSUED_AT_SECONDS + 10,
            "exposure_class": "declared_assets",
            "declared_exposure": "decimal-lexeme",
            "anchored_capacity": 1,
            "terminator": "org:external-root",
            "chain_length": 2,
        }
        payload_bytes = canonical_json(payload).replace(
            b'"decimal-lexeme"', b"1e999999"
        )
        raw = compact_token(
            canonical_json({"alg": "ES256", "kid": KEY_ID, "typ": "ktp+jwt"}),
            payload_bytes,
            VALID_SIGNATURE,
        )
        keys = SpyKeySource(trusted_key())
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        with self.assertRaises(ProofClaimsError):
            TrustProofs(proof_crypto(verifier)).verify(raw, cutoff=CUTOFF, keys=keys)

        self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_unknown_members_are_rejected_only_after_cryptographic_success(self):
        mutations = {
            "top": lambda payload: payload.__setitem__("application", {}),
            "ktp": lambda payload: payload["ktp"].__setitem__(  # type: ignore[union-attr]
                "application", {}
            ),
            "context": lambda payload: payload["ktp"]["context"].__setitem__(  # type: ignore[index,union-attr]
                "seventh_factor", 0
            ),
            "soul": lambda payload: payload["ktp"]["soul"].__setitem__(  # type: ignore[index,union-attr]
                "permission", True
            ),
            "ceiling": lambda payload: payload["ktp"][  # type: ignore[index]
                "applicable_ceilings"
            ][0].__setitem__("policy", "allow"),  # type: ignore[index,union-attr]
            "root": lambda payload: payload["ktp"]["root_instrument"].__setitem__(  # type: ignore[index,union-attr]
                "decision", "permit"
            ),
        }
        for location, mutate in mutations.items():
            payload = valid_payload()
            mutate(payload)
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(location=location),
                self.assertRaises(ProofClaimsError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=payload), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_untrusted_claim_mapping_never_preempts_crypto_outcome(self):
        payload = valid_payload()
        payload["application"] = {"decision": "permit"}
        cases = (
            (
                SignatureVerificationOutcome.INVALID_SIGNATURE,
                InvalidSignatureError,
            ),
            (ProviderFailure("failed"), CryptoProviderFailureError),
        )
        for effect, outward in cases:
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(effect)
            with self.subTest(effect=type(effect).__name__):
                with self.assertRaises(outward):
                    TrustProofs(proof_crypto(verifier)).verify(
                        proof_token(payload=payload), cutoff=CUTOFF, keys=keys
                    )
                self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_required_profile_bindings_are_exact_and_bounded(self):
        invalid: list[tuple[str, dict[str, object]]] = []
        for member in ("generation", "resilience_hash"):
            payload = valid_payload()
            del payload["ktp"][member]  # type: ignore[index]
            invalid.append((f"missing-{member}", payload))
        for label, generation in (
            ("negative-generation", -1),
            ("huge-generation", 2**63),
        ):
            payload = valid_payload()
            payload["ktp"]["generation"] = generation  # type: ignore[index]
            invalid.append((label, payload))
        for label, resilience_hash in (
            ("bare-digest", "a" * 64),
            ("uppercase-digest", "sha256:" + ("A" * 64)),
            ("short-digest", "sha256:abc"),
        ):
            payload = valid_payload()
            payload["ktp"]["resilience_hash"] = resilience_hash  # type: ignore[index]
            invalid.append((label, payload))
        payload = valid_payload()
        payload["ktp"]["oracle_quorum"] = "3/5"  # type: ignore[index]
        invalid.append(("malformed-quorum", payload))

        for label, payload in invalid:
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(label=label),
                self.assertRaises(ProofClaimsError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=payload), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_all_optional_claims_and_external_active_soul_are_preserved(self):
        payload = valid_payload()
        ktp = payload["ktp"]
        ktp.update(  # type: ignore[union-attr]
            {
                "e_base": 45,
                "e_trust": 40.5,
                "de_dt": -2.3,
                "sigma": 0.15,
                "lineage": "sponsored",
                "generation": 2,
                "sponsor": "urn:agent:sponsor",
                "zone": "zone-blue-research",
                "oracle_quorum": "2-of-3",
                "soul": {
                    "soul": 1,
                    "constraint_type": "tk_label",
                    "constraint_id": "TK-NC-001",
                    "constraint_name": "TK Non-Commercial",
                    "authority": "https://localcontexts.org/label/tk-nc/",
                    "community": "Example Indigenous Community",
                    "remediation": "Contact the community data steward",
                },
                "root_instrument": {
                    "status": "current",
                    "end_time": ISSUED_AT_SECONDS + 60,
                    "exposure_class": None,
                    "declared_exposure": None,
                    "anchored_capacity": None,
                    "terminator": None,
                    "chain_length": None,
                },
            }
        )
        ktp["applicable_ceilings"][1]["value"] = 45  # type: ignore[index]
        keys = SpyKeySource(trusted_key())
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        result = TrustProofs(proof_crypto(verifier)).verify(
            proof_token(payload=payload), cutoff=CUTOFF, keys=keys
        )

        claims = result.claims
        self.assertEqual(claims.velocity, Decimal("-2.3"))
        self.assertEqual(claims.volatility, Decimal("0.15"))
        self.assertEqual(claims.sponsor, "urn:agent:sponsor")
        self.assertEqual(claims.zone, "zone-blue-research")
        self.assertEqual(claims.oracle_quorum, "2-of-3")
        self.assertEqual(claims.soul.soul, 1)
        self.assertEqual(claims.soul.constraint_type.value, "tk_label")
        self.assertEqual(claims.soul.constraint_id, "TK-NC-001")
        self.assertEqual(claims.soul.constraint_name, "TK Non-Commercial")
        self.assertEqual(
            claims.soul.authority,
            "https://localcontexts.org/label/tk-nc/",
        )
        self.assertEqual(claims.soul.community, "Example Indigenous Community")
        self.assertEqual(
            claims.soul.remediation,
            "Contact the community data steward",
        )
        self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_schema_types_nested_coherence_and_text_policy_close_after_auth(self):
        invalid: list[tuple[str, dict[str, object]]] = []

        payload = valid_payload()
        del payload["sub"]
        invalid.append(("missing-top-member", payload))

        payload = valid_payload()
        del payload["ktp"]["r"]  # type: ignore[index]
        invalid.append(("missing-ktp-member", payload))

        payload = valid_payload()
        del payload["ktp"]["context"]["trust_trend"]  # type: ignore[index]
        invalid.append(("missing-context-member", payload))

        payload = valid_payload()
        payload["ktp"]["e_base"] = True  # type: ignore[index]
        invalid.append(("boolean-number", payload))

        payload = valid_payload()
        payload["ktp"]["context"]["moment_criticality"] = 1.1  # type: ignore[index]
        invalid.append(("context-out-of-range", payload))

        payload = valid_payload()
        payload["sub"] = "relative/agent"
        invalid.append(("relative-subject", payload))

        payload = valid_payload()
        payload["jti"] = "proof 1"
        invalid.append(("whitespace-proof-id", payload))

        payload = valid_payload()
        payload["iat"] = 10**100
        invalid.append(("unrepresentable-numeric-date", payload))

        payload = valid_payload()
        payload["ktp"]["generation"] = True  # type: ignore[index]
        invalid.append(("boolean-generation", payload))

        payload = valid_payload()
        payload["ktp"]["soul"] = {  # type: ignore[index]
            "soul": 0,
            "authority": "https://authority.example",
        }
        invalid.append(("clear-soul-with-details", payload))

        payload = valid_payload()
        payload["ktp"]["soul"] = {  # type: ignore[index]
            "soul": 1,
            "constraint_type": "tk_label",
        }
        invalid.append(("active-soul-without-authority", payload))

        payload = valid_payload()
        payload["ktp"]["applicable_ceilings"] = [{}]  # type: ignore[index]
        invalid.append(("malformed-ceiling", payload))

        payload = valid_payload()
        payload["ktp"]["root_instrument"] = {  # type: ignore[index]
            "status": "none",
            "end_time": ISSUED_AT_SECONDS + 10,
        }
        invalid.append(("none-root-with-detail", payload))

        payload = valid_payload()
        payload["ktp"]["root_instrument"] = {"status": "current"}  # type: ignore[index]
        invalid.append(("active-root-without-end", payload))

        payload = valid_payload()
        payload["ktp"]["zone"] = "zone-e\u0301"  # type: ignore[index]
        invalid.append(("non-nfc-zone", payload))

        for member in ("de_dt", "sigma", "zone", "oracle_quorum"):
            payload = valid_payload()
            payload["ktp"][member] = None  # type: ignore[index]
            invalid.append((f"null-{member}", payload))

        payload = valid_payload()
        payload["ktp"]["root_instrument"] = {  # type: ignore[index]
            "status": "none",
            "end_time": None,
        }
        invalid.append(("null-root-end-time", payload))

        for label, payload in invalid:
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(label=label),
                self.assertRaises(ProofClaimsError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=payload), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))


class AuthenticatedCoreCoherenceTests(unittest.TestCase):
    def test_none_root_composition_bound_tracks_declared_peer_share(self):
        cases = (
            (0, 70, 71),
            (10, 73, 74),
            (20, 76, 77),
        )
        for peer_share, reachable_maximum, maximum_plus_one in cases:
            valid = valid_payload()
            valid["ktp"].update(  # type: ignore[union-attr]
                {
                    "e_base": reachable_maximum,
                    "e_trust": reachable_maximum,
                    "r": 0,
                    "peer_share": peer_share,
                }
            )
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with self.subTest(peer_share=peer_share, boundary="maximum"):
                result = TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=valid), cutoff=CUTOFF, keys=keys
                )
                self.assertEqual(result.claims.base_trust, Decimal(reachable_maximum))
                self.assertEqual((keys.calls, verifier.calls), (1, 1))

            invalid = deepcopy(valid)
            invalid["ktp"].update(  # type: ignore[union-attr]
                {
                    "e_base": maximum_plus_one,
                    "e_trust": maximum_plus_one,
                }
            )
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(peer_share=peer_share, boundary="maximum-plus-one"),
                self.assertRaises(ProofClaimsError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=invalid), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_active_root_composition_uses_authenticated_root_details(self):
        cases = (
            ("current", 0, 50, 100, 85, 86),
            ("non_renewable", 20, 25, 100, 82, 83),
        )
        for (
            status,
            peer_share,
            declared_exposure,
            anchored_capacity,
            reachable_maximum,
            maximum_plus_one,
        ) in cases:
            valid = valid_payload()
            valid["ktp"].update(  # type: ignore[union-attr]
                {
                    "e_base": reachable_maximum,
                    "e_trust": reachable_maximum,
                    "r": 0,
                    "peer_share": peer_share,
                    "root_instrument": {
                        "status": status,
                        "end_time": ISSUED_AT_SECONDS + 60,
                        "exposure_class": "declared-assets",
                        "declared_exposure": declared_exposure,
                        "anchored_capacity": anchored_capacity,
                        "terminator": "org:external-root",
                        "chain_length": 2,
                    },
                }
            )
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with self.subTest(status=status, boundary="maximum"):
                result = TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=valid), cutoff=CUTOFF, keys=keys
                )
                self.assertEqual(result.claims.base_trust, Decimal(reachable_maximum))
                self.assertEqual((keys.calls, verifier.calls), (1, 1))

            invalid = deepcopy(valid)
            invalid["ktp"].update(  # type: ignore[union-attr]
                {
                    "e_base": maximum_plus_one,
                    "e_trust": maximum_plus_one,
                }
            )
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(status=status, boundary="maximum-plus-one"),
                self.assertRaises(ProofClaimsError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=invalid), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_effective_trust_equation_uses_the_fixed_ktp_decimal_context(self):
        payload = valid_payload()
        payload["ktp"].update(  # type: ignore[union-attr]
            {
                "e_base": "base-lexeme",
                "e_trust": "effective-lexeme",
                "r": "risk-lexeme",
                "root_instrument": {
                    "status": "current",
                    "end_time": ISSUED_AT_SECONDS + 60,
                    "exposure_class": "declared-assets",
                    "declared_exposure": 50,
                    "anchored_capacity": 100,
                    "terminator": "org:external-root",
                    "chain_length": 2,
                },
            }
        )
        payload_bytes = canonical_json(payload)
        payload_bytes = payload_bytes.replace(
            b'"base-lexeme"', b"84.99999999999999999999999999999999"
        )
        payload_bytes = payload_bytes.replace(
            b'"effective-lexeme"', b"74.5061729339506172933950617293395"
        )
        payload_bytes = payload_bytes.replace(
            b'"risk-lexeme"', b"0.1234567890123456789012345678901234"
        )
        raw = compact_token(
            canonical_json({"alg": "ES256", "kid": KEY_ID, "typ": "ktp+jwt"}),
            payload_bytes,
            VALID_SIGNATURE,
        )
        keys = SpyKeySource(trusted_key())
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        result = TrustProofs(proof_crypto(verifier)).verify(
            raw, cutoff=CUTOFF, keys=keys
        )

        self.assertEqual(
            result.claims.effective_trust,
            Decimal("74.5061729339506172933950617293395"),
        )
        self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_effective_trust_equation_is_independent_of_ambient_decimal_context(self):
        payload = valid_payload()
        payload["ktp"].update(  # type: ignore[union-attr]
            {
                "e_base": 90.99,
                "e_trust": 79.761834,
                "r": 0.1234,
                "root_instrument": {
                    "status": "current",
                    "end_time": ISSUED_AT_SECONDS + 60,
                    "exposure_class": "declared-assets",
                    "declared_exposure": 70,
                    "anchored_capacity": 100,
                    "terminator": "org:external-root",
                    "chain_length": 2,
                },
            }
        )
        keys = SpyKeySource(trusted_key())
        verifier = SpyVerifier(SignatureVerificationOutcome.VALID)

        with localcontext() as context:
            context.prec = 2
            result = TrustProofs(proof_crypto(verifier)).verify(
                proof_token(payload=payload), cutoff=CUTOFF, keys=keys
            )

        self.assertEqual(result.claims.effective_trust, Decimal("79.761834"))
        self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_scores_lineage_peer_share_and_ceilings_are_cross_bound(self):
        invalid: list[tuple[str, dict[str, object]]] = []

        payload = valid_payload()
        payload["ktp"]["e_trust"] = 71.999  # type: ignore[index]
        invalid.append(("effective-trust-equation", payload))

        for label, generation, lineage in (
            ("sponsored-generation", 2, "guarantor"),
            ("independent-generation", 5, "guarantor"),
            ("guarantor-generation", 7, "independent"),
        ):
            payload = valid_payload()
            payload["ktp"]["generation"] = generation  # type: ignore[index]
            payload["ktp"]["lineage"] = lineage  # type: ignore[index]
            invalid.append((label, payload))

        sponsored = valid_payload()
        sponsored["ktp"].update(  # type: ignore[union-attr]
            {
                "e_base": 45,
                "e_trust": 40.5,
                "lineage": "sponsored",
                "generation": 2,
            }
        )
        sponsored["ktp"]["applicable_ceilings"][1]["value"] = 45  # type: ignore[index]
        invalid.append(("missing-sponsor", sponsored))

        sponsor_null = deepcopy(sponsored)
        sponsor_null["ktp"]["sponsor"] = None  # type: ignore[index]
        invalid.append(("null-sponsor", sponsor_null))

        payload = valid_payload()
        payload["ktp"]["sponsor"] = None  # type: ignore[index]
        invalid.append(("forbidden-sponsor-member", payload))

        for share in (5, 21):
            payload = valid_payload()
            payload["ktp"]["peer_share"] = share  # type: ignore[index]
            invalid.append((f"peer-share-{share}", payload))

        payload = valid_payload()
        payload["ktp"]["applicable_ceilings"] = []  # type: ignore[index]
        invalid.append(("empty-ceilings", payload))

        payload = valid_payload()
        payload["ktp"]["applicable_ceilings"].append(  # type: ignore[index,union-attr]
            {"ceiling": "ial", "value": 95}
        )
        invalid.append(("duplicate-ceiling", payload))

        payload = valid_payload()
        payload["ktp"]["applicable_ceilings"] = [  # type: ignore[index]
            item
            for item in payload["ktp"]["applicable_ceilings"]  # type: ignore[index,union-attr]
            if item["ceiling"] != "generation"
        ]
        invalid.append(("missing-generation-ceiling", payload))

        payload = valid_payload()
        payload["ktp"]["applicable_ceilings"][1]["value"] = 99  # type: ignore[index]
        invalid.append(("wrong-generation-ceiling", payload))

        payload = valid_payload()
        payload["ktp"]["applicable_ceilings"][2]["value"] = 69  # type: ignore[index]
        invalid.append(("base-exceeds-ceiling", payload))

        payload = valid_payload()
        payload["ktp"]["applicable_ceilings"] = [  # type: ignore[index]
            item
            for item in payload["ktp"]["applicable_ceilings"]  # type: ignore[index,union-attr]
            if item["ceiling"] != "adversity"
        ]
        invalid.append(("missing-full-core-ceiling", payload))

        for label, payload in invalid:
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(label=label),
                self.assertRaises(ProofClaimsError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=payload), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_active_root_details_follow_lineage_and_hard_chain_bound(self):
        invalid: list[tuple[str, dict[str, object]]] = []

        for status in ("current", "non_renewable"):
            payload = valid_payload()
            payload["ktp"]["root_instrument"] = {  # type: ignore[index]
                "status": status,
                "end_time": ISSUED_AT_SECONDS + 10,
            }
            invalid.append((f"{status}-missing-attestation-details", payload))

        payload = valid_payload()
        payload["ktp"]["root_instrument"] = {  # type: ignore[index]
            "status": "current",
            "end_time": ISSUED_AT_SECONDS + 10,
            "exposure_class": "declared_assets",
            "declared_exposure": 50,
            "anchored_capacity": 0,
            "terminator": "org:external-root",
            "chain_length": 2,
        }
        invalid.append(("zero-anchored-capacity", payload))

        payload = valid_payload()
        payload["ktp"]["root_instrument"] = {  # type: ignore[index]
            "status": "current",
            "end_time": ISSUED_AT_SECONDS + 10,
            "exposure_class": "declared_assets",
            "declared_exposure": 50,
            "anchored_capacity": 60,
            "terminator": "org:external-root",
            "chain_length": 13,
        }
        invalid.append(("chain-over-twelve", payload))

        sponsored = valid_payload()
        sponsored["ktp"].update(  # type: ignore[union-attr]
            {
                "e_base": 45,
                "e_trust": 40.5,
                "lineage": "sponsored",
                "generation": 2,
                "sponsor": "urn:agent:sponsor",
                "root_instrument": {
                    "status": "current",
                    "end_time": ISSUED_AT_SECONDS + 10,
                    "exposure_class": "declared_assets",
                    "declared_exposure": 50,
                    "anchored_capacity": 60,
                    "terminator": "org:external-root",
                    "chain_length": 2,
                },
            }
        )
        sponsored["ktp"]["applicable_ceilings"][1]["value"] = 45  # type: ignore[index]
        invalid.append(("sponsored-attestation-details", sponsored))

        for label, payload in invalid:
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(label=label),
                self.assertRaises(ProofClaimsError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=payload), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))

    def test_active_root_lifetime_is_tightened_and_valid_details_are_preserved(self):
        for status in ("current", "non_renewable"):
            payload = valid_payload()
            payload["ktp"]["root_instrument"] = {  # type: ignore[index]
                "status": status,
                "end_time": ISSUED_AT_SECONDS + 10,
                "exposure_class": "declared_assets",
                "declared_exposure": 50,
                "anchored_capacity": 60,
                "terminator": "org:external-root",
                "chain_length": 12,
            }
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with self.subTest(status=status):
                result = TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=payload), cutoff=CUTOFF, keys=keys
                )
                root = result.claims.root_instrument
                self.assertEqual(root.status.value, status)
                self.assertEqual(root.end_time, ISSUED_AT + timedelta(seconds=10))
                self.assertEqual(root.exposure_class, "declared_assets")
                self.assertEqual(root.declared_exposure, Decimal(50))
                self.assertEqual(root.anchored_capacity, Decimal(60))
                self.assertEqual(root.terminator, "org:external-root")
                self.assertEqual(root.chain_length, 12)
                self.assertEqual((keys.calls, verifier.calls), (1, 1))

        for label, end_time in (
            ("proof-outlives-root", ISSUED_AT_SECONDS + 9),
            ("root-expired-at-cutoff", ISSUED_AT_SECONDS + 5),
        ):
            payload = valid_payload()
            payload["ktp"]["root_instrument"] = {  # type: ignore[index]
                "status": "current",
                "end_time": end_time,
                "exposure_class": "declared_assets",
                "declared_exposure": 50,
                "anchored_capacity": 60,
                "terminator": "org:external-root",
                "chain_length": 2,
            }
            keys = SpyKeySource(trusted_key())
            verifier = SpyVerifier(SignatureVerificationOutcome.VALID)
            with (
                self.subTest(label=label),
                self.assertRaises(ProofLifetimeError),
            ):
                TrustProofs(proof_crypto(verifier)).verify(
                    proof_token(payload=payload), cutoff=CUTOFF, keys=keys
                )
            self.assertEqual((keys.calls, verifier.calls), (1, 1))


if __name__ == "__main__":
    unittest.main()
