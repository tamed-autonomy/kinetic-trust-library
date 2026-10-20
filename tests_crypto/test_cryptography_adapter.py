"""Official optional PyCA Trust Proof adapter tests."""

from __future__ import annotations

import asyncio
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
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
    ed25519_public_key_bytes,
    es256_public_key_bytes,
)
from kinetic_trust_library.errors import CryptoConfigurationError
from kinetic_trust_library.models.proof import (
    KeyPurpose,
    OracleSigningIdentity,
    ProofAlgorithm,
    SignatureVerificationOutcome,
)
from kinetic_trust_library.protocols import ProviderFailure, ProviderUnavailable


P256_ORDER = int(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    16,
)
P256_FIELD_PRIME = int(
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    16,
)
ED25519_ORDER = int(
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
    16,
)
ED25519_FIELD_PRIME = int(
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
    16,
)
ED25519_CURVE_D = int(
    "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
    16,
)
ED25519_NON_POINT_Y_TWO = bytes.fromhex("02" + ("00" * 31))
ED25519_NON_POINT_Y_TWO_SIGNED = ED25519_NON_POINT_Y_TWO[:-1] + b"\x80"
FIXED_SIGNING_INPUT = b"header.payload"
FIXED_ES256_SIGNATURE = bytes.fromhex(
    "923d05fc827f94ce2fac62796a0ce8b106cf0a7f133e0d931608c5d306721a34"
    "7c105399c15d547f65c1b6116ae8f655fd3b79e16b3ac06b02bc08f3704e9d43"
)
P256_GENERATOR = bytes.fromhex(
    "04"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
ED25519_SMALL_ORDER_ENCODINGS = tuple(
    bytes.fromhex(value)
    for value in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    )
)
_NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


def _implemented(call, /, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except NotImplementedError as error:
        raise AssertionError("optional adapter behavior is not implemented") from error


def _es256_private_key():
    return ec.derive_private_key(1, ec.SECP256R1())


def _ed25519_private_key():
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _identity(
    algorithm: ProofAlgorithm,
    public_key: bytes,
    *,
    purpose: KeyPurpose = KeyPurpose.ORACLE_TRUST_PROOF,
) -> OracleSigningIdentity:
    return OracleSigningIdentity(
        issuer="https://oracle.example",
        key_id=f"{algorithm.name.lower()}-key-1",
        algorithm=algorithm,
        purpose=purpose,
        public_key=public_key,
        signing_not_before=_NOW - timedelta(minutes=1),
        signing_not_after=_NOW + timedelta(minutes=1),
        revoked_at=None,
    )


def _es256_identity(private_key=None) -> OracleSigningIdentity:
    key = _es256_private_key() if private_key is None else private_key
    return _identity(
        ProofAlgorithm.ES256,
        _implemented(es256_public_key_bytes, key.public_key()),
    )


def _ed25519_identity(private_key=None) -> OracleSigningIdentity:
    key = _ed25519_private_key() if private_key is None else private_key
    return _identity(
        ProofAlgorithm.ED25519,
        _implemented(ed25519_public_key_bytes, key.public_key()),
    )


def _sync_verifier(algorithm: ProofAlgorithm):
    configured = _implemented(cryptography_proof_crypto)
    return next(
        binding.verifier
        for binding in configured.bindings
        if binding.algorithm is algorithm
    )


def _async_verifier(algorithm: ProofAlgorithm):
    configured = _implemented(async_cryptography_proof_crypto)
    return next(
        binding.verifier
        for binding in configured.bindings
        if binding.algorithm is algorithm
    )


def _fake_es256_modules(
    real_modules,
    *,
    signing_effect: object = b"",
    verification_effect: object = None,
    load_effect: BaseException | None = None,
    capability_effect: BaseException | None = None,
):
    public_bytes = b"\x04" + (b"\x01" * 64)

    class FakeCurve:
        group_order = P256_ORDER

    class FakePublicKey:
        curve = FakeCurve()

        @classmethod
        def from_encoded_point(cls, curve, encoded):
            if load_effect is not None:
                raise load_effect
            return cls()

        def public_bytes(self, encoding, format):
            return public_bytes

        def verify(self, signature, message, algorithm):
            if isinstance(verification_effect, BaseException):
                raise verification_effect
            return verification_effect

    class FakePrivateKey:
        def __init__(self) -> None:
            self.sign_calls = 0

        def public_key(self):
            return FakePublicKey()

        def sign(self, signing_input, algorithm):
            self.sign_calls += 1
            if isinstance(signing_effect, BaseException):
                raise signing_effect
            return signing_effect

    def ecdsa(algorithm, *, deterministic_signing=False):
        if capability_effect is not None and deterministic_signing:
            raise capability_effect
        return (algorithm, deterministic_signing)

    fake_ec = SimpleNamespace(
        ECDSA=ecdsa,
        EllipticCurvePrivateKey=FakePrivateKey,
        EllipticCurvePublicKey=FakePublicKey,
        SECP256R1=FakeCurve,
    )
    return replace(real_modules, ec=fake_ec), FakePrivateKey(), public_bytes


def _fake_ed25519_modules(real_modules, *, signing_effect: object):
    real_key = _ed25519_private_key()
    public_bytes = real_key.public_key().public_bytes_raw()

    class FakePublicKey:
        @classmethod
        def from_public_bytes(cls, encoded):
            return cls()

        def public_bytes_raw(self):
            return public_bytes

        def verify(self, signature, signing_input):
            return None

    class FakePrivateKey:
        def __init__(self) -> None:
            self.sign_calls = 0

        def public_key(self):
            return FakePublicKey()

        def sign(self, signing_input):
            self.sign_calls += 1
            if isinstance(signing_effect, BaseException):
                raise signing_effect
            return signing_effect

    fake_ed25519 = SimpleNamespace(
        Ed25519PrivateKey=FakePrivateKey,
        Ed25519PublicKey=FakePublicKey,
    )
    return (
        replace(real_modules, ed25519=fake_ed25519),
        FakePrivateKey(),
        public_bytes,
    )


class CryptographyAdapterConfigurationTests(unittest.TestCase):
    def test_factories_enable_both_closed_algorithms_without_signing_capability(self):
        capability = UnsupportedAlgorithm("deterministic ECDSA unavailable")
        with patch.object(ec, "ECDSA", side_effect=capability):
            sync = _implemented(cryptography_proof_crypto)
            asynchronous = _implemented(async_cryptography_proof_crypto)

        expected = (ProofAlgorithm.ES256, ProofAlgorithm.ED25519)
        self.assertEqual(
            tuple(binding.algorithm for binding in sync.bindings), expected
        )
        self.assertEqual(
            tuple(binding.algorithm for binding in asynchronous.bindings),
            expected,
        )

    def test_deterministic_capability_is_required_only_by_es256_signer_construction(
        self,
    ):
        es_key = _es256_private_key()
        ed_key = _ed25519_private_key()
        capability = UnsupportedAlgorithm("deterministic ECDSA unavailable")

        with patch.object(ec, "ECDSA", side_effect=capability):
            _implemented(Ed25519LocalSigner, _ed25519_identity(ed_key), ed_key)
            _implemented(AsyncEd25519LocalSigner, _ed25519_identity(ed_key), ed_key)
            with self.assertRaises(CryptoConfigurationError) as sync_raised:
                _implemented(ES256LocalSigner, _es256_identity(es_key), es_key)
            with self.assertRaises(CryptoConfigurationError) as async_raised:
                _implemented(AsyncES256LocalSigner, _es256_identity(es_key), es_key)

        self.assertIs(sync_raised.exception.__cause__, capability)
        self.assertIs(async_raised.exception.__cause__, capability)

    def test_signer_constructors_require_exact_identity_key_and_algorithm_coherence(
        self,
    ):
        es_key = _es256_private_key()
        ed_key = _ed25519_private_key()
        wrong_es_key = ec.derive_private_key(2, ec.SECP256R1())
        wrong_ed_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        wrong_purpose = copy.copy(_es256_identity(es_key))
        object.__setattr__(wrong_purpose, "purpose", object())

        cases = (
            (ES256LocalSigner, object(), es_key),
            (
                ES256LocalSigner,
                _identity(ProofAlgorithm.ED25519, P256_GENERATOR),
                es_key,
            ),
            (AsyncES256LocalSigner, wrong_purpose, es_key),
            (
                AsyncES256LocalSigner,
                _es256_identity(es_key),
                wrong_es_key,
            ),
            (ES256LocalSigner, _es256_identity(es_key), ed_key),
            (
                Ed25519LocalSigner,
                _identity(
                    ProofAlgorithm.ES256,
                    _implemented(ed25519_public_key_bytes, ed_key.public_key()),
                ),
                ed_key,
            ),
            (
                AsyncEd25519LocalSigner,
                _ed25519_identity(ed_key),
                wrong_ed_key,
            ),
            (Ed25519LocalSigner, _ed25519_identity(ed_key), es_key),
        )
        for signer_type, identity, key in cases:
            with (
                self.subTest(signer=signer_type.__name__),
                self.assertRaises(CryptoConfigurationError),
            ):
                _implemented(signer_type, identity, key)

    def test_signer_constructors_revalidate_and_own_fresh_exact_identity(self):
        cases = (
            (ES256LocalSigner, _es256_private_key(), _es256_identity),
            (AsyncES256LocalSigner, _es256_private_key(), _es256_identity),
            (Ed25519LocalSigner, _ed25519_private_key(), _ed25519_identity),
            (AsyncEd25519LocalSigner, _ed25519_private_key(), _ed25519_identity),
        )
        for signer_type, key, identity_factory in cases:
            identity = identity_factory(key)
            signer = _implemented(signer_type, identity, key)

            with self.subTest(signer=signer_type.__name__):
                self.assertIsNot(signer.identity, identity)
                self.assertEqual(signer.identity, identity)
                original_key_id = signer.identity.key_id
                object.__setattr__(identity, "key_id", "caller-mutated")
                self.assertEqual(signer.identity.key_id, original_key_id)

        forged = object.__new__(OracleSigningIdentity)
        object.__setattr__(forged, "algorithm", ProofAlgorithm.ES256)
        object.__setattr__(forged, "purpose", KeyPurpose.ORACLE_TRUST_PROOF)
        try:
            _implemented(ES256LocalSigner, forged, _es256_private_key())
        except CryptoConfigurationError:
            pass
        except Exception as error:
            self.fail(
                "malformed exact identity escaped stable configuration mapping: "
                f"{type(error).__name__}"
            )
        else:
            self.fail("malformed exact identity was accepted")

    def test_es256_signer_rejects_non_p256_key_even_with_matching_shape(self):
        key = ec.derive_private_key(1, ec.SECP384R1())
        identity = _identity(
            ProofAlgorithm.ES256,
            b"\x04" + (b"\x01" * 64),
        )

        with self.assertRaises(CryptoConfigurationError):
            _implemented(ES256LocalSigner, identity, key)


class ES256AdapterTests(unittest.TestCase):
    def test_fixed_input_signing_is_deterministic_low_s_and_known_answer(self):
        key = _es256_private_key()
        signer = _implemented(ES256LocalSigner, _es256_identity(key), key)

        first = signer.sign(FIXED_SIGNING_INPUT)
        second = signer.sign(FIXED_SIGNING_INPUT)

        self.assertEqual(first, FIXED_ES256_SIGNATURE)
        self.assertEqual(second, FIXED_ES256_SIGNATURE)
        self.assertIs(type(first), bytes)
        self.assertEqual(len(first), 64)
        self.assertLessEqual(int.from_bytes(first[32:], "big"), P256_ORDER // 2)
        r = int.from_bytes(first[:32], "big")
        s = int.from_bytes(first[32:], "big")
        key.public_key().verify(
            utils.encode_dss_signature(r, s),
            FIXED_SIGNING_INPUT,
            ec.ECDSA(hashes.SHA256()),
        )

    def test_verifier_accepts_raw_positive_and_rejects_wrong_message_and_key(self):
        key = _es256_private_key()
        signer = _implemented(ES256LocalSigner, _es256_identity(key), key)
        signature = signer.sign(FIXED_SIGNING_INPUT)
        verifier = _sync_verifier(ProofAlgorithm.ES256)
        public_key = _implemented(es256_public_key_bytes, key.public_key())
        wrong_key = _implemented(
            es256_public_key_bytes,
            ec.derive_private_key(2, ec.SECP256R1()).public_key(),
        )

        self.assertIs(
            verifier.verify(
                public_key=public_key,
                signing_input=FIXED_SIGNING_INPUT,
                signature=signature,
            ),
            SignatureVerificationOutcome.VALID,
        )
        for changed_key, changed_message in (
            (public_key, b"header.changed"),
            (wrong_key, FIXED_SIGNING_INPUT),
        ):
            with self.subTest(key=changed_key, message=changed_message):
                self.assertIs(
                    verifier.verify(
                        public_key=changed_key,
                        signing_input=changed_message,
                        signature=signature,
                    ),
                    SignatureVerificationOutcome.INVALID_SIGNATURE,
                )

    def test_verifier_rejects_der_width_prefix_coordinates_points_and_scalars(self):
        key = _es256_private_key()
        signer = _implemented(ES256LocalSigner, _es256_identity(key), key)
        signature = signer.sign(FIXED_SIGNING_INPUT)
        public_key = _implemented(es256_public_key_bytes, key.public_key())
        verifier = _sync_verifier(ProofAlgorithm.ES256)
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der = utils.encode_dss_signature(r, s)
        high_s = r.to_bytes(32, "big") + (P256_ORDER - s).to_bytes(32, "big")

        invalid_keys = (
            b"",
            public_key[:-1],
            b"\x03" + public_key[1:],
            key.public_key().public_bytes(
                encoding=adapter._load_cryptography().serialization.Encoding.X962,
                format=adapter._load_cryptography().serialization.PublicFormat.CompressedPoint,
            ),
            b"\x04" + (b"\x00" * 64),
            b"\x04" + P256_FIELD_PRIME.to_bytes(32, "big") + (1).to_bytes(32, "big"),
        )
        for malformed_key in invalid_keys:
            with self.subTest(key=malformed_key.hex()[:20]):
                self.assertIs(
                    verifier.verify(
                        public_key=malformed_key,
                        signing_input=FIXED_SIGNING_INPUT,
                        signature=signature,
                    ),
                    SignatureVerificationOutcome.INVALID_PUBLIC_KEY,
                )

        invalid_signatures = (
            b"",
            der,
            (0).to_bytes(32, "big") + (1).to_bytes(32, "big"),
            P256_ORDER.to_bytes(32, "big") + (1).to_bytes(32, "big"),
            (1).to_bytes(32, "big") + (0).to_bytes(32, "big"),
            (1).to_bytes(32, "big") + P256_ORDER.to_bytes(32, "big"),
            high_s,
        )
        for malformed_signature in invalid_signatures:
            with self.subTest(signature=malformed_signature.hex()[:20]):
                self.assertIs(
                    verifier.verify(
                        public_key=public_key,
                        signing_input=FIXED_SIGNING_INPUT,
                        signature=malformed_signature,
                    ),
                    SignatureVerificationOutcome.INVALID_SIGNATURE,
                )

    def test_backend_signer_output_failures_are_typed_and_never_reinterpreted(self):
        real_modules = adapter._load_cryptography()
        valid_der = utils.encode_dss_signature(1, 1)
        effects = (
            bytearray(valid_der),
            b"\x00",
            utils.encode_dss_signature(0, 1),
            utils.encode_dss_signature(P256_ORDER, 1),
            utils.encode_dss_signature(1, 0),
            utils.encode_dss_signature(1, P256_ORDER),
            InternalError("backend sign failed", []),
        )
        for effect in effects:
            modules, private_key, public_bytes = _fake_es256_modules(
                real_modules,
                signing_effect=effect,
            )
            identity = _identity(ProofAlgorithm.ES256, public_bytes)
            with patch.object(adapter, "_load_cryptography", return_value=modules):
                signer = _implemented(ES256LocalSigner, identity, private_key)
            with self.subTest(effect=repr(effect)), self.assertRaises(ProviderFailure):
                signer.sign(FIXED_SIGNING_INPUT)
            self.assertEqual(private_key.sign_calls, 1)

    def test_post_signature_backend_processing_failures_are_definite_provider_failures(
        self,
    ):
        real_modules = adapter._load_cryptography()
        valid_der = utils.encode_dss_signature(1, 1)

        def fail_decode(encoded):
            raise RuntimeError("decoder failed after signature return")

        modules, private_key, public_bytes = _fake_es256_modules(
            real_modules,
            signing_effect=valid_der,
        )
        modules = replace(
            modules,
            asymmetric_utils=SimpleNamespace(decode_dss_signature=fail_decode),
        )
        identity = _identity(ProofAlgorithm.ES256, public_bytes)
        with patch.object(adapter, "_load_cryptography", return_value=modules):
            signer = _implemented(ES256LocalSigner, identity, private_key)

        try:
            signer.sign(FIXED_SIGNING_INPUT)
        except ProviderFailure as raised:
            self.assertIsInstance(raised.__cause__, RuntimeError)
        except Exception as error:
            self.fail(
                "post-signature processing escaped typed provider failure: "
                f"{type(error).__name__}"
            )
        else:
            self.fail("post-signature processing failure was accepted")
        self.assertEqual(private_key.sign_calls, 1)

        control = KeyboardInterrupt()

        def interrupt_decode(encoded):
            raise control

        modules = replace(
            modules,
            asymmetric_utils=SimpleNamespace(decode_dss_signature=interrupt_decode),
        )
        with patch.object(adapter, "_load_cryptography", return_value=modules):
            signer = _implemented(ES256LocalSigner, identity, private_key)
        with self.assertRaises(KeyboardInterrupt) as interrupted:
            signer.sign(FIXED_SIGNING_INPUT)
        self.assertIs(interrupted.exception, control)

    def test_post_dispatch_capability_failure_is_typed_unavailable(self):
        real_modules = adapter._load_cryptography()
        es_effect = UnsupportedAlgorithm("ES256 sign unavailable")
        es_modules, es_key, es_public = _fake_es256_modules(
            real_modules,
            signing_effect=es_effect,
        )
        ed_effect = UnsupportedAlgorithm("Ed25519 sign unavailable")
        ed_modules, ed_key, ed_public = _fake_ed25519_modules(
            real_modules,
            signing_effect=ed_effect,
        )
        cases = (
            (
                ES256LocalSigner,
                es_modules,
                es_key,
                _identity(ProofAlgorithm.ES256, es_public),
                es_effect,
            ),
            (
                Ed25519LocalSigner,
                ed_modules,
                ed_key,
                _identity(ProofAlgorithm.ED25519, ed_public),
                ed_effect,
            ),
        )
        for signer_type, modules, key, identity, effect in cases:
            with patch.object(adapter, "_load_cryptography", return_value=modules):
                signer = _implemented(signer_type, identity, key)
            with self.subTest(signer=signer_type.__name__):
                try:
                    signer.sign(FIXED_SIGNING_INPUT)
                except ProviderUnavailable as raised:
                    self.assertIs(raised.__cause__, effect)
                except Exception as error:
                    self.fail(
                        "post-dispatch capability failure had wrong classification: "
                        f"{type(error).__name__}"
                    )
                else:
                    self.fail("post-dispatch capability failure was accepted")
                self.assertEqual(key.sign_calls, 1)

    def test_backend_verifier_taxonomy_is_precise(self):
        real_modules = adapter._load_cryptography()
        signature = (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
        cases = (
            (
                "invalid-signature",
                InvalidSignature(),
                None,
                SignatureVerificationOutcome.INVALID_SIGNATURE,
            ),
            (
                "invalid-key",
                None,
                ValueError("invalid point"),
                SignatureVerificationOutcome.INVALID_PUBLIC_KEY,
            ),
        )
        for name, verification_effect, load_effect, expected in cases:
            modules, _, public_bytes = _fake_es256_modules(
                real_modules,
                verification_effect=verification_effect,
                load_effect=load_effect,
            )
            with patch.object(adapter, "_load_cryptography", return_value=modules):
                verifier = _sync_verifier(ProofAlgorithm.ES256)
            with self.subTest(name=name):
                self.assertIs(
                    verifier.verify(
                        public_key=public_bytes,
                        signing_input=FIXED_SIGNING_INPUT,
                        signature=signature,
                    ),
                    expected,
                )

        for effect, outward in (
            (
                UnsupportedAlgorithm("verification unavailable"),
                ProviderUnavailable,
            ),
            (InternalError("backend verify failed", []), ProviderFailure),
        ):
            modules, _, public_bytes = _fake_es256_modules(
                real_modules,
                verification_effect=effect,
            )
            with patch.object(adapter, "_load_cryptography", return_value=modules):
                verifier = _sync_verifier(ProofAlgorithm.ES256)
            with (
                self.subTest(effect=type(effect).__name__),
                self.assertRaises(outward) as raised,
            ):
                verifier.verify(
                    public_key=public_bytes,
                    signing_input=FIXED_SIGNING_INPUT,
                    signature=signature,
                )
            self.assertIs(raised.exception.__cause__, effect)

    def test_process_control_signals_are_never_swallowed_or_reclassified(self):
        real_modules = adapter._load_cryptography()
        valid_der = utils.encode_dss_signature(1, 1)
        signature = (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
        for signal in (KeyboardInterrupt(), SystemExit(23), GeneratorExit()):
            modules, private_key, public_bytes = _fake_es256_modules(
                real_modules,
                signing_effect=signal,
                verification_effect=signal,
            )
            identity = _identity(ProofAlgorithm.ES256, public_bytes)
            with patch.object(adapter, "_load_cryptography", return_value=modules):
                signer = _implemented(ES256LocalSigner, identity, private_key)
                verifier = _sync_verifier(ProofAlgorithm.ES256)
            with (
                self.subTest(stage="sign", signal=type(signal).__name__),
                self.assertRaises(type(signal)) as sign_raised,
            ):
                signer.sign(FIXED_SIGNING_INPUT)
            self.assertIs(sign_raised.exception, signal)
            with (
                self.subTest(stage="verify", signal=type(signal).__name__),
                self.assertRaises(type(signal)) as verify_raised,
            ):
                verifier.verify(
                    public_key=public_bytes,
                    signing_input=FIXED_SIGNING_INPUT,
                    signature=signature,
                )
            self.assertIs(verify_raised.exception, signal)

        modules, private_key, public_bytes = _fake_es256_modules(
            real_modules,
            signing_effect=valid_der,
        )
        identity = _identity(ProofAlgorithm.ES256, public_bytes)
        with patch.object(adapter, "_load_cryptography", return_value=modules):
            signer = _implemented(ES256LocalSigner, identity, private_key)
        self.assertEqual(signer.sign(FIXED_SIGNING_INPUT), signature)


class Ed25519AdapterTests(unittest.TestCase):
    def test_signing_is_deterministic_and_verifies_with_wrong_inputs_rejected(self):
        key = _ed25519_private_key()
        signer = _implemented(Ed25519LocalSigner, _ed25519_identity(key), key)
        signature = signer.sign(FIXED_SIGNING_INPUT)
        verifier = _sync_verifier(ProofAlgorithm.ED25519)
        public_key = _implemented(ed25519_public_key_bytes, key.public_key())
        wrong_key = _implemented(
            ed25519_public_key_bytes,
            ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes(range(1, 33))
            ).public_key(),
        )

        self.assertEqual(signature, signer.sign(FIXED_SIGNING_INPUT))
        self.assertIs(type(signature), bytes)
        self.assertEqual(len(signature), 64)
        self.assertIs(
            verifier.verify(
                public_key=public_key,
                signing_input=FIXED_SIGNING_INPUT,
                signature=signature,
            ),
            SignatureVerificationOutcome.VALID,
        )
        for changed_key, changed_message in (
            (public_key, b"header.changed"),
            (wrong_key, FIXED_SIGNING_INPUT),
        ):
            with self.subTest(key=changed_key, message=changed_message):
                self.assertIs(
                    verifier.verify(
                        public_key=changed_key,
                        signing_input=changed_message,
                        signature=signature,
                    ),
                    SignatureVerificationOutcome.INVALID_SIGNATURE,
                )

    def test_library_owned_canonical_checks_cover_all_small_order_encodings(self):
        key = _ed25519_private_key()
        signer = _implemented(Ed25519LocalSigner, _ed25519_identity(key), key)
        signature = signer.sign(FIXED_SIGNING_INPUT)
        public_key = _implemented(ed25519_public_key_bytes, key.public_key())
        verifier = _sync_verifier(ProofAlgorithm.ED25519)

        for encoded in ED25519_SMALL_ORDER_ENCODINGS:
            with self.subTest(kind="key", encoded=encoded.hex()):
                self.assertIs(
                    verifier.verify(
                        public_key=encoded,
                        signing_input=FIXED_SIGNING_INPUT,
                        signature=signature,
                    ),
                    SignatureVerificationOutcome.INVALID_PUBLIC_KEY,
                )
            with self.subTest(kind="signature-R", encoded=encoded.hex()):
                self.assertIs(
                    verifier.verify(
                        public_key=public_key,
                        signing_input=FIXED_SIGNING_INPUT,
                        signature=encoded + (1).to_bytes(32, "little"),
                    ),
                    SignatureVerificationOutcome.INVALID_SIGNATURE,
                )

    def test_noncanonical_ed25519_points_signs_scalars_and_widths_are_rejected(self):
        key = _ed25519_private_key()
        signer = _implemented(Ed25519LocalSigner, _ed25519_identity(key), key)
        signature = signer.sign(FIXED_SIGNING_INPUT)
        public_key = _implemented(ed25519_public_key_bytes, key.public_key())
        verifier = _sync_verifier(ProofAlgorithm.ED25519)
        invalid_x_sign = bytearray((1).to_bytes(32, "little"))
        invalid_x_sign[31] |= 0x80

        invalid_keys = (
            b"",
            public_key[:-1],
            ED25519_FIELD_PRIME.to_bytes(32, "little"),
            bytes(invalid_x_sign),
        )
        for malformed_key in invalid_keys:
            with self.subTest(key=malformed_key.hex()):
                self.assertIs(
                    verifier.verify(
                        public_key=malformed_key,
                        signing_input=FIXED_SIGNING_INPUT,
                        signature=signature,
                    ),
                    SignatureVerificationOutcome.INVALID_PUBLIC_KEY,
                )

        invalid_signatures = (
            b"",
            signature[:-1],
            ED25519_FIELD_PRIME.to_bytes(32, "little") + signature[32:],
            bytes(invalid_x_sign) + signature[32:],
            signature[:32] + ED25519_ORDER.to_bytes(32, "little"),
        )
        for malformed_signature in invalid_signatures:
            with self.subTest(signature=malformed_signature.hex()[:20]):
                self.assertIs(
                    verifier.verify(
                        public_key=public_key,
                        signing_input=FIXED_SIGNING_INPUT,
                        signature=malformed_signature,
                    ),
                    SignatureVerificationOutcome.INVALID_SIGNATURE,
                )

    def test_y_two_non_point_has_mathematical_and_typed_rejection(self):
        y = 2
        y_squared = y * y
        x_squared = (
            (y_squared - 1)
            * pow(
                (ED25519_CURVE_D * y_squared + 1) % ED25519_FIELD_PRIME,
                ED25519_FIELD_PRIME - 2,
                ED25519_FIELD_PRIME,
            )
        ) % ED25519_FIELD_PRIME
        self.assertEqual(
            x_squared,
            int(
                "600e0cd185b2df905cce8984b8ef4435975591e71b48470092dff7c9115bf3c8",
                16,
            ),
        )
        self.assertEqual(
            pow(
                x_squared,
                (ED25519_FIELD_PRIME - 1) // 2,
                ED25519_FIELD_PRIME,
            ),
            ED25519_FIELD_PRIME - 1,
        )

        key = _ed25519_private_key()
        signer = _implemented(Ed25519LocalSigner, _ed25519_identity(key), key)
        signature = signer.sign(FIXED_SIGNING_INPUT)
        public_key = _implemented(ed25519_public_key_bytes, key.public_key())
        verifier = _sync_verifier(ProofAlgorithm.ED25519)

        for non_point in (
            ED25519_NON_POINT_Y_TWO,
            ED25519_NON_POINT_Y_TWO_SIGNED,
        ):
            with self.subTest(non_point=non_point.hex()):
                self.assertIs(
                    verifier.verify(
                        public_key=non_point,
                        signing_input=FIXED_SIGNING_INPUT,
                        signature=signature,
                    ),
                    SignatureVerificationOutcome.INVALID_PUBLIC_KEY,
                )
                self.assertIs(
                    verifier.verify(
                        public_key=public_key,
                        signing_input=FIXED_SIGNING_INPUT,
                        signature=non_point + signature[32:],
                    ),
                    SignatureVerificationOutcome.INVALID_SIGNATURE,
                )

    def test_non_points_are_rejected_before_backend_key_loading_or_verify(self):
        real_modules = adapter._load_cryptography()
        key = _ed25519_private_key()
        signer = _implemented(Ed25519LocalSigner, _ed25519_identity(key), key)
        signature = signer.sign(FIXED_SIGNING_INPUT)
        public_key = _implemented(ed25519_public_key_bytes, key.public_key())

        class CountingPublicKey:
            load_calls = 0
            verify_calls = 0

            @classmethod
            def from_public_bytes(cls, encoded):
                cls.load_calls += 1
                return cls()

            def verify(self, signature, signing_input):
                type(self).verify_calls += 1

        modules = replace(
            real_modules,
            ed25519=SimpleNamespace(
                Ed25519PrivateKey=real_modules.ed25519.Ed25519PrivateKey,
                Ed25519PublicKey=CountingPublicKey,
            ),
        )
        with patch.object(adapter, "_load_cryptography", return_value=modules):
            verifier = _sync_verifier(ProofAlgorithm.ED25519)

        self.assertIs(
            verifier.verify(
                public_key=ED25519_NON_POINT_Y_TWO,
                signing_input=FIXED_SIGNING_INPUT,
                signature=signature,
            ),
            SignatureVerificationOutcome.INVALID_PUBLIC_KEY,
        )
        self.assertIs(
            verifier.verify(
                public_key=public_key,
                signing_input=FIXED_SIGNING_INPUT,
                signature=ED25519_NON_POINT_Y_TWO + signature[32:],
            ),
            SignatureVerificationOutcome.INVALID_SIGNATURE,
        )
        self.assertEqual(CountingPublicKey.load_calls, 0)
        self.assertEqual(CountingPublicKey.verify_calls, 0)

    def test_non_point_official_signer_output_is_provider_failure(self):
        real_modules = adapter._load_cryptography()
        signature = ED25519_NON_POINT_Y_TWO + (1).to_bytes(32, "little")
        modules, private_key, public_bytes = _fake_ed25519_modules(
            real_modules,
            signing_effect=signature,
        )
        identity = _identity(ProofAlgorithm.ED25519, public_bytes)
        with patch.object(adapter, "_load_cryptography", return_value=modules):
            signer = _implemented(Ed25519LocalSigner, identity, private_key)

        with self.assertRaises(ProviderFailure):
            signer.sign(FIXED_SIGNING_INPUT)
        self.assertEqual(private_key.sign_calls, 1)


class PublicKeyConversionTests(unittest.TestCase):
    def test_p256_uncompressed_conversion_matches_known_generator_and_round_trips(self):
        key = _es256_private_key().public_key()

        encoded = _implemented(es256_public_key_bytes, key)
        reconstructed = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), encoded
        )

        self.assertEqual(encoded, P256_GENERATOR)
        self.assertEqual(
            reconstructed.public_numbers(),
            key.public_numbers(),
        )

    def test_ed25519_raw_conversion_round_trips(self):
        key = _ed25519_private_key().public_key()

        encoded = _implemented(ed25519_public_key_bytes, key)
        reconstructed = ed25519.Ed25519PublicKey.from_public_bytes(encoded)

        message = b"round-trip"
        signature = _ed25519_private_key().sign(message)
        reconstructed.verify(signature, message)
        self.assertEqual(len(encoded), 32)

    def test_ed25519_converter_rejects_backend_accepted_non_point(self):
        backend_key = ed25519.Ed25519PublicKey.from_public_bytes(
            ED25519_NON_POINT_Y_TWO
        )

        with self.assertRaises(CryptoConfigurationError):
            _implemented(ed25519_public_key_bytes, backend_key)

    def test_converters_reject_wrong_backend_key_types_as_configuration(self):
        for converter, key in (
            (es256_public_key_bytes, _ed25519_private_key().public_key()),
            (ed25519_public_key_bytes, _es256_private_key().public_key()),
        ):
            with (
                self.subTest(converter=converter.__name__),
                self.assertRaises(CryptoConfigurationError),
            ):
                _implemented(converter, key)


class AsyncCryptographyAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_signers_and_verifiers_have_exact_sync_parity(self):
        cases = (
            (
                ProofAlgorithm.ES256,
                _es256_private_key(),
                AsyncES256LocalSigner,
                _es256_identity,
                es256_public_key_bytes,
            ),
            (
                ProofAlgorithm.ED25519,
                _ed25519_private_key(),
                AsyncEd25519LocalSigner,
                _ed25519_identity,
                ed25519_public_key_bytes,
            ),
        )
        for algorithm, key, signer_type, identity_factory, converter in cases:
            signer = _implemented(signer_type, identity_factory(key), key)
            signature = await signer.sign(FIXED_SIGNING_INPUT)
            outcome = await _async_verifier(algorithm).verify(
                public_key=_implemented(converter, key.public_key()),
                signing_input=FIXED_SIGNING_INPUT,
                signature=signature,
            )

            self.assertIs(outcome, SignatureVerificationOutcome.VALID)

    async def test_pre_entry_cancellation_starts_no_local_signing_operation(self):
        real_modules = adapter._load_cryptography()
        valid_der = utils.encode_dss_signature(1, 1)
        modules, private_key, public_bytes = _fake_es256_modules(
            real_modules,
            signing_effect=valid_der,
        )
        identity = _identity(ProofAlgorithm.ES256, public_bytes)
        with patch.object(adapter, "_load_cryptography", return_value=modules):
            signer = _implemented(AsyncES256LocalSigner, identity, private_key)

        operation = asyncio.create_task(signer.sign(FIXED_SIGNING_INPUT))
        self.assertTrue(operation.cancel())
        with self.assertRaises(asyncio.CancelledError):
            await operation

        self.assertEqual(private_key.sign_calls, 0)

    async def test_async_post_dispatch_capability_failure_is_typed_unavailable(self):
        real_modules = adapter._load_cryptography()
        es_effect = UnsupportedAlgorithm("ES256 async sign unavailable")
        es_modules, es_key, es_public = _fake_es256_modules(
            real_modules,
            signing_effect=es_effect,
        )
        ed_effect = UnsupportedAlgorithm("Ed25519 async sign unavailable")
        ed_modules, ed_key, ed_public = _fake_ed25519_modules(
            real_modules,
            signing_effect=ed_effect,
        )
        cases = (
            (
                AsyncES256LocalSigner,
                es_modules,
                es_key,
                _identity(ProofAlgorithm.ES256, es_public),
                es_effect,
            ),
            (
                AsyncEd25519LocalSigner,
                ed_modules,
                ed_key,
                _identity(ProofAlgorithm.ED25519, ed_public),
                ed_effect,
            ),
        )
        for signer_type, modules, key, identity, effect in cases:
            with patch.object(adapter, "_load_cryptography", return_value=modules):
                signer = _implemented(signer_type, identity, key)
            with self.subTest(signer=signer_type.__name__):
                try:
                    await signer.sign(FIXED_SIGNING_INPUT)
                except ProviderUnavailable as raised:
                    self.assertIs(raised.__cause__, effect)
                except Exception as error:
                    self.fail(
                        "async post-dispatch capability failure had wrong "
                        f"classification: {type(error).__name__}"
                    )
                else:
                    self.fail("async post-dispatch capability failure was accepted")
                self.assertEqual(key.sign_calls, 1)

    async def test_async_ed25519_non_points_have_sync_equivalent_outcomes(self):
        key = _ed25519_private_key()
        signer = _implemented(Ed25519LocalSigner, _ed25519_identity(key), key)
        signature = signer.sign(FIXED_SIGNING_INPUT)
        public_key = _implemented(ed25519_public_key_bytes, key.public_key())
        verifier = _async_verifier(ProofAlgorithm.ED25519)

        for non_point in (
            ED25519_NON_POINT_Y_TWO,
            ED25519_NON_POINT_Y_TWO_SIGNED,
        ):
            self.assertIs(
                await verifier.verify(
                    public_key=non_point,
                    signing_input=FIXED_SIGNING_INPUT,
                    signature=signature,
                ),
                SignatureVerificationOutcome.INVALID_PUBLIC_KEY,
            )
            self.assertIs(
                await verifier.verify(
                    public_key=public_key,
                    signing_input=FIXED_SIGNING_INPUT,
                    signature=non_point + signature[32:],
                ),
                SignatureVerificationOutcome.INVALID_SIGNATURE,
            )

    async def test_async_non_point_official_signer_output_is_provider_failure(self):
        real_modules = adapter._load_cryptography()
        signature = ED25519_NON_POINT_Y_TWO + (1).to_bytes(32, "little")
        modules, private_key, public_bytes = _fake_ed25519_modules(
            real_modules,
            signing_effect=signature,
        )
        identity = _identity(ProofAlgorithm.ED25519, public_bytes)
        with patch.object(adapter, "_load_cryptography", return_value=modules):
            signer = _implemented(AsyncEd25519LocalSigner, identity, private_key)

        with self.assertRaises(ProviderFailure):
            await signer.sign(FIXED_SIGNING_INPUT)
        self.assertEqual(private_key.sign_calls, 1)


if __name__ == "__main__":
    unittest.main()
