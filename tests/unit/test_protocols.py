"""Canonical Trust Proof provider-protocol tests."""

from datetime import datetime, timedelta, timezone
import inspect
from typing import get_type_hints
import unittest

import kinetic_trust_library.protocols as protocols
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models.proof import (
    AsyncVerifierBinding,
    KeyLookup,
    KeyPurpose,
    OracleSigningIdentity,
    ProofAlgorithm,
    SignatureVerificationOutcome,
    TrustedVerificationKey,
    UnknownVerificationKey,
    UntrustedVerificationKey,
    VerifierBinding,
)
from kinetic_trust_library.protocols import (
    AsyncProofSigner,
    AsyncSignatureVerifier,
    AsyncVerificationKeySource,
    ProofSigner,
    ProviderFailure,
    ProviderSignal,
    ProviderUnavailable,
    SignatureVerifier,
    SigningOutcomeUnknown,
    VerificationKeySource,
)


UTC_NOW = datetime(2026, 8, 24, 12, 0, 0, 123456, tzinfo=timezone.utc)
PROTOCOL_EXPORTS = [
    "AsyncProofSigner",
    "AsyncSignatureVerifier",
    "AsyncVerificationKeySource",
    "ProofSigner",
    "ProviderFailure",
    "ProviderSignal",
    "ProviderUnavailable",
    "SignatureVerifier",
    "SigningOutcomeUnknown",
    "VerificationKeySource",
]


class HostileBytes(bytes):
    def __bytes__(self) -> bytes:
        raise AssertionError("bytes hook must not run")


class HostileString(str):
    def encode(self, *args: object, **kwargs: object) -> bytes:
        raise AssertionError("string hook must not run")


class HostileDateTime(datetime):
    @property
    def tzinfo(self):  # type: ignore[override]
        raise AssertionError("datetime hook must not run")


def es256_public_key_bytes() -> bytes:
    return b"\x04" + bytes(range(1, 65))


def oracle_identity(**overrides: object) -> OracleSigningIdentity:
    values: dict[str, object] = {
        "issuer": "https://oracle.example",
        "key_id": "oracle-clé-Δ",
        "algorithm": ProofAlgorithm.ES256,
        "purpose": KeyPurpose.ORACLE_TRUST_PROOF,
        "public_key": es256_public_key_bytes(),
        "signing_not_before": UTC_NOW,
        "signing_not_after": UTC_NOW + timedelta(days=1),
        "revoked_at": None,
    }
    values.update(overrides)
    return OracleSigningIdentity(**values)  # type: ignore[arg-type]


def trusted_key(**overrides: object) -> TrustedVerificationKey:
    values: dict[str, object] = {
        "issuer": "https://oracle.example",
        "key_id": "oracle-clé-Δ",
        "algorithm": ProofAlgorithm.ES256,
        "purpose": KeyPurpose.ORACLE_TRUST_PROOF,
        "public_key": es256_public_key_bytes(),
        "signing_not_before": UTC_NOW,
        "signing_not_after": UTC_NOW + timedelta(days=1),
        "verification_not_after": UTC_NOW + timedelta(days=2),
        "revoked_at": None,
    }
    values.update(overrides)
    return TrustedVerificationKey(**values)  # type: ignore[arg-type]


class ProtocolContractTests(unittest.TestCase):
    def test_provider_values_use_owned_bytes_not_backend_objects(self):
        source = bytearray(es256_public_key_bytes())
        identity = oracle_identity(public_key=bytes(source))
        key = trusted_key(public_key=bytes(source))

        source[:] = b"\x00" * len(source)
        self.assertEqual(identity.public_key, es256_public_key_bytes())
        self.assertEqual(key.public_key, es256_public_key_bytes())
        with self.assertRaises(AttributeError):
            identity.public_key = b"changed"
        with self.assertRaises(AttributeError):
            key.key_id = "changed"

    def test_mutable_and_hostile_byte_values_are_rejected_directly(self):
        for invalid in (
            bytearray(es256_public_key_bytes()),
            memoryview(es256_public_key_bytes()),
            HostileBytes(es256_public_key_bytes()),
        ):
            with (
                self.subTest(kind=type(invalid).__name__),
                self.assertRaises(TypeError),
            ):
                oracle_identity(public_key=invalid)
            with (
                self.subTest(kind=type(invalid).__name__),
                self.assertRaises(TypeError),
            ):
                trusted_key(public_key=invalid)

    def test_key_identifiers_use_bounded_nfc_preserving_unicode(self):
        identifier = "Oracle-Clé-Δ"
        identity = oracle_identity(key_id=identifier)
        self.assertEqual(identity.key_id, identifier)

        for invalid in (
            "",
            " leading",
            "trailing ",
            "line\nbreak",
            "zero\u200bwidth",
            "Cafe\u0301",
            "é" * 129,
            "\ud800",
            HostileString("kid"),
        ):
            with (
                self.subTest(invalid=repr(invalid)),
                self.assertRaises(ValidationError),
            ):
                oracle_identity(key_id=invalid)
            with (
                self.subTest(invalid=repr(invalid)),
                self.assertRaises(ValidationError),
            ):
                UnknownVerificationKey(invalid)  # type: ignore[arg-type]

    def test_issuer_values_reuse_exact_absolute_uri_validation(self):
        issuer = "HTTPS://Oracle.Example/Path%2FValue"
        self.assertEqual(oracle_identity(issuer=issuer).issuer, issuer)
        for invalid in (
            "relative/path",
            "https://oracle.example/space here",
            "https://oracle.example/" + ("a" * 2048),
            HostileString("https://oracle.example"),
        ):
            with (
                self.subTest(invalid=repr(invalid)),
                self.assertRaises(ValidationError),
            ):
                oracle_identity(issuer=invalid)

    def test_key_lifecycle_times_are_exact_utc_and_preserve_subseconds(self):
        identity = oracle_identity()
        key = trusted_key()
        self.assertEqual(identity.signing_not_before.microsecond, 123456)
        self.assertEqual(key.signing_not_before.microsecond, 123456)

        for invalid in (
            UTC_NOW.replace(tzinfo=None),
            UTC_NOW.astimezone(timezone(timedelta(hours=1))),
            HostileDateTime(2026, 8, 24),
        ):
            with (
                self.subTest(invalid=repr(invalid)),
                self.assertRaises(ValidationError),
            ):
                oracle_identity(signing_not_before=invalid)
        with self.assertRaises(ValidationError):
            oracle_identity(signing_not_after=UTC_NOW)
        with self.assertRaises(ValidationError):
            trusted_key(verification_not_after=UTC_NOW)

    def test_key_carriers_reject_wrong_enum_types_and_validate_lookup(self):
        for field, invalid in (
            ("algorithm", "ES256"),
            ("purpose", "oracle-trust-proof"),
        ):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                oracle_identity(**{field: invalid})
            with self.subTest(field=field), self.assertRaises(ValidationError):
                trusted_key(**{field: invalid})

        lookup = KeyLookup(
            untrusted_issuer="urn:oracle:example",
            key_id="k-Δ",
            algorithm=ProofAlgorithm.ES256,
            purpose=KeyPurpose.ORACLE_TRUST_PROOF,
            cutoff=UTC_NOW,
        )
        self.assertEqual(lookup.cutoff, UTC_NOW)
        self.assertEqual(UnknownVerificationKey("k-Δ").key_id, "k-Δ")
        self.assertEqual(UntrustedVerificationKey("k-Δ").key_id, "k-Δ")
        with self.assertRaises(ValidationError):
            KeyLookup(
                untrusted_issuer="relative",
                key_id="k-Δ",
                algorithm=ProofAlgorithm.ES256,
                purpose=KeyPurpose.ORACLE_TRUST_PROOF,
                cutoff=UTC_NOW,
            )


class CanonicalProtocolTests(unittest.TestCase):
    def test_protocol_module_has_exact_public_surface(self):
        namespace: dict[str, object] = {}
        exec("from kinetic_trust_library.protocols import *", namespace)

        self.assertEqual(protocols.__all__, PROTOCOL_EXPORTS)
        self.assertEqual(set(namespace) - {"__builtins__"}, set(PROTOCOL_EXPORTS))

    def test_obsolete_sensor_protocol_is_absent(self):
        self.assertFalse(hasattr(protocols, "SensorPlugin"))

    def test_obsolete_sensor_protocol_is_not_exported(self):
        self.assertNotIn("SensorPlugin", protocols.__all__)

    def test_protocols_are_static_contracts_not_runtime_checks(self):
        class Candidate:
            pass

        for protocol in (
            ProofSigner,
            SignatureVerifier,
            VerificationKeySource,
            AsyncProofSigner,
            AsyncSignatureVerifier,
            AsyncVerificationKeySource,
        ):
            with self.subTest(protocol=protocol.__name__), self.assertRaises(TypeError):
                isinstance(Candidate(), protocol)

    def test_protocol_method_shapes_and_annotations_are_canonical(self):
        sign = inspect.signature(ProofSigner.sign)
        self.assertEqual(
            sign.parameters["signing_input"].kind,
            inspect.Parameter.POSITIONAL_ONLY,
        )
        self.assertIs(
            get_type_hints(ProofSigner.identity.fget)["return"],
            OracleSigningIdentity,
        )
        self.assertIs(get_type_hints(ProofSigner.sign)["signing_input"], bytes)
        self.assertIs(get_type_hints(ProofSigner.sign)["return"], bytes)

        resolve = inspect.signature(VerificationKeySource.resolve)
        self.assertEqual(
            resolve.parameters["lookup"].kind,
            inspect.Parameter.POSITIONAL_ONLY,
        )
        self.assertIs(
            get_type_hints(VerificationKeySource.resolve)["lookup"], KeyLookup
        )

        verify = inspect.signature(SignatureVerifier.verify)
        for name in ("public_key", "signing_input", "signature"):
            self.assertEqual(
                verify.parameters[name].kind, inspect.Parameter.KEYWORD_ONLY
            )
            self.assertIs(get_type_hints(SignatureVerifier.verify)[name], bytes)
        self.assertIs(
            get_type_hints(SignatureVerifier.verify)["return"],
            SignatureVerificationOutcome,
        )

        self.assertTrue(inspect.iscoroutinefunction(AsyncProofSigner.sign))
        self.assertTrue(inspect.iscoroutinefunction(AsyncVerificationKeySource.resolve))
        self.assertTrue(inspect.iscoroutinefunction(AsyncSignatureVerifier.verify))
        self.assertEqual(
            VerifierBinding.__annotations__,
            {"algorithm": "ProofAlgorithm", "verifier": "SignatureVerifier"},
        )
        self.assertEqual(
            AsyncVerifierBinding.__annotations__,
            {
                "algorithm": "ProofAlgorithm",
                "verifier": "AsyncSignatureVerifier",
            },
        )

    def test_provider_signal_hierarchy_and_bounded_reference(self):
        self.assertTrue(issubclass(ProviderSignal, Exception))
        self.assertTrue(issubclass(ProviderUnavailable, ProviderSignal))
        self.assertTrue(issubclass(ProviderFailure, ProviderSignal))
        self.assertTrue(issubclass(SigningOutcomeUnknown, ProviderSignal))
        self.assertIsNone(SigningOutcomeUnknown().provider_reference)
        self.assertEqual(
            SigningOutcomeUnknown("request-Δ").provider_reference,
            "request-Δ",
        )
        self.assertEqual(
            SigningOutcomeUnknown(
                provider_reference="request-keyword"
            ).provider_reference,
            "request-keyword",
        )

        with self.assertRaises(TypeError):
            SigningOutcomeUnknown(HostileString("request"))
        with self.assertRaises(ValueError):
            SigningOutcomeUnknown("é" * 129)
        with self.assertRaises(ValueError):
            SigningOutcomeUnknown("\ud800")


if __name__ == "__main__":
    unittest.main()
