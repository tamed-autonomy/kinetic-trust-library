"""Lazy optional PyCA adapter for KTP Trust Proof providers."""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType
from typing import TYPE_CHECKING

from kinetic_trust_library.errors import CryptoConfigurationError
from kinetic_trust_library.models.proof import (
    AsyncProofCrypto,
    AsyncVerifierBinding,
    KeyPurpose,
    OracleSigningIdentity,
    ProofAlgorithm,
    ProofCrypto,
    SignatureVerificationOutcome,
    VerifierBinding,
)
from kinetic_trust_library.proofs._algorithms import (
    _PublicKeyShapeError,
    _SignatureShapeError,
    validate_ed25519_public_key,
    validate_ed25519_signature,
    validate_es256_public_key,
    validate_es256_signature,
)
from kinetic_trust_library.protocols import ProviderFailure, ProviderUnavailable

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519


_ED25519_FIELD_PRIME = (1 << 255) - 19
_ED25519_CURVE_D = (
    37095705934669439343138083508754565189542113879843219016388785533085940283555
)


@dataclass(frozen=True, slots=True)
class _CryptographyModules:
    ec: ModuleType
    ed25519: ModuleType
    hashes: ModuleType
    asymmetric_utils: ModuleType
    serialization: ModuleType
    exceptions: ModuleType


def _import_cryptography_modules() -> _CryptographyModules:
    from cryptography import exceptions
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

    return _CryptographyModules(
        ec=ec,
        ed25519=ed25519,
        hashes=hashes,
        asymmetric_utils=utils,
        serialization=serialization,
        exceptions=exceptions,
    )


def _load_cryptography() -> _CryptographyModules:
    try:
        return _import_cryptography_modules()
    except ModuleNotFoundError as error:
        if error.name != "cryptography":
            raise
        raise CryptoConfigurationError(
            "install kinetic-trust-library[cryptography] to use the optional PyCA proof adapter"
        ) from error


def cryptography_proof_crypto() -> ProofCrypto:
    modules = _load_cryptography()
    return ProofCrypto(
        (
            VerifierBinding(ProofAlgorithm.ES256, _ES256Verifier(modules)),
            VerifierBinding(ProofAlgorithm.ED25519, _Ed25519Verifier(modules)),
        )
    )


def async_cryptography_proof_crypto() -> AsyncProofCrypto:
    modules = _load_cryptography()
    return AsyncProofCrypto(
        (
            AsyncVerifierBinding(
                ProofAlgorithm.ES256,
                _AsyncES256Verifier(modules),
            ),
            AsyncVerifierBinding(
                ProofAlgorithm.ED25519,
                _AsyncEd25519Verifier(modules),
            ),
        )
    )


class _ES256Verifier:
    __slots__ = ("_modules",)

    def __init__(self, modules: _CryptographyModules, /) -> None:
        self._modules = modules

    def verify(
        self,
        *,
        public_key: bytes,
        signing_input: bytes,
        signature: bytes,
    ) -> SignatureVerificationOutcome:
        return _verify_es256(
            self._modules,
            public_key=public_key,
            signing_input=signing_input,
            signature=signature,
        )


class _AsyncES256Verifier:
    __slots__ = ("_modules",)

    def __init__(self, modules: _CryptographyModules, /) -> None:
        self._modules = modules

    async def verify(
        self,
        *,
        public_key: bytes,
        signing_input: bytes,
        signature: bytes,
    ) -> SignatureVerificationOutcome:
        return _verify_es256(
            self._modules,
            public_key=public_key,
            signing_input=signing_input,
            signature=signature,
        )


class _Ed25519Verifier:
    __slots__ = ("_modules",)

    def __init__(self, modules: _CryptographyModules, /) -> None:
        self._modules = modules

    def verify(
        self,
        *,
        public_key: bytes,
        signing_input: bytes,
        signature: bytes,
    ) -> SignatureVerificationOutcome:
        return _verify_ed25519(
            self._modules,
            public_key=public_key,
            signing_input=signing_input,
            signature=signature,
        )


class _AsyncEd25519Verifier:
    __slots__ = ("_modules",)

    def __init__(self, modules: _CryptographyModules, /) -> None:
        self._modules = modules

    async def verify(
        self,
        *,
        public_key: bytes,
        signing_input: bytes,
        signature: bytes,
    ) -> SignatureVerificationOutcome:
        return _verify_ed25519(
            self._modules,
            public_key=public_key,
            signing_input=signing_input,
            signature=signature,
        )


def _verify_es256(
    modules: _CryptographyModules,
    *,
    public_key: bytes,
    signing_input: bytes,
    signature: bytes,
) -> SignatureVerificationOutcome:
    if type(signing_input) is not bytes:
        raise ProviderFailure("ES256 signing input must be exact immutable bytes")
    try:
        validate_es256_public_key(public_key)
    except _PublicKeyShapeError:
        return SignatureVerificationOutcome.INVALID_PUBLIC_KEY
    try:
        validate_es256_signature(signature)
    except _SignatureShapeError:
        return SignatureVerificationOutcome.INVALID_SIGNATURE

    try:
        key = modules.ec.EllipticCurvePublicKey.from_encoded_point(
            modules.ec.SECP256R1(),
            public_key,
        )
    except ValueError:
        return SignatureVerificationOutcome.INVALID_PUBLIC_KEY
    except modules.exceptions.UnsupportedAlgorithm as error:
        raise ProviderUnavailable("ES256 verification is unavailable") from error
    except Exception as error:
        raise ProviderFailure("ES256 public-key loading failed") from error

    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        encoded_signature = modules.asymmetric_utils.encode_dss_signature(r, s)
        key.verify(
            encoded_signature,
            signing_input,
            modules.ec.ECDSA(modules.hashes.SHA256()),
        )
    except modules.exceptions.InvalidSignature:
        return SignatureVerificationOutcome.INVALID_SIGNATURE
    except modules.exceptions.UnsupportedAlgorithm as error:
        raise ProviderUnavailable("ES256 verification is unavailable") from error
    except Exception as error:
        raise ProviderFailure("ES256 verification failed") from error
    return SignatureVerificationOutcome.VALID


def _verify_ed25519(
    modules: _CryptographyModules,
    *,
    public_key: bytes,
    signing_input: bytes,
    signature: bytes,
) -> SignatureVerificationOutcome:
    if type(signing_input) is not bytes:
        raise ProviderFailure("Ed25519 signing input must be exact immutable bytes")
    try:
        validate_ed25519_public_key(public_key)
    except _PublicKeyShapeError:
        return SignatureVerificationOutcome.INVALID_PUBLIC_KEY
    if not _is_ed25519_curve_point(public_key):
        return SignatureVerificationOutcome.INVALID_PUBLIC_KEY
    try:
        validate_ed25519_signature(signature)
    except _SignatureShapeError:
        return SignatureVerificationOutcome.INVALID_SIGNATURE
    if not _is_ed25519_curve_point(signature[:32]):
        return SignatureVerificationOutcome.INVALID_SIGNATURE

    try:
        key = modules.ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError:
        return SignatureVerificationOutcome.INVALID_PUBLIC_KEY
    except modules.exceptions.UnsupportedAlgorithm as error:
        raise ProviderUnavailable("Ed25519 verification is unavailable") from error
    except Exception as error:
        raise ProviderFailure("Ed25519 public-key loading failed") from error

    try:
        key.verify(signature, signing_input)
    except modules.exceptions.InvalidSignature:
        return SignatureVerificationOutcome.INVALID_SIGNATURE
    except modules.exceptions.UnsupportedAlgorithm as error:
        raise ProviderUnavailable("Ed25519 verification is unavailable") from error
    except Exception as error:
        raise ProviderFailure("Ed25519 verification failed") from error
    return SignatureVerificationOutcome.VALID


def _is_ed25519_curve_point(encoded: bytes, /) -> bool:
    if type(encoded) is not bytes or len(encoded) != 32:
        return False
    encoded_y = bytearray(encoded)
    x_sign = encoded_y[31] >> 7
    encoded_y[31] &= 0x7F
    y = int.from_bytes(encoded_y, "little")
    if y >= _ED25519_FIELD_PRIME:
        return False

    y_squared = y * y % _ED25519_FIELD_PRIME
    numerator = (y_squared - 1) % _ED25519_FIELD_PRIME
    denominator = (_ED25519_CURVE_D * y_squared + 1) % _ED25519_FIELD_PRIME
    if denominator == 0:
        return False
    if numerator == 0:
        return x_sign == 0

    quotient_character = pow(
        numerator * denominator % _ED25519_FIELD_PRIME,
        (_ED25519_FIELD_PRIME - 1) // 2,
        _ED25519_FIELD_PRIME,
    )
    return quotient_character == 1


class _ES256SignerBase:
    __slots__ = (
        "_identity",
        "_modules",
        "_private_key",
        "_signature_algorithm",
    )

    def __init__(
        self,
        identity: OracleSigningIdentity,
        private_key: "ec.EllipticCurvePrivateKey",
        /,
    ) -> None:
        modules = _load_cryptography()
        owned_identity = _own_signing_identity(identity, ProofAlgorithm.ES256)
        if not isinstance(private_key, modules.ec.EllipticCurvePrivateKey):
            raise CryptoConfigurationError(
                "ES256 local signer requires a PyCA EC private key"
            )
        try:
            public_key = private_key.public_key()
        except Exception as error:
            raise CryptoConfigurationError(
                "ES256 local signer public key is unavailable"
            ) from error
        encoded_public_key = _es256_public_key_bytes(modules, public_key)
        if encoded_public_key != owned_identity.public_key:
            raise CryptoConfigurationError(
                "ES256 local signer key does not match its Oracle identity"
            )
        try:
            signature_algorithm = modules.ec.ECDSA(
                modules.hashes.SHA256(),
                deterministic_signing=True,
            )
        except modules.exceptions.UnsupportedAlgorithm as error:
            raise CryptoConfigurationError(
                "deterministic ES256 signing is unavailable"
            ) from error
        self._identity = owned_identity
        self._modules = modules
        self._private_key = private_key
        self._signature_algorithm = signature_algorithm

    @property
    def identity(self) -> OracleSigningIdentity:
        return self._identity

    def _sign(self, signing_input: bytes, /) -> bytes:
        if type(signing_input) is not bytes:
            raise ProviderFailure("ES256 signing input must be exact immutable bytes")
        try:
            encoded = self._private_key.sign(
                signing_input,
                self._signature_algorithm,
            )
        except self._modules.exceptions.UnsupportedAlgorithm as error:
            raise ProviderUnavailable(
                "deterministic ES256 signing is unavailable"
            ) from error
        except Exception as error:
            raise ProviderFailure("ES256 local signing failed") from error
        if type(encoded) is not bytes:
            raise ProviderFailure("ES256 backend returned a non-bytes signature")
        try:
            r, s = self._modules.asymmetric_utils.decode_dss_signature(encoded)
            order = self._modules.ec.SECP256R1().group_order
            if not 0 < r < order or not 0 < s < order:
                raise ProviderFailure("ES256 backend returned out-of-range scalars")
            if s > order // 2:
                s = order - s
            raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            validate_es256_signature(raw)
        except ProviderFailure:
            raise
        except Exception as error:
            raise ProviderFailure(
                "ES256 backend signature postprocessing failed"
            ) from error
        return raw


class _Ed25519SignerBase:
    __slots__ = ("_identity", "_modules", "_private_key")

    def __init__(
        self,
        identity: OracleSigningIdentity,
        private_key: "ed25519.Ed25519PrivateKey",
        /,
    ) -> None:
        modules = _load_cryptography()
        owned_identity = _own_signing_identity(identity, ProofAlgorithm.ED25519)
        if not isinstance(private_key, modules.ed25519.Ed25519PrivateKey):
            raise CryptoConfigurationError(
                "Ed25519 local signer requires a PyCA Ed25519 private key"
            )
        try:
            public_key = private_key.public_key()
        except Exception as error:
            raise CryptoConfigurationError(
                "Ed25519 local signer public key is unavailable"
            ) from error
        encoded_public_key = _ed25519_public_key_bytes(modules, public_key)
        if encoded_public_key != owned_identity.public_key:
            raise CryptoConfigurationError(
                "Ed25519 local signer key does not match its Oracle identity"
            )
        self._identity = owned_identity
        self._modules = modules
        self._private_key = private_key

    @property
    def identity(self) -> OracleSigningIdentity:
        return self._identity

    def _sign(self, signing_input: bytes, /) -> bytes:
        if type(signing_input) is not bytes:
            raise ProviderFailure("Ed25519 signing input must be exact immutable bytes")
        try:
            signature = self._private_key.sign(signing_input)
        except self._modules.exceptions.UnsupportedAlgorithm as error:
            raise ProviderUnavailable("Ed25519 signing is unavailable") from error
        except Exception as error:
            raise ProviderFailure("Ed25519 local signing failed") from error
        if type(signature) is not bytes:
            raise ProviderFailure("Ed25519 backend returned a non-bytes signature")
        try:
            validate_ed25519_signature(signature)
        except _SignatureShapeError as error:
            raise ProviderFailure(
                "Ed25519 backend returned a noncanonical signature"
            ) from error
        if not _is_ed25519_curve_point(signature[:32]):
            raise ProviderFailure("Ed25519 backend returned a non-point signature")
        return signature


def _own_signing_identity(
    identity: object,
    algorithm: ProofAlgorithm,
    /,
) -> OracleSigningIdentity:
    if type(identity) is not OracleSigningIdentity:
        raise CryptoConfigurationError(
            "local signer identity must be an exact OracleSigningIdentity"
        )
    try:
        owned = OracleSigningIdentity(
            issuer=identity.issuer,
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            purpose=identity.purpose,
            public_key=identity.public_key,
            signing_not_before=identity.signing_not_before,
            signing_not_after=identity.signing_not_after,
            revoked_at=identity.revoked_at,
        )
    except Exception as error:
        raise CryptoConfigurationError("local signer identity is malformed") from error
    if owned.algorithm is not algorithm:
        raise CryptoConfigurationError(
            "local signer identity algorithm does not match the key adapter"
        )
    if owned.purpose is not KeyPurpose.ORACLE_TRUST_PROOF:
        raise CryptoConfigurationError(
            "local signer identity purpose must be Oracle Trust Proof"
        )
    return owned


class ES256LocalSigner(_ES256SignerBase):
    def __init__(
        self,
        identity: OracleSigningIdentity,
        private_key: "ec.EllipticCurvePrivateKey",
        /,
    ) -> None:
        super().__init__(identity, private_key)

    def sign(self, signing_input: bytes, /) -> bytes:
        return self._sign(signing_input)


class AsyncES256LocalSigner(_ES256SignerBase):
    def __init__(
        self,
        identity: OracleSigningIdentity,
        private_key: "ec.EllipticCurvePrivateKey",
        /,
    ) -> None:
        super().__init__(identity, private_key)

    async def sign(self, signing_input: bytes, /) -> bytes:
        return self._sign(signing_input)


class Ed25519LocalSigner(_Ed25519SignerBase):
    def __init__(
        self,
        identity: OracleSigningIdentity,
        private_key: "ed25519.Ed25519PrivateKey",
        /,
    ) -> None:
        super().__init__(identity, private_key)

    def sign(self, signing_input: bytes, /) -> bytes:
        return self._sign(signing_input)


class AsyncEd25519LocalSigner(_Ed25519SignerBase):
    def __init__(
        self,
        identity: OracleSigningIdentity,
        private_key: "ed25519.Ed25519PrivateKey",
        /,
    ) -> None:
        super().__init__(identity, private_key)

    async def sign(self, signing_input: bytes, /) -> bytes:
        return self._sign(signing_input)


def es256_public_key_bytes(
    public_key: "ec.EllipticCurvePublicKey",
    /,
) -> bytes:
    modules = _load_cryptography()
    return _es256_public_key_bytes(modules, public_key)


def ed25519_public_key_bytes(
    public_key: "ed25519.Ed25519PublicKey",
    /,
) -> bytes:
    modules = _load_cryptography()
    return _ed25519_public_key_bytes(modules, public_key)


def _es256_public_key_bytes(
    modules: _CryptographyModules,
    public_key: object,
    /,
) -> bytes:
    if not isinstance(public_key, modules.ec.EllipticCurvePublicKey):
        raise CryptoConfigurationError(
            "ES256 public-key conversion requires a PyCA EC public key"
        )
    try:
        curve = public_key.curve
    except Exception as error:
        raise CryptoConfigurationError(
            "ES256 public-key curve is unavailable"
        ) from error
    if not isinstance(curve, modules.ec.SECP256R1):
        raise CryptoConfigurationError("ES256 public key must use P-256")
    try:
        encoded = public_key.public_bytes(
            encoding=modules.serialization.Encoding.X962,
            format=modules.serialization.PublicFormat.UncompressedPoint,
        )
    except Exception as error:
        raise CryptoConfigurationError("ES256 public-key conversion failed") from error
    if type(encoded) is not bytes:
        raise CryptoConfigurationError("ES256 public-key conversion returned non-bytes")
    try:
        validate_es256_public_key(encoded)
    except _PublicKeyShapeError as error:
        raise CryptoConfigurationError(
            "ES256 public-key conversion returned a noncanonical point"
        ) from error
    return encoded


def _ed25519_public_key_bytes(
    modules: _CryptographyModules,
    public_key: object,
    /,
) -> bytes:
    if not isinstance(public_key, modules.ed25519.Ed25519PublicKey):
        raise CryptoConfigurationError(
            "Ed25519 public-key conversion requires a PyCA Ed25519 public key"
        )
    try:
        encoded = public_key.public_bytes_raw()
    except Exception as error:
        raise CryptoConfigurationError(
            "Ed25519 public-key conversion failed"
        ) from error
    if type(encoded) is not bytes:
        raise CryptoConfigurationError(
            "Ed25519 public-key conversion returned non-bytes"
        )
    try:
        validate_ed25519_public_key(encoded)
    except _PublicKeyShapeError as error:
        raise CryptoConfigurationError(
            "Ed25519 public-key conversion returned a noncanonical point"
        ) from error
    if not _is_ed25519_curve_point(encoded):
        raise CryptoConfigurationError(
            "Ed25519 public-key conversion returned a non-point"
        )
    return encoded


__all__ = [
    "AsyncES256LocalSigner",
    "AsyncEd25519LocalSigner",
    "ES256LocalSigner",
    "Ed25519LocalSigner",
    "async_cryptography_proof_crypto",
    "cryptography_proof_crypto",
    "ed25519_public_key_bytes",
    "es256_public_key_bytes",
]
