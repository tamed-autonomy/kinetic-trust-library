"""Signed decision-binding tests for the optional PyCA adapter."""

import unittest
from base64 import urlsafe_b64encode

from cryptography.hazmat.primitives.asymmetric import ec

from kinetic_trust_library.adapters.cryptography import (
    ES256LocalSigner,
    cryptography_proof_crypto,
)
from kinetic_trust_library.errors import InvalidSignatureError, ProofClaimsError
from kinetic_trust_library.models.proof import OracleSigningIdentity
from kinetic_trust_library.proofs import TrustProofs
from tests.unit.proofs._fakes import SpyKeySource
from tests.unit.proofs._fixtures import compact_token
from tests.unit.proofs.test_verify import (
    CUTOFF,
    KEY_ID,
    canonical_json,
    trusted_key,
    valid_payload,
)


class SignedDecisionBindingTests(unittest.TestCase):
    def setUp(self):
        key = trusted_key()
        self.signer = ES256LocalSigner(
            OracleSigningIdentity(
                issuer=key.issuer,
                key_id=key.key_id,
                algorithm=key.algorithm,
                purpose=key.purpose,
                public_key=key.public_key,
                signing_not_before=key.signing_not_before,
                signing_not_after=key.signing_not_after,
                revoked_at=None,
            ),
            ec.derive_private_key(1, ec.SECP256R1()),
        )
        self.facade = TrustProofs(cryptography_proof_crypto())

    def signed_token(self, payload):
        header = canonical_json({"alg": "ES256", "kid": KEY_ID, "typ": "ktp+jwt"})
        body = canonical_json(payload)
        signing_input = (
            urlsafe_b64encode(header).rstrip(b"=")
            + b"."
            + urlsafe_b64encode(body).rstrip(b"=")
        )
        return compact_token(header, body, self.signer.sign(signing_input))

    def test_mutating_each_binding_with_original_signature_fails_authentication(self):
        original = self.signed_token(valid_payload())
        verified = self.facade.verify(
            original, cutoff=CUTOFF, keys=SpyKeySource(trusted_key())
        )
        self.assertEqual(verified.claims.action, "c" * 64)

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
            with self.subTest(field=field):
                payload = valid_payload()
                target = payload if field in {"sub", "iat", "exp"} else payload["ktp"]
                target[field] = 0 if field in {"iat", "exp"} else ""
                header, _, signature = original.split(".")
                body = (
                    urlsafe_b64encode(canonical_json(payload))
                    .rstrip(b"=")
                    .decode("ascii")
                )
                with self.assertRaises(InvalidSignatureError):
                    self.facade.verify(
                        f"{header}.{body}.{signature}",
                        cutoff=CUTOFF,
                        keys=SpyKeySource(trusted_key()),
                    )

    def test_independently_signed_unbound_payload_is_rejected(self):
        for field in (
            None,
            "action",
            "resource",
            "context_hash",
            "trajectory_id",
            "decision_id",
        ):
            with self.subTest(missing=field):
                payload = valid_payload()
                for missing in (
                    (field,)
                    if field
                    else (
                        "action",
                        "resource",
                        "context_hash",
                        "trajectory_id",
                        "decision_id",
                    )
                ):
                    del payload["ktp"][missing]
                with self.assertRaises(ProofClaimsError):
                    self.facade.verify(
                        self.signed_token(payload),
                        cutoff=CUTOFF,
                        keys=SpyKeySource(trusted_key()),
                    )


if __name__ == "__main__":
    unittest.main()
