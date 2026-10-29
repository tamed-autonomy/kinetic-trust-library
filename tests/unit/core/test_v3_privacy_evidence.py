"""Real crypto; modeled authority and fixed test keys/nonces are unsafe in production."""
from importlib.util import find_spec
import copy
import unittest

from kinetic_trust_library.v3.privacy_evidence import (
    AuthenticatedPrivacyArchive, AuthenticatedPrivacyAccess,
    InstalledPrivacyEvidenceVerifier, InstalledPrivacyEvidenceReader,
    PrivacyArchiveUnavailable, PrivacyAccessUnavailable,
)

HAS_EXTRAS = all(find_spec(name) for name in ("rfc8785", "cryptography", "jsonschema"))


def fixture(level=2, algorithm="Ed25519", *, original=None):
    from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, ec, utils
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from kinetic_trust_library.v3 import _privacy_reference as p
    from kinetic_trust_library.v3 import _trajectory_reference as t
    if original is None:
        original = b'{ "evidence" : "caf\xc3\xa9", "signed_bytes":true }\n'
    context = dict(envelope_id="entry-1", zone_id="zone-1", chain_id="archive-1",
                   purpose_id="review", privacy_policy_digest=t.digest({"approved": "bounded-policy"}, level),
                   issuer_id="archive-issuer", conformance_level=level)
    envelope = dict(format=p.FORMAT, **context, sequence=1, previous_hash=None,
                    created_at=100, delete_after=200,
                    encryption=dict(algorithm="A256GCM", key_ref="key-ref-1", nonce=t.b64(bytes(12)), ciphertext=""))
    key = bytes(range(32))
    envelope["encryption"]["ciphertext"] = t.b64(AESGCM(key).encrypt(bytes(12), original, p.associated_data(envelope)))
    if algorithm in ("ES256", "ES384"):
        private = ec.derive_private_key(17, ec.SECP256R1() if algorithm == "ES256" else ec.SECP384R1())
        numbers = private.public_key().public_numbers()
        size = 32 if algorithm == "ES256" else 48
        jwk = dict(kty="EC", crv="P-256" if size == 32 else "P-384", x=t.b64(numbers.x.to_bytes(size,"big")), y=t.b64(numbers.y.to_bytes(size,"big")))
        alg = algorithm
    else:
        private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([17])*32) if algorithm == "Ed25519" else ed448.Ed448PrivateKey.from_private_bytes(bytes([17])*57)
        jwk = dict(kty="OKP", crv=algorithm, x=t.b64(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)))
        alg = "EdDSA"
    keys = {"archive-key": dict(jwk, kid="archive-key", alg=alg, subject="archive-issuer", zone_id="zone-1",
                                purpose=t.PRIVACY_EVIDENCE_TYPE, revoked=False, not_before=50, not_after=150)}
    def sign():
        message = (t.b64(t.canonical(dict(alg=alg, kid="archive-key", typ=t.PRIVACY_EVIDENCE_TYPE)))+"."+t.b64(t.canonical(p.body(envelope)))).encode()
        if alg in ("ES256", "ES384"):
            r, s = utils.decode_dss_signature(private.sign(message, ec.ECDSA(hashes.SHA256() if alg == "ES256" else hashes.SHA384())))
            signature = r.to_bytes(size,"big")+min(s,t.ORDERS[alg]-s).to_bytes(size,"big")
        else: signature = private.sign(message)
        envelope["signature"] = message.decode()+"."+t.b64(signature)
        envelope["record_hash"] = p.record_digest(envelope, level)
    sign()
    state = dict(context=context, checked_at=110,
                 anchor=dict(sequence=1, previous_hash=None, record_hash=envelope["record_hash"]))
    class Archive:
        unavailable = False
        def __init__(self): self.calls=[]
        def resolve(self, **kwargs):
            self.calls.append(kwargs)
            if self.unavailable: raise PrivacyArchiveUnavailable()
            return AuthenticatedPrivacyArchive(t.canonical(state), t.canonical(keys), b"modeled-approved-policy/archive/key-registry")
    archive = Archive()
    verifier = InstalledPrivacyEvidenceVerifier(t.canonical(context), archive)
    operation = dict(request_id="request-1", subject="urn:person:1", actor="urn:reader:1",
                     audience="urn:archive:1", operation="urn:operation:read-evidence", resource="urn:entry:1",
                     parameters={}, replay_domain="urn:replay:archive")
    class Access:
        unavailable = False
        def __init__(self):
            self.calls=[]
            self.key=key
        def authorize_and_resolve_key(self, **kwargs):
            self.calls.append(kwargs)
            if self.unavailable: raise PrivacyAccessUnavailable()
            authorization = dict(context=context, operation=operation, record_hash=envelope["record_hash"],
                                 key_ref=envelope["encryption"]["key_ref"], checked_at=state["checked_at"], expires_at=200)
            return AuthenticatedPrivacyAccess(t.canonical(authorization), self.key, b"modeled-purpose-limited-access")
    access = Access()
    return dict(envelope=envelope, state=state, context=context, keys=keys, key=key, original=original,
                verifier=verifier, archive=archive, access=access, operation=operation, sign=sign, p=p, t=t)


def check(f):
    return f["verifier"].verify(f["t"].canonical(f["envelope"]), now=f["state"]["checked_at"], clock_healthy=True)


def read(f):
    return InstalledPrivacyEvidenceReader(f["verifier"], f["access"]).open(
        f["t"].canonical(f["envelope"]), actual_operation=f["operation"], now=f["state"]["checked_at"], clock_healthy=True)


@unittest.skipUnless(HAS_EXTRAS, "install v3-proofs")
class PrivacyEvidenceTests(unittest.TestCase):
    def test_original_signature_can_be_independently_replayed_after_recovery(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from kinetic_trust_library.v3 import _trajectory_reference as t
        private = Ed25519PrivateKey.from_private_bytes(bytes([43])*32)
        body = {"assertion": "fixture-evidence", "subject": "urn:person:1"}
        message = (t.b64(t.canonical(dict(alg="EdDSA",kid="original-key",typ=t.AGENT_TYPE)))+"."+t.b64(t.canonical(body))).encode()
        token = message.decode()+"."+t.b64(private.sign(message))
        f = fixture(original=token.encode("ascii"))
        recovered = read(f)
        self.assertEqual(recovered.reason, "PRIVACY_BYTES_RECOVERED_UNREVIEWED")
        binding = t.KeyBinding("original-key", "original-issuer", "EdDSA", t.AGENT_TYPE, private.public_key(), "zone-1")
        t.verify_jws(recovered.plaintext_bytes.decode("ascii"), body, binding, level=2)
        with self.assertRaises(t.InvalidRecord):
            t.verify_jws(recovered.plaintext_bytes.decode("ascii"), dict(body,subject="urn:person:2"), binding, level=2)

    def test_real_crypto_all_classical_profiles_and_exact_recovery(self):
        for level, algorithm in ((1,"ES256"),(2,"Ed25519"),(2,"ES384"),(3,"ES384"),(3,"Ed448")):
            with self.subTest(level=level, algorithm=algorithm):
                f = fixture(level, algorithm)
                result = check(f)
                self.assertEqual(result.reason, "PRIVACY_OUTER_INTEGRITY_ONLY")
                self.assertNotIn("envelope_bytes", f["archive"].calls[0])
                self.assertIsNotNone(result.authenticated_state_bytes)
                opened = read(f)
                self.assertEqual(opened.reason, "PRIVACY_BYTES_RECOVERED_UNREVIEWED")
                self.assertEqual(opened.plaintext_bytes, f["original"])
                self.assertNotIn("plaintext_bytes", repr(opened))
                self.assertNotIn("data_key", repr(AuthenticatedPrivacyAccess(b"{}", f["key"], b"evidence")))

    def test_every_candidate_field_mutation_rejected(self):
        f = fixture()
        original = copy.deepcopy(f["envelope"])
        for name in original:
            f["envelope"].clear(); f["envelope"].update(copy.deepcopy(original))
            if name == "encryption": f["envelope"][name]["key_ref"] = "changed-key"
            elif name == "previous_hash": f["envelope"][name] = f["t"].digest({},2)
            elif type(original[name]) is int: f["envelope"][name] += 1
            else: f["envelope"][name] += "-changed"
            with self.subTest(field=name): self.assertEqual(check(f).reason, "PRIVACY_INVALID")

    def test_reanchoring_resigning_cannot_repair_aead_binding(self):
        f = fixture()
        f["envelope"]["encryption"]["key_ref"] = "changed-key"
        f["sign"]()
        f["state"]["anchor"]["record_hash"] = f["envelope"]["record_hash"]
        self.assertEqual(check(f).reason, "PRIVACY_OUTER_INTEGRITY_ONLY")
        self.assertEqual(read(f).reason, "PRIVACY_DECRYPTION_FAILED")

    def test_archive_anchor_role_zone_registry_and_time_are_independent(self):
        for mode in ("anchor", "purpose", "zone", "issuer", "revoked", "key-expired-at-creation", "future", "stale"):
            f = fixture()
            key = f["keys"]["archive-key"]
            if mode == "anchor": f["state"]["anchor"]["record_hash"] = f["t"].digest({},2)
            elif mode == "purpose": key["purpose"] = f["t"].AGENT_TYPE
            elif mode == "zone": key["zone_id"] = "zone-2"
            elif mode == "issuer": key["subject"] = "issuer-2"
            elif mode == "revoked": key["revoked"] = True
            elif mode == "key-expired-at-creation": key["not_after"] = 100
            elif mode == "future": f["state"]["checked_at"] = 99
            else: f["state"]["context"] = dict(f["context"], purpose_id="other-purpose")
            with self.subTest(mode=mode):
                self.assertEqual(check(f).reason, "PRIVACY_UNAVAILABLE" if mode == "stale" else "PRIVACY_INVALID")

    def test_access_unavailable_wrong_key_wrong_invocation_and_retention(self):
        f = fixture()
        f["access"].unavailable = True
        self.assertEqual(read(f).reason, "PRIVACY_ACCESS_UNAVAILABLE")
        f["access"].unavailable = False
        f["access"].key = bytes([99])*32
        self.assertEqual(read(f).reason, "PRIVACY_DECRYPTION_FAILED")
        f["access"].key = f["key"]
        other_operation = dict(f["operation"], subject="urn:person:other")
        reader = InstalledPrivacyEvidenceReader(f["verifier"], f["access"])
        result = reader.open(f["t"].canonical(f["envelope"]), actual_operation=other_operation, now=110, clock_healthy=True)
        self.assertEqual(result.reason, "PRIVACY_ACCESS_INVALID")
        for now in (199, 200, 201):
            f["state"]["checked_at"] = now
            self.assertEqual(check(f).reason, "PRIVACY_OUTER_INTEGRITY_ONLY")
            self.assertEqual(read(f).reason, "PRIVACY_BYTES_RECOVERED_UNREVIEWED" if now == 199 else "PRIVACY_RETENTION_EXPIRED")

    def test_unknown_clock_unavailable_archive_and_weak_level3(self):
        f = fixture()
        raw = f["t"].canonical(f["envelope"])
        self.assertEqual(f["verifier"].verify(raw, now=110, clock_healthy=False).reason, "PRIVACY_UNAVAILABLE")
        self.assertEqual(f["archive"].calls, [])
        f["archive"].unavailable = True
        self.assertEqual(check(f).reason, "PRIVACY_UNAVAILABLE")
        for algorithm in ("ES256", "Ed25519"):
            self.assertEqual(check(fixture(3, algorithm)).reason, "PRIVACY_INVALID")

    def test_anchored_successor_and_genesis_predecessor_rules(self):
        f = fixture()
        previous = f["envelope"]["record_hash"]
        f["envelope"].update(sequence=2, previous_hash=previous)
        # Re-encryption uses the updated exact associated data, then a new
        # signature; the independent fixture archive anchors the successor.
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        f["envelope"]["encryption"]["nonce"] = f["t"].b64(bytes([1])*12)
        f["envelope"]["encryption"]["ciphertext"] = f["t"].b64(AESGCM(f["key"]).encrypt(
            bytes([1])*12, f["original"], f["p"].associated_data(f["envelope"])))
        f["sign"]()
        f["state"]["anchor"].update(sequence=2, previous_hash=previous, record_hash=f["envelope"]["record_hash"])
        self.assertEqual(read(f).plaintext_bytes, f["original"])
        f["envelope"]["previous_hash"] = None
        f["sign"]()
        f["state"]["anchor"].update(previous_hash=None, record_hash=f["envelope"]["record_hash"])
        self.assertEqual(check(f).reason, "PRIVACY_INVALID")

    def test_raw_shapes_and_ciphertext_authentication_are_checked(self):
        for mode in ("tag", "short", "padded", "nonce", "unknown", "bool"):
            f = fixture()
            if mode == "tag":
                cipher = f["p"].unb64(f["envelope"]["encryption"]["ciphertext"])
                f["envelope"]["encryption"]["ciphertext"] = f["t"].b64(cipher[:-1]+bytes([cipher[-1]^1]))
            elif mode == "short": f["envelope"]["encryption"]["ciphertext"] = f["t"].b64(bytes(16))
            elif mode == "padded": f["envelope"]["encryption"]["ciphertext"] += "="
            elif mode == "nonce": f["envelope"]["encryption"]["nonce"] = f["t"].b64(bytes(11))
            elif mode == "unknown": f["envelope"]["grant_access"] = True
            else: f["envelope"]["sequence"] = True
            f["sign"]()
            f["state"]["anchor"]["record_hash"] = f["envelope"]["record_hash"]
            with self.subTest(mode=mode):
                result = read(f)
                self.assertEqual(result.reason, "PRIVACY_DECRYPTION_FAILED" if mode == "tag" else "PRIVACY_INVALID")
                self.assertIsNone(result.plaintext_bytes)
        f = fixture()
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{}', b' ' * 262145):
            self.assertEqual(f["verifier"].verify(raw, now=110, clock_healthy=True).reason, "PRIVACY_INVALID")
