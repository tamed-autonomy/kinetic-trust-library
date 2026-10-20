"""Strict compact Trust Proof framing tests."""

from dataclasses import FrozenInstanceError, fields
import unittest

from kinetic_trust_library.errors import (
    DisabledProofAlgorithmError,
    ProofFormatError,
    UnsupportedProofAlgorithmError,
)
from kinetic_trust_library.models.proof import ProofAlgorithm
from kinetic_trust_library.proofs._jwt import (
    _require_compact_token_width,
    _require_decoded_header_width,
    _require_enabled_algorithm,
    _require_header_segment_width,
    _require_payload_segment_width,
    _require_signature_segment_width,
    _require_signing_input_width,
    canonical_payload_bytes,
    parse_compact,
    parse_payload,
)

from ._fixtures import (
    _segment,
    array_item_payload,
    compact_token,
    nested_payload,
    numeric_lexeme_payload,
    object_member_payload,
    payload_of_size,
    string_payload,
    total_collection_item_payload,
    total_object_member_payload,
    trust_proof_claims,
)


class JWTFramingTests(unittest.TestCase):
    def test_valid_compact_token_preserves_owned_phase_values(self):
        raw = compact_token(
            b'{"alg":"ES256","kid":"k1","typ":"ktp+jwt"}',
            b'{"iss":"urn:oracle:test"}',
            b"x",
        )

        parsed = parse_compact(raw)

        self.assertEqual(parsed.raw, raw)
        self.assertEqual(parsed.algorithm, ProofAlgorithm.ES256)
        self.assertEqual(parsed.key_id, "k1")
        self.assertEqual(parsed.untrusted_issuer, "urn:oracle:test")
        self.assertEqual(parsed.payload_bytes, b'{"iss":"urn:oracle:test"}')
        self.assertEqual(parsed.signature, b"x")

    def test_raw_token_requires_an_exact_ascii_string_before_hooks(self):
        class HostileString(str):
            def encode(self, *args: object, **kwargs: object) -> bytes:
                raise AssertionError("string hook must not run")

            def split(self, *args: object, **kwargs: object) -> list[str]:
                raise AssertionError("string hook must not run")

        for raw in (b"a.b.c", HostileString("a.b.c"), "a.b.\N{SNOWMAN}"):
            with self.subTest(raw=repr(raw)), self.assertRaises(ProofFormatError):
                parse_compact(raw)  # type: ignore[arg-type]

    def test_compact_framing_requires_exactly_three_nonempty_segments(self):
        for raw in (
            "a.b",
            "a.b.c.d",
            ".b.c",
            "a..c",
            "a.b.",
        ):
            with self.subTest(raw=raw), self.assertRaises(ProofFormatError):
                parse_compact(raw)

    def test_strict_base64url_rejects_alphabet_padding_length_and_pad_bits(self):
        valid_header = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoia3RwK2p3dCJ9"
        valid_payload = "eyJpc3MiOiJ1cm46b3JhY2xlOnRlc3QifQ"
        for signature_segment in (
            "*A",
            "+A",
            "/A",
            "eA==",
            "A",
            "_x",
            "__9",
        ):
            raw = f"{valid_header}.{valid_payload}.{signature_segment}"
            with (
                self.subTest(signature_segment=signature_segment),
                self.assertRaises(ProofFormatError),
            ):
                parse_compact(raw)

    def test_segment_widths_reject_maximum_plus_one_before_decoding(self):
        valid_header = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoia3RwK2p3dCJ9"
        valid_payload = "eyJpc3MiOiJ1cm46b3JhY2xlOnRlc3QifQ"
        for raw in (
            f"{'A' * 2049}.{valid_payload}.eA",
            f"{valid_header}.{'A' * 60001}.eA",
            f"{valid_header}.{valid_payload}.{'A' * 129}",
        ):
            with self.subTest(widths=tuple(map(len, raw.split(".")))):
                with self.assertRaises(ProofFormatError):
                    parse_compact(raw)

    def test_redundant_aggregate_width_guards_accept_maximum_and_reject_next(self):
        _require_compact_token_width("A" * 65_536)
        with self.assertRaises(ProofFormatError):
            _require_compact_token_width("A" * 65_537)

        _require_signing_input_width(b"A" * 62_049)
        with self.assertRaises(ProofFormatError):
            _require_signing_input_width(b"A" * 62_050)


class StrictJSONTests(unittest.TestCase):
    def test_payload_requires_exact_bytes_before_decode_hooks(self):
        class HostileBytes(bytes):
            def decode(self, *args: object, **kwargs: object) -> str:
                raise AssertionError("bytes hook must not run")

        for payload in (bytearray(b"{}"), memoryview(b"{}"), HostileBytes(b"{}")):
            with (
                self.subTest(payload_type=type(payload).__name__),
                self.assertRaises(ProofFormatError),
            ):
                parse_payload(payload)  # type: ignore[arg-type]

    def test_duplicate_members_are_rejected_at_every_depth(self):
        payloads = (
            b'{"a":1,"a":2}',
            b'{"outer":{"a":1,"a":2}}',
            b'{"items":[{"a":1,"a":2}]}',
        )
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(ProofFormatError):
                parse_payload(payload)

        raw = compact_token(
            b'{"alg":"ES256","alg":"EdDSA","kid":"k1","typ":"ktp+jwt"}',
            b'{"iss":"urn:oracle:test"}',
            b"x",
        )
        with self.assertRaises(ProofFormatError):
            parse_compact(raw)

    def test_invalid_utf8_surrogates_bom_and_trailing_data_are_rejected(self):
        payloads = (
            b'{"x":"\xff"}',
            b'{"x":"\\ud800"}',
            b'{"x":"\\udc00"}',
            b"\xef\xbb\xbf{}",
            b"{}{}",
            b"{} true",
            b'{"x":"line\nfeed"}',
        )
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(ProofFormatError):
                parse_payload(payload)

    def test_only_canonical_json_encoding_is_accepted(self):
        self.assertEqual(
            parse_payload(b'{"a":1,"b":"\xc3\xa9"}'),
            {"a": 1, "b": "\N{LATIN SMALL LETTER E WITH ACUTE}"},
        )
        for payload in (
            b'{ "a":1}',
            b'{"b":2,"a":1}',
            b'{"a":"\\u0061"}',
            b'{"a":1.0}',
            b'{"a":-0}',
            b'{"a":1e0}',
        ):
            with self.subTest(payload=payload), self.assertRaises(ProofFormatError):
                parse_payload(payload)

    def test_payload_decoder_requires_a_top_level_object(self):
        for payload in (b"[]", b"null", b'"text"', b"1"):
            with self.subTest(payload=payload), self.assertRaises(ProofFormatError):
                parse_payload(payload)

    def test_protected_header_must_use_canonical_json_encoding(self):
        payload = b'{"iss":"urn:oracle:test"}'
        for header in (
            b'{"alg":"ES256","typ":"ktp+jwt","kid":"k1"}',
            b'{"alg":"ES256", "kid":"k1","typ":"ktp+jwt"}',
        ):
            with self.subTest(header=header), self.assertRaises(ProofFormatError):
                parse_compact(compact_token(header, payload, b"x"))


class HeaderPolicyTests(unittest.TestCase):
    def test_closed_header_requires_exact_members_and_string_types(self):
        payload = b'{"iss":"urn:oracle:test"}'
        headers = (
            b'{"alg":"ES256","kid":"k1","typ":"ktp+jwt","x":1}',
            b'{"alg":"ES256","typ":"ktp+jwt"}',
            b'{"alg":1,"kid":"k1","typ":"ktp+jwt"}',
            b'{"alg":"ES256","kid":1,"typ":"ktp+jwt"}',
            b'{"alg":"ES256","kid":"k1","typ":1}',
        )
        for header in headers:
            with self.subTest(header=header), self.assertRaises(ProofFormatError):
                parse_compact(compact_token(header, payload, b"x"))


class ResourceBoundTests(unittest.TestCase):
    def test_all_json_limits_accept_maximum_and_reject_maximum_plus_one(self):
        fixtures = (
            ("nesting depth", 16, nested_payload(16), nested_payload(17)),
            (
                "members in one object",
                128,
                object_member_payload(128),
                object_member_payload(129),
            ),
            (
                "total object members",
                512,
                total_object_member_payload(512),
                total_object_member_payload(513),
            ),
            (
                "items in one array",
                256,
                array_item_payload(256),
                array_item_payload(257),
            ),
            (
                "total collection items",
                1_024,
                total_collection_item_payload(1_024),
                total_collection_item_payload(1_025),
            ),
            (
                "iss string bytes",
                2_048,
                string_payload("iss", 2_048),
                string_payload("iss", 2_049),
            ),
            (
                "sub string bytes",
                2_048,
                string_payload("sub", 2_048),
                string_payload("sub", 2_049),
            ),
            (
                "kid string bytes",
                256,
                string_payload("kid", 256),
                string_payload("kid", 257),
            ),
            (
                "jti string bytes",
                256,
                string_payload("jti", 256),
                string_payload("jti", 257),
            ),
            (
                "other string bytes",
                4_096,
                string_payload("x", 4_096),
                string_payload("x", 4_097),
            ),
            (
                "numeric lexeme bytes",
                128,
                numeric_lexeme_payload(128),
                numeric_lexeme_payload(129),
            ),
        )

        for name, maximum, accepted, rejected in fixtures:
            with self.subTest(name=name, maximum=maximum):
                self.assertIs(type(parse_payload(accepted)), dict)
                with self.assertRaises(ProofFormatError):
                    parse_payload(rejected)

    def test_decoded_payload_limit_accepts_45000_and_rejects_45001_bytes(self):
        maximum = payload_of_size(45_000)
        oversized = payload_of_size(45_001)
        self.assertEqual(len(maximum), 45_000)
        self.assertEqual(len(oversized), 45_001)

        self.assertIs(type(parse_payload(maximum)), dict)
        with self.assertRaises(ProofFormatError):
            parse_payload(oversized)

    def test_reachable_segment_limits_accept_maximum_and_reject_next(self):
        header = b'{"alg":"ES256","kid":"k1","typ":"ktp+jwt"}'
        payload = payload_of_size(45_000)
        payload_segment = _segment(payload)
        self.assertEqual(len(payload_segment), 60_000)
        parsed = parse_compact(f"{_segment(header)}.{payload_segment}.{'A' * 128}")
        self.assertEqual(len(parsed.payload_bytes), 45_000)
        self.assertEqual(len(parsed.signature), 96)

        oversized_payload_segment = _segment(payload_of_size(45_001))
        self.assertEqual(len(oversized_payload_segment), 60_002)
        with self.assertRaises(ProofFormatError):
            parse_compact(f"{_segment(header)}.{oversized_payload_segment}.{'A' * 128}")
        with self.assertRaises(ProofFormatError):
            parse_compact(f"{_segment(header)}.{payload_segment}.{'A' * 129}")

    def test_unreachable_header_and_segment_caps_are_exercised_at_private_guards(self):
        _require_header_segment_width("A" * 2_048)
        with self.assertRaises(ProofFormatError):
            _require_header_segment_width("A" * 2_049)

        _require_payload_segment_width("A" * 60_000)
        with self.assertRaises(ProofFormatError):
            _require_payload_segment_width("A" * 60_001)

        _require_signature_segment_width("A" * 128)
        with self.assertRaises(ProofFormatError):
            _require_signature_segment_width("A" * 129)

        _require_decoded_header_width(b"A" * 1_536)
        with self.assertRaises(ProofFormatError):
            _require_decoded_header_width(b"A" * 1_537)


class HeaderValuePolicyTests(unittest.TestCase):
    def test_typ_is_exact_and_unknown_algorithm_is_distinct(self):
        payload = b'{"iss":"urn:oracle:test"}'
        alternate_typ = b'{"alg":"ES256","kid":"k1","typ":"ktp-trust-proof+jwt"}'
        with self.assertRaises(ProofFormatError):
            parse_compact(compact_token(alternate_typ, payload, b"x"))

        unknown_algorithm = b'{"alg":"RS256","kid":"k1","typ":"ktp+jwt"}'
        with self.assertRaises(UnsupportedProofAlgorithmError):
            parse_compact(compact_token(unknown_algorithm, payload, b"x"))

    def test_closed_profile_parses_both_known_algorithm_literals(self):
        payload = b'{"iss":"urn:oracle:test"}'
        ed25519_header = b'{"alg":"EdDSA","kid":"k1","typ":"ktp+jwt"}'

        parsed = parse_compact(compact_token(ed25519_header, payload, b"x"))

        self.assertEqual(parsed.algorithm, ProofAlgorithm.ED25519)

    def test_deployment_disabled_algorithm_is_a_distinct_policy_failure(self):
        enabled = (ProofAlgorithm.ES256,)
        _require_enabled_algorithm(ProofAlgorithm.ES256, enabled)
        with self.assertRaises(DisabledProofAlgorithmError):
            _require_enabled_algorithm(ProofAlgorithm.ED25519, enabled)

    def test_key_id_uses_bounded_nfc_preserving_unicode_policy(self):
        payload = b'{"iss":"urn:oracle:test"}'
        maximum = b'{"alg":"ES256","kid":"' + (b"a" * 256) + b'","typ":"ktp+jwt"}'
        self.assertEqual(
            parse_compact(compact_token(maximum, payload, b"x")).key_id,
            "a" * 256,
        )
        invalid_headers = (
            b'{"alg":"ES256","kid":"","typ":"ktp+jwt"}',
            b'{"alg":"ES256","kid":"' + (b"a" * 257) + b'","typ":"ktp+jwt"}',
            b'{"alg":"ES256","kid":"Cafe\xcc\x81","typ":"ktp+jwt"}',
            b'{"alg":"ES256","kid":"k 1","typ":"ktp+jwt"}',
            b'{"alg":"ES256","kid":"k\\n1","typ":"ktp+jwt"}',
        )
        for header in invalid_headers:
            with self.subTest(header=header), self.assertRaises(ProofFormatError):
                parse_compact(compact_token(header, payload, b"x"))

    def test_untrusted_issuer_is_top_level_bounded_and_absolute(self):
        header = b'{"alg":"ES256","kid":"k1","typ":"ktp+jwt"}'
        maximum_issuer = "urn:" + ("a" * 2_044)
        maximum_payload = ('{"iss":"' + maximum_issuer + '"}').encode("ascii")
        self.assertEqual(
            parse_compact(
                compact_token(header, maximum_payload, b"x")
            ).untrusted_issuer,
            maximum_issuer,
        )
        invalid_payloads = (
            b"{}",
            b'{"iss":1}',
            b'{"iss":"relative/path"}',
            ('{"iss":"urn:' + ("a" * 2_045) + '"}').encode("ascii"),
            b'{"nested":{"iss":"urn:oracle:test"}}',
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload), self.assertRaises(ProofFormatError):
                parse_compact(compact_token(header, payload, b"x"))


class CanonicalPayloadTests(unittest.TestCase):
    def test_full_claims_encode_to_independently_checked_canonical_bytes(self):
        expected = (
            b'{"exp":1787572810,"iat":1787572800,"iss":"https://oracle.example",'
            b'"jti":"proof-1","ktp":{"action":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","advancement_floor":0,'
            b'"applicable_ceilings":[{"ceiling":"generation","value":80}],'
            b'"context":{"adversarial_pressure":0.3,"attestation_coverage":0.5,'
            b'"evidence_density":0.1,"moment_criticality":0.6,"trust_trend":0.2,'
            b'"update_resistance":0.4},"context_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
            b'"de_dt":-0.5,"decision_id":"decision-1","e_base":80,"e_trust":72,'
            b'"generation":2,"lineage":"sponsored","oracle_quorum":"1-of-1",'
            b'"peer_share":0,"r":0.1,'
            b'"resilience_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
            b'"resource":"urn:resource:document:42",'
            b'"root_instrument":{"anchored_capacity":60,"chain_length":2,'
            b'"declared_exposure":50,"end_time":1787576400,"exposure_class":"legal",'
            b'"status":"current","terminator":"org:root"},"sigma":0.2,'
            b'"soul":{"authority":"https://authority.example",'
            b'"community":"Example Community","constraint_id":"TK-NC-001",'
            b'"constraint_name":"TK Non-Commercial","constraint_type":"tk_label",'
            b'"remediation":"Ask first","soul":1},"sponsor":"urn:agent:sponsor",'
            b'"trajectory_id":"trajectory-1","zone":"zone-blue"},"sub":"urn:agent:test"}'
        )

        encoded = canonical_payload_bytes(trust_proof_claims(full=True))

        self.assertIs(type(encoded), bytes)
        self.assertEqual(encoded, expected)

    def test_sparse_claims_omit_optional_values_and_none_root_details(self):
        expected = (
            b'{"exp":1787572810,"iat":1787572800,"iss":"https://oracle.example",'
            b'"jti":"proof-1","ktp":{"action":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","advancement_floor":0,'
            b'"applicable_ceilings":[],"context":{"adversarial_pressure":0.3,'
            b'"attestation_coverage":0.5,"evidence_density":0.1,'
            b'"moment_criticality":0.6,"trust_trend":0.2,"update_resistance":0.4},'
            b'"context_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
            b'"decision_id":"decision-1","e_base":80,"e_trust":72,"generation":7,"lineage":"guarantor",'
            b'"peer_share":0,"r":0.1,'
            b'"resilience_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
            b'"resource":"urn:resource:document:42",'
            b'"root_instrument":{"status":"none"},"soul":{"soul":0},"trajectory_id":"trajectory-1"},'
            b'"sub":"urn:agent:test"}'
        )

        self.assertEqual(
            canonical_payload_bytes(trust_proof_claims(full=False)),
            expected,
        )

    def test_payload_encoder_requires_the_guarded_claims_type(self):
        with self.assertRaises(TypeError):
            canonical_payload_bytes(object())  # type: ignore[arg-type]

    def test_payload_encoder_rejects_hostile_optional_values_before_hooks(self):
        class HostileOptional:
            def __getattribute__(self, name: str) -> object:
                raise AssertionError(f"optional-value hook must not run: {name}")

        claims = trust_proof_claims(full=False)
        object.__setattr__(claims, "sponsor", HostileOptional())

        with self.assertRaises(ProofFormatError):
            canonical_payload_bytes(claims)


class PhaseBoundaryTests(unittest.TestCase):
    def test_untrusted_payload_framing_precedes_header_policy(self):
        unknown_header = b'{"alg":"RS256","kid":"k1","typ":"ktp+jwt"}'
        with self.assertRaises(ProofFormatError):
            parse_compact(compact_token(unknown_header, b"not-json", b"x"))

    def test_payload_resource_guard_precedes_header_policy(self):
        unknown_header = b'{"alg":"RS256","kid":"k1","typ":"ktp+jwt"}'
        with self.assertRaises(ProofFormatError):
            parse_compact(compact_token(unknown_header, payload_of_size(45_001), b"x"))

    def test_parsed_phase_value_is_frozen_and_carries_no_decoded_mapping(self):
        raw = compact_token(
            b'{"alg":"ES256","kid":"k1","typ":"ktp+jwt"}',
            b'{"iss":"urn:oracle:test"}',
            b"x",
        )
        parsed = parse_compact(raw)
        self.assertEqual(
            {field.name for field in fields(parsed)},
            {
                "raw",
                "header_segment",
                "payload_segment",
                "signature_segment",
                "signing_input",
                "signature",
                "algorithm",
                "key_id",
                "untrusted_issuer",
                "payload_bytes",
            },
        )
        self.assertNotIn(dict, {type(value) for value in vars_for_slots(parsed)})
        with self.assertRaises(FrozenInstanceError):
            parsed.raw = "changed"  # type: ignore[misc]

    def test_payload_decoder_returns_fresh_non_authoritative_containers(self):
        first = parse_payload(b'{"a":{"b":[1]}}')
        second = parse_payload(b'{"a":{"b":[1]}}')
        self.assertIsNot(first, second)
        first_inner = first["a"]
        second_inner = second["a"]
        self.assertIs(type(first_inner), dict)
        self.assertIs(type(second_inner), dict)
        first_list = first_inner["b"]  # type: ignore[index]
        self.assertIs(type(first_list), list)
        first_list.append(2)  # type: ignore[union-attr]
        self.assertEqual(second, {"a": {"b": [1]}})


def vars_for_slots(value: object) -> tuple[object, ...]:
    return tuple(getattr(value, field.name) for field in fields(value))


if __name__ == "__main__":
    unittest.main()
