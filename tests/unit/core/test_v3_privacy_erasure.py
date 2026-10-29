"""Modeled authenticated inventory/disposal services, never real deletion."""
from dataclasses import asdict, replace
import copy
import unittest
from importlib.util import find_spec

from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.privacy_erasure import (
    AuthenticatedErasureContext, ErasureContextUnavailable,
    ErasureAccountingResult, InstalledErasureReceiptVerifier,
)


NOW = 1000
HAS_V3_EXTRAS = all(find_spec(name) for name in ("jsonschema", "rfc8785", "cryptography"))
if HAS_V3_EXTRAS:
    from kinetic_trust_library.v3 import _human_reference as h


def fixture(level=2):
    d = lambda value: h.digest({"modeled_erasure_source": value}, level)
    copies = [dict(copy_id=name, kind=kind,
                   recipient_id="recipient-1" if kind == "downstream" else None,
                   key_ids=["key-1"] if kind == "backup" else [], disposition="pending",
                   verification_digest=None, acknowledgement_digest=None, retention=None)
              for name, kind in (("primary", "primary"), ("replica", "replica"),
                                 ("backup", "backup"), ("recipient", "downstream"))]
    receipt = dict(receipt_version="ktp-privacy-erasure-receipt-v1", receipt_id="receipt-1",
                   purpose_id="privacy-erasure", request_digest=d("request"),
                   subject_scope_digest=d("scope"), inventory_digest=d("placeholder"),
                   inventory_version=3, scope_cutoff=990, evaluated_at=NOW,
                   inventory_complete=True, copies=copies,
                   keys=[dict(key_id="key-1", shared=False, disposition="active", destruction_digest=None)],
                   status="pending")
    receipt["inventory_digest"] = h.digest(h.inventory_body(receipt), level)
    inventory = h.TrustedErasureInventory(
        receipt["request_digest"], receipt["subject_scope_digest"], receipt["inventory_digest"],
        3, 990, True, NOW, ["recipient-1"], ["security-audit"], {}, {}, {}, {})
    context = dict(receipt_id="receipt-1", request_digest=receipt["request_digest"],
                   subject_scope_digest=receipt["subject_scope_digest"],
                   privacy_policy_digest=d("approved-policy"), conformance_level=level)
    return receipt, inventory, context


class Source:
    """Fixture has independently modeled auth of exact receipt and inventory."""
    def __init__(self, receipt, inventory, context):
        self.receipt = receipt
        self.inventory = inventory
        self.context = context
        self.calls = []
        self.unavailable = False

    def resolve(self, **kwargs):
        self.calls.append(kwargs)
        if self.unavailable:
            raise ErasureContextUnavailable()
        state = dict(context=self.context, checked_at=NOW,
                     authenticated_receipt_digest=h.digest(self.receipt, self.context["conformance_level"]),
                     inventory=asdict(self.inventory))
        return AuthenticatedErasureContext(h.canonical(state), b"modeled inventory/disposal/receipt authentication")


def install(level=2):
    receipt, inventory, context = fixture(level)
    source = Source(receipt, inventory, context)
    return receipt, source, InstalledErasureReceiptVerifier(h.canonical(context), source)


def erase(source, index, crypto=False):
    receipt = source.receipt
    level = source.context["conformance_level"]
    item = receipt["copies"][index]
    item.update(disposition="crypto_erased" if crypto else "deleted",
                verification_digest=h.digest({"modeled_disposal": item["copy_id"]}, level))
    source.inventory = replace(source.inventory, copy_verifications={
        **source.inventory.copy_verifications, item["copy_id"]: h.digest(h.copy_disposition_body(item), level)})
    if item["kind"] == "downstream":
        item["acknowledgement_digest"] = h.digest({"modeled_ack": item["copy_id"]}, level)
        source.inventory = replace(source.inventory, recipient_acknowledgements={
            **source.inventory.recipient_acknowledgements, item["copy_id"]: item["acknowledgement_digest"]})
    if crypto:
        key = receipt["keys"][0]
        key.update(disposition="destroyed", destruction_digest=h.digest({"modeled_destruction": key["key_id"]}, level))
        source.inventory = replace(source.inventory, key_destructions={key["key_id"]: key["destruction_digest"]})
    receipt["status"] = "complete" if all(item["disposition"] in ("deleted", "crypto_erased")
                                               for item in receipt["copies"]) else "partial"


def verify(verifier, receipt):
    return verifier.verify(h.canonical(receipt), now=NOW, clock_healthy=True)


@unittest.skipUnless(HAS_V3_EXTRAS, "install v3-proofs")
class ErasureAccountingTests(unittest.TestCase):
    def test_all_levels_pending_partial_complete_and_retained_evidence(self):
        for level in (1, 2, 3):
            receipt, source, verifier = install(level)
            self.assertEqual(verify(verifier, receipt).status, "pending")
            erase(source, 0)
            self.assertEqual(verify(verifier, receipt).status, "partial")
            erase(source, 1); erase(source, 2, crypto=True); erase(source, 3)
            result = verify(verifier, receipt)
            self.assertEqual((result.reason, result.status), ("ERASURE_ACCOUNTING_VERIFIED", "complete"))
            self.assertEqual(result.receipt_bytes, h.canonical(receipt))
            self.assertIsNotNone(result.authenticated_state_bytes)
            self.assertIsNotNone(result.source_evidence_bytes)
            self.assertEqual(result.conformance_level, level)
            self.assertNotIn("receipt_bytes", source.calls[0])
            self.assertEqual(source.calls[0], dict(expected_context_bytes=verifier.expected_context_bytes, checked_at=NOW))
            with self.assertRaises(TypeError): ErasureAccountingResult()
            with self.assertRaises(AttributeError): result.status = "pending"

    def test_candidate_cannot_supply_receipt_authentication(self):
        receipt, source, verifier = install()
        changed = dict(receipt, receipt_id="attacker-receipt")
        self.assertEqual(verify(verifier, changed).reason, "ERASURE_INVALID")
        changed = dict(receipt, status="complete")
        self.assertEqual(verify(verifier, changed).reason, "ERASURE_INVALID")
        self.assertEqual(source.receipt, receipt)

    def test_authenticated_but_semantically_false_disposal_is_rejected(self):
        modes = ("missing-copy", "missing-ack", "shared-key", "no-destruction", "relabeled", "incomplete", "scope", "downgrade")
        for mode in modes:
            receipt, source, verifier = install(3 if mode == "downgrade" else 2)
            for index in range(4): erase(source, index, crypto=index == 2)
            if mode == "missing-copy": receipt["copies"].pop(1)
            elif mode == "missing-ack": receipt["copies"][3]["acknowledgement_digest"] = None
            elif mode == "shared-key": receipt["keys"][0]["shared"] = True
            elif mode == "no-destruction": source.inventory = replace(source.inventory, key_destructions={})
            elif mode == "relabeled": receipt["copies"][2]["disposition"] = "deleted"
            elif mode == "incomplete":
                receipt["inventory_complete"] = False
                source.inventory = replace(source.inventory, inventory_complete=False)
            elif mode == "scope": receipt["subject_scope_digest"] = h.digest({"other": True}, 2)
            else: receipt["copies"][0]["verification_digest"] = h.digest({"weak": True}, 2)
            with self.subTest(mode=mode):
                self.assertEqual(verify(verifier, receipt).reason, "ERASURE_INVALID")

    def test_retention_and_overdue_retention_remain_partial(self):
        for deadline in (999, 1100):
            receipt, source, verifier = install()
            exception = dict(exception_id="exception-1", purpose_id="security-audit",
                             access_policy_digest=h.digest({"restricted": True}, 2), delete_by=deadline,
                             authorization_digest=h.digest({"approved": True}, 2))
            receipt["copies"][2].update(disposition="retained", retention=exception)
            receipt["status"] = "partial"
            source.inventory = replace(source.inventory, retention_authorizations={"backup": h.digest(exception, 2)})
            result = verify(verifier, receipt)
            self.assertEqual(result.status, "partial")
            self.assertEqual(result.overdue_retention_copy_ids, ("backup",) if deadline <= NOW else ())
            receipt["copies"][2]["retention"]["purpose_id"] = "marketing"
            self.assertEqual(verify(verifier, receipt).reason, "ERASURE_INVALID")

    def test_reindexed_inventory_still_requires_recipients_and_all_keys(self):
        for mode in ("recipient", "second-key", "incomplete"):
            receipt, source, verifier = install()
            for index in range(4): erase(source, index, crypto=index == 2)
            if mode == "recipient": receipt["copies"].pop(3)
            elif mode == "second-key":
                receipt["keys"].append(dict(key_id="key-2", shared=False, disposition="active", destruction_digest=None))
                receipt["copies"][2]["key_ids"].append("key-2")
            else:
                receipt.update(inventory_complete=False, status="partial")
            receipt["inventory_digest"] = h.digest(h.inventory_body(receipt), 2)
            source.inventory = replace(source.inventory, inventory_digest=receipt["inventory_digest"],
                                       inventory_complete=receipt["inventory_complete"])
            with self.subTest(mode=mode):
                result = verify(verifier, receipt)
                self.assertEqual(result.reason, "ERASURE_ACCOUNTING_VERIFIED" if mode == "incomplete" else "ERASURE_INVALID")
                if mode == "incomplete": self.assertEqual(result.status, "partial")

    def test_receipt_tokens_unknown_fields_and_future_cutoff_fail(self):
        for mode in ("bool", "float", "duplicate-id", "extra", "future"):
            receipt, source, verifier = install()
            if mode == "bool": receipt["inventory_version"] = True
            elif mode == "float": receipt["inventory_version"] = 3.5
            elif mode == "duplicate-id": receipt["copies"].append(copy.deepcopy(receipt["copies"][0]))
            elif mode == "extra": receipt["clear_revocation"] = True
            else:
                receipt["scope_cutoff"] = NOW + 1
                receipt["inventory_digest"] = h.digest(h.inventory_body(receipt), 2)
                source.inventory = replace(source.inventory, scope_cutoff=NOW+1, inventory_digest=receipt["inventory_digest"])
            with self.subTest(mode=mode): self.assertEqual(verify(verifier, receipt).reason, "ERASURE_INVALID")

    def test_current_context_clock_and_availability(self):
        receipt, source, verifier = install()
        self.assertEqual(verifier.verify(h.canonical(receipt), now=NOW, clock_healthy=False).reason, "ERASURE_UNAVAILABLE")
        self.assertEqual(source.calls, [])
        source.unavailable = True
        self.assertEqual(verify(verifier, receipt).reason, "ERASURE_UNAVAILABLE")
        source.unavailable = False
        source.inventory = replace(source.inventory, checked_at=NOW-1)
        self.assertEqual(verify(verifier, receipt).reason, "ERASURE_INVALID")
        source.inventory = replace(source.inventory, checked_at=NOW)
        source.context = dict(source.context, privacy_policy_digest=h.digest({"changed": True}, 2))
        self.assertEqual(verify(verifier, receipt).reason, "ERASURE_UNAVAILABLE")

    def test_raw_json_limits_and_no_mutation(self):
        receipt, source, verifier = install()
        before = copy.deepcopy(receipt)
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{}', b' ' * 262145):
            self.assertEqual(verifier.verify(raw, now=NOW, clock_healthy=True).reason, "ERASURE_INVALID")
        verify(verifier, receipt)
        self.assertEqual(receipt, before)
        with self.assertRaises(ValidationError): verifier.verify({}, now=NOW, clock_healthy=True)
