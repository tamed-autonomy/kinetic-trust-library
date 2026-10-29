"""Private semantic delivery projection for Federation §6.5 (not a wire format).

The installed caller must authenticate a complete destination inventory scoped
to the actual subject, originating record and agreement. Coverage and historical
delivery are different facts: notification follows the latter. This pure helper
neither delivers records nor evaluates or closes receiving-zone standing.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError


@dataclass(frozen=True, slots=True)
class FederationDeliveryPlan:
    disposition: str
    required_destinations: tuple[str, ...]
    permitted_destinations: tuple[str, ...]
    blocked_destinations: tuple[str, ...]
    notification_payload: tuple[tuple[str, str], ...]
    closes_receiver_exposure: bool = False


def plan_federation_delivery(*, kind, subject_profile, breach_anchor,
                             reconciliation_anchor, destinations):
    """Plan mandatory exposure/notification delivery, without granting authority.

    For exposure the caller retains the authenticated breach/withdrawal record;
    this helper does not replace that record with an anchor. Only an anchoring
    notification has a generated payload, containing exactly its two anchors.
    A veto/delta/personal reconciliation record has no delivery route here.
    Positive standing attestations use the separately selected federation path.
    Agreement applicability includes the relevant same-terms and current
    acceptance/expiry assessment; it cannot be inferred from mere existence.
    """
    def identifier(value):return type(value) is str and bool(value)
    fields={"zone","agreement_applicable","standing_admitted","bond_ever_opened",
            "attestation_admitted","breach_previously_delivered","sovereignty_enforced"}
    if (kind not in ("breach","withdrawal-for-cause","reconciliation-anchored",
                     "silent-veto","soul-veto","delta","reconciliation-record")
            or type(kind) is not str or subject_profile not in ("software","person")
            or type(subject_profile) is not str or not identifier(breach_anchor)
            or type(destinations) is not tuple or len(destinations)>4096
            or kind=="reconciliation-anchored" and
                (not identifier(reconciliation_anchor) or reconciliation_anchor==breach_anchor)
            or kind!="reconciliation-anchored" and reconciliation_anchor is not None):
        raise ValidationError("invalid federation record delivery projection")
    seen=set();required=[];permitted=[];blocked=[]
    for item in destinations:
        if (type(item) is not dict or set(item)!=fields or not identifier(item["zone"])
                or item["zone"] in seen
                or any(type(item[name]) is not bool for name in fields-{"zone"})):
            raise ValidationError("invalid or duplicate federation destination evidence")
        seen.add(item["zone"])
        covered=(item["standing_admitted"] or item["bond_ever_opened"] or item["attestation_admitted"])
        selected=(item["breach_previously_delivered"] if kind=="reconciliation-anchored"
                  else covered if kind in ("breach","withdrawal-for-cause") else False)
        if not selected or not item["agreement_applicable"]:continue
        required.append(item["zone"])
        (permitted if item["sovereignty_enforced"] else blocked).append(item["zone"])
    disposition=("exposure" if kind in ("breach","withdrawal-for-cause") else
                 "anchor-notification" if kind=="reconciliation-anchored" else "none")
    payload=(("breach_anchor",breach_anchor),("reconciliation_anchor",reconciliation_anchor)) if kind=="reconciliation-anchored" else ()
    return FederationDeliveryPlan(disposition,tuple(sorted(required)),tuple(sorted(permitted)),
                                  tuple(sorted(blocked)),payload)
