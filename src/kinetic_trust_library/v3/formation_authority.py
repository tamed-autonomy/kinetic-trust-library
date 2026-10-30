"""Pure relation-formation authority checks against authenticated Source facts.

Source establishes actual identity, signatures, anchors and complete objection
history. This projection neither authenticates those facts nor mints/revokes a
lease. An unresolved formation objection requires a new classified formation;
this selected record model provides no implicit objection-resolution flag.
"""
from dataclasses import dataclass, field

from kinetic_trust_library.errors import ValidationError
from .execution_observation import _name, _digest
from .root_lifecycle import _time


@dataclass(frozen=True, slots=True)
class FormationAuthorityProjection:
    direct_revocation: bool
    suspend_required: bool
    human_classification_required: bool
    identity_assurance_required: bool
    minting_suspended: bool
    action_permitted: bool = field(default=False, init=False)


def project_formation_authority(*,subject,relation_id,consequence_class,principal,
                                claimant,template_digest,grant_issued_at,evaluated_at,formation):
    """Bind formation witness to this relation, template, class and grant.

    Times use this private adapter's explicit integer-second profile. Missing
    witnesses produce contest obligations; malformed or contradictory supplied
    witnesses are errors, never an alternate source of direct authority.
    """
    if (any(not _name(v) for v in (subject,relation_id,principal,claimant))
            or consequence_class not in ("Logistics","Coordination","Relational")
            or not _digest(template_digest) or not _time(grant_issued_at)
            or not _time(evaluated_at) or grant_issued_at>evaluated_at):
        raise ValidationError("invalid actual formation authority inputs")
    witnessed=False;objected=False
    if formation is not None:
        f=formation
        if (type(f) is not dict or set(f)!={"subject","relation_id","consequence_class","template_digest",
                "counterparty","registered_at","formed_at","countersigned_at","witness_anchor",
                "countersignature_anchor","objection_at"}
                or any(f[k]!=v for k,v in (("subject",subject),("relation_id",relation_id),
                    ("consequence_class",consequence_class),("template_digest",template_digest)))
                or any(not _name(f[k]) for k in ("counterparty","witness_anchor","countersignature_anchor"))
                or any(not _time(f[k]) for k in ("registered_at","formed_at","countersigned_at"))
                or not f["registered_at"]<=f["formed_at"]<=f["countersigned_at"]<=grant_issued_at
                or f["objection_at"] is not None and (not _time(f["objection_at"])
                    or not f["formed_at"]<=f["objection_at"]<=evaluated_at)):
            raise ValidationError("formation witness differs from actual relation/template/grant")
        witnessed=claimant==f["counterparty"] and consequence_class=="Relational"
        objected=f["objection_at"] is not None
    # An objection blocks grant formation, but does not take away the issuing
    # principal's independent ability to revoke an already issued grant.
    direct=claimant==principal or witnessed and not objected
    contest=not direct
    return FormationAuthorityProjection(direct,contest,contest or objected,
                                        contest and not witnessed,objected)
