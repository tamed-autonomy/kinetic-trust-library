"""Pure hand-back §6 lease/intent checks over authenticated semantic facts.

This does not authenticate a principal, mint/renew a lease, establish a valid
template, clear an action or consume a relational nonce. Callers install those
authorities and fence actual current registry/consumption state at commit.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time
from .execution_observation import _name,_digest as is_digest


@dataclass(frozen=True,slots=True,init=False)
class LeaseProjection:
    active: bool
    reason: str
    lease_id: str
    subject: str
    consequence_class: str
    issued_at: int
    expires_at: int | None
    single_use_required: bool
    nonce: str | None
    template_digest: str

    def __init__(self,*args,**kwargs):raise TypeError("lease projections require bound authenticated facts")


def project_lease(lease,intent,*,actual_actor,actual_operation_digest,actual_consequence_class,mutates_relation,
                  principal,lease_authority,template_digest,current_grant_epoch,principal_token_max_age_seconds,evaluated_at):
    """Check signed whole-action intent, authority, tempo and live grant state.

    Principal token freshness is tested at mint time; ordinary proof refresh
    never renews the independent lease. A relational grant has a single nonce,
    not a duration (including not a zero-length duration). No consumption occurs.
    """
    if (any(not _name(i) for i in (actual_actor,principal,lease_authority))
            or not is_digest(actual_operation_digest) or not is_digest(template_digest)
            or actual_consequence_class not in ("Logistics","Coordination","Relational") or type(mutates_relation) is not bool
            or mutates_relation and actual_consequence_class!="Relational" or not _time(current_grant_epoch)
            or not _time(principal_token_max_age_seconds) or principal_token_max_age_seconds==0 or not _time(evaluated_at)
            or type(lease) is not dict or set(lease)!={"id","issuer","subject","operation_digest","consequence_class","issued_at",
                "expires_at","kind","nonce","consumed","revoked","template_digest","principal_token_digest","grant_epoch"}
            or type(intent) is not dict or set(intent)!={"actor","operation_digest","consequence_class","principal","issued_at","expires_at","record_digest"}):
        raise ValidationError("complete installed lease/intent/context required")
    if (not _name(lease["id"]) or lease["issuer"]!=lease_authority or lease["subject"]!=actual_actor
            or lease["operation_digest"]!=actual_operation_digest or lease["consequence_class"]!=actual_consequence_class
            or not _time(lease["issued_at"]) or not _time(lease["grant_epoch"])
            or lease["template_digest"]!=template_digest or type(lease["consumed"]) is not bool or type(lease["revoked"]) is not bool
            or intent["actor"]!=actual_actor or intent["principal"]!=principal or intent["operation_digest"]!=actual_operation_digest
            or intent["consequence_class"]!=actual_consequence_class or not is_digest(intent["record_digest"])
            or lease["principal_token_digest"]!=intent["record_digest"] or not _time(intent["issued_at"]) or not _time(intent["expires_at"])
            or not intent["issued_at"]<=lease["issued_at"]<intent["expires_at"]
            or lease["issued_at"]-intent["issued_at"]>principal_token_max_age_seconds):
        raise ValidationError("lease differs from actual signed intent, authority, class or template")
    relational=actual_consequence_class=="Relational"
    if relational:
        if lease["kind"]!="single-use" or not _name(lease["nonce"]) or lease["expires_at"] is not None:
            raise ValidationError("relational grant must be a single-use nonce, never a duration")
    elif (lease["kind"]!="duration" or lease["nonce"] is not None or lease["consumed"] is not False
            or not _time(lease["expires_at"]) or not lease["issued_at"]<lease["expires_at"]
            or lease["expires_at"]-lease["issued_at"]>{"Logistics":259200,"Coordination":1800}[actual_consequence_class]):
        raise ValidationError("duration lease exceeds its class ceiling or has nonce state")
    reason=("LEASE_REVOKED" if lease["revoked"] else "LEASE_EPOCH_CHANGED" if lease["grant_epoch"]!=current_grant_epoch
            else "LEASE_CONSUMED" if lease["consumed"] else "LEASE_NOT_YET_ACTIVE" if evaluated_at<lease["issued_at"]
            else "LEASE_EXPIRED" if not relational and evaluated_at>=lease["expires_at"] else "LEASE_ACTIVE")
    result=object.__new__(LeaseProjection)
    for key,value in dict(active=reason=="LEASE_ACTIVE",reason=reason,lease_id=lease["id"],subject=actual_actor,
            consequence_class=actual_consequence_class,issued_at=lease["issued_at"],expires_at=lease["expires_at"],
            single_use_required=relational,nonce=lease["nonce"],template_digest=template_digest).items():object.__setattr__(result,key,value)
    return result
