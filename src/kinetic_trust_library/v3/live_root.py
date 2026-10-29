"""Current-use External Root verification through installed source boundaries.

The inventory resolver authenticates completeness, currentness and scope of the
entire required candidate set. The instrument verifier separately authenticates
instruments, witnesses, current inputs and lifecycle history. A timestamp or
inventory label alone establishes none of these facts. Products fence this
state with protected effects; these results grant no execution permission.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError, ProofFormatError
from .installed_root import InstalledRootVerifier
from .assessed_root_selection import AssessedRootSelection, select_assessed_roots
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time


class RootInventoryUnavailable(Exception):
    """The installed source cannot establish a current complete inventory."""


@dataclass(frozen=True, slots=True)
class AuthenticatedRootInventory:
    complete_instruments: tuple[bytes, ...]
    evidence_bytes: bytes
    context_bytes: bytes
    checked_at: int
    no_credit_reason: str = "missing"


@dataclass(frozen=True, slots=True, init=False)
class RootProofVerificationResult:
    reason: str
    checked_at: int
    context_bytes: bytes
    inventory_evidence_bytes: bytes | None
    selection: AssessedRootSelection | None
    payload_bytes: bytes

    def __init__(self,*args,**kwargs):
        raise TypeError("current root results are derived by an installed verifier")

    @property
    def valid(self):
        return self.reason=="ROOT_CURRENT"


@dataclass(frozen=True, slots=True)
class InstalledLiveRootVerifier:
    instrument_verifier: InstalledRootVerifier
    inventory_source: object
    context_bytes: bytes
    expected_zone: str

    def __post_init__(self):
        if (type(self.instrument_verifier) is not InstalledRootVerifier or type(self.context_bytes) is not bytes
                or type(self.expected_zone) is not str or not self.expected_zone
                or not callable(getattr(self.inventory_source,"resolve",None))):
            raise ValidationError("installed current root verifier is invalid")
        context=_parse_jcs_object(self.context_bytes)
        if context.get("subject_profile") not in ("software","person") or type(context.get("subject")) is not str:
            raise ValidationError("current root source subject class/scope is invalid")

    def __call__(self, payload_bytes: bytes, now: int) -> RootProofVerificationResult:
        return self.evaluate(payload_bytes,evaluated_at=now)

    def evaluate(self, payload_bytes: bytes, *, evaluated_at: int) -> RootProofVerificationResult:
        from .native_proof_profile import RootProofBinding
        if type(payload_bytes) is not bytes or not _time(evaluated_at):
            raise ValidationError("current root verification requires immutable claims and trusted time")
        inventory_evidence=None
        selection=None
        def result(reason):
            value=object.__new__(RootProofVerificationResult)
            for name,member in (("reason",reason),("checked_at",evaluated_at),("context_bytes",self.context_bytes),
                ("inventory_evidence_bytes",inventory_evidence),("selection",selection)):
                object.__setattr__(value,name,member)
            object.__setattr__(value,"payload_bytes",payload_bytes)
            return value
        try:
            inventory=self.inventory_source.resolve(context_bytes=self.context_bytes,evaluated_at=evaluated_at)
        except RootInventoryUnavailable:
            return result("ROOT_UNAVAILABLE")
        if (type(inventory) is not AuthenticatedRootInventory or type(inventory.complete_instruments) is not tuple
                or any(type(raw) is not bytes for raw in inventory.complete_instruments)
                or type(inventory.evidence_bytes) is not bytes or not inventory.evidence_bytes
                or type(inventory.context_bytes) is not bytes or inventory.context_bytes!=self.context_bytes
                or not _time(inventory.checked_at) or inventory.checked_at!=evaluated_at
                or type(inventory.no_credit_reason) is not str):
            return result("ROOT_UNAVAILABLE")
        inventory_evidence=inventory.evidence_bytes
        candidates=tuple(self.instrument_verifier.evaluate(raw,context_bytes=self.context_bytes,evaluated_at=evaluated_at)
            for raw in inventory.complete_instruments)
        selection=select_assessed_roots(candidates,context_bytes=self.context_bytes,evaluated_at=evaluated_at,
            algorithm=self.instrument_verifier.algorithm)
        try:
            valid=RootProofBinding(selection,self.expected_zone,inventory.no_credit_reason)(payload_bytes,evaluated_at)
        except (ValidationError,ProofFormatError,KeyError,TypeError,ValueError):
            valid=False
        return result("ROOT_CURRENT" if valid else "ROOT_INVALID")


__all__=["InstalledLiveRootVerifier","AuthenticatedRootInventory","RootProofVerificationResult","RootInventoryUnavailable"]
