"""Deterministic synchronous and asynchronous Trust Proof provider spies."""

from __future__ import annotations

from kinetic_trust_library.models.proof import (
    KeyLookup,
    OracleSigningIdentity,
    SignatureVerificationOutcome,
)


class SpySigner:
    def __init__(
        self,
        identity: object,
        effect: object,
        *,
        events: list[str] | None = None,
    ) -> None:
        self._identity = identity
        self.effect = effect
        self.events = events if events is not None else []
        self.identity_reads = 0
        self.arguments: list[bytes] = []

    @property
    def identity(self) -> OracleSigningIdentity:
        self.identity_reads += 1
        self.events.append("signer.identity")
        if isinstance(self._identity, BaseException):
            raise self._identity
        return self._identity  # type: ignore[return-value]

    @property
    def calls(self) -> int:
        return len(self.arguments)

    def sign(self, signing_input: bytes, /) -> bytes:
        self.arguments.append(signing_input)
        self.events.append("signer.sign")
        if isinstance(self.effect, BaseException):
            raise self.effect
        return self.effect  # type: ignore[return-value]


class SpyKeySource:
    def __init__(self, effect: object, *, events: list[str] | None = None) -> None:
        self.effect = effect
        self.events = events if events is not None else []
        self.arguments: list[KeyLookup] = []

    @property
    def calls(self) -> int:
        return len(self.arguments)

    def resolve(self, lookup: KeyLookup, /) -> object:
        self.arguments.append(lookup)
        self.events.append("keys.resolve")
        if isinstance(self.effect, BaseException):
            raise self.effect
        return self.effect


class MutatingKeySource(SpyKeySource):
    def __init__(
        self,
        effect: object,
        *,
        changed_key_id: str,
        events: list[str] | None = None,
    ) -> None:
        super().__init__(effect, events=events)
        self.changed_key_id = changed_key_id

    def resolve(self, lookup: KeyLookup, /) -> object:
        self.arguments.append(lookup)
        self.events.append("keys.resolve")
        object.__setattr__(lookup, "key_id", self.changed_key_id)
        if isinstance(self.effect, BaseException):
            raise self.effect
        return self.effect


class SpyVerifier:
    def __init__(self, effect: object, *, events: list[str] | None = None) -> None:
        self.effect = effect
        self.events = events if events is not None else []
        self.arguments: list[dict[str, bytes]] = []

    @property
    def calls(self) -> int:
        return len(self.arguments)

    def verify(
        self,
        *,
        public_key: bytes,
        signing_input: bytes,
        signature: bytes,
    ) -> SignatureVerificationOutcome:
        self.arguments.append(
            {
                "public_key": public_key,
                "signing_input": signing_input,
                "signature": signature,
            }
        )
        self.events.append("verifier.verify")
        if isinstance(self.effect, BaseException):
            raise self.effect
        return self.effect  # type: ignore[return-value]


class AsyncSpySigner(SpySigner):
    def __init__(
        self,
        identity: object,
        effect: object,
        *,
        events: list[str] | None = None,
    ) -> None:
        super().__init__(identity, effect, events=events)
        self.body_entries = 0

    async def sign(self, signing_input: bytes, /) -> bytes:
        self.body_entries += 1
        self.arguments.append(signing_input)
        self.events.append("signer.sign")
        if isinstance(self.effect, BaseException):
            raise self.effect
        return self.effect  # type: ignore[return-value]


class AsyncSpyKeySource(SpyKeySource):
    def __init__(self, effect: object, *, events: list[str] | None = None) -> None:
        super().__init__(effect, events=events)
        self.body_entries = 0

    async def resolve(self, lookup: KeyLookup, /) -> object:
        self.body_entries += 1
        self.arguments.append(lookup)
        self.events.append("keys.resolve")
        if isinstance(self.effect, BaseException):
            raise self.effect
        return self.effect


class AsyncMutatingKeySource(AsyncSpyKeySource):
    def __init__(
        self,
        effect: object,
        *,
        changed_key_id: str,
        events: list[str] | None = None,
    ) -> None:
        super().__init__(effect, events=events)
        self.changed_key_id = changed_key_id

    async def resolve(self, lookup: KeyLookup, /) -> object:
        self.body_entries += 1
        self.arguments.append(lookup)
        self.events.append("keys.resolve")
        object.__setattr__(lookup, "key_id", self.changed_key_id)
        if isinstance(self.effect, BaseException):
            raise self.effect
        return self.effect


class AsyncSpyVerifier(SpyVerifier):
    def __init__(self, effect: object, *, events: list[str] | None = None) -> None:
        super().__init__(effect, events=events)
        self.body_entries = 0

    async def verify(
        self,
        *,
        public_key: bytes,
        signing_input: bytes,
        signature: bytes,
    ) -> SignatureVerificationOutcome:
        self.body_entries += 1
        self.arguments.append(
            {
                "public_key": public_key,
                "signing_input": signing_input,
                "signature": signature,
            }
        )
        self.events.append("verifier.verify")
        if isinstance(self.effect, BaseException):
            raise self.effect
        return self.effect  # type: ignore[return-value]
