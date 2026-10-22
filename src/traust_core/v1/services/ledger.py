from __future__ import annotations

import json
from dataclasses import replace
from typing import Any
from uuid import UUID

from traust_ledger._internal.integrity import (
    Severity,
    SigningConfig,
    canonical_event_bytes,
    sign_if_configured,
    stamp_merkle_metadata,
    verify_merkle_integrity,
    verify_merkle_signature,
)
from traust_ledger._internal.integrity.merkle import LEAF_FORMAT_CURRENT

from traust_core.v1.errors import NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.findings import Decision
from traust_core.v1.models.ledger import (
    AppendReceipt,
    Checkpoint,
    Event,
    Layer,
    Signing,
    VerifyResult,
)
from traust_core.v1.repositories.traust_ledger import LedgerUnitOfWork

_MERKLE = (
    "merkle_root",
    "merkle_epoch",
    "merkle_size",
    "merkle_root_signature",
    "merkle_signing_method",
    "merkle_signature_format",
)


class LedgerService:
    """Proof that decisions weren't changed: traust-ledger computes, these tables store.

    Optional: decisions live in the decision table either way. Share the caller's unit of
    work to append in the decision's transaction.
    """

    def __init__(
        self,
        uow: LedgerUnitOfWork,
        signing: SigningConfig,
        *,
        public_key_path: str | None = None,
        signing_required: bool = False,
    ) -> None:
        self._uow = uow
        self._signing = signing
        self._public_key_path = public_key_path
        self._signing_required = signing_required

    def append_decision(self, decision: Decision, repository_id: UUID) -> AppendReceipt:
        """Append the decision's event to the repository layer, then restamp and sign it."""
        if decision.id is None:
            raise ValidationError("ledger: append a saved decision")
        with self._uow:
            layer = self._uow.layers.find_for_update(repository_id) or self._uow.layers.add(
                Layer(repository_id=repository_id, merkle_signing_method=self._signing.method)
            )
            assert layer.id is not None
            event = self._uow.events.find_by_decision(decision.id)
            if event is None:
                last = self._uow.events.last_seq(layer.id)
                event = self._uow.events.add(
                    Event(
                        layer_id=layer.id,
                        decision_id=decision.id,
                        seq=0 if last is None else last + 1,
                        event_payload=canonical_event_bytes(decision.model_dump(mode="json")),
                    )
                )
            checkpoint = self._finalize(layer)
            self._uow.commit()
        return AppendReceipt(event=event, checkpoint=checkpoint)

    def checkpoint(self, repository_id: UUID) -> Checkpoint:
        """Restamp and sign the repository layer, e.g. once a signing key is configured."""
        with self._uow:
            layer = self._uow.layers.find_for_update(repository_id)
            if layer is None:
                raise NotFoundError(f"ledger layer for repository {repository_id}")
            checkpoint = self._finalize(layer)
            self._uow.commit()
        return checkpoint

    def verify(self, layer_id: UUID) -> VerifyResult:
        """Recompute the layer's root from its stored events and check the signature."""
        with self._uow:
            document = self._document(self._uow.layers.get(layer_id))
        issues = [
            *verify_merkle_integrity(document),
            *verify_merkle_signature(document, self._public_key_path),
        ]
        return VerifyResult(
            layer_id=layer_id,
            errors=tuple(i.message for i in issues if i.severity is Severity.ERROR),
            warnings=tuple(i.message for i in issues if i.severity is not Severity.ERROR),
        )

    def _finalize(self, layer: Layer) -> Checkpoint:
        document = self._document(layer)
        dropped = stamp_merkle_metadata(document)
        attempt = sign_if_configured(document, self._signing)
        if dropped and attempt.status != Signing.SIGNED:
            attempt = replace(attempt, stale_signature_dropped=True)
        signing = Signing(attempt.status)
        if self._signing_required and signing is not Signing.SIGNED:
            raise ServiceError(f"ledger: layer {layer.id} not signed ({attempt.error or signing})")
        meta = document["metadata"]
        meta.setdefault("merkle_signing_method", layer.merkle_signing_method)  # NOT NULL column
        saved = self._uow.layers.update(layer.model_copy(update={k: meta.get(k) for k in _MERKLE}))
        return Checkpoint(layer=saved, signing=signing, warning=attempt.warning())

    def _document(self, layer: Layer) -> dict[str, Any]:
        assert layer.id is not None
        meta = {k: v for k in _MERKLE if (v := getattr(layer, k)) is not None}
        meta["leaf_format"] = LEAF_FORMAT_CURRENT  # the only format core writes; not a column
        events = [json.loads(e.event_payload) for e in self._uow.events.list_for_layer(layer.id)]
        return {"events": events, "metadata": meta}
