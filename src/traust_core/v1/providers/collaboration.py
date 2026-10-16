from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.attestation import Comment
from traust_core.v1.models.base import Dto
from traust_core.v1.models.remediation import ExternalRef
from traust_core.v1.providers.base import Readiness, Result


class TrackerIssue(Dto): ...


class ProductDocument(Dto): ...


class CommentSource(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def comments(self, ref: ExternalRef) -> Result[list[Comment]]: ...


class TrackerProvider(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def issues(self, ref: ExternalRef) -> Result[list[TrackerIssue]]: ...

    def link(self, issue: ExternalRef, target: ExternalRef) -> None: ...


class DocSource(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def fetch(self, product_id: UUID) -> Result[list[ProductDocument]]: ...
