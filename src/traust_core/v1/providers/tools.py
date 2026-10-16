from __future__ import annotations

from pathlib import Path
from typing import Protocol, TypeVar

from traust_core.v1.models.base import Dto
from traust_core.v1.models.code_facts import CodeFactDetail, CodeFactKind
from traust_core.v1.providers.base import Readiness, Result

Res = TypeVar("Res", covariant=True)


class ToolRequest(Dto):
    workspace: Path


class ToolProvider(Protocol[Res]):
    name: str

    def check(self) -> Readiness: ...

    def acquire(self, request: ToolRequest) -> Result[Res]: ...


class FactEnumerator(Protocol):
    kind: CodeFactKind

    def check(self) -> Readiness: ...

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]: ...
