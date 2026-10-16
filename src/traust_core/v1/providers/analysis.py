from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.exposure import Advisory, Dependency, ImpactEvidence
from traust_core.v1.providers.base import Readiness, Result
from traust_core.v1.providers.tools import ToolRequest


class DependencyExtractor(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def extract(self, request: ToolRequest) -> Result[list[Dependency]]: ...


class ImpactAnalyzer(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def evidence(
        self, advisory: Advisory, request: ToolRequest
    ) -> Result[list[ImpactEvidence]]: ...
