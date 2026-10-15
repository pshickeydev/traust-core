from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.assessment import Permission
from traust_core.v1.models.compliance import ComplianceTarget, InventorySnapshot
from traust_core.v1.models.validation import ClusterScope, ClusterSnapshot
from traust_core.v1.providers.base import Readiness, Result


class ClusterProvider(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def snapshot(self, scope: ClusterScope) -> Result[ClusterSnapshot]: ...

    def privileges(self, scope: ClusterScope) -> Result[list[Permission]]: ...


class CloudInventoryProvider(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def collect(self, targets: list[ComplianceTarget]) -> Result[InventorySnapshot]: ...
