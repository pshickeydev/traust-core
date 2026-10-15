from __future__ import annotations

from decimal import Decimal
from typing import Protocol

from traust_core.v1.models.base import Dto
from traust_core.v1.models.operations import ModelName
from traust_core.v1.providers.base import Readiness


class ModelSpec(Dto): ...


class TokenUsage(Dto): ...


class ModelCatalog(Protocol):
    def check(self) -> Readiness: ...

    def resolve(self, name: ModelName) -> ModelSpec: ...

    def cost(self, model: ModelName, usage: TokenUsage) -> Decimal: ...
