from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.base import Dto
from traust_core.v1.models.validation import PlanStep, ValidationScope
from traust_core.v1.providers.base import Readiness, Result


class StepResult(Dto): ...


class ValidationAdapter(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def execute(self, step: PlanStep, scope: ValidationScope) -> Result[StepResult]: ...
