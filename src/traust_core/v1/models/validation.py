from __future__ import annotations

from datetime import datetime
from uuid import UUID

from traust_core.v1.models.base import Entity, Model
from traust_core.v1.models.findings import EvidenceRef, SkillInput
from traust_core.v1.models.vocabulary import (
    ValidationAdapterKind,
    ValidationApprovalMode,
    ValidationTechnique,
    ValidationVerdict,
)


# Shapes land with their implementation slice.
class ValidationAction(Model): ...


class ClusterScope(Model): ...


class OffLimit(Model): ...


class BrowserTarget(Model): ...


class ValidationTarget(Model): ...


class PlanStep(Model): ...


class RefusalReason(Model): ...


class SoundnessResult(Model): ...


class ResourceState(Model): ...


class ClusterDiff(Model): ...


class FindingChain(Model): ...


class Authorization(Model): ...


class TargetObservation(Model): ...


class TargetAttestation(Model): ...


class ValidationRun(Model): ...


class ValidationFilter(Model): ...


class ValidationDimension(Model): ...


class ValidationRollup(Model): ...


class ValidationInput(SkillInput): ...


class ValidationScope(Model):
    actions: frozenset[ValidationAction] = frozenset()
    clusters: tuple[ClusterScope, ...] = ()
    off_limits: tuple[OffLimit, ...] = ()
    browser: tuple[BrowserTarget, ...] = ()

    def permits(self, action: ValidationAction, target: ValidationTarget) -> bool:
        raise NotImplementedError("stub: replaces validation/scope.py x2, browser scope.py")


class ValidationPlan(Entity):
    finding_id: UUID
    target: ValidationTarget
    technique: ValidationTechnique
    adapter: ValidationAdapterKind
    approval_mode: ValidationApprovalMode
    steps: tuple[PlanStep, ...] = ()
    refusal: RefusalReason | None = None

    def requires_approval(self) -> bool:
        raise NotImplementedError("stub: replaces validate-findings approval mode")


class ValidationAttempt(Entity):
    plan_id: UUID
    verdict: ValidationVerdict
    evidence: tuple[EvidenceRef, ...] = ()
    started_at: datetime
    finished_at: datetime

    def soundness(self) -> SoundnessResult:
        raise NotImplementedError("stub: replaces soundness.py x2, lint_refutation_soundness.py")


class ClusterSnapshot(Model):
    taken_at: datetime
    resources: tuple[ResourceState, ...] = ()

    def diff(self, other: ClusterSnapshot) -> ClusterDiff:
        raise NotImplementedError("stub: replaces cluster_state_diff.diff")
