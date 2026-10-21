from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from traust_core.v1.models.artifacts import ArtifactDocument
from traust_core.v1.models.base import Model


# Shapes land with the first Lint rule set (triage citation gate).
class LintRuleId(Model): ...


class LintContext(Model): ...


class Violation(Model): ...


class LintReport(Model): ...


class LintRule(Protocol):
    id: LintRuleId

    def check(self, subject: ArtifactDocument, context: LintContext) -> list[Violation]: ...


class Lint:
    def __init__(self, rules: Mapping[type[ArtifactDocument], Sequence[LintRule]]) -> None:
        self._rules = rules

    def run(self, subject: ArtifactDocument, context: LintContext) -> LintReport:
        raise NotImplementedError(
            "stub: replaces check_citations, lint_verdict_citations,"
            " validate_compliance_assessment, validate_isolation_review,"
            " rbac_bucket_proposal_check, reporting/lint.py"
        )
