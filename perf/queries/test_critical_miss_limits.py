from __future__ import annotations

from datetime import UTC, datetime

import pytest

from perf.harness import Profile
from perf.seed import HOT_REPOSITORY
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import RecordBudget, TimeWindow
from traust_core.v1.models.findings import FindingLabel
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog


@pytest.mark.parametrize(
    "query",
    [
        "window",
        "findings",
        "decisions",
        "finding-cwes",
        "cwes",
        "labels",
        "occurrences",
        "assessment-occurrences",
        "locations",
        "refs",
        "repositories-refs",
        "assessments",
        "refs-assessments",
    ],
)
def test_critical_miss_input_queries_refuse_overflow_at_volume(
    explained: Profile, query: str
) -> None:
    def read(uow: SqlTraustUnitOfWork) -> None:
        repository = uow.repositories.find_by_url(HOT_REPOSITORY)
        assert repository is not None and repository.id is not None
        findings = uow.findings.list_for_repository(repository.id)
        all_ids = [finding.id for finding in findings if finding.id is not None]
        occurrences = uow.occurrences.list_for_findings(all_ids)[:20]
        finding_ids = {occurrence.finding_id for occurrence in occurrences}
        occurrence_ids = [occurrence.id for occurrence in occurrences if occurrence.id is not None]
        assessment_ids = {occurrence.assessment_id for occurrence in occurrences}
        refs = uow.repository_refs.list_for(repository.id)
        ref_ids = [ref.id for ref in refs if ref.id is not None]
        links = uow.finding_cwes.list_for_findings(finding_ids)
        if query == "labels":
            for n in range(3):
                uow.finding_labels.add(
                    FindingLabel(
                        finding_id=occurrences[0].finding_id, taxonomy="perf", label=str(n)
                    )
                )
        budget = RecordBudget(1, "critical misses")
        with pytest.raises(ValidationError):
            match query:
                case "window":
                    AssessmentLog(uow).list_within(
                        TimeWindow(
                            start=datetime(2000, 1, 1, tzinfo=UTC),
                            end=datetime(2100, 1, 1, tzinfo=UTC),
                        ),
                        read_budget=budget,
                    )
                case "findings":
                    uow.findings.list_by_ids(finding_ids, read_budget=budget)
                case "decisions":
                    uow.decisions.list_for_findings(finding_ids, read_budget=budget)
                case "finding-cwes":
                    uow.finding_cwes.list_for_findings(finding_ids, read_budget=budget)
                case "cwes":
                    uow.cwes.list_by_ids({link.cwe_id for link in links}, read_budget=budget)
                case "labels":
                    uow.finding_labels.list_for_findings(finding_ids, read_budget=budget)
                case "occurrences":
                    uow.occurrences.list_for_findings(finding_ids, read_budget=budget)
                case "assessment-occurrences":
                    uow.occurrences.list_for_assessment(
                        occurrences[0].assessment_id, read_budget=budget
                    )
                case "locations":
                    uow.locations.list_for_occurrences(occurrence_ids, read_budget=budget)
                case "refs":
                    uow.repository_refs.list_for(repository.id, read_budget=budget)
                case "repositories-refs":
                    uow.repository_refs.list_for_repositories([repository.id], read_budget=budget)
                case "assessments":
                    uow.assessments.list_by_ids(assessment_ids, read_budget=budget)
                case "refs-assessments":
                    uow.assessments.list_for_refs(ref_ids, read_budget=budget)

    *_, limited = explained(read)
    assert limited.execution_ms < 100, limited.plan
