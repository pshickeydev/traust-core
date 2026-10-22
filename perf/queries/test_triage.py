"""3a/3b · A triage's input at a year's volume: one assessment's findings and their locations."""

from __future__ import annotations

from datetime import UTC, datetime

from perf.harness import Profile
from perf.queries.test_findings import reads
from perf.queries.test_ledger import fast
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.lint import Lint


def prepare(uow: SqlTraustUnitOfWork) -> None:
    repo = uow.repositories.find_by_url("https://forge.example/org/r2")
    assert repo is not None and repo.id is not None
    scan = next(
        a for r in uow.repository_refs.list_for(repo.id) for a in uow.assessments.list_for_ref(r.id)
    )
    FindingDecisions(uow, None, Lint({}), clock=FixedClock(datetime.now(UTC))).prepare(scan.id)


def test_prepare_reads_each_table_once_by_index(explained: Profile) -> None:
    *_, assessment, ref, repository, occurrences, findings, locations = reads(explained(prepare))
    fast(assessment, "assessment_pkey", 1)
    fast(ref, "repository_ref_id_repository_id_key", 1)
    fast(repository, "repository_pkey", 1)
    fast(occurrences, "idx_occurrence_assessment", 1)
    fast(findings, "finding_pkey", 2)
    fast(locations, "uq_location_range", 2)
    fast(locations, "uq_location_file", 2)
