"""RemediationSchedulingService over SQLite and Postgres: the door that starts the pipeline,
and the status sync that keeps the remediation row beside the decisions that move it."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_remediation import provenance, report
from tests.v1.services.test_verification import World, audited
from tests.v1.services.test_verification import provenance as verification_provenance
from tests.v1.services.test_verification import report as verification_report
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import ProcessConfig
from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import OrderState
from traust_core.v1.models.remediation_scheduling import RemediationFindingRequest
from traust_core.v1.models.vocabulary import ActorKind, RemediationStatus
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.remediation import RemediationConfig
from traust_core.v1.services.remediation_scheduling import (
    REMEDIATE_FINDING,
    RemediationSchedulingService,
)

FORK = "https://github.com/example-mirrors/example-service"
BRANCH = "fix/1f0e8dad-e8d3-4c1e-9a1a-8b2f6b0d1b7c/title"
GIT = ProcessConfig(allowed_binaries=("git",))
PRIVATE = RemediationConfig(fork_org="mirror-org")
PERSON = Principal(identity="analyst@example.com", kind=ActorKind.HUMAN, display="Analyst")


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path, remediation=PRIVATE, process=GIT))
    ctx.__dict__["database"] = engine
    return ctx


@pytest.fixture
def service(context: Context) -> RemediationSchedulingService:
    return context.services().remediation_scheduling


def seeded(
    engine: Engine, *, findings: int = 1, **finding: Any
) -> tuple[UUID, list[UUID], list[UUID]]:
    """A repository on its default branch and confirmed, open findings on it."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}")
        seed.repository_ref(repo, is_default=True)
        made = [seed.finding(repo, **finding) for _ in range(findings)]
        for f in made:
            seed.decision(
                f, validity="confirmed", severity="high", actor="human:analyst@example.com"
            )
        uow.commit()
        return repo.id, [f.id for f in made], [f.repository_id for f in made]  # type: ignore[misc]


def pairs(finding_ids: list[UUID], repository_ids: list[UUID]) -> list[RemediationFindingRequest]:
    return [
        RemediationFindingRequest(finding_id=f, repository_id=r)
        for f, r in zip(finding_ids, repository_ids, strict=True)
    ]


def row(engine: Engine, remediation_id: UUID | None) -> Any:
    assert remediation_id is not None
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.remediations.get(remediation_id)


def queued_orders(engine: Engine, repository_id: UUID) -> list[Any]:
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.run_orders.list_for_repository(repository_id, OrderState.QUEUED)


def default_ref(engine: Engine, repository_id: UUID) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        return next(r.id for r in uow.repository_refs.list_for(repository_id) if r.is_default)  # type: ignore[arg-type]


# create


def test_create_schedules_the_row_the_findings_the_work_item_and_the_order(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine, findings=2)
    scheduled = service.create(FORK, BRANCH, pairs(finding_ids, repository_ids), PERSON)
    assert (scheduled.fork_url, scheduled.fork_branch, scheduled.status) == (
        FORK,
        BRANCH,
        "candidate",
    )
    detail = service.get(scheduled.id)
    assert {(f.finding_id, f.repository_id) for f in detail.findings} == set(
        zip(finding_ids, repository_ids, strict=True)
    )
    assert detail.assessment is not None
    assert detail.assessment.status == "candidate"
    assert detail.assessment.finding_ids == tuple(sorted(finding_ids, key=str))
    assert context.services().remediation.get(detail.assessment.work_item_id) == detail.assessment
    (order,) = queued_orders(engine, repository_id)
    assert (order.asset, order.repository_id, order.state, order.requested_by) == (
        REMEDIATE_FINDING,
        repository_id,
        "queued",
        "human:analyst@example.com",
    )


def test_create_schedules_the_same_findings_once(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine, findings=2)
    request = pairs(finding_ids, repository_ids)
    first = service.create(FORK, BRANCH, request + request, PERSON)  # a retried pair is a no-op
    assert service.create(FORK, BRANCH, list(reversed(request)), PERSON) == first
    assert len(queued_orders(engine, repository_id)) == 1
    assert service.list() == [first]


def test_create_refuses_what_it_cannot_schedule(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    repository_id, finding_ids, _ = seeded(engine, findings=2)
    _, elsewhere, elsewhere_repos = seeded(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = uow.repositories.get(repository_id)
        closed = seed.finding(repo, fingerprint="fp-closed")
        seed.decision(closed, validity="confirmed", severity="high", actor="human:a@example.com")
        seed.decision(closed, resolution="resolved", validity=None, actor="human:a@example.com")
        uow.commit()
    cases = [
        ([], "at least one finding"),
        ([(finding_ids[0], elsewhere_repos[0])], "is not in repository"),
        ([(closed.id, repository_id)], "is closed"),
        ([(finding_ids[0], repository_id), (elsewhere[0], elsewhere_repos[0])], "one repository"),
    ]
    for finding_pairs, message in cases:
        request = [
            RemediationFindingRequest(finding_id=f, repository_id=r) for f, r in finding_pairs
        ]
        with pytest.raises(ValidationError, match=message):
            service.create(FORK, BRANCH, request, PERSON)
    with pytest.raises(NotFoundError, match="findings"):
        service.create(
            FORK,
            BRANCH,
            [RemediationFindingRequest(finding_id=uuid4(), repository_id=repository_id)],
            PERSON,
        )
    assert service.list() == []


def test_create_refuses_a_fork_that_is_not_https_or_a_branch_git_would_reject(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    _, finding_ids, repository_ids = seeded(engine)
    request = pairs(finding_ids, repository_ids)
    for fork in ("http://github.com/example-mirrors/example-service", "github.com/x/y", "https://"):
        with pytest.raises(ValidationError, match="repo url"):
            service.create(fork, BRANCH, request, PERSON)
    for branch in (
        "",
        "-leading-dash",
        "a..b",
        "a//b",
        "/leading",
        "trailing/",
        "ends.lock",
        "a~b",
        "a^b",
        "a:b",
        "a?b",
        "a*b",
        "a[b",
        "a\\b",
        "@",
        "a@{b",
        "a b",
    ):
        with pytest.raises(ValidationError, match="fork_branch"):
            service.create(FORK, branch, request, PERSON)
    assert service.list() == []


def test_create_needs_the_repositorys_default_line_to_patch(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/bare-{uuid4().hex[:8]}")
        finding = seed.finding(repo)
        seed.decision(
            finding, validity="confirmed", severity="high", actor="human:analyst@example.com"
        )
        uow.commit()
        repository_id, finding_id = repo.id, finding.id
    with pytest.raises(ValidationError, match="no single default ref"):
        service.create(
            FORK,
            BRANCH,
            [RemediationFindingRequest(finding_id=finding_id, repository_id=repository_id)],
            PERSON,
        )


# get, list


def test_get_and_list_filter_the_scheduled_efforts(
    service: RemediationSchedulingService, engine: Engine
) -> None:
    repository_id, finding_ids, repository_ids = seeded(engine, findings=2)
    other_repository, other_findings, other_repos = seeded(engine)
    first = service.create(FORK, BRANCH, pairs(finding_ids[:1], repository_ids[:1]), PERSON)
    second = service.create(FORK, BRANCH, pairs(finding_ids[1:], repository_ids[1:]), PERSON)
    third = service.create(FORK, BRANCH, pairs(other_findings, other_repos), PERSON)
    assert service.list() == [first, second, third]
    assert service.list(repository_id=repository_id) == [first, second]
    assert service.list(finding_id=finding_ids[0]) == [first]
    assert service.list(repository_id=other_repository) == [third]
    assert service.list(status=RemediationStatus("candidate")) == [first, second, third]
    assert service.list(status=RemediationStatus("merged")) == []
    detail = service.get(second.id)
    assert detail.remediation == second
    assert [f.finding_id for f in detail.findings] == [finding_ids[1]]
    with pytest.raises(NotFoundError):
        service.get(uuid4())


# status sync


def test_record_progress_moves_the_scheduled_row_with_the_work_item(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    _, finding_ids, repository_ids = seeded(engine)
    scheduled = service.create(FORK, BRANCH, pairs(finding_ids, repository_ids), PERSON)
    remediation = context.services().remediation
    remediation.record_progress(scheduled.assessment_id, RemediationStatus("forked"))
    assert row(engine, scheduled.id).status == "forked"
    remediation.record_progress(scheduled.assessment_id, RemediationStatus("patched"))
    assert row(engine, scheduled.id).status == "patched"
    with pytest.raises(ConflictError, match="can't move"):
        remediation.record_progress(scheduled.assessment_id, RemediationStatus("candidate"))


def test_record_moves_the_scheduled_row_with_the_report(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    _, finding_ids, repository_ids = seeded(engine)
    scheduled = service.create(FORK, BRANCH, pairs(finding_ids, repository_ids), PERSON)
    done = context.services().remediation.record(report(finding_ids), provenance())
    assert done.status == "checks_passed"
    assert row(engine, scheduled.id).status == "checks_passed"


def test_work_items_without_a_scheduled_effort_record_as_before(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    repository_id, finding_ids, _ = seeded(engine)
    remediation = context.services().remediation
    item = remediation.open(finding_ids, default_ref(engine, repository_id))
    remediation.record_progress(item.work_item_id, RemediationStatus("forked"))
    done = remediation.record(report(finding_ids), provenance())
    assert (done.status, service.list()) == ("checks_passed", [])


def test_a_verification_revalidates_the_scheduled_row(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, patched_name="main")
    audited(engine, world, world.base)
    scheduled = service.create(
        FORK, BRANCH, pairs(world.ids, [world.repo.id] * len(world.ids)), PERSON
    )
    fixed = context.services().verification.record(
        verification_report(world), verification_provenance()
    )
    assert fixed.verdicts
    assert row(engine, scheduled.id).status == "revalidated_fixed"


def test_a_verification_that_leaves_a_finding_open_marks_the_effort_still_vulnerable(
    service: RemediationSchedulingService, context: Context, engine: Engine
) -> None:
    world = World(engine, findings=2, patched_name="main")
    audited(engine, world, world.base)
    scheduled = service.create(
        FORK, BRANCH, pairs(world.ids, [world.repo.id] * len(world.ids)), PERSON
    )
    got = context.services().verification.record(
        verification_report(world, {world.ids[0]: "resolved", world.ids[1]: "unresolved"}),
        verification_provenance(),
    )
    assert len(got.verdicts) == 2
    assert row(engine, scheduled.id).status == "revalidated_still_vulnerable"
