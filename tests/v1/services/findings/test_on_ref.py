"""FindingService.on_ref on SQLite and Postgres: a named line's findings, folded on that line."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_reads import T0, engine, service  # noqa: F401
from traust_core.v1.errors import NotFoundError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

HUMAN = "human:alice@example.com"


def test_a_release_line_keeps_its_own_findings_and_its_own_resolution(
    engine: Engine,  # noqa: F811
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/org/{uuid4()}")
        main = seed.repository_ref(repo, name="main", sha="a" * 40, is_default=True)
        release = seed.repository_ref(repo, name="release-1", sha="b" * 40)
        patched = seed.repository_ref(repo, name="release-1", sha="c" * 40)
        on_main = seed.assessment(main, kind="secure-code", occurred_at=T0)
        on_release = seed.assessment(release, kind="secure-code", occurred_at=T0)
        shared = seed.finding(repo, fingerprint=str(uuid4()), title="shared")
        seed.occurrence(shared, on_main)
        seed.occurrence(shared, on_release)
        branch_only = seed.finding(repo, fingerprint=str(uuid4()), title="release only")
        seed.occurrence(branch_only, on_release)
        main_only = seed.finding(repo, fingerprint=str(uuid4()), title="main only")
        seed.occurrence(main_only, on_main)
        fixed = seed.assessment(patched, kind="verification", occurred_at=T0 + timedelta(days=1))
        seed.decision(
            shared,
            validity=None,
            resolution="resolved",
            assessment_id=fixed.id,
            actor=None,
            occurred_at=T0 + timedelta(days=1),
        )
        uow.commit()
    findings = service(engine)
    branch = {v.finding.title: v for v in findings.on_ref(patched.id)}
    assert set(branch) == {"shared", "release only"}
    assert not branch["shared"].is_open() and branch["release only"].is_open()
    default = {v.finding.title: v for v in findings.on_ref(main.id)}
    assert set(default) == {"shared", "main only"}
    assert default["shared"].is_open()


def test_a_ref_without_findings_is_empty(engine: Engine) -> None:  # noqa: F811
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref(is_default=True)
        uow.commit()
    assert service(engine).on_ref(ref.id) == []


def test_an_unknown_ref_is_not_found(engine: Engine) -> None:  # noqa: F811
    with pytest.raises(NotFoundError):
        service(engine).on_ref(uuid4())
