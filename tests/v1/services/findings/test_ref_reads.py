from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed, saved_id
from tests.v1.services.findings import test_reads
from tests.v1.services.findings.test_reads import T0, service
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.inventory import ref_line
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

engine = test_reads.engine


@pytest.mark.parametrize("observed_default", [False, True])
def test_on_ref_keeps_the_line_population_and_folds_resolution_on_the_baseline_line(
    engine: Engine,
    observed_default: bool,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        main = seed.repository_ref(repository, is_default=observed_default)
        release = seed.repository_ref(repository, name="release-1", sha="b" * 40)
        tip = seed.repository_ref(repository, name="release-1", sha="c" * 40)
        head = seed.assessment(main, occurred_at=T0)
        baseline = seed.assessment(release, occurred_at=T0)
        on_main, shared, branch_only = (seed.finding(repository) for _ in range(3))
        seed.occurrence(on_main, head, severity="high")
        seed.occurrence(shared, head, severity="high")
        seed.occurrence(shared, baseline, severity="high")
        seed.occurrence(branch_only, baseline, severity="high")
        verification = seed.assessment(
            tip,
            kind="verification",
            baseline_assessment_id=saved_id(baseline),
            occurred_at=T0 + timedelta(days=2),
        )
        seed.decision(
            shared,
            assessment_id=saved_id(verification),
            actor=None,
            resolution="resolved",
            occurred_at=T0 + timedelta(days=2),
        )
        uow.commit()

    findings = service(engine)
    main_views = {view.finding.id: view for view in findings.on_ref(saved_id(main))}
    branch_views = {view.finding.id: view for view in findings.on_ref(saved_id(tip))}
    assert set(main_views) == {on_main.id, shared.id}
    assert set(branch_views) == {shared.id, branch_only.id}
    assert main_views[shared.id].is_open()
    assert not branch_views[shared.id].is_open()
    assert branch_views[branch_only.id].is_open()


def test_on_ref_bare_commits_match_only_observed_shas_not_inferred_ancestry(
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        release = seed.repository_ref(repository, name="release-1", sha="b" * 40)
        bare = seed.repository_ref(repository, name=None, kind=None, sha="b" * 40)
        unrelated = seed.repository_ref(repository, name=None, kind=None, sha="c" * 40)
        finding = seed.finding(repository)
        isolated = seed.finding(repository)
        seed.occurrence(finding, seed.assessment(bare, occurred_at=T0), severity="high")
        seed.occurrence(isolated, seed.assessment(unrelated, occurred_at=T0), severity="high")
        uow.commit()

    findings = service(engine)
    assert [view.finding.id for view in findings.on_ref(saved_id(release))] == [finding.id]
    assert [view.finding.id for view in findings.on_ref(saved_id(bare))] == [finding.id]
    assert [view.finding.id for view in findings.on_ref(saved_id(unrelated))] == [isolated.id]


def test_ref_line_uses_default_history_and_never_crosses_repository_boundaries(
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        old = seed.repository_ref(repository, is_default=True, sha="a" * 40)
        current = seed.repository_ref(repository, sha="b" * 40)
        bare = seed.repository_ref(repository, name=None, kind=None, sha="a" * 40)
        release = seed.repository_ref(repository, name="release-1", sha="a" * 40)
        foreign = seed.repository_ref(seed.repository(), is_default=True, sha="a" * 40)
        refs = [old, current, bare, release, foreign]
        uow.commit()

    assert ref_line(current, refs) == {old.id, current.id, bare.id}
    assert ref_line(release, refs) == {release.id, bare.id}


def test_on_ref_is_empty_for_an_unreported_repository_and_names_a_missing_ref(
    engine: Engine,
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    findings = service(engine)
    assert findings.on_ref(saved_id(ref)) == []
    missing = uuid4()
    with pytest.raises(NotFoundError, match=str(missing)):
        findings.on_ref(missing)
