from __future__ import annotations

from datetime import timedelta

from tests.v1.repositories.tables.conftest import T0, Seed


def test_find_current_ownership_matches_repository_and_team_and_ignores_history(seed: Seed) -> None:
    repo, other_repo = seed.repository(), seed.repository()
    team, other_team = seed.team(), seed.team()
    seed.ownership(repo, team, valid_to=T0 + timedelta(days=1))
    seed.ownership(repo, other_team)
    seed.ownership(other_repo, team)
    assert seed.uow.ownerships.find_current(repo.id, team.id) is None
    current = seed.ownership(repo, team, valid_from=T0 + timedelta(days=2))
    assert seed.uow.ownerships.find_current(repo.id, team.id) == current
