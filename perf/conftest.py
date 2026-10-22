from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from perf.harness import Explained, Profile, profile, timed
from perf.seed import seeded_database
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

REPORT = Path(__file__).resolve().parent.parent / ".perf" / "report.md"


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    url = os.environ.get("TRAUST_TEST_DATABASE_URL")
    if not url:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set (make db-up)")
    eng = seeded_database(url)
    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def clock_rows() -> list[tuple[str, str, float]]:
    return []


@pytest.fixture(scope="session")
def report(clock_rows: list[tuple[str, str, float]]) -> Iterator[list[tuple[str, Explained]]]:
    rows: list[tuple[str, Explained]] = []
    yield rows
    REPORT.parent.mkdir(exist_ok=True)
    lines = ["| Case | Plan key line | Execution |", "|---|---|---|"]
    lines += [f"| {case} | `{e.key_line}` | {e.execution_ms:.3f} ms |" for case, e in rows]
    if clock_rows:
        lines += ["", "| Case | Call | Wall clock (median) |", "|---|---|---|"]
        lines += [f"| {case} | {what} | {ms:.2f} ms |" for case, what, ms in clock_rows]
    REPORT.write_text("\n".join(lines) + "\n")


@pytest.fixture
def explained(engine: Engine, report: list, request: pytest.FixtureRequest) -> Profile:
    def run(call: Callable[[SqlTraustUnitOfWork], object]) -> list[Explained]:
        found = profile(engine, call)
        report.extend((request.node.name, e) for e in found)
        return found

    return run


Clocked = Callable[[str, Callable[[SqlTraustUnitOfWork], object]], float]


@pytest.fixture
def clocked(
    engine: Engine, clock_rows: list, report: list, request: pytest.FixtureRequest
) -> Clocked:
    def run(what: str, call: Callable[[SqlTraustUnitOfWork], object]) -> float:
        ms = timed(engine, call)
        clock_rows.append((request.node.name, what, ms))
        return ms

    return run
