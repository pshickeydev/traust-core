import json
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

import pytest

from tests.v1.conftest import apply_contract_db, contract_db
from tests.v1.example.artifact_publishing import example_specs as default_specs
from tests.v1.fixtures import TRIAGE
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, DocumentError, RepositoryError
from traust_core.v1.models.analysis_results import ResultKind, Subject
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.analysis_results import AnalysisResultsRepository
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, SqlArtifactIndex

SUBJECT = Subject(tree="findings", product="openshift", repo_dir="oc", base="oc")
FINDING = {
    "id": "f001",
    "title": "SQL injection in handler",
    "verdict": "true_positive",
    "severity": "high",
    "file": "pkg/api/handler.go",
    "line": 42,
}


def triage_with(*findings: dict) -> bytes:
    doc = json.loads(TRIAGE)
    doc["findings"] = list(findings)
    return json.dumps(doc).encode()


@pytest.fixture(params=["files-only", "sqlite-index"])
def setup(
    request: pytest.FixtureRequest, tmp_path: Path
) -> Iterator[tuple[ArtifactPublisher, object]]:
    results = AnalysisResultsRepository(InMemoryObjectStore())
    if request.param == "files-only":
        yield ArtifactPublisher(default_specs(), results), None
        return
    with contract_db("sqlite", tmp_path) as engine:

        def make() -> SqlTraustUnitOfWork:
            return SqlTraustUnitOfWork(engine)

        yield ArtifactPublisher(default_specs(), results, SqlArtifactIndex(make)), make


def test_submit_writes_json_then_rendered_markdown(setup: tuple[ArtifactPublisher, object]) -> None:
    service, _ = setup
    result = service.publish("triage", SUBJECT, triage_with(FINDING), run_id="r1")
    assert result.written == (
        "findings/openshift/oc/oc-triage.json",
        "findings/openshift/oc/oc-triage.md",
    )
    assert not result.degraded


def test_markdown_is_rendered_from_the_validated_document() -> None:
    results = AnalysisResultsRepository(InMemoryObjectStore())
    publisher = ArtifactPublisher(default_specs(), results)
    publisher.publish("triage", SUBJECT, triage_with(FINDING), "r1")
    md = results.get(SUBJECT, ResultKind.TRIAGE_MD).decode()
    assert "# Triage: example.invalid/synthetic/repository" in md
    assert (
        "| f001 | SQL injection in handler | true_positive | high | pkg/api/handler.go:42 |" in md
    )


def test_index_records_an_artifact_row_that_points_at_the_json_file(
    setup: tuple[ArtifactPublisher, object],
) -> None:
    service, uow = setup
    result = service.publish("triage", SUBJECT, triage_with(FINDING), run_id="r1")
    if uow is None:
        assert result.artifact_id is None
        return
    assert result.artifact_id is not None
    with uow() as u:  # type: ignore[operator]
        row = u.artifacts.get(result.artifact_id)
    assert row.uri == "findings/openshift/oc/oc-triage.json"
    assert row.kind == "triage" and row.assessment_id is None


def test_invalid_input_writes_nothing_and_returns_every_issue() -> None:
    store = InMemoryObjectStore()
    service = ArtifactPublisher(default_specs(), AnalysisResultsRepository(store))
    bad = triage_with({"id": "x1", "title": "no", "verdict": "maybe"})
    with pytest.raises(DocumentError) as err:
        service.publish("triage", SUBJECT, bad, run_id="r1")
    paths = {i.path for i in err.value.issues}
    assert {"findings/0/id", "findings/0/title", "findings/0/verdict"} <= paths
    assert list(store.list()) == []


def test_non_json_input_is_a_single_issue() -> None:
    service = ArtifactPublisher(default_specs(), AnalysisResultsRepository(InMemoryObjectStore()))
    with pytest.raises(DocumentError) as err:
        service.publish("triage", SUBJECT, b"not json", run_id="r1")
    assert err.value.issues[0].path == "$"


def test_unknown_artifact_lists_the_known_ones() -> None:
    service = ArtifactPublisher(default_specs(), AnalysisResultsRepository(InMemoryObjectStore()))
    with pytest.raises(ConfigError, match="known: triage"):
        service.publish("nope", SUBJECT, b"{}", run_id="r1")


def test_save_a_typed_artifact_from_code() -> None:
    results = AnalysisResultsRepository(InMemoryObjectStore())
    triage = TriageArtifact.from_document(json.loads(triage_with(FINDING)))
    result = ArtifactPublisher(default_specs(), results).publish_artifact(triage, SUBJECT, "r1")
    assert result.written[0].endswith("oc-triage.json")
    assert results.get(SUBJECT, ResultKind.TRIAGE) == triage.payload


def test_reader_returns_the_named_artifact(tmp_path: Path) -> None:
    ctx = Context(Config.model_validate({"artifacts": {"path": str(tmp_path / "ar")}}))
    ctx.artifact_publisher(default_specs()).publish("triage", SUBJECT, triage_with(FINDING), "r1")
    triage = ctx.analysis_results().read(TriageArtifact, SUBJECT)
    assert isinstance(triage, TriageArtifact)
    assert triage.findings[0].title == "SQL injection in handler"
    found = ctx.analysis_results().read_all(TriageArtifact, "findings")
    assert [s.key for s, _ in found] == [SUBJECT.key]


def test_index_failure_keeps_files_and_reports_degraded() -> None:
    class BrokenIndex:
        def record(self, *_: object) -> UUID:
            raise RepositoryError("database down")

    results = AnalysisResultsRepository(InMemoryObjectStore())
    result = ArtifactPublisher(default_specs(), results, BrokenIndex()).publish(
        "triage", SUBJECT, triage_with(), "r1"
    )
    assert result.degraded and "database down" in (result.index_error or "")
    assert results.exists(SUBJECT, ResultKind.TRIAGE)


def test_resubmitting_is_idempotent(setup: tuple[ArtifactPublisher, object]) -> None:
    service, _ = setup
    first = service.publish("triage", SUBJECT, triage_with(FINDING), run_id="r1")
    again = service.publish("triage", SUBJECT, triage_with(FINDING), run_id="r1")
    assert (again.written, again.artifact_id) == (first.written, first.artifact_id)


def test_context_builds_files_only_or_indexed_from_config(tmp_path: Path) -> None:
    files_only = Context(Config.model_validate({"artifacts": {"path": str(tmp_path / "ar")}}))
    assert (
        files_only.artifact_publisher(default_specs())
        .publish("triage", SUBJECT, TRIAGE, "r1")
        .artifact_id
        is None
    )

    indexed = Context(
        Config.model_validate(
            {
                "artifacts": {"path": str(tmp_path / "ar2")},
                "database": {"url": f"sqlite:///{tmp_path}/db.sqlite"},
            }
        ),
    )
    apply_contract_db(indexed.database)
    published = indexed.artifact_publisher(default_specs()).publish("triage", SUBJECT, TRIAGE, "r1")
    assert published.artifact_id is not None
    assert (tmp_path / "ar2/findings/openshift/oc/oc-triage.md").is_file()
