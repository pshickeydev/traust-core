from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Generic, Protocol, TypeVar
from uuid import UUID

from traust_core.v1.errors import ConfigError, DocumentError, Issue, TraustError
from traust_core.v1.models.analysis_results import ResultKind, Subject
from traust_core.v1.models.artifacts import ArtifactDocument
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.base import Dto
from traust_core.v1.repositories.objects.analysis_results import (
    AnalysisResultsRepository,
    artifact_kind,
)
from traust_core.v1.repositories.objects.store import ObjectRef
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork

A = TypeVar("A", bound=ArtifactDocument)


class InputFormat(Protocol):
    def to_json(self, artifact: str, raw: bytes) -> bytes: ...


class JsonInput:
    def to_json(self, artifact: str, raw: bytes) -> bytes:
        if not raw.strip():
            raise DocumentError(artifact, [Issue("$", "empty input")])
        return raw


@dataclass(frozen=True, slots=True)
class Companion(Generic[A]):
    kind: ResultKind
    render: Callable[[A], bytes]


@dataclass(frozen=True, slots=True)
class PublishSpec(Generic[A]):
    artifact: type[A]
    companions: tuple[Companion[A], ...] = ()
    input: InputFormat = field(default_factory=JsonInput)

    @property
    def name(self) -> str:
        return self.artifact.name


class PublishSpecs:
    def __init__(self, *specs: PublishSpec[Any]) -> None:
        self._specs: dict[str, PublishSpec[Any]] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: PublishSpec[Any]) -> None:
        if spec.name in self._specs:
            raise ConfigError(f"artifact spec {spec.name!r} registered twice")
        self._specs[spec.name] = spec

    def get(self, name: str) -> PublishSpec[Any]:
        try:
            return self._specs[name]
        except KeyError:
            raise ConfigError(
                f"unknown artifact {name!r}; known: {', '.join(sorted(self._specs))}"
            ) from None

    def names(self) -> list[str]:
        return sorted(self._specs)


class ArtifactIndex(Protocol):
    def record(
        self, artifact: ArtifactDocument, subject: Subject, ref: ObjectRef, run_id: str
    ) -> UUID: ...


class SqlArtifactIndex:
    """Records each published document as an artifact row; same bytes, same row."""

    def __init__(self, uow: Callable[[], AssessmentsUnitOfWork]) -> None:
        self._uow = uow

    def record(
        self, artifact: ArtifactDocument, subject: Subject, ref: ObjectRef, run_id: str
    ) -> UUID:
        with self._uow() as u:
            row = u.artifacts.find(None, ref.sha256) or u.artifacts.add(
                Artifact(digest=ref.sha256, kind=artifact.schema, uri=str(ref.key))
            )
            u.commit()
        assert row.id is not None
        return row.id


class PublishResult(Dto):
    artifact: str
    written: tuple[str, ...]
    artifact_id: UUID | None = None
    index_error: str | None = None

    @property
    def degraded(self) -> bool:
        return self.index_error is not None


class ArtifactPublisher:
    def __init__(
        self,
        specs: PublishSpecs,
        results: AnalysisResultsRepository,
        index: ArtifactIndex | None = None,
    ) -> None:
        self._specs = specs
        self._results = results
        self._index = index

    def publish(self, name: str, subject: Subject, raw: bytes, run_id: str) -> PublishResult:
        spec = self._specs.get(name)
        artifact = spec.artifact.parse(spec.input.to_json(name, raw))
        return self.publish_artifact(artifact, subject, run_id)

    def publish_artifact(
        self, artifact: ArtifactDocument, subject: Subject, run_id: str
    ) -> PublishResult:
        spec = self._specs.get(artifact.name)
        primary = self._results.put(subject, artifact_kind(spec.artifact), artifact.payload)
        written = [
            primary,
            *(self._results.put(subject, c.kind, c.render(artifact)) for c in spec.companions),
        ]
        result = PublishResult(artifact=spec.name, written=tuple(str(r.key) for r in written))
        if self._index is None:
            return result
        try:
            artifact_id = self._index.record(artifact, subject, primary, run_id)
        except TraustError as e:
            return result.model_copy(update={"index_error": str(e)})
        return result.model_copy(update={"artifact_id": artifact_id})

    def get(self, artifact_id: UUID) -> ArtifactDocument:
        raise NotImplementedError("stub: replaces AnalysisResultsRepository.read by path subject")

    def verify(self, artifact_id: UUID) -> DigestCheck:
        raise NotImplementedError("stub: replaces verify_report_digests.py, ledger report digests")

    def list_for_assessment(self, assessment_id: UUID) -> list[Artifact]:
        raise NotImplementedError("stub: replaces corpus/report_store listing")


class DigestCheck(Dto): ...


class Redacted(Dto): ...


class RedactionPolicy:
    def redact(self, payload: bytes) -> Redacted:
        raise NotImplementedError("stub: replaces _util/redact.py")
