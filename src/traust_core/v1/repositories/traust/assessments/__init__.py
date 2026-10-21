"""3a · Assessments - what was examined. One repository per table."""

from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.tables import SqlTablesUnitOfWork
from traust_core.v1.repositories.traust.assessments.artifact import (
    ARTIFACT,
    ArtifactRepository,
    SqlArtifactRepository,
)
from traust_core.v1.repositories.traust.assessments.assessment import (
    ASSESSMENT,
    AssessmentRepository,
    SqlAssessmentRepository,
)
from traust_core.v1.repositories.traust.assessments.location import (
    LOCATION,
    LocationRepository,
    SqlLocationRepository,
)
from traust_core.v1.repositories.traust.assessments.occurrence import (
    OCCURRENCE,
    OccurrenceRepository,
    SqlOccurrenceRepository,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork

TABLES = (ASSESSMENT, ARTIFACT, OCCURRENCE, LOCATION)


class AssessmentsUnitOfWork(UnitOfWork, Protocol):
    assessments: AssessmentRepository
    artifacts: ArtifactRepository
    occurrences: OccurrenceRepository
    locations: LocationRepository


class SqlAssessmentsUnitOfWork(SqlTablesUnitOfWork):
    def _open_repositories(self) -> None:
        conn, tables = self.connection, self.tables
        self.assessments = SqlAssessmentRepository(conn, tables)
        self.artifacts = SqlArtifactRepository(conn, tables)
        self.occurrences = SqlOccurrenceRepository(conn, tables)
        self.locations = SqlLocationRepository(conn, tables)


__all__ = [
    "TABLES",
    "ArtifactRepository",
    "AssessmentRepository",
    "AssessmentsUnitOfWork",
    "LocationRepository",
    "OccurrenceRepository",
    "SqlArtifactRepository",
    "SqlAssessmentRepository",
    "SqlAssessmentsUnitOfWork",
    "SqlLocationRepository",
    "SqlOccurrenceRepository",
]
