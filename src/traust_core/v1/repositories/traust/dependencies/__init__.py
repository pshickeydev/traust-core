"""2 · Dependencies - third-party code and known vulnerabilities. One repository per table."""

from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.tables import SqlTablesUnitOfWork
from traust_core.v1.repositories.traust.dependencies.advisory import (
    ADVISORY,
    AdvisoryRepository,
    SqlAdvisoryRepository,
)
from traust_core.v1.repositories.traust.dependencies.advisory_package import (
    ADVISORY_PACKAGE,
    AdvisoryPackageRepository,
    SqlAdvisoryPackageRepository,
)
from traust_core.v1.repositories.traust.dependencies.dependency import (
    DEPENDENCY,
    DependencyRepository,
    SqlDependencyRepository,
)
from traust_core.v1.repositories.traust.dependencies.image import (
    IMAGE,
    ImageRepository,
    SqlImageRepository,
)
from traust_core.v1.repositories.traust.dependencies.package import (
    PACKAGE,
    PackageRepository,
    SqlPackageRepository,
)
from traust_core.v1.repositories.traust.dependencies.sbom import (
    SBOM,
    SbomRepository,
    SqlSbomRepository,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork

TABLES = (PACKAGE, SBOM, DEPENDENCY, IMAGE, ADVISORY, ADVISORY_PACKAGE)


class DependenciesUnitOfWork(UnitOfWork, Protocol):
    packages: PackageRepository
    sboms: SbomRepository
    dependencies: DependencyRepository
    images: ImageRepository
    advisories: AdvisoryRepository
    advisory_packages: AdvisoryPackageRepository


class SqlDependenciesUnitOfWork(SqlTablesUnitOfWork):
    def _open_repositories(self) -> None:
        conn, tables = self.connection, self.tables
        self.packages = SqlPackageRepository(conn, tables)
        self.sboms = SqlSbomRepository(conn, tables)
        self.dependencies = SqlDependencyRepository(conn, tables)
        self.images = SqlImageRepository(conn, tables)
        self.advisories = SqlAdvisoryRepository(conn, tables)
        self.advisory_packages = SqlAdvisoryPackageRepository(conn, tables)


__all__ = [
    "TABLES",
    "AdvisoryPackageRepository",
    "AdvisoryRepository",
    "DependenciesUnitOfWork",
    "DependencyRepository",
    "ImageRepository",
    "PackageRepository",
    "SbomRepository",
    "SqlAdvisoryPackageRepository",
    "SqlAdvisoryRepository",
    "SqlDependenciesUnitOfWork",
    "SqlDependencyRepository",
    "SqlImageRepository",
    "SqlPackageRepository",
    "SqlSbomRepository",
]
