"""2 · Dependencies - third-party code and known vulnerabilities. One repository per table."""

from __future__ import annotations

from typing import Protocol

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
    "SqlDependencyRepository",
    "SqlImageRepository",
    "SqlPackageRepository",
    "SqlSbomRepository",
]
