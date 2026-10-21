"""1 · Inventory - what exists and who owns it. One repository per table."""

from __future__ import annotations

from typing import Protocol

from traust_core.v1.repositories.traust.inventory.component import (
    COMPONENT,
    ComponentRepository,
    SqlComponentRepository,
)
from traust_core.v1.repositories.traust.inventory.ownership import (
    OWNERSHIP,
    OwnershipRepository,
    SqlOwnershipRepository,
)
from traust_core.v1.repositories.traust.inventory.product import (
    PRODUCT,
    ProductRepository,
    SqlProductRepository,
)
from traust_core.v1.repositories.traust.inventory.release import (
    RELEASE,
    ReleaseRepository,
    SqlReleaseRepository,
)
from traust_core.v1.repositories.traust.inventory.repository import (
    REPOSITORY,
    RepositoryRepository,
    SqlRepositoryRepository,
)
from traust_core.v1.repositories.traust.inventory.repository_ref import (
    REPOSITORY_REF,
    RepositoryRefRepository,
    SqlRepositoryRefRepository,
)
from traust_core.v1.repositories.traust.inventory.team import (
    TEAM,
    SqlTeamRepository,
    TeamRepository,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork

TABLES = (PRODUCT, RELEASE, COMPONENT, REPOSITORY, REPOSITORY_REF, TEAM, OWNERSHIP)


class InventoryUnitOfWork(UnitOfWork, Protocol):
    products: ProductRepository
    releases: ReleaseRepository
    components: ComponentRepository
    repositories: RepositoryRepository
    repository_refs: RepositoryRefRepository
    teams: TeamRepository
    ownerships: OwnershipRepository


__all__ = [
    "TABLES",
    "ComponentRepository",
    "InventoryUnitOfWork",
    "OwnershipRepository",
    "ProductRepository",
    "ReleaseRepository",
    "RepositoryRefRepository",
    "RepositoryRepository",
    "SqlComponentRepository",
    "SqlOwnershipRepository",
    "SqlProductRepository",
    "SqlReleaseRepository",
    "SqlRepositoryRefRepository",
    "SqlRepositoryRepository",
    "SqlTeamRepository",
    "TeamRepository",
]
