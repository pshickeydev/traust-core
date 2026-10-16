from __future__ import annotations

from traust_core.v1.models.base import Dto
from traust_core.v1.providers.base import Readiness


class Capability(Dto): ...


class ProviderBinding(Dto): ...


class ToolchainStamp(Dto): ...


class DatabaseStatus(Dto): ...


class ProviderCatalog:
    def resolve(self, capability: Capability) -> ProviderBinding:
        raise NotImplementedError("stub: replaces registry/models.resolve, rule pack lookup")

    def readiness(self, capability: Capability | None) -> list[Readiness]:
        raise NotImplementedError("stub: replaces toolchain _check/_preflight, ops/doctor.py")

    def stamp(self) -> ToolchainStamp:
        raise NotImplementedError("stub: replaces toolchain _freeze/_stamp, assets.harness_version")

    def fetch_databases(self) -> list[DatabaseStatus]:
        raise NotImplementedError("stub: replaces toolchain _fetch_dbs, cli/toolchain fetch-dbs")
