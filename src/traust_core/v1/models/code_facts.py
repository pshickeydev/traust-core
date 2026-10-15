from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from traust_core.v1.models.base import Entity, Model
from traust_core.v1.models.common import Location


class CodeFactKind(StrEnum):
    SYMBOL = "symbol"
    ROUTE_GUARD = "route-guard"
    CONFIG = "config"
    SANITIZER = "sanitizer"
    FORK_LAG = "fork-lag"
    TAINT_FLOW = "taint-flow"
    CRYPTO = "crypto"
    BINARY = "binary"
    LANGUAGES = "languages"
    IAC_PATH = "iac-path"
    PRIVILEGE = "privilege"


# One detail model per enumerator; fields land with the enumerator's slice.
class SymbolFact(Model): ...


class RouteGuardFact(Model): ...


class ConfigFact(Model): ...


class SanitizerFact(Model): ...


class ForkLagFact(Model): ...


class TaintFlowFact(Model): ...


class CryptoFact(Model): ...


class BinaryFact(Model): ...


class LanguageStats(Model): ...


class IacPathFact(Model): ...


class PrivilegeFact(Model): ...


CodeFactDetail = (
    SymbolFact
    | RouteGuardFact
    | ConfigFact
    | SanitizerFact
    | ForkLagFact
    | TaintFlowFact
    | CryptoFact
    | BinaryFact
    | LanguageStats
    | IacPathFact
    | PrivilegeFact
)


class SymbolQuery(Model): ...


class CollectResult(Model): ...


class CodeFact(Entity):
    revision_id: UUID
    kind: CodeFactKind
    location: Location | None = None
    detail: CodeFactDetail
