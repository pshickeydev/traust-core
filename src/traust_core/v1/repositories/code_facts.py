from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.code_facts import CodeFact, CodeFactKind, SymbolFact, SymbolQuery
from traust_core.v1.models.common import Location, Page, PageRequest
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class CodeFactRepository(Protocol):
    def add_many(self, facts: Sequence[CodeFact]) -> list[CodeFact]: ...
    def list(
        self, revision_id: UUID, kinds: Sequence[CodeFactKind], page: PageRequest
    ) -> Page[CodeFact]: ...
    def find_symbols(self, revision_id: UUID, query: SymbolQuery) -> list[SymbolFact]: ...
    def references(self, revision_id: UUID, query: SymbolQuery) -> list[Location]: ...


class CodeFactsUnitOfWork(UnitOfWork, Protocol):
    code_facts: CodeFactRepository
