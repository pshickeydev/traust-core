from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.models.code_facts import (
    CodeFact,
    CodeFactKind,
    CollectResult,
    LanguageStats,
    SymbolFact,
    SymbolQuery,
)
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.providers.sources import SourceProvider
from traust_core.v1.providers.tools import FactEnumerator
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork


class CodeFactsService:
    def __init__(
        self,
        uow: AssessmentsUnitOfWork,
        sources: SourceProvider,
        enumerators: Sequence[FactEnumerator],
    ) -> None:
        self._uow = uow
        self._sources = sources
        self._enumerators = enumerators

    def collect(self, repository_ref_id: UUID, kinds: Sequence[CodeFactKind]) -> CollectResult:
        raise NotImplementedError("stub: replaces build_symbol_index, secure-code enumerators")

    def list(
        self, repository_ref_id: UUID, kinds: Sequence[CodeFactKind], page: PageRequest
    ) -> Page[CodeFact]:
        raise NotImplementedError("stub: code facts read")

    def symbols(self, repository_ref_id: UUID, query: SymbolQuery) -> list[SymbolFact]:
        raise NotImplementedError("stub: replaces query_index.py, build_diff_packet.callers_for")

    def language_stats(self, repository_ref_id: UUID) -> LanguageStats:
        raise NotImplementedError("stub: replaces loc-dashboard GitHub language fetch")
