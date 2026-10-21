# Repository

One repository per contract table. The DDL is owned by traust-contracts; you never write DDL, and a table that isn't in the pinned contracts yet is a gap to report, not one to invent.

## Add a table repository

Files mirror the contracts namespaces: `repositories/traust/<section>/<table>.py`, `repositories/traust_ops/<table>.py`, `repositories/traust_ledger/<table>.py`. Copy `repositories/traust/inventory/repository.py`.

1. **Model** in `models/<section>.py`: subclass `Entity` (mutable table) or `AppendOnly` (append-only table); fields are the columns, named as in the DDL; no behaviour, no database types.
2. **Spec**: `TableSpec(TRAUST | TRAUST_OPS | TRAUST_LEDGER, "<table>", lambda: (<domain columns>), append_only=...)` using `uuid_column` / `text_column` / `timestamp_column` (or `sa.Column` for booleans, integers, numerics). Base columns come from the spec; don't declare them. `TableFactory` builds it per dialect (Postgres schema or SQLite `ops_`/`ledger_` prefix).
3. **Protocol**: `class XRepository(MutableRecordRepository[X] | RecordRepository[X], Protocol)` listing only this table's queries.
4. **SQL class**: `class SqlXRepository(SqlMutableRepository[X] | SqlAppendOnlyRepository[X])` with `spec = X_SPEC`, `record = X`. `add`/`get`/`update` are inherited; each query uses `self._one(...)` / `self._many(..., order_by=...)` over `self.table.c`. Missing row → `NotFoundError`; database refusals surface as `ConflictError` from `_execute`.
5. **Register**: add the spec to the section `__init__.py` `TABLES`, the repository to its section unit-of-work protocol, and the attribute to `SqlTraustUnitOfWork` in `repositories/contract.py`.
6. **Seed + tests**: add `new_<table>()` / `<table>()` to `Seed` in `tests/v1/repositories/tables/conftest.py` — the per-table CRUD tests then cover it automatically — and a test per query in the section's test module.

New reads go on the owning table's module: no duplicate queries of the same data, no speculative helpers, never reshape a table to fit a caller.

## Unit of work

Services declare the narrow protocol they need (`InventoryUnitOfWork`, `FindingsUnitOfWork`, …, `TraustUnitOfWork` across sections). `SqlTraustUnitOfWork(engine)` opens every repository on one connection, so one `commit()` or `rollback()` covers every section. Services that write together share one instance.

```python
class FindingIntake:
    def __init__(self, uow: TraustUnitOfWork) -> None:
        self._uow = uow

    def accept(self, assessment_id: UUID, candidates: Sequence[FindingCandidate]) -> IntakeResult:
        with self._uow as uow:
            ...  # occurrences, findings, decisions
            uow.commit()  # all or nothing
```

## Tests

Behaviour only, in `tests/v1/repositories/tables/`, each test running on SQLite and Postgres (`make test-repositories`; Postgres needs `make db-up`). Use the `uow` and `seed` fixtures; a test states only what it is about: `seed.decision(seed.finding(), severity="high")`.

- Per query: the right rows come back (and `None` / `[]` when they shouldn't).
- Assert list order only where the query defines it (`occurred_at`, `seq`, `priority`); otherwise compare with `same_rows`.
- Never restate the DDL (columns, constraints, triggers, indexes): contracts owns and tests that.
