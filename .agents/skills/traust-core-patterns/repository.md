# Repository

1. Model in `models/<subject>.py`: `Entity`/`Model` subclass or frozen dataclass. No database types.
2. Interface: a `Protocol` over one aggregate, in `repositories/<subject>.py`, using the shared verbs only as needed: `get(id) -> T` (raises `NotFoundError`), `find_*(...) -> T | None`, `list(filter, page) -> Page[T]`, `add(T) -> T` and `update(T) -> T` returning the saved record (database-generated `id`, `created_at`, `updated_at` via `RETURNING`). IDs are `UUID`, named `<entity>_id`. No generic CRUD base, no cross-domain tables.
3. Unit-of-work protocol: `class XUnitOfWork(UnitOfWork, Protocol): xs: XRepository`.
4. SQL implementation:
   - `sa.Table(...)` describing the existing table (DDL is owned by traust-contracts)
   - `class SqlXRepository(SqlRepository)`; every statement goes through `self._execute("<operation> <id>", stmt)`
   - `_to_row(model)` / `_to_model(row)` private functions; rows never leave the repository
   - missing row → `NotFoundError`; duplicates surface as `ConflictError` from `_execute`
5. `class SqlXUnitOfWork(SqlUnitOfWork)` attaching the repository in `_open_repositories`.
6. In-memory double implementing the same interface, raising the same errors.
7. Contract tests parametrized over `["memory", *SQL_BACKENDS]` using `tests/v1/conftest.py::database`. The Postgres case is marked `integration` and runs with `make db-up && make test-integration`.

The domain service takes the unit of work in its constructor and opens it per use case:

```python
class TaskService:
    def __init__(self, uow: TaskUnitOfWork) -> None:
        self._uow = uow

    def complete(self, task_id: UUID) -> Task:
        with self._uow as uow:
            done = uow.tasks.update(uow.tasks.get(task_id).complete())  # rule on the model
            uow.commit()
        return done
```

## Aggregate repository

One repository per aggregate (the thing the domain asks questions about), not per table. `repositories/triage.py` shows the SQL mechanics (table, mapping, `schema_drift`, idempotency); its string ids and `record_triage` free function are legacy and get replaced in the Findings slice — copy the mechanics, not the shape.

1. Domain model in `models/<subject>.py` (`TriageVerdict` in `models/findings.py`): fields = the projection's columns, typed.
2. Protocol with the domain questions only (`for_binding`, `for_source_finding`, `true_positives`); no generic CRUD.
3. `sa.Table` describing the contracts table (DDL from traust-contracts); match JSON columns' encoding to existing writers (`JSON(none_as_null=True)`, compact serializer from `create_database_engine`).
4. SQL + in-memory implementations; a unit of work that exposes it alongside any repository it must write with (`evidence` + `triage_verdicts`).
5. Domain service writes in one transaction: `bind_artifact(...)` then the projection, then `commit()`.
6. Tests: contract tests on memory/sqlite (+ Postgres `integration`), `schema_drift` against the DDL, idempotency.
7. Files go by role then subject: `models/<subject>.py`, `repositories/<subject>.py`, `services/<subject>.py`; tests mirror under `tests/v1/<role>/`.
