from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Literal, Self
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Connection, CursorResult, Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.compiler import compiles

from traust_core.v1.errors import ConflictError, NotFoundError, RepositoryError

STORAGE_SCHEMA = "traust_storage"
LEDGER_SCHEMA = "traust_ledger"


def _compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def create_database_engine(url: str | sa.URL) -> Engine:
    engine = sa.create_engine(url, json_serializer=_compact_json)
    if engine.dialect.name != "sqlite":
        return engine

    @sa.event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn: Any, _: Any) -> None:
        dbapi_conn.execute("PRAGMA foreign_keys = ON")

    return engine.execution_options(
        schema_translate_map={STORAGE_SCHEMA: None, LEDGER_SCHEMA: None}
    )


def contract_dialect(engine: Engine | Connection) -> Literal["sqlite", "postgres"]:
    return "postgres" if engine.dialect.name == "postgresql" else "sqlite"


class UtcTimestamp(sa.TypeDecorator[datetime]):
    impl = sa.DateTime(timezone=True)
    cache_ok = True

    def load_dialect_impl(self, dialect: sa.Dialect) -> sa.TypeEngine[Any]:
        return dialect.type_descriptor(sa.Text() if dialect.name == "sqlite" else self.impl)

    def process_bind_param(self, value: datetime | None, dialect: sa.Dialect) -> Any:
        return value.isoformat() if value is not None and dialect.name == "sqlite" else value

    def process_result_value(self, value: Any, dialect: sa.Dialect) -> datetime | None:
        if isinstance(value, str):
            value = datetime.fromisoformat(value)
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)  # SQLite CURRENT_TIMESTAMP is UTC without offset
        return value


class _GeneratedUuid(sa.FunctionElement[UUID]):
    name = "generated_uuid"
    inherit_cache = True


@compiles(_GeneratedUuid, "postgresql")
def _postgres_uuid(element: Any, compiler: Any, **kw: Any) -> str:
    return "gen_random_uuid()"


@compiles(_GeneratedUuid, "sqlite")
def _sqlite_uuid(element: Any, compiler: Any, **kw: Any) -> str:
    # ext/misc/uuid.c isn't loadable everywhere; v4 straight from randomblob, in the
    # 32-char lowercase hex form the Uuid type binds.
    return (
        "substr(lower(hex(randomblob(16))), 1, 12) || '4' "
        "|| substr(lower(hex(randomblob(16))), 14, 3) "
        "|| '8' || substr(lower(hex(randomblob(16))), 2, 15)"
    )


def record_columns() -> tuple[sa.Column[UUID], sa.Column[datetime], sa.Column[datetime]]:
    """Mutable base columns: database-generated UUIDv4 id, created_at, updated_at."""
    return (
        sa.Column("id", sa.Uuid, primary_key=True, server_default=_GeneratedUuid()),
        sa.Column("created_at", UtcTimestamp, nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            UtcTimestamp,
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
    )


def append_only_columns() -> tuple[sa.Column[UUID], sa.Column[datetime]]:
    """Append-only base columns: database-generated UUIDv4 id and created_at, no updated_at."""
    return (
        sa.Column("id", sa.Uuid, primary_key=True, server_default=_GeneratedUuid()),
        sa.Column("created_at", UtcTimestamp, nullable=False, server_default=sa.func.now()),
    )


def apply_schema(engine: Engine, statements: Iterable[str]) -> None:
    try:
        with engine.begin() as conn:
            # Raw cursor, no params: a '%' in DDL text is never parsed as a placeholder.
            cursor = conn.connection.cursor()
            try:
                for stmt in statements:
                    cursor.execute(stmt)
            finally:
                cursor.close()
    except SQLAlchemyError as e:
        raise RepositoryError(f"apply schema failed: {e}") from e


class SqlUnitOfWork:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._connection: Connection | None = None

    @property
    def connection(self) -> Connection:
        if self._connection is None:
            raise RepositoryError(f"{type(self).__name__}: used outside a 'with' block")
        return self._connection

    def _open_repositories(self) -> None:
        pass

    def __enter__(self) -> Self:
        try:
            self._connection = self._engine.connect()
        except SQLAlchemyError as e:
            raise RepositoryError(f"{type(self).__name__}: connect failed: {e}") from e
        self._open_repositories()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            self.rollback()
        finally:
            self.connection.close()
            self._connection = None

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()


class SqlRepository:
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def _insert_record(
        self, operation: str, table: sa.Table, values: Mapping[str, Any]
    ) -> dict[str, UUID | datetime]:
        """INSERT domain columns; returns the database-generated base columns the table has."""
        returning = [table.c.id, table.c.created_at]
        if "updated_at" in table.c:
            returning.append(table.c.updated_at)
        stmt = sa.insert(table).values(**values).returning(*returning)
        return dict(self._execute(operation, stmt).mappings().one())

    def _update_record(
        self, operation: str, table: sa.Table, record_id: UUID, values: Mapping[str, Any]
    ) -> dict[str, UUID | datetime]:
        """UPDATE by id; returns the saved id/created_at/updated_at (updated_at maintained)."""
        stmt = (
            sa.update(table)
            .where(table.c.id == record_id)
            .values(**values)
            .returning(table.c.id, table.c.created_at, table.c.updated_at)
        )
        row = self._execute(operation, stmt).mappings().first()
        if row is None:
            raise NotFoundError(f"{type(self).__name__}: {operation}: not found")
        return dict(row)

    def _execute(
        self,
        operation: str,
        stmt: sa.Executable | str,
        params: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
    ) -> CursorResult[Any]:
        statement = sa.text(stmt) if isinstance(stmt, str) else stmt
        name = type(self).__name__
        if isinstance(params, Sequence):
            bound: Any = [dict(p) for p in params]
        else:
            bound = dict(params or {})
        try:
            return self._connection.execute(statement, bound)
        except IntegrityError as e:
            raise ConflictError(f"{name}: {operation}: {e.orig}") from e
        except SQLAlchemyError as e:
            raise RepositoryError(f"{name}: {operation} failed: {e}") from e


def schema_drift(engine: Engine, metadata: sa.MetaData) -> list[str]:
    inspector = sa.inspect(engine)
    translate = engine.get_execution_options().get("schema_translate_map", {})
    problems: list[str] = []
    for table in metadata.sorted_tables:
        schema = translate.get(table.schema, table.schema)
        if not inspector.has_table(table.name, schema=schema):
            problems.append(f"{table.name}: missing in database")
            continue
        actual = {c["name"]: c for c in inspector.get_columns(table.name, schema=schema)}
        for column in table.columns:
            found = actual.pop(column.name, None)
            if found is None:
                problems.append(f"{table.name}.{column.name}: missing in database")
            elif found["nullable"] != column.nullable and not column.primary_key:
                problems.append(
                    f"{table.name}.{column.name}: nullable {found['nullable']} in database, "
                    f"{column.nullable} in Table"
                )
        problems += [f"{table.name}.{name}: not declared in Table" for name in sorted(actual)]
    return problems
