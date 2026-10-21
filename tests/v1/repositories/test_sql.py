from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from re import fullmatch
from time import sleep
from uuid import UUID

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, sqlite

from tests.v1.conftest import SQL_BACKENDS, database
from traust_core.v1.errors import ConflictError, NotFoundError
from traust_core.v1.models.base import AppendOnly, Entity
from traust_core.v1.repositories import (
    SqlRepository,
    SqlUnitOfWork,
    append_only_columns,
    apply_schema,
    record_columns,
)


class Record(Entity):
    name: str
    status: str


class Reading(AppendOnly):
    sensor: str


metadata = sa.MetaData()

records = sa.Table(
    "base_records",
    metadata,
    *record_columns(),
    sa.Column("name", sa.Text, nullable=False, unique=True),
    sa.Column("status", sa.Text, nullable=False),
)

readings = sa.Table(
    "base_readings",
    metadata,
    *append_only_columns(),
    sa.Column("sensor", sa.Text, nullable=False),
)


def _to_row(record: Record) -> dict[str, str]:
    return {"name": record.name, "status": record.status}


class RecordRepository(SqlRepository):
    def add(self, record: Record) -> Record:
        saved = self._insert_record(f"add {record.name}", records, _to_row(record))
        return record.model_copy(update=saved)

    def update(self, record: Record) -> Record:
        assert record.id is not None
        saved = self._update_record(f"update {record.id}", records, record.id, _to_row(record))
        return record.model_copy(update=saved)

    def get(self, record_id: UUID) -> Record:
        stmt = sa.select(records).where(records.c.id == record_id)
        row = self._execute(f"get {record_id}", stmt).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"record {record_id}")
        return Record.model_validate(dict(row))


class ReadingRepository(SqlRepository):
    def add(self, reading: Reading) -> Reading:
        saved = self._insert_record(f"add {reading.sensor}", readings, {"sensor": reading.sensor})
        return reading.model_copy(update=saved)

    def get(self, reading_id: UUID) -> Reading:
        stmt = sa.select(readings).where(readings.c.id == reading_id)
        row = self._execute(f"get {reading_id}", stmt).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"reading {reading_id}")
        return Reading.model_validate(dict(row))


class RecordUnitOfWork(SqlUnitOfWork):
    records: RecordRepository
    readings: ReadingRepository

    def _open_repositories(self) -> None:
        self.records = RecordRepository(self.connection)
        self.readings = ReadingRepository(self.connection)


# The contracts touch trigger, mirrored for the test table (updated_at is the DB's).
_TOUCH_SQLITE = """
CREATE TRIGGER IF NOT EXISTS base_records_touch
AFTER UPDATE ON base_records FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at BEGIN
  UPDATE base_records SET updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id = NEW.id;
END;
"""

_TOUCH_POSTGRES = """
CREATE OR REPLACE FUNCTION base_records_touch_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := statement_timestamp();
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS base_records_touch ON base_records;
CREATE TRIGGER base_records_touch BEFORE UPDATE ON base_records
FOR EACH ROW EXECUTE FUNCTION base_records_touch_updated_at();
"""


@pytest.fixture(params=SQL_BACKENDS)
def uow(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[RecordUnitOfWork]:
    with database(request.param, tmp_path, metadata) as engine:
        touch = _TOUCH_POSTGRES if request.param == "postgres" else _TOUCH_SQLITE
        apply_schema(engine, [touch])
        yield RecordUnitOfWork(engine)


def test_record_columns_declare_the_base_shape() -> None:
    id_col, created_col, updated_col = record_columns()
    assert id_col.name == "id"
    assert id_col.primary_key
    assert created_col.name == "created_at"
    assert updated_col.name == "updated_at"
    assert created_col.nullable is False
    assert updated_col.nullable is False
    assert updated_col.onupdate is None  # the touch trigger owns updated_at, not the app


def test_append_only_columns_declare_the_base_shape() -> None:
    id_col, created_col = append_only_columns()
    assert id_col.name == "id"
    assert id_col.primary_key
    assert created_col.name == "created_at"
    assert created_col.nullable is False
    assert "updated_at" not in readings.c
    assert "updated_at" not in Reading.model_fields


def test_uuid_default_compiles_per_dialect() -> None:
    create = sa.schema.CreateTable(records)
    sqlite_ddl = str(create.compile(dialect=sqlite.dialect()))
    postgres_ddl = str(create.compile(dialect=postgresql.dialect()))
    assert "uuid()" in sqlite_ddl
    assert "gen_random_uuid()" in postgres_ddl


def test_add_returns_the_database_generated_record(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.records.add(Record(name="a", status="open"))
        u.commit()
    assert isinstance(saved.id, UUID)
    assert saved.id.version == 4
    assert saved.created_at is not None
    assert saved.created_at.tzinfo is not None
    assert saved.updated_at is not None
    assert saved.updated_at >= saved.created_at


def test_append_only_add_returns_the_database_generated_reading(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.readings.add(Reading(sensor="temp"))
        u.commit()
    assert isinstance(saved.id, UUID)
    assert saved.id.version == 4
    assert saved.created_at is not None
    assert saved.created_at.tzinfo is not None


def test_append_only_reading_round_trips_by_id(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.readings.add(Reading(sensor="temp"))
        u.commit()
    assert saved.id is not None
    with uow as u:
        reread = u.readings.get(saved.id)
    assert reread == saved


def test_each_row_gets_its_own_id(uow: RecordUnitOfWork) -> None:
    with uow as u:
        first = u.records.add(Record(name="a", status="open"))
        second = u.records.add(Record(name="b", status="open"))
        u.commit()
    assert first.id != second.id


def test_duplicate_natural_key_raises_conflict(uow: RecordUnitOfWork) -> None:
    with uow as u:
        u.records.add(Record(name="a", status="open"))
        u.commit()
    with uow as u:
        with pytest.raises(ConflictError):
            u.records.add(Record(name="a", status="open"))
        u.rollback()


def test_update_returns_the_saved_record_and_maintains_updated_at(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.records.add(Record(name="a", status="open"))
        u.commit()
    assert saved.id is not None
    sleep(0.01)  # the touch trigger has millisecond precision
    with uow as u:
        done = u.records.update(saved.model_copy(update={"status": "done"}))
        u.commit()
    assert done.status == "done"
    assert done.updated_at is not None
    assert done.updated_at > done.created_at  # type: ignore[operator]


def test_raw_sql_update_outside_the_app_still_touches_updated_at(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.records.add(Record(name="a", status="open"))
        u.commit()
    assert saved.id is not None
    sleep(0.01)
    with uow as u:
        u.records._execute(
            f"raw update {saved.id}",
            sa.text("UPDATE base_records SET status = 'done' WHERE id = :id"),
            {"id": str(saved.id)},  # raw SQL carries no type information
        )
        u.commit()
        reread = u.records.get(saved.id)
    assert reread.status == "done"
    assert reread.updated_at > saved.updated_at  # type: ignore[operator]


def test_sqlite_columns_match_the_contracts_text_formats(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.readings.add(Reading(sensor="temp"))
        u.commit()
    assert saved.id is not None
    with uow as u:
        row = u.readings._execute(
            f"raw get {saved.id}",
            sa.text("SELECT id, created_at FROM base_readings WHERE id = :id"),
            {"id": str(saved.id)},
        ).one()
    if not isinstance(row[0], str):  # Postgres returns native types
        return
    assert fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", row[0])
    assert fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", row[1])


def test_update_missing_row_raises_not_found(uow: RecordUnitOfWork) -> None:
    with uow as u:
        with pytest.raises(NotFoundError):
            u.records.update(Record(id=UUID(int=1), name="a", status="done"))
        u.rollback()


def test_saved_record_round_trips_by_id(uow: RecordUnitOfWork) -> None:
    with uow as u:
        saved = u.records.add(Record(name="a", status="open"))
        u.commit()
    assert saved.id is not None
    with uow as u:
        reread = u.records.get(saved.id)
    assert reread == saved
