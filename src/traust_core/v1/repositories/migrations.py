from __future__ import annotations

from typing import NewType

from sqlalchemy.engine import Engine

SchemaVersion = NewType("SchemaVersion", str)


# NEED(local->server): moving from local (SQLite + dir) to Postgres + object storage is one
# step: copy rows and blobs as-is. UUID keys mean nothing is re-keyed or re-linked.
class Migrations:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def current(self) -> SchemaVersion:
        raise NotImplementedError("stub: replaces traust_storage_meta / schema_revision")

    def apply(self) -> SchemaVersion:
        raise NotImplementedError("stub: replaces contracts migrations/*.sql runners")
