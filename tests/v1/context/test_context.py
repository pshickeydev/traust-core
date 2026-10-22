from pathlib import Path

import pytest
import sqlalchemy as sa

from tests.v1.example.repository import SqlTaskUnitOfWork, metadata
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "traust.yaml"
    path.write_text(text)
    return path


def test_empty_file_defaults_to_sqlite_under_home(tmp_path: Path) -> None:
    config = Config.from_file(_write(tmp_path, f"home: {tmp_path / 'home'}\n"))
    assert config.database.url is None
    assert config.record_store_url() == sa.make_url(f"sqlite:///{tmp_path / 'home' / 'traust.db'}")


def test_database_password_comes_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config.model_validate(
        {"database": {"url": "postgresql+psycopg://traust@db/traust", "password_env": "DB_PW"}}
    )
    monkeypatch.setenv("DB_PW", "s3cret")
    assert config.database.engine_url().password == "s3cret"


def test_unknown_keys_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        Config.from_file(_write(tmp_path, "databse:\n  url: sqlite:///x.db\n"))


def test_unit_of_work_uses_configured_database(tmp_path: Path) -> None:
    config = Config.model_validate({"database": {"url": f"sqlite:///{tmp_path / 'x.db'}"}})
    ctx = Context(config)
    metadata.create_all(ctx.database)
    uow = ctx.unit_of_work(SqlTaskUnitOfWork)
    with uow:
        assert uow.tasks.list_by_status("queued") == []
    assert (tmp_path / "x.db").exists()
