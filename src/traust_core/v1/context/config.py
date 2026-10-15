from __future__ import annotations

import os
from pathlib import Path

import pydantic
import sqlalchemy as sa
import yaml

from traust_core.v1.errors import ConfigError


class _Model(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid", frozen=True)


def _read_env(name: str | None, field: str) -> str | None:
    if name is None:
        return None
    if (value := os.environ.get(name)) is None:
        raise ConfigError(f"{field} names unset variable {name}")
    return value


class DatabaseConfig(_Model):
    url: str | None = None
    password_env: str | None = None

    def password(self) -> str | None:
        return _read_env(self.password_env, "database.password_env")

    def engine_url(self) -> sa.URL:
        # NEED(local): "files-only" goes away; with no url the record store is SQLite under home.
        if self.url is None:
            raise ConfigError("database.url is not set (files-only setup)")
        try:
            url = sa.make_url(self.url)
        except sa.exc.ArgumentError as e:
            raise ConfigError(f"database.url is invalid: {self.url}") from e
        return url.set(password=pw) if (pw := self.password()) else url


class ArtifactsConfig(_Model):
    path: Path = Path("artifacts")


class ProcessConfig(_Model):
    allowed_binaries: tuple[str, ...] = ()
    keep_env: tuple[str, ...] = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
    timeout_seconds: float = 600.0


# NEED(logging): one logging setup from Config — per-logger levels, JSON or text, stderr + rolling
# file, and a correlation ID set at every entry point and carried on every line (AGENTS.md).
# NEED(config): too busy and too clunky today. Target: one shape, one home, few keys —
# home dir, record store (SQLite default, Postgres optional), blob store (local dir or S3),
# identity, ledger. Pack data (catalogs, product maps) is not config; env only for secrets.
class Config(_Model):
    database: DatabaseConfig = DatabaseConfig()
    artifacts: ArtifactsConfig = ArtifactsConfig()
    process: ProcessConfig = ProcessConfig()
    allowed_repo_hosts: tuple[str, ...] = ()

    @classmethod
    def from_file(cls, path: Path) -> Config:
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except (OSError, yaml.YAMLError) as e:
            raise ConfigError(f"cannot read {path}") from e
        try:
            return cls.model_validate(data)
        except pydantic.ValidationError as e:
            raise ConfigError(f"{path}: {e}") from e
