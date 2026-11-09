from pathlib import Path

import pytest
import sqlalchemy as sa

from tests.v1.example.repository import SqlTaskUnitOfWork, metadata
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import DatabaseConfig
from traust_core.v1.errors import ConfigError
from traust_core.v1.repositories import ObjectKey


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "traust.yaml"
    path.write_text(text)
    return path


def test_empty_file_defaults_to_sqlite_under_home(tmp_path: Path) -> None:
    config = Config.from_file(_write(tmp_path, f"home: {tmp_path / 'home'}\n"))
    assert config.database.url is None
    assert config.record_store_url() == sa.make_url(f"sqlite:///{tmp_path / 'home' / 'traust.db'}")


def test_artifacts_live_under_home_unless_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    home = tmp_path / "home"
    assert Config(home=home).artifacts_path() == home / "artifacts"
    assert Config(home=home, artifacts={"path": "blobs"}).artifacts_path() == home / "blobs"  # type: ignore[arg-type]
    elsewhere = tmp_path / "shared"
    assert Config(home=home, artifacts={"path": str(elsewhere)}).artifacts_path() == elsewhere  # type: ignore[arg-type]
    ref = Context(Config(home=home)).object_store.put(ObjectKey.parse("triage/x.json"), b"{}")
    assert (home / "artifacts" / str(ref.key)).is_file()
    assert not (tmp_path / "artifacts").exists()


def test_database_password_comes_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config.model_validate(
        {"database": {"url": "postgresql+psycopg://traust@db/traust", "password_env": "DB_PW"}}
    )
    monkeypatch.setenv("DB_PW", "s3cret")
    assert config.database.engine_url().password == "s3cret"


def test_invalid_database_url_does_not_echo_a_credential() -> None:
    secret = "synthetic-only-never-a-real-credential"
    with pytest.raises(ConfigError) as caught:
        DatabaseConfig(url=f"invalid-url-{secret}").engine_url()
    assert secret not in str(caught.value)


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


def test_recording_start_capabilities_parse_machine_assets_and_native_repositories(
    tmp_path: Path,
) -> None:
    repository_id = "271e3796-e1ac-4f25-bf81-6bac8c85e33a"
    config = Config.from_file(
        _write(
            tmp_path,
            "recording:\n"
            "  verification: [verify]\n"
            "  start:\n"
            "    - principal: machine:runner\n"
            "      assets: [verify]\n"
            f"      repository_ids: [{repository_id}]\n",
        )
    )
    (scope,) = config.recording.start
    assert scope.principal == "machine:runner"
    assert scope.assets == ("verify",)
    assert tuple(map(str, scope.repository_ids)) == (repository_id,)
    assert Config().recording.start == ()


@pytest.mark.parametrize(
    "scope",
    [
        {"principal": "machine:runner", "repository_ids": ["not-a-native-id"]},
        {"principal": "machine:runner", "repository_id": "unexpected-field"},
        {"principal": ""},
    ],
)
def test_recording_start_rejects_malformed_capabilities(scope: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        Config.model_validate({"recording": {"start": [scope]}})


def test_a_local_database_from_before_the_manifest_scan_pointer_is_upgraded(
    tmp_path: Path,
) -> None:
    _without_scan_pointer(tmp_path)
    engine = Context(Config(home=tmp_path)).database
    columns = {c["name"] for c in sa.inspect(engine).get_columns("repository_ref")}
    assert "manifest_sbom_assessment_id" in columns
    again = Context(Config(home=tmp_path)).database  # present: nothing applied twice
    assert "manifest_sbom_assessment_id" in {
        c["name"] for c in sa.inspect(again).get_columns("repository_ref")
    }


def _without_scan_pointer(home: Path) -> None:
    with Context(Config(home=home)).database.begin() as conn:
        conn.exec_driver_sql("DROP INDEX idx_repository_ref_manifest_sbom_assessment")
        conn.exec_driver_sql("ALTER TABLE repository_ref DROP COLUMN manifest_sbom_assessment_id")


def test_a_configured_database_missing_the_scan_pointer_is_refused_with_its_upgrade(
    tmp_path: Path,
) -> None:
    _without_scan_pointer(tmp_path)
    configured = Config(
        home=tmp_path / "elsewhere",
        database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'traust.db'}"),
    )
    with pytest.raises(ConfigError, match="manifest_sbom_binding_upgrade"):
        _ = Context(configured).database


def test_a_store_another_process_upgraded_first_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import traust_core.v1.context.context as module

    _without_scan_pointer(tmp_path)
    real = module.apply_schema

    def raced(engine: sa.Engine, statements: list[str]) -> None:
        real(engine, statements)  # the other process's upgrade lands first
        real(engine, statements)  # ours then hits the driver's duplicate-column error

    monkeypatch.setattr(module, "apply_schema", raced)
    engine = Context(Config(home=tmp_path)).database
    assert "manifest_sbom_assessment_id" in {
        c["name"] for c in sa.inspect(engine).get_columns("repository_ref")
    }


@pytest.mark.parametrize(
    ("column", "door"),
    [
        (("traust", "artifact", "run_order_id"), "_artifact_run_order"),
        (("traust", "repository_ref", "default_named_at"), "_default_named_at"),
        (("traust_ops", "run_order", "fork_scheduled_at"), "_run_order_fork_scheduled"),
    ],
)
def test_an_additive_column_upgrades_a_local_store_and_refuses_a_configured_one(
    tmp_path: Path, column: tuple[str, str, str], door: str
) -> None:
    from traust_core.v1.context import context as wiring

    namespace, name, column_name = column
    table = name if namespace == "traust" else f"ops_{name}"
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:  # the tables as they were before the column, after #117
        conn.exec_driver_sql(f"CREATE TABLE {table} (id TEXT, repository_id TEXT, is_default INT)")
        if table != "ops_run_order":
            conn.exec_driver_sql("CREATE TABLE ops_run_order (id TEXT, work_item_id TEXT)")
    with pytest.raises(ConfigError, match=f"{table} predates {column_name}: apply"):
        getattr(wiring, door)(engine, upgrade=False)
    getattr(wiring, door)(engine, upgrade=True)
    assert column_name in {c["name"] for c in sa.inspect(engine).get_columns(table)}
    getattr(wiring, door)(engine, upgrade=False)  # present now: nothing to refuse


def test_a_store_whose_run_order_predates_the_fork_columns_is_refused(tmp_path: Path) -> None:
    home = tmp_path / "home"
    Context(Config(home=home)).services()  # a local store with the current schema
    with Context(Config(home=home)).database.begin() as conn:
        conn.exec_driver_sql("ALTER TABLE ops_run_order DROP COLUMN fork_branch")
        conn.exec_driver_sql("ALTER TABLE ops_run_order DROP COLUMN fork_url")
    with pytest.raises(ConfigError, match="apply the additive statements"):
        Context(Config(home=home)).services()


def test_local_fingerprint_index_upgrade_preserves_finding_identity(tmp_path: Path) -> None:
    from tests.v1.repositories.tables.conftest import Seed
    from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

    engine = Context(Config(home=tmp_path)).database
    with SqlTraustUnitOfWork(engine) as uow:
        finding = Seed(uow).finding()
        uow.connection.exec_driver_sql("DROP INDEX idx_finding_repository_fingerprint")
        uow.commit()
    engine.dispose()
    upgraded = Context(Config(home=tmp_path)).database
    with SqlTraustUnitOfWork(upgraded) as uow:
        assert (
            uow.findings.find_by_fingerprint(finding.repository_id, None, finding.fingerprint)
            == finding
        )
    assert any(
        index["column_names"] == ["repository_id", "fingerprint"]
        for index in sa.inspect(upgraded).get_indexes("finding")
    )


def test_configured_database_missing_fingerprint_index_requires_owner_upgrade(
    tmp_path: Path,
) -> None:
    engine = Context(Config(home=tmp_path)).database
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP INDEX idx_finding_repository_fingerprint")
    engine.dispose()
    configured = Config(
        home=tmp_path / "elsewhere",
        database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'traust.db'}"),
    )
    with pytest.raises(ConfigError, match="finding_fingerprint_index_upgrade"):
        _ = Context(configured).database


def test_local_external_reference_attempt_upgrade_does_not_attribute_old_links(
    tmp_path: Path,
) -> None:
    from tests.v1.repositories.tables.conftest import Seed
    from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

    engine = Context(Config(home=tmp_path)).database
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        link = seed.finding_external_ref()
        _drop_external_scope_guards(uow.connection)
        uow.connection.exec_driver_sql("DROP INDEX idx_finding_external_ref_assessment")
        uow.connection.exec_driver_sql("ALTER TABLE finding_external_ref DROP COLUMN assessment_id")
        uow.commit()
    engine.dispose()
    upgraded = Context(Config(home=tmp_path)).database
    with SqlTraustUnitOfWork(upgraded) as uow:
        assert uow.finding_external_refs.get(link.id).assessment_id is None


def test_configured_external_reference_attempt_upgrade_is_explicit(tmp_path: Path) -> None:
    engine = Context(Config(home=tmp_path)).database
    with engine.begin() as connection:
        _drop_external_scope_guards(connection)
        connection.exec_driver_sql("DROP INDEX idx_finding_external_ref_assessment")
        connection.exec_driver_sql("ALTER TABLE finding_external_ref DROP COLUMN assessment_id")
    engine.dispose()
    configured = Config(
        home=tmp_path / "elsewhere",
        database=DatabaseConfig(url=f"sqlite:///{tmp_path / 'traust.db'}"),
    )
    with pytest.raises(ConfigError, match="finding_external_ref_assessment_upgrade"):
        _ = Context(configured).database


@pytest.fixture(params=["publication", "spend"])
def legacy_attribution_store(request: pytest.FixtureRequest, tmp_path: Path):
    from tests.v1.repositories.tables.conftest import Seed
    from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

    config = Config(home=tmp_path)
    engine = Context(config).database
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        saved = (
            seed.artifact(assessment_id=None, kind="feed", publication_revision=1)
            if request.param == "publication"
            else seed.spend_event()
        )
        uow.commit()
    with engine.begin() as connection:
        if request.param == "publication":
            connection.exec_driver_sql("DROP TRIGGER artifact_imported_revision_required")
            connection.exec_driver_sql("DROP INDEX idx_artifact_imported_kind")
            connection.exec_driver_sql("ALTER TABLE artifact DROP COLUMN publication_revision")
            connection.exec_driver_sql(
                "CREATE INDEX idx_artifact_imported_kind ON artifact "
                "(kind, created_at DESC, id DESC) WHERE assessment_id IS NULL"
            )
        else:
            connection.exec_driver_sql("DROP INDEX idx_ops_spend_event_repository_occurred")
            for column in ("repository_id", "repository_label", "loc", "batch", "note"):
                connection.exec_driver_sql(f"ALTER TABLE ops_spend_event DROP COLUMN {column}")
    engine.dispose()
    return request.param, config, saved


def test_local_store_upgrades_preserve_original_history(legacy_attribution_store) -> None:
    from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

    kind, config, original = legacy_attribution_store
    with SqlTraustUnitOfWork(Context(config).database) as uow:
        if kind == "publication":
            restored = uow.artifacts.latest_imported("feed")
            assert restored.publication_revision == 1
            assert restored.model_dump(exclude={"publication_revision"}) == original.model_dump(
                exclude={"publication_revision"}
            )
        else:
            restored = uow.spend_events.get(original.id)
            assert restored == original
            assert (restored.repository_id, restored.repository_label, restored.loc) == (
                None,
                None,
                None,
            )


def test_configured_legacy_store_refuses_before_first_read(legacy_attribution_store) -> None:
    kind, config, _ = legacy_attribution_store
    configured = Config(
        home=config.home / "elsewhere",
        database=DatabaseConfig(url=str(config.record_store_url())),
    )
    upgrade = (
        "artifact_publication_revision_upgrade"
        if kind == "publication"
        else "spend_event_metadata_upgrade"
    )
    with pytest.raises(ConfigError, match=upgrade):
        Context(configured).services()


def test_partial_spend_upgrade_is_not_silently_accepted(tmp_path: Path) -> None:
    engine = Context(Config(home=tmp_path)).database
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE ops_spend_event DROP COLUMN note")
    engine.dispose()
    with pytest.raises(ConfigError, match="partial spend metadata"):
        Context(Config(home=tmp_path)).services()


def _drop_external_scope_guards(connection: sa.Connection) -> None:
    for name in (
        "finding_external_ref_scope_insert",
        "finding_external_ref_scope_update",
        "finding_external_ref_finding_scope_update",
        "finding_external_ref_repository_ref_scope_update",
    ):
        connection.exec_driver_sql(f"DROP TRIGGER IF EXISTS {name}")


@pytest.mark.parametrize("configured", [False, True])
@pytest.mark.parametrize("missing", ["index", "guards"])
def test_partial_tracker_upgrade_is_repaired_locally_or_refused(
    tmp_path: Path, configured: bool, missing: str
) -> None:
    from tests.v1.repositories.tables.conftest import Seed
    from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

    original = Config(home=tmp_path)
    engine = Context(original).database
    with SqlTraustUnitOfWork(engine) as uow:
        link = Seed(uow).finding_external_ref()
        if missing == "index":
            uow.connection.exec_driver_sql("DROP INDEX idx_finding_external_ref_assessment")
        else:
            _drop_external_scope_guards(uow.connection)
        uow.commit()
    engine.dispose()
    if configured:
        selected = Config(
            home=tmp_path / "elsewhere",
            database=DatabaseConfig(url=str(original.record_store_url())),
        )
        with pytest.raises(ConfigError, match="finding_external_ref_scope_upgrade"):
            Context(selected).services()
    else:
        reopened = Context(original).database
        with SqlTraustUnitOfWork(reopened) as uow:
            assert uow.finding_external_refs.get(link.id) == link
        assert any(
            index["name"] == "idx_finding_external_ref_assessment"
            for index in sa.inspect(reopened).get_indexes("finding_external_ref")
        )
