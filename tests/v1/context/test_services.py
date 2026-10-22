from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import OrderRequest
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.ledger import LedgerConfig

OPERATOR = Principal(id=uuid4(), kind=ActorKind("human"), display="operator")


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "traust.yaml"
    path.write_text(text)
    return path


@pytest.fixture(params=SQL_BACKENDS)
def configured(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Context]:
    with contract_db(request.param, tmp_path) as engine:
        url = engine.url.render_as_string(hide_password=False)
        yield Context.from_file(
            _write(tmp_path, f"home: {tmp_path / 'home'}\ndatabase:\n  url: {url}\nrating: {{}}\n")
        )


def test_services_build_from_a_config_file(configured: Context) -> None:
    services = configured.services()
    order = services.ops.submit(OrderRequest(asset="feeds_cache", priority=1), OPERATOR)
    assert order.id is not None
    assert services.findings.open_count(uuid4(), []) == 0
    assert not (configured.config.home / "traust.db").exists()


def test_services_share_one_unit_of_work() -> None:
    services = Context(Config()).services()
    units = {
        id(unit)
        for unit in (
            services.assessment._uow,
            services.portfolio._uow,
            services.findings._uow,
            services.findings.intake._uow,
            services.findings.decisions._uow,
            services.exposure._uow,
            services.ops._uow,
        )
    }
    assert len(units) == 1


@pytest.mark.parametrize(
    "text",
    ["hom: /x\n", "rating:\n  sla_days: 7\n", "database:\n  uri: x\n"],
)
def test_a_typo_in_config_is_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        Context.from_file(_write(tmp_path, text))


def test_default_store_works_with_no_config(tmp_path: Path) -> None:
    config = Config(home=tmp_path / "home")
    first = Context(config).services()
    order = first.ops.submit(OrderRequest(asset="feeds_cache", priority=2), OPERATOR)

    assert (tmp_path / "home" / "traust.db").is_file()
    again = Context(config).services()
    with SqlTraustUnitOfWork(Context(config).database) as uow:
        assert uow.run_orders.get(order.id).asset == "feeds_cache"
    assert again.findings.open_count(uuid4(), []) == 0


def test_default_home_is_under_the_user_home_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    config = Config()
    assert config.home == tmp_path / ".traust"
    assert Config(home=Path("~/elsewhere")).home == tmp_path / "elsewhere"
    assert config.record_store_url().database == str(tmp_path / ".traust" / "traust.db")


def test_a_configured_database_is_never_bootstrapped(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    ctx = Context(Config(home=tmp_path / "home", database={"url": url}))  # type: ignore[arg-type]
    assert sa.inspect(ctx.database).get_table_names() == []
    assert not (tmp_path / "home").exists()


def test_no_ledger_section_leaves_the_ledger_off() -> None:
    services = Context(Config()).services()
    assert services.ledger is None
    assert services.findings.decisions._ledger is None


def test_a_ledger_section_wires_one_ledger_into_decisions(tmp_path: Path) -> None:
    config = Config.from_file(
        _write(
            tmp_path,
            f"home: {tmp_path / 'home'}\n"
            f"ledger:\n  key_path: {tmp_path / 'cosign.key'}\n"
            f"  public_key_path: {tmp_path / 'cosign.pub'}\n  required: true\n",
        )
    )
    services = Context(config).services()
    assert services.ledger is not None
    assert services.findings.decisions._ledger is services.ledger
    assert services.ledger._uow is services.findings._uow
    assert services.ledger._signing.key_path == str(tmp_path / "cosign.key")
    assert services.ledger._signing_required


def test_a_typo_in_the_ledger_section_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        Config.from_file(_write(tmp_path, "ledger:\n  key_pth: /keys/cosign.key\n"))


def test_a_configured_ledger_proves_a_decision(configured: Context) -> None:
    config = configured.config.model_copy(update={"ledger": LedgerConfig()})
    ctx = Context(config)
    with SqlTraustUnitOfWork(ctx.database) as uow:
        seed = Seed(uow)
        repo, decision = seed.repository(), seed.decision()
        uow.commit()
    assert repo.id is not None
    ledger = ctx.services().ledger
    assert ledger is not None
    receipt = ledger.append_decision(decision, repo.id)
    assert receipt.checkpoint.layer.merkle_size == 1
    assert receipt.checkpoint.layer.id is not None
    assert ledger.verify(receipt.checkpoint.layer.id).passed
