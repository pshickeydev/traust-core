"""Tests for shared (repo, commit) read-only checkouts and refcounting."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.v1.conftest import commit_all, git
from tests.v1.providers.test_mirror import Forge, LocalForge, NoHttp, SpyRunner
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, LocalRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.local import LocalCheckout
from traust_core.v1.providers.mirror import MirrorCheckout
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest

AT = datetime(2026, 11, 22, tzinfo=UTC)
URL = HttpsRepoUrl.parse("https://github.com/o/r", ("github.com",))


def test_mirror_shared_checkout_reuses_worktree_and_refcounts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forge = Forge(tmp_path)
    (forge.work / "spring-beans").mkdir(parents=True, exist_ok=True)
    sha = forge.commit("spring-beans/Cache.java", b"public class Cache { public void get() {} }\n")
    cfg = tmp_path / "gitconfig"
    cfg.write_text(f'[url "file://{forge.bare}"]\n\tinsteadOf = {URL}\n', encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))

    spy = SpyRunner(LocalForge(allowed=("git",), keep_env=("PATH", "HOME", "GIT_CONFIG_GLOBAL")))
    mirror = MirrorCheckout(spy, FixedClock(AT), tmp_path / "mirrors", ForgeApi(NoHttp(), {}))

    first = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    adds_after_first = sum(1 for a in spy.argv if "worktree" in a and "add" in a)
    second = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    adds_after_second = sum(1 for a in spy.argv if "worktree" in a and "add" in a)

    assert first.path == second.path
    assert first.shared and second.shared
    assert adds_after_first == 1
    assert adds_after_second == 1  # zero extra git worktree add

    # Releasing one holder keeps the shared worktree alive and blocks eviction.
    mirror.release(first)
    assert second.path.is_dir()
    old_ts = (AT - timedelta(days=2)).timestamp()
    last_use = tmp_path / "mirrors" / "github.com" / "o" / "r.git" / "traust-last-checkout"
    os.utime(last_use, (old_ts, old_ts))
    assert mirror.evict(1) == []

    # Releasing the last holder removes the shared worktree and unblocks eviction.
    mirror.release(second)
    assert not second.path.exists()
    assert mirror.evict(1) == [URL]


def test_shared_checkout_refuses_writable(tmp_path: Path) -> None:
    mirror = MirrorCheckout(
        ProcessRunner(allowed=("git",)),
        FixedClock(AT),
        tmp_path / "mirrors",
        ForgeApi(NoHttp(), {}),  # type: ignore[arg-type]
    )
    with pytest.raises(ValidationError, match="read-only"):
        mirror.checkout(
            CheckoutRequest(repo=URL, ref=GitSha.parse("a" * 40), shared=True, writable=True)
        )


def test_local_shared_checkout_reuses_worktree_and_refcounts(tmp_path: Path) -> None:
    repo = tmp_path / "monorepo-fixture"
    repo.mkdir()
    git(repo, "init", "-q")
    ts_file = repo / "packages" / "cache-lib" / "src" / "cache.ts"
    ts_file.parent.mkdir(parents=True)
    ts_file.write_text(
        "export class ItemCache {}\nexport function lookupById(id: string) { return id; }\n",
        encoding="utf-8",
    )
    sha = GitSha.parse(commit_all(repo, "add ts cache"))
    local_url = LocalRepoUrl.parse(repo.as_uri())

    local = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(AT))
    ws1 = local.checkout(CheckoutRequest(repo=local_url, ref=sha, shared=True)).data
    ws2 = local.checkout(CheckoutRequest(repo=local_url, ref=sha, shared=True)).data
    assert ws1.path == ws2.path

    local.release(ws1)
    assert ws2.path.is_dir()
    local.release(ws2)
    assert not ws2.path.exists()
