"""Unit tests for deterministic component PURL resolution (Spring, LangChain, Pi, negatives)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError as PydanticValidationError

from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import UnresolvedTargetError
from traust_core.v1.models.component_target import (
    ComponentTarget,
    ComponentTargetRequest,
    ComponentTargetStrategy,
    ComponentTargetVerification,
    UnresolvedTargetReason,
)
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.package_manifests import PackageManifestScanner
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.services.component_target import ComponentTargetResolver


def _git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_AUTHOR_NAME": "Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()


def _init_repo(root: Path, files: dict[str, str], tags: tuple[str, ...] = ()) -> str:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "--quiet", "-b", "main")
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "--quiet", "-m", "fixture commit")
    sha = _git(root, "rev-parse", "HEAD")
    for tag in tags:
        _git(root, "tag", tag)
    return sha


def _resolver() -> ComponentTargetResolver:
    return ComponentTargetResolver(
        GitCheckout(ProcessRunner(allowed=("git",))),
        PackageManifestScanner(yaml_documents),
    )


def test_shared_release_maven_multi_module_resolves_sibling_modules(tmp_path: Path) -> None:
    repo = tmp_path / "spring-framework"
    sha = _init_repo(
        repo,
        {
            "pom.xml": (
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version><packaging>pom</packaging>"
                "<modules><module>spring-core</module><module>spring-beans</module>"
                "<module>spring-context</module></modules></project>\n"
            ),
            "spring-core/pom.xml": (
                "<project><parent><groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version></parent>"
                "<artifactId>spring-core</artifactId></project>\n"
            ),
            "spring-beans/pom.xml": (
                "<project><parent><groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version></parent>"
                "<artifactId>spring-beans</artifactId></project>\n"
            ),
            "spring-context/pom.xml": (
                "<project><parent><groupId>org.springframework</groupId>"
                "<artifactId>spring-framework-parent</artifactId>"
                "<version>7.1.0</version></parent>"
                "<artifactId>spring-context</artifactId></project>\n"
            ),
        },
        tags=("v7.1.0",),
    )
    resolver = _resolver()

    beans = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.springframework/spring-beans@7.1.0",
            repository="https://github.com/spring-projects/spring-framework",
            commit=sha,
        ),
        repo,
    )
    context = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.springframework/spring-context@7.1.0",
            repository="https://github.com/spring-projects/spring-framework",
            commit=sha,
        ),
        repo,
    )

    assert beans.module_path == "spring-beans"
    assert beans.release_ref == "v7.1.0"
    assert beans.verification.strategy is ComponentTargetStrategy.SHARED_RELEASE
    assert beans.verification.manifest_paths == ("pom.xml", "spring-beans/pom.xml")
    assert context.module_path == "spring-context"
    assert context.commit == beans.commit == sha


def test_langchain_style_package_release_tag_resolves(tmp_path: Path) -> None:
    repo = tmp_path / "langchain"
    sha = _init_repo(
        repo,
        {
            "libs/core/pyproject.toml": ('[project]\nname = "langchain-core"\nversion = "1.8.4"\n'),
            "libs/langchain/pyproject.toml": ('[project]\nname = "langchain"\nversion = "1.2.0"\n'),
        },
        tags=("langchain-core==1.8.4",),
    )
    resolved = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:pypi/langchain-core@1.8.4",
            repository="https://github.com/langchain-ai/langchain",
            release_ref="langchain-core==1.8.4",
        ),
        repo,
    )
    assert resolved.commit == sha
    assert resolved.module_path == "libs/core"
    assert resolved.release_ref == "langchain-core==1.8.4"
    assert resolved.verification.strategy is ComponentTargetStrategy.PACKAGE_RELEASE
    assert resolved.verification.manifest_paths == ("libs/core/pyproject.toml",)


def test_pi_style_public_workspace_ignores_private_root_version(tmp_path: Path) -> None:
    repo = tmp_path / "pi"
    sha = _init_repo(
        repo,
        {
            "package.json": json.dumps(
                {
                    "name": "pi-monorepo",
                    "private": True,
                    "version": "0.0.1-private",
                    "workspaces": ["packages/*"],
                }
            ),
            "packages/ai/package.json": json.dumps(
                {"name": "@earendil-works/pi-ai", "version": "1.6.0"}
            ),
            "packages/coding-agent/package.json": json.dumps(
                {"name": "@earendil-works/pi-coding-agent", "version": "1.6.0"}
            ),
        },
        tags=("v1.6.0",),
    )
    resolved = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40earendil-works/pi-ai@1.6.0",
            repository="https://github.com/earendil-works/pi",
            commit=sha,
        ),
        repo,
    )
    assert resolved.module_path == "packages/ai"
    assert resolved.verification.strategy is ComponentTargetStrategy.WORKSPACE_PACKAGE
    assert "packages/ai/package.json" in resolved.verification.manifest_paths

    # Matching only the private root version must be rejected.
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolver().resolve(
            ComponentTargetRequest(
                purl="pkg:npm/%40earendil-works/pi-ai@0.0.1-private",
                repository="https://github.com/earendil-works/pi",
                commit=sha,
            ),
            repo,
        )
    assert exc.value.reason == UnresolvedTargetReason.VERSION_MISMATCH

    with pytest.raises(UnresolvedTargetError) as root_exc:
        _resolver().resolve(
            ComponentTargetRequest(
                purl="pkg:npm/pi-monorepo@0.0.1-private",
                repository="https://github.com/earendil-works/pi",
                commit=sha,
            ),
            repo,
        )
    assert root_exc.value.reason == UnresolvedTargetReason.PRIVATE_ROOT_ONLY


def test_unresolved_rejects_dir_name_only_default_branch_and_conflicts(tmp_path: Path) -> None:
    repo = tmp_path / "monorepo"
    sha = _init_repo(
        repo,
        {
            # Directory name matches "spring-beans" but there is no manifest declaring it.
            "spring-beans/Cache.java": "class Cache {}\n",
            "libs/core/pyproject.toml": '[project]\nname = "demo-core"\nversion = "2.0.0"\n',
        },
        tags=("demo-core==2.0.0",),
    )
    resolver = _resolver()

    with pytest.raises(UnresolvedTargetError) as dir_only:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:maven/org.springframework/spring-beans@7.1.0",
                repository="https://github.com/example/monorepo",
                commit=sha,
            ),
            repo,
        )
    assert dir_only.value.reason == UnresolvedTargetReason.NO_MANIFEST_MATCH

    with pytest.raises(UnresolvedTargetError) as default_branch:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:pypi/demo-core@2.0.0",
                repository="https://github.com/example/monorepo",
                ref_kind="default",
            ),
            repo,
        )
    assert default_branch.value.reason == UnresolvedTargetReason.DEFAULT_BRANCH_DISALLOWED

    with pytest.raises(UnresolvedTargetError) as unversioned:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:pypi/demo-core",
                repository="https://github.com/example/monorepo",
                commit=sha,
            ),
            repo,
        )
    assert unversioned.value.reason == UnresolvedTargetReason.MISSING_VERSION

    with pytest.raises(UnresolvedTargetError) as path_conflict:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:pypi/demo-core@2.0.0",
                repository="https://github.com/example/monorepo",
                commit=sha,
                module_path="libs/wrong",
            ),
            repo,
        )
    assert path_conflict.value.reason == UnresolvedTargetReason.SUPPLIED_PATH_CONFLICT

    with pytest.raises(UnresolvedTargetError) as tag_conflict:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:pypi/demo-core@2.0.0",
                repository="https://github.com/example/monorepo",
                commit="0" * 40,
                release_ref="demo-core==2.0.0",
            ),
            repo,
        )
    assert tag_conflict.value.reason == UnresolvedTargetReason.TAG_COMMIT_MISMATCH


@pytest.mark.parametrize(
    ("settings_file", "settings_body", "module_file"),
    [
        (
            "settings.gradle",
            'include "spring-core", "spring-beans", "spring-context"\n',
            "spring-context/spring-context.gradle",
        ),
        (
            "settings.gradle.kts",
            'include(\n    ":spring-core",\n    ":spring-beans",\n    ":spring-context",\n)\n',
            "spring-context/spring-context.gradle.kts",
        ),
    ],
)
def test_scripted_gradle_builds_fail_closed_as_unresolved(
    tmp_path: Path, settings_file: str, settings_body: str, module_file: str
) -> None:
    repo = tmp_path / "gradle-scripted"
    sha = _init_repo(
        repo,
        {
            "gradle.properties": "version=7.1.0\ngroup=org.springframework\n",
            settings_file: settings_body,
            module_file: 'description = "Spring Context"\n',
        },
        tags=("v7.1.0",),
    )
    with pytest.raises(UnresolvedTargetError) as exc:
        _resolver().resolve(
            ComponentTargetRequest(
                purl="pkg:maven/org.springframework/spring-context@7.1.0",
                repository="https://github.com/spring-projects/spring-framework",
                commit=sha,
                module_path="spring-context",
            ),
            repo,
        )
    assert exc.value.reason == UnresolvedTargetReason.NO_MANIFEST_MATCH


def test_pnpm_workspace_yaml_resolves_via_injected_yaml_loader(tmp_path: Path) -> None:
    repo = tmp_path / "pnpm-mono"
    sha = _init_repo(
        repo,
        {
            "package.json": json.dumps({"name": "root", "private": True, "version": "0.0.0"}),
            "pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n  - '!packages/ignored'\n",
            "packages/sdk/package.json": json.dumps({"name": "@acme/sdk", "version": "3.2.1"}),
            "packages/ignored/package.json": json.dumps(
                {"name": "@acme/ignored", "version": "3.2.1"}
            ),
        },
        tags=("v3.2.1",),
    )
    resolved = _resolver().resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40acme/sdk@3.2.1",
            repository="https://github.com/acme/pnpm-mono",
            commit=sha,
        ),
        repo,
    )
    assert resolved.module_path == "packages/sdk"
    assert resolved.verification.strategy is ComponentTargetStrategy.WORKSPACE_PACKAGE
    assert "pnpm-workspace.yaml" in resolved.verification.manifest_paths


def test_maven_parent_requires_all_three_coordinates_and_respects_empty_relative_path(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "maven-parent-guards"
    sha = _init_repo(
        repo,
        {
            "pom.xml": (
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>org.example</groupId><artifactId>parent</artifactId>"
                "<version>2.0.0</version><packaging>pom</packaging>"
                "<properties><release.version>2.0.0</release.version></properties>"
                "</project>\n"
            ),
            # Parent version mismatch (1.0.0 != 2.0.0): must NOT borrow root ${release.version}.
            "bad-ver/pom.xml": (
                "<project><parent><groupId>org.example</groupId><artifactId>parent</artifactId>"
                "<version>1.0.0</version></parent>"
                "<artifactId>bad-ver</artifactId>"
                "<version>${release.version}</version></project>\n"
            ),
            # Empty <relativePath/> disables local parent lookup even when coordinates match.
            "no-local/pom.xml": (
                "<project><parent><groupId>org.example</groupId><artifactId>parent</artifactId>"
                "<version>2.0.0</version><relativePath/></parent>"
                "<artifactId>no-local</artifactId>"
                "<version>${release.version}</version></project>\n"
            ),
            # Nested module with explicit <relativePath> and matching 3 coordinates resolves.
            "services/good/pom.xml": (
                "<project><parent><groupId>org.example</groupId><artifactId>parent</artifactId>"
                "<version>2.0.0</version><relativePath>../../pom.xml</relativePath></parent>"
                "<artifactId>good</artifactId></project>\n"
            ),
        },
        tags=("v2.0.0",),
    )
    resolver = _resolver()

    with pytest.raises(UnresolvedTargetError) as bad_ver:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:maven/org.example/bad-ver@2.0.0",
                repository="https://github.com/example/maven-parent-guards",
                commit=sha,
            ),
            repo,
        )
    assert bad_ver.value.reason == UnresolvedTargetReason.VERSION_MISMATCH

    with pytest.raises(UnresolvedTargetError) as no_local:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:maven/org.example/no-local@2.0.0",
                repository="https://github.com/example/maven-parent-guards",
                commit=sha,
            ),
            repo,
        )
    assert no_local.value.reason == UnresolvedTargetReason.VERSION_MISMATCH

    good = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:maven/org.example/good@2.0.0",
            repository="https://github.com/example/maven-parent-guards",
            commit=sha,
        ),
        repo,
    )
    assert good.module_path == "services/good"
    assert good.verification.strategy is ComponentTargetStrategy.SHARED_RELEASE
    assert good.verification.manifest_paths == ("pom.xml", "services/good/pom.xml")


def test_npm_workspace_single_star_does_not_match_nested_fixture_package(tmp_path: Path) -> None:
    repo = tmp_path / "npm-glob"
    sha = _init_repo(
        repo,
        {
            "package.json": json.dumps(
                {
                    "name": "root",
                    "private": True,
                    "version": "0.0.0",
                    "workspaces": ["packages/*", "deep/**"],
                }
            ),
            "packages/ai/package.json": json.dumps({"name": "@acme/ai", "version": "1.0.0"}),
            # Nested under packages/ai/examples — must NOT match single-segment `packages/*`.
            "packages/ai/examples/demo/package.json": json.dumps(
                {"name": "@acme/demo", "version": "1.0.0"}
            ),
            # Nested under deep/** — MUST match multi-segment `**`.
            "deep/a/b/package.json": json.dumps({"name": "@acme/deep-pkg", "version": "1.0.0"}),
        },
        tags=("unrelated-tag",),
    )
    resolver = _resolver()

    with pytest.raises(UnresolvedTargetError) as nested:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:npm/%40acme/demo@1.0.0",
                repository="https://github.com/acme/npm-glob",
                commit=sha,
            ),
            repo,
        )
    assert nested.value.reason == UnresolvedTargetReason.NO_MANIFEST_MATCH

    deep = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:npm/%40acme/deep-pkg@1.0.0",
            repository="https://github.com/acme/npm-glob",
            commit=sha,
        ),
        repo,
    )
    assert deep.module_path == "deep/a/b"
    assert deep.verification.strategy is ComponentTargetStrategy.WORKSPACE_PACKAGE


def test_component_commit_rejects_64_hex_and_normalizes_uppercase(tmp_path: Path) -> None:
    repo = tmp_path / "sha-pin"
    sha = _init_repo(
        repo,
        {"libs/core/pyproject.toml": '[project]\nname = "demo-core"\nversion = "1.0.0"\n'},
        tags=("demo-core==1.0.0",),
    )
    sha64 = "a" * 64
    resolver = _resolver()

    with pytest.raises(UnresolvedTargetError) as bad64:
        resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:pypi/demo-core@1.0.0",
                repository="https://github.com/example/sha-pin",
                commit=sha64,
            ),
            repo,
        )
    assert bad64.value.reason == UnresolvedTargetReason.MISSING_PIN

    with pytest.raises(PydanticValidationError, match="40-char SHA"):
        ComponentTarget(
            purl="pkg:pypi/demo-core@1.0.0",
            repository="https://github.com/example/sha-pin",
            commit=sha64,
            module_path="libs/core",
            verification=ComponentTargetVerification(
                strategy=ComponentTargetStrategy.PACKAGE_RELEASE,
                manifest_paths=("libs/core/pyproject.toml",),
            ),
        )

    upper = resolver.resolve(
        ComponentTargetRequest(
            purl="pkg:pypi/demo-core@1.0.0",
            repository="https://github.com/example/sha-pin",
            commit=f"  {sha.upper()}  ",
        ),
        repo,
    )
    assert upper.commit == sha

    model = ComponentTarget(
        purl="pkg:pypi/demo-core@1.0.0",
        repository="https://github.com/example/sha-pin",
        commit=f" {sha.upper()} ",
        module_path="libs/core",
        verification=ComponentTargetVerification(
            strategy=ComponentTargetStrategy.PACKAGE_RELEASE,
            manifest_paths=("libs/core/pyproject.toml",),
        ),
    )
    assert model.commit == sha
