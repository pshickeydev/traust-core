"""SyftSbom as a tool provider: the argv digest on its result, and its own version and database."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.providers.base import argv_digest
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.syft import SyftSbom, unresolved_manifests
from traust_core.v1.providers.tools import NoDatabase, ToolProvider, ToolRequest

AT = datetime(2026, 10, 26, tzinfo=UTC)
CDX = json.dumps({"metadata": {"tools": {"components": [{"name": "syft", "version": "1.51.1"}]}}})


class Runner:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout.encode()
        self.argv: list[str] = []
        self.env: dict[str, str] | None = None

    def run(
        self, argv: list[str], *, check: bool = True, env: dict[str, str] | None = None
    ) -> ProcessResult:
        self.argv, self.env = argv, env
        return ProcessResult(tuple(argv), 0, self.stdout, b"", 0.1)


def syft(stdout: str) -> SyftSbom:
    return SyftSbom(Runner(stdout), FixedClock(AT))  # type: ignore[arg-type]


def test_argv_digest_is_the_sha256_of_the_argv_as_a_json_array() -> None:
    expected = hashlib.sha256(b'["syft", "dir:a b"]').hexdigest()
    assert argv_digest(["syft", "dir:a b"]) == expected
    assert argv_digest(["syft", "dir:a", "b"]) != expected


def test_the_sbom_carries_the_digest_of_the_argv_it_ran(tmp_path: Path) -> None:
    tool = syft(CDX)
    found = tool.acquire(ToolRequest(workspace=tmp_path)).acquisition
    assert found.argv_sha256 == argv_digest(tool._process.argv)  # type: ignore[attr-defined]
    assert (found.version, found.db_built_at) == ("1.51.1", None)


def test_npm_dev_dependencies_are_in_the_sbom(tmp_path: Path) -> None:
    tool = syft(CDX)
    tool.acquire(ToolRequest(workspace=tmp_path))
    assert tool._process.env == {"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"}  # type: ignore[attr-defined]


def test_syft_reports_its_version_and_keeps_no_database() -> None:
    tool = syft(json.dumps({"application": "syft", "version": "1.51.1"}))
    assert isinstance(tool, ToolProvider)
    assert (tool.version(), tool.database()) == ("1.51.1", None)
    assert tool._process.argv == ["syft", "version", "-o", "json"]  # type: ignore[attr-defined]
    with pytest.raises(NoDatabase, match="syft keeps no database"):
        tool.update_database()


def test_an_unreadable_version_is_a_service_error() -> None:
    with pytest.raises(ServiceError, match="syft version wrote no version"):
        syft("{}").version()


@pytest.mark.parametrize(("allowed", "ready"), [(["syft"], True), (["git"], False)])
def test_syft_is_ready_only_when_the_allowlist_grants_it(
    monkeypatch: pytest.MonkeyPatch, allowed: list[str], ready: bool
) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/bin/syft")
    assert SyftSbom(ProcessRunner(allowed), FixedClock(AT)).check().ready is ready


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


PEP621 = '[project]\nname = "app"\ndependencies = ["requests>=2"]\n'
PACKAGE = json.dumps({"dependencies": {"lodash": "^4"}})
CSPROJ = '<Project><ItemGroup><PackageReference Include="X" Version="1" /></ItemGroup></Project>'


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ({}, []),
        ({"pyproject.toml": PEP621}, [("pypi", "pyproject.toml")]),
        ({"pyproject.toml": PEP621, "uv.lock": ""}, []),
        ({"pyproject.toml": PEP621, "requirements.txt": "requests==2.32.0\n"}, []),
        ({"pyproject.toml": '[project]\nname = "app"\n'}, []),  # declares nothing
        ({"pyproject.toml": "not = = toml"}, [("pypi", "pyproject.toml")]),  # unreadable
        ({"ui/package.json": PACKAGE}, [("npm", "ui/package.json")]),
        ({"ui/package.json": PACKAGE, "yarn.lock": ""}, []),  # a workspace lock above
        ({"ui/package.json": json.dumps({"name": "tool"})}, []),
        ({"vendor/x/package.json": PACKAGE, "node_modules/y/package.json": PACKAGE}, []),
        (
            {"crates/a/Cargo.toml": '[dependencies]\nserde = "1"\n'},
            [("cargo", "crates/a/Cargo.toml")],
        ),
        ({"crates/a/Cargo.toml": '[dependencies]\nserde = "1"\n', "Cargo.lock": ""}, []),
        ({"Gemfile": "gem 'rails'\n"}, [("ruby", "Gemfile")]),
        ({"Pipfile": "[packages]\n", "Pipfile.lock": "{}"}, []),
        ({"src/App/App.csproj": CSPROJ}, [("nuget", "src/App/App.csproj")]),
        # a project file's lock sits beside it, never above
        (
            {"src/App/App.csproj": CSPROJ, "packages.lock.json": "{}"},
            [("nuget", "src/App/App.csproj")],
        ),
        ({"src/App/App.csproj": "<Project />"}, []),
    ],
)
def test_manifests_with_nothing_to_pin_them_are_unresolved(
    tmp_path: Path, files: dict[str, str], expected: list[tuple[str, str]]
) -> None:
    found = unresolved_manifests(_tree(tmp_path, files))
    assert [(m.ecosystem, m.path) for m in found] == expected
    assert all(m.reason == "no-lockfile" for m in found)


def test_a_missing_workspace_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        unresolved_manifests(tmp_path / "missing")
