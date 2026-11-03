"""A checkout's manifest SBOM from syft (CycloneDX JSON): the standard tool, never a custom
manifest parser."""

from __future__ import annotations

import json
import os
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.common import RepoPath
from traust_core.v1.models.dependencies import UnresolvedManifest
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, Readiness, Result, argv_digest
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools import DatabaseStatus, NoDatabase, ToolRequest
from traust_core.v1.providers.tree import SKIP_DIRS

# npm devDependencies count, as the retired portfolio graph counted them: without this syft
# drops them from package-lock (not from yarn.lock), measured 2026-10-28 (dependencies log).
_ENV = {"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"}

# The files syft's directory catalogers read (syft 1.51): an archive checkout keeps only these.
# Measured 2026-10-28 on 60 repositories: 53,881 of 53,884 packages, the rest from checked-in
# binaries (continuous-ops evidence 19). Re-measure after a syft upgrade.
MANIFESTS: tuple[str, ...] = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "action.yml",
    "action.yaml",
    "go.mod",
    "go.sum",
    "go.work",
    "go.work.sum",
    "modules.txt",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "requirements*.txt",
    "*requirements.txt",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "METADATA",
    "PKG-INFO",
    "RECORD",
    "top_level.txt",
    "direct_url.json",
    "pom.xml",
    "*.pom",
    "gradle.lockfile*",
    "*.gradle",
    "*.gradle.kts",
    "pom.properties",
    "*.jar",
    "*.war",
    "*.ear",
    "*.par",
    "*.sar",
    "*.nar",
    "*.jpi",
    "*.hpi",
    "*.lpkg",
    "Cargo.lock",
    "Cargo.toml",
    "Gemfile",
    "Gemfile.lock",
    "*.gemspec",
    "packages.lock.json",
    "*.deps.json",
    "*.csproj",
    "packages.config",
    "composer.lock",
    "installed.json",
    "composer.json",
    "pubspec.lock",
    "pubspec.yaml",
    "mix.lock",
    "rebar.lock",
    "stack.yaml",
    "stack.yaml.lock",
    "cabal.project.freeze",
    "Package.resolved",
    "Podfile.lock",
    "conanfile.txt",
    "conanfile.py",
    "conan.lock",
    "*.rockspec",
    "DESCRIPTION",
    "*.opam",
    ".terraform.lock.hcl",
    "Chart.yaml",
    "Chart.lock",
)


class SyftSbom:
    name = "syft"

    def __init__(self, process: ProcessRunner, clock: Clock) -> None:
        self._process = process
        self._clock = clock

    def check(self) -> Readiness:
        return self._process.readiness(self.name)

    def acquire(self, request: ToolRequest) -> Result[bytes]:
        workspace = request.checkout()
        run = self._process.run(
            [self.name, "-q", f"dir:{workspace}", "-o", "cyclonedx-json"], check=False, env=_ENV
        )
        if run.returncode != 0:
            tail = run.stderr.decode(errors="replace").strip()[-300:] or "no stderr"
            raise ServiceError(f"syft exited {run.returncode}: {tail}")
        version = _tool_version(run.stdout)
        return Result(
            run.stdout,
            Acquisition(
                provider=self.name,
                acquired_at=self._clock.now(),
                source=str(workspace),
                version=version,
                argv_sha256=argv_digest(run.argv),
            ),
        )

    def version(self) -> str | None:
        run = self._process.run([self.name, "version", "-o", "json"])
        try:
            return str(json.loads(run.stdout)["version"])
        except (ValueError, KeyError, TypeError) as e:
            raise ServiceError(f"syft version wrote no version: {e}") from e

    def database(self) -> DatabaseStatus | None:
        return None

    def update_database(self) -> DatabaseStatus:
        raise NoDatabase(f"{self.name} keeps no database to update")


def _tool_version(raw: bytes) -> str | None:
    try:
        tools = json.loads(raw)["metadata"]["tools"]
    except (ValueError, KeyError, TypeError) as e:
        raise ServiceError(f"syft wrote no CycloneDX metadata: {e}") from e
    listed = tools.get("components", []) if isinstance(tools, dict) else tools
    return next((str(t["version"]) for t in listed if t.get("name") == "syft"), None)


def _json_deps(text: str) -> bool:
    doc = json.loads(text)
    keys = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    return isinstance(doc, dict) and any(doc.get(k) for k in keys)


def _pyproject_deps(text: str) -> bool:
    doc = tomllib.loads(text)
    poetry = doc.get("tool", {}).get("poetry", {}).get("dependencies", {})
    return bool(doc.get("project", {}).get("dependencies")) or bool(set(poetry) - {"python"})


def _cargo_deps(text: str) -> bool:
    doc = tomllib.loads(text)
    tables = ("dependencies", "dev-dependencies", "build-dependencies")
    return any(doc.get(t) for t in tables) or bool(doc.get("workspace", {}).get("dependencies"))


def _requirements(name: str) -> bool:
    return name.endswith(".txt") and "requirements" in name


@dataclass(frozen=True)
class _Locked:
    """A manifest whose versions syft reads only from a lockfile (syft 1.51), the files that pin
    it, and whether one above it counts (workspaces lock at their root; a project file's
    packages.lock.json sits beside it). Measured gaps: dependencies log 2026-10-28."""

    ecosystem: Ecosystem
    manifest: Callable[[str], bool]
    declares: Callable[[str], bool]
    locks: frozenset[str]
    above: bool = True
    beside: Callable[[str], bool] = lambda _: False


_LOCKED = (
    _Locked(Ecosystem.NPM, lambda n: n == "package.json", _json_deps,
            frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                       "bun.lock"})),
    _Locked(Ecosystem.PYPI, lambda n: n == "pyproject.toml", _pyproject_deps,
            frozenset({"poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"}),
            beside=_requirements),
    _Locked(Ecosystem.PYPI, lambda n: n == "Pipfile", lambda _: True, frozenset({"Pipfile.lock"}),
            above=False),
    _Locked(Ecosystem.CARGO, lambda n: n == "Cargo.toml", _cargo_deps, frozenset({"Cargo.lock"})),
    _Locked(Ecosystem.RUBY, lambda n: n == "Gemfile", lambda _: True, frozenset({"Gemfile.lock"})),
    _Locked(Ecosystem.NUGET, lambda n: n.endswith((".csproj", ".fsproj", ".vbproj")),
            lambda text: "<PackageReference" in text, frozenset({"packages.lock.json"}),
            above=False),
)  # fmt: skip


def _declares(rule: _Locked, path: Path) -> bool:
    try:
        return rule.declares(path.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, tomllib.TOMLDecodeError):
        return True  # syft can't read it either: whatever it declares is unknown
    except OSError as e:
        raise ServiceError(f"cannot read manifest {path.name}: {e}") from e


def unresolved_manifests(workspace: Path) -> tuple[UnresolvedManifest, ...]:
    """The checkout's dependency manifests that declare dependencies with nothing to pin them:
    syft resolves them only through a lockfile, so their packages are missing from the SBOM.
    Vendored and generated trees are skipped, as the profilers skip them."""
    if not workspace.is_dir():
        raise ValidationError(f"workspace is not a directory: {workspace}")
    held: dict[PurePosixPath, set[str]] = {}
    for top, dirs, names in os.walk(workspace, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        held[PurePosixPath(Path(top).relative_to(workspace).as_posix())] = set(names)

    def locked(rule: _Locked, directory: PurePosixPath) -> bool:
        if any(n in rule.locks or rule.beside(n) for n in held[directory]):
            return True
        return rule.above and any(rule.locks & held.get(d, set()) for d in directory.parents)

    found = []
    for directory, names in sorted(held.items()):
        for name in sorted(names):
            path = workspace / directory / name
            if path.is_symlink() or not path.is_file():
                continue
            for rule in _LOCKED:
                if rule.manifest(name) and not locked(rule, directory) and _declares(rule, path):
                    rel = RepoPath((directory / name).as_posix())
                    found.append(UnresolvedManifest(ecosystem=rule.ecosystem, path=rel))
    return tuple(found)
