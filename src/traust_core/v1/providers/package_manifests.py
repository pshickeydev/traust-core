"""Deterministic declarative manifest extraction from a pinned repository tree.

Reads declarative Maven (`pom.xml`), Python (`pyproject.toml`), and npm/pnpm/yarn workspace
(`package.json`, `pnpm-workspace.yaml`) metadata without executing repo code or following symlinks
outside the checkout root. Scripted build DSLs (e.g. Gradle Groovy/Kotlin, Bazel, `setup.py`) are
intentionally not regex-parsed and fail closed when no declarative manifest verifies the target.
"""

from __future__ import annotations

import fnmatch
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.component_target import PackageManifestCandidate
from traust_core.v1.models.purl import canonical_package_id
from traust_core.v1.providers.tree import SKIP_DIRS as TREE_SKIP_DIRS
from traust_core.v1.providers.tree import TreeFile, tree_files

YamlLoader = Callable[[str], list[object]]

SKIP_DIRS = TREE_SKIP_DIRS | frozenset({"target"})

_XML_PROP = re.compile(r"\$\{([^}]+)\}")


def _read_text(entry: TreeFile) -> str | None:
    try:
        return entry.text
    except ServiceError:
        return None


def _rel_dir(rel: str) -> str:
    parent, sep, _ = rel.rpartition("/")
    return parent if sep and parent else "."


def _xml_tag(elem: ET.Element) -> str:
    return elem.tag.rsplit("}", 1)[-1]


def _xml_child_text(parent: ET.Element, name: str) -> str | None:
    for child in parent:
        if _xml_tag(child) == name and child.text and child.text.strip():
            return child.text.strip()
    return None


def _xml_properties(root_el: ET.Element) -> dict[str, str]:
    props: dict[str, str] = {}
    for child in root_el:
        if _xml_tag(child) == "properties":
            for prop in child:
                if prop.text and prop.text.strip():
                    props[_xml_tag(prop)] = prop.text.strip()
    return props


def _resolve_maven_prop(value: str | None, props: dict[str, str]) -> str | None:
    if value is None:
        return None
    resolved = _XML_PROP.sub(lambda m: props.get(m.group(1), m.group(0)), value)
    return None if "${" in resolved else resolved


def _resolve_maven_parent_rel(mod_dir: str, relative_path: str) -> str | None:
    """Resolve a Maven `<relativePath>` against `mod_dir` without escaping the checkout root."""
    parts = [] if mod_dir == "." else mod_dir.split("/")
    for seg in relative_path.replace("\\", "/").split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(seg)
    if not parts:
        return "pom.xml"
    if parts[-1].endswith(".xml"):
        return "/".join(parts)
    return "/".join((*parts, "pom.xml"))


def _scan_maven(files: list[TreeFile]) -> list[PackageManifestCandidate]:
    poms = [f for f in files if f.name == "pom.xml"]
    if not poms:
        return []
    parsed_by_rel: dict[str, tuple[str, ET.Element, dict[str, str]]] = {}
    for pom in poms:
        text = _read_text(pom)
        if text is None:
            continue
        try:
            el = ET.fromstring(text)
        except ET.ParseError:
            continue
        parsed_by_rel[pom.rel] = (_rel_dir(pom.rel), el, _xml_properties(el))

    coords_by_rel: dict[str, tuple[str | None, str | None, str | None]] = {}
    for rel_path, (_, el, props) in parsed_by_rel.items():
        p_el = next((c for c in el if _xml_tag(c) == "parent"), None)
        g = _xml_child_text(el, "groupId") or (
            _xml_child_text(p_el, "groupId") if p_el is not None else None
        )
        a = _xml_child_text(el, "artifactId")
        raw_v = _xml_child_text(el, "version")
        if raw_v is not None:
            v = _resolve_maven_prop(raw_v, props)
        else:
            v = (
                _resolve_maven_prop(_xml_child_text(p_el, "version"), props)
                if p_el is not None
                else None
            )
        coords_by_rel[rel_path] = (g, a, v)

    candidates: list[PackageManifestCandidate] = []
    for rel_path, (mod_dir, el, local_props) in sorted(parsed_by_rel.items()):
        parent_el = next((c for c in el if _xml_tag(c) == "parent"), None)
        parent_group = _xml_child_text(parent_el, "groupId") if parent_el is not None else None
        parent_artifact = (
            _xml_child_text(parent_el, "artifactId") if parent_el is not None else None
        )
        raw_parent_version = (
            _xml_child_text(parent_el, "version") if parent_el is not None else None
        )

        matched_parent_rel: str | None = None
        parent_version: str | None = None
        if parent_el is not None and parent_group and parent_artifact and raw_parent_version:
            rel_el = next((c for c in parent_el if _xml_tag(c) == "relativePath"), None)
            if rel_el is None:
                target_rel = _resolve_maven_parent_rel(mod_dir, "../pom.xml")
            elif rel_el.text and rel_el.text.strip():
                target_rel = _resolve_maven_parent_rel(mod_dir, rel_el.text.strip())
            else:
                # Explicit empty `<relativePath/>` disables local parent lookup in Maven.
                target_rel = None
            if target_rel is not None and target_rel != rel_path and target_rel in parsed_by_rel:
                candidate_props = {**parsed_by_rel[target_rel][2], **local_props}
                candidate_parent_version = _resolve_maven_prop(raw_parent_version, candidate_props)
                if candidate_parent_version is not None and coords_by_rel[target_rel] == (
                    parent_group,
                    parent_artifact,
                    candidate_parent_version,
                ):
                    matched_parent_rel = target_rel
                    parent_version = candidate_parent_version
            if matched_parent_rel is None:
                parent_version = _resolve_maven_prop(raw_parent_version, local_props)

        parent_props = parsed_by_rel[matched_parent_rel][2] if matched_parent_rel else {}
        props = {**parent_props, **local_props}
        artifact_id = _xml_child_text(el, "artifactId")
        group_id = _xml_child_text(el, "groupId") or parent_group
        raw_explicit_version = _xml_child_text(el, "version")
        if raw_explicit_version is not None:
            version = _resolve_maven_prop(raw_explicit_version, props)
            inherits = False
        else:
            version = parent_version
            inherits = matched_parent_rel is not None
        if not artifact_id or not group_id:
            continue
        manifests = [rel_path]
        if matched_parent_rel is not None:
            manifests.append(matched_parent_rel)
        candidates.append(
            PackageManifestCandidate(
                ecosystem="maven",
                package_id=canonical_package_id("maven", group_id, artifact_id),
                version=version,
                module_path=mod_dir,
                manifest_paths=tuple(sorted(set(manifests))),
                is_workspace_root=(mod_dir == "."),
                is_workspace_member=(mod_dir != "."),
                inherits_root_version=inherits,
            )
        )
    return candidates


def _scan_pyproject(files: list[TreeFile]) -> list[PackageManifestCandidate]:
    candidates: list[PackageManifestCandidate] = []
    for entry in files:
        if entry.name != "pyproject.toml":
            continue
        text = _read_text(entry)
        if text is None:
            continue
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            continue
        raw_project = data.get("project")
        project: dict[str, Any] = raw_project if isinstance(raw_project, dict) else {}
        raw_tool = data.get("tool")
        raw_poetry = raw_tool.get("poetry") if isinstance(raw_tool, dict) else None
        poetry: dict[str, Any] = raw_poetry if isinstance(raw_poetry, dict) else {}
        name = project.get("name") or poetry.get("name")
        version = project.get("version") or poetry.get("version")
        if not isinstance(name, str) or not name.strip():
            continue
        ver_str = version.strip() if isinstance(version, str) and version.strip() else None
        mod_dir = _rel_dir(entry.rel)
        candidates.append(
            PackageManifestCandidate(
                ecosystem="pypi",
                package_id=canonical_package_id("pypi", None, name.strip()),
                version=ver_str,
                module_path=mod_dir,
                manifest_paths=(entry.rel,),
                is_workspace_root=(mod_dir == "."),
                is_workspace_member=(mod_dir != "."),
            )
        )
    return candidates


def _workspace_globs(
    files: list[TreeFile], load_yaml: YamlLoader | None
) -> tuple[list[str], list[str]]:
    by_rel = {f.rel: f for f in files}
    patterns: list[str] = []
    manifests: list[str] = []
    if "package.json" in by_rel:
        text = _read_text(by_rel["package.json"])
        if text:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            ws = data.get("workspaces") if isinstance(data, dict) else None
            raw_list: list[Any] = (
                ws
                if isinstance(ws, list)
                else (ws.get("packages", []) if isinstance(ws, dict) else [])
            )
            if raw_list:
                manifests.append("package.json")
                patterns.extend(
                    str(p).strip().rstrip("/") for p in raw_list if isinstance(p, str) and p.strip()
                )
    if "pnpm-workspace.yaml" in by_rel:
        if load_yaml is None:
            raise ConfigError(
                "pnpm-workspace.yaml requires a YAML loader "
                "(inject context.documents.yaml_documents)"
            )
        text = _read_text(by_rel["pnpm-workspace.yaml"])
        if text:
            try:
                docs = load_yaml(text)
            except ValidationError:
                docs = []
            first = docs[0] if docs and isinstance(docs[0], dict) else {}
            raw_pkgs = first.get("packages")
            pkgs = (
                [str(p).strip().rstrip("/") for p in raw_pkgs if isinstance(p, str) and p.strip()]
                if isinstance(raw_pkgs, list)
                else []
            )
            if pkgs:
                manifests.append("pnpm-workspace.yaml")
                patterns.extend(pkgs)
    return patterns, manifests


def _match_segments(parts: tuple[str, ...], pats: tuple[str, ...]) -> bool:
    if not pats:
        return not parts
    head, rest = pats[0], pats[1:]
    if head == "**":
        return _match_segments(parts, rest) or (bool(parts) and _match_segments(parts[1:], pats))
    if not parts:
        return False
    return fnmatch.fnmatchcase(parts[0], head) and _match_segments(parts[1:], rest)


def _matches_workspace(mod_dir: str, patterns: list[str]) -> bool:
    if mod_dir == "." or not patterns:
        return False
    mod_parts = tuple(p for p in mod_dir.split("/") if p)
    included = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        pat = pattern[1:] if negated else pattern
        pat_parts = tuple(p for p in pat.strip("/").split("/") if p and p != ".")
        if pat_parts and _match_segments(mod_parts, pat_parts):
            included = not negated
    return included


def _scan_npm(
    files: list[TreeFile], load_yaml: YamlLoader | None
) -> list[PackageManifestCandidate]:
    pkg_files = [f for f in files if f.name == "package.json"]
    if not pkg_files:
        return []
    ws_patterns, ws_manifests = _workspace_globs(files, load_yaml)
    candidates: list[PackageManifestCandidate] = []
    for entry in pkg_files:
        text = _read_text(entry)
        if text is None:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        raw_version = data.get("version")
        version = (
            raw_version.strip() if isinstance(raw_version, str) and raw_version.strip() else None
        )
        is_private = bool(data.get("private") is True)
        mod_dir = _rel_dir(entry.rel)
        is_root = mod_dir == "."
        is_member = _matches_workspace(mod_dir, ws_patterns)
        manifests = [entry.rel]
        if is_member:
            manifests.extend(ws_manifests)
        ns, pkg_name = (
            (name.strip().split("/", 1)[0], name.strip().split("/", 1)[1])
            if name.strip().startswith("@") and "/" in name.strip()
            else (None, name.strip())
        )
        candidates.append(
            PackageManifestCandidate(
                ecosystem="npm",
                package_id=canonical_package_id("npm", ns, pkg_name),
                version=version,
                module_path=mod_dir,
                manifest_paths=tuple(sorted(set(manifests))),
                is_private=is_private,
                is_workspace_root=is_root,
                is_workspace_member=is_member,
            )
        )
    return candidates


class PackageManifestScanner:
    """Reads build and workspace manifests from a pinned local checkout."""

    def __init__(self, load_yaml: YamlLoader | None = None) -> None:
        self._load_yaml = load_yaml

    def scan(self, checkout: Path) -> list[PackageManifestCandidate]:
        files = tree_files(checkout, skip=SKIP_DIRS)
        return [
            *_scan_maven(files),
            *_scan_pyproject(files),
            *_scan_npm(files, self._load_yaml),
        ]
