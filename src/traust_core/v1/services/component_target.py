"""Deterministic resolution and verification of component PURL targets against pinned checkouts.

Owns `deterministic-rules-placement`: neither CLI glue nor skills guess module paths or release
associations. Every resolution is verified from build/workspace metadata and git pin evidence.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from traust_core.v1.errors import UnresolvedTargetError, ValidationError
from traust_core.v1.models.component_target import (
    ComponentTarget,
    ComponentTargetRequest,
    ComponentTargetStrategy,
    ComponentTargetVerification,
    PackageManifestCandidate,
    ParsedPurl,
    UnresolvedTargetReason,
    normalize_component_commit,
    normalize_module_path,
)
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.package_manifests import PackageManifestScanner

_PKG_TAG_SEPARATORS = ("==", "@", "-v", "-", "/v", "/")


def _is_shared_release_tag(tag: str, version: str) -> bool:
    return tag in (version, f"v{version}", f"release-{version}", f"rel/{version}")


def _package_tag_names(purl: ParsedPurl) -> tuple[str, ...]:
    names = [purl.name]
    if purl.type == "pypi":
        names.extend([purl.package_id, purl.name.replace("_", "-"), purl.name.replace("-", "_")])
    elif purl.namespace:
        names.append(f"{purl.namespace}/{purl.name}")
    return tuple(dict.fromkeys(names))


def _is_package_release_tag(tag: str, purl: ParsedPurl) -> bool:
    for pkg in _package_tag_names(purl):
        for sep in _PKG_TAG_SEPARATORS:
            if tag == f"{pkg}{sep}{purl.version}":
                return True
    return False


def _conflicting_package_tag(tags: Sequence[str], purl: ParsedPurl) -> str | None:
    """Detect when a tag at the pinned commit releases this package at another version."""
    for tag in tags:
        for pkg in _package_tag_names(purl):
            for sep in ("==", "@"):
                prefix = f"{pkg}{sep}"
                if tag.startswith(prefix) and tag[len(prefix) :] != purl.version:
                    return tag
    return None


def _classify_candidate(
    candidate: PackageManifestCandidate,
    purl: ParsedPurl,
    tags: Sequence[str],
    requested_release_ref: str | None,
) -> tuple[ComponentTargetStrategy, str | None] | None:
    """Determine which verified release strategy applies, or None when evidence is insufficient."""
    if candidate.is_private:
        return None
    if candidate.version != purl.version:
        return None

    pkg_tag = next((t for t in tags if _is_package_release_tag(t, purl)), None)
    if pkg_tag is not None:
        return ComponentTargetStrategy.PACKAGE_RELEASE, requested_release_ref or pkg_tag

    shared_tag = next((t for t in tags if _is_shared_release_tag(t, purl.version)), None)
    if candidate.is_workspace_member and not candidate.inherits_root_version:
        # Public workspace member declaring its own version (Pi-style, or explicit workspace pkg).
        if candidate.ecosystem == "npm" or shared_tag is None:
            return ComponentTargetStrategy.WORKSPACE_PACKAGE, requested_release_ref or shared_tag
        return ComponentTargetStrategy.SHARED_RELEASE, requested_release_ref or shared_tag

    if shared_tag is not None:
        return ComponentTargetStrategy.SHARED_RELEASE, requested_release_ref or shared_tag

    return None


class ComponentTargetResolver:
    """Verifies that a versioned PURL maps deterministically to one module in a pinned tree."""

    def __init__(
        self,
        git: GitCheckout,
        scanner: PackageManifestScanner | None = None,
    ) -> None:
        self._git = git
        self._scanner = scanner or PackageManifestScanner()

    def resolve(self, request: ComponentTargetRequest, checkout: Path) -> ComponentTarget:
        purl = ParsedPurl.parse(request.purl)

        if request.ref_kind in ("default", "branch") and not request.commit:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.DEFAULT_BRANCH_DISALLOWED,
                f"mutable ref kind {request.ref_kind!r} without an immutable commit pin",
            )

        commit: str | None = None
        if request.commit:
            try:
                commit = normalize_component_commit(request.commit)
            except ValidationError as exc:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.MISSING_PIN,
                    f"commit must be a 40-char SHA, got {request.commit!r}",
                ) from exc
        release_ref = request.release_ref.strip() if request.release_ref else None
        if release_ref:
            tag_sha = self._git.resolve_tag(checkout, release_ref)
            if tag_sha is None:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.TAG_COMMIT_MISMATCH,
                    f"release tag {release_ref!r} not found in pinned checkout",
                )
            if commit is not None and commit != tag_sha:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.TAG_COMMIT_MISMATCH,
                    f"release tag {release_ref!r} points to {tag_sha}, not {commit}",
                )
            commit = tag_sha

        if commit is None:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.MISSING_PIN,
                "an immutable 40-char commit SHA or verified release tag is required",
            )

        head = self._git.head(checkout).lower()
        if head != commit:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.TAG_COMMIT_MISMATCH,
                f"checkout HEAD {head} does not match pinned commit {commit}",
            )

        tags = self._git.tags_at(checkout, commit)
        if conflict_tag := _conflicting_package_tag(tags, purl):
            raise UnresolvedTargetError(
                UnresolvedTargetReason.VERSION_MISMATCH,
                f"commit {commit} carries conflicting tag {conflict_tag!r} for {purl.raw}",
            )

        supplied_path: str | None = None
        if request.module_path is not None:
            supplied_path = normalize_module_path(request.module_path)
        elif purl.subpath is not None:
            supplied_path = purl.subpath

        candidates = self._scanner.scan(checkout)
        same_eco = [c for c in candidates if c.ecosystem == purl.type]
        matched_name = [c for c in same_eco if c.package_id == purl.package_id]

        if not matched_name:
            private_root_version_match = [
                c
                for c in same_eco
                if c.is_workspace_root and c.is_private and c.version == purl.version
            ]
            if private_root_version_match:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.PRIVATE_ROOT_ONLY,
                    f"only private workspace root matches version {purl.version} for {purl.raw}",
                )
            raise UnresolvedTargetError(
                UnresolvedTargetReason.NO_MANIFEST_MATCH,
                f"no manifest declares {purl.package_id!r} ({purl.type}) at {commit}",
            )

        if all(c.is_private and c.is_workspace_root for c in matched_name):
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PRIVATE_ROOT_ONLY,
                f"{purl.raw} matches only a private workspace root manifest",
            )

        verified: list[tuple[PackageManifestCandidate, ComponentTargetStrategy, str | None]] = []
        version_mismatch = False
        for cand in matched_name:
            if cand.is_private:
                continue
            if cand.version != purl.version:
                version_mismatch = True
                continue
            classified = _classify_candidate(cand, purl, tags, release_ref)
            if classified is not None:
                verified.append((cand, classified[0], classified[1]))

        if not verified:
            if version_mismatch:
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.VERSION_MISMATCH,
                    f"manifest version for {purl.package_id!r} != {purl.version!r} at {commit}",
                )
            raise UnresolvedTargetError(
                UnresolvedTargetReason.NO_MANIFEST_MATCH,
                f"release/build metadata at {commit} does not verify {purl.raw}",
            )

        if supplied_path is not None:
            narrowed = [item for item in verified if item[0].module_path == supplied_path]
            if not narrowed:
                found_paths = ", ".join(sorted(item[0].module_path for item in verified))
                raise UnresolvedTargetError(
                    UnresolvedTargetReason.SUPPLIED_PATH_CONFLICT,
                    f"supplied module_path {supplied_path!r} conflicts with {found_paths}",
                )
            verified = narrowed

        if len(verified) > 1:
            found_paths = ", ".join(sorted(item[0].module_path for item in verified))
            raise UnresolvedTargetError(
                UnresolvedTargetReason.AMBIGUOUS_MODULE_MATCH,
                f"{purl.raw} matched multiple modules at {commit}: {found_paths}",
            )

        cand, strategy, matched_ref = verified[0]
        if cand.module_path == ".":
            raise UnresolvedTargetError(
                UnresolvedTargetReason.NO_MANIFEST_MATCH,
                f"{purl.raw} resolved to repo root; whole-repository audits are separate",
            )

        return ComponentTarget(
            purl=purl.raw,
            repository=request.repository,
            commit=commit,
            module_path=cand.module_path,
            release_ref=matched_ref,
            verification=ComponentTargetVerification(
                strategy=strategy,
                manifest_paths=cand.manifest_paths,
            ),
        )
