"""Canonical Package URL (PURL) parsing backed by `packageurl-python`.

One module owns the `packageurl` dependency and the PURL-type -> `Ecosystem` mapping; callers
validate extra constraints (such as mandatory `@version` on component audit targets) on top.
"""

from __future__ import annotations

from dataclasses import dataclass

from packageurl import PackageURL

from traust_core.v1.models.dependencies import package_name
from traust_core.v1.models.vocabulary import Ecosystem

PURL_ECOSYSTEMS: dict[str, Ecosystem] = {
    "golang": Ecosystem.GO,
    "npm": Ecosystem.NPM,
    "pypi": Ecosystem.PYPI,
    "maven": Ecosystem.MAVEN,
    "cargo": Ecosystem.CARGO,
    "gem": Ecosystem.RUBY,
    "nuget": Ecosystem.NUGET,
    "github": Ecosystem.ACTIONS,
    "githubactions": Ecosystem.ACTIONS,
    "docker": Ecosystem.DOCKER,
    "oci": Ecosystem.DOCKER,
    "helm": Ecosystem.HELM,
    "rpm": Ecosystem.RPM,
    "deb": Ecosystem.DEB,
    "apk": Ecosystem.APK,
}
# Distro PURLs carry the vendor as namespace (`pkg:deb/debian/openssl`); the package is `name`.
_VENDOR_NAMESPACE = frozenset({Ecosystem.RPM, Ecosystem.DEB, Ecosystem.APK})


def canonical_package_id(purl_type: str, namespace: str | None, name: str) -> str:
    """Canonical package identity normalized via `models.dependencies.package_name`."""
    kind = purl_type.lower()
    ecosystem = PURL_ECOSYSTEMS.get(kind)
    if kind == "maven":
        raw = f"{namespace.replace('/', '.')}:{name}" if namespace else name
    elif ecosystem in _VENDOR_NAMESPACE:
        raw = name
    else:
        raw = f"{namespace}/{name}" if namespace else name
    return package_name(ecosystem, raw) if ecosystem is not None else raw


@dataclass(frozen=True, slots=True)
class Purl:
    raw: str
    type: str
    namespace: str | None
    name: str
    version: str | None
    subpath: str | None

    @property
    def ecosystem(self) -> Ecosystem | None:
        return PURL_ECOSYSTEMS.get(self.type)

    @property
    def package_id(self) -> str:
        return canonical_package_id(self.type, self.namespace, self.name)


def parse_purl(raw: str) -> Purl:
    """Parse a PURL string via `packageurl-python`; raises `ValueError` on invalid input."""
    text = raw.strip()
    parsed = PackageURL.from_string(text)
    return Purl(
        raw=text,
        type=parsed.type,
        namespace=parsed.namespace or None,
        name=parsed.name,
        version=parsed.version or None,
        subpath=parsed.subpath or None,
    )


def try_parse_purl(raw: str) -> Purl | None:
    """`parse_purl`, returning `None` for empty or malformed PURLs."""
    if not raw or not raw.strip():
        return None
    try:
        return parse_purl(raw)
    except ValueError:
        return None
