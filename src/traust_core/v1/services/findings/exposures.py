"""A dependency finding's identity: the exposure key (repository, advisory, package) that an
impact analysis and a report both mint, so one advisory reaching one package in one
repository is one finding, whichever records first."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from traust_core.v1.models.dependencies import Advisory, Ecosystem, package_name
from traust_core.v1.models.findings import ExposureKey, FindingCandidate

if TYPE_CHECKING:
    from uuid import UUID

    from traust_core.v1.repositories.contract import TraustUnitOfWork


def stored_name(ecosystem: str, module: str) -> str:
    """The package name as core stores it for its ecosystem (`package_name`): PyPI names
    compare normalised, npm names lower-case; other ecosystems keep their spelling."""
    try:
        return package_name(Ecosystem(ecosystem), module)
    except ValueError:
        return module


def exposure_key(advisory: Advisory, ecosystem: str, module: str) -> ExposureKey:
    """The key both an impact analysis and a report use, the package spelled as core stores it."""
    assert advisory.id is not None
    return ExposureKey(
        advisory_id=advisory.id,
        advisory=advisory.identifier,
        ecosystem=ecosystem,
        package=stored_name(ecosystem, module),
    )


class StoredAdvisories:
    """What core keeps about an advisory: a read, never a fetch."""

    def __init__(self, uow: TraustUnitOfWork) -> None:
        self._uow = uow

    def canonical(self, identifier: str) -> Advisory | None:
        """The canonical advisory a stored identifier or alias names."""
        with self._uow as uow:
            found = uow.advisories.find_by_identifier(identifier)
            if found is None or found.alias_of_id is None:
                return found
            return uow.advisories.get(found.alias_of_id)

    def ecosystem_of(self, advisory_id: UUID, module: str) -> str | None:
        """The one ecosystem in which the stored advisory names `module`; None when it names
        the module in none or in more than one, so an ecosystem is never guessed."""
        with self._uow as uow:
            packages = (
                uow.packages.get(link.package_id)
                for link in uow.advisory_packages.list_for_advisory(advisory_id)
            )
            ecosystems = {
                p.ecosystem
                for p in packages
                if p is not None
                and stored_name(p.ecosystem, p.name) == stored_name(p.ecosystem, module)
            }
        return ecosystems.pop() if len(ecosystems) == 1 else None


def with_exposures(
    doc: Any, candidates: Sequence[FindingCandidate], advisories: StoredAdvisories
) -> list[FindingCandidate]:
    """A report finding whose `dependency` names a stored advisory and its module is identified
    as the dependency finding an impact analysis files for it. An omitted ecosystem is taken
    from the stored advisory only when it names the module in exactly one; a dependency
    naming an advisory core doesn't keep stays fingerprinted as reported. Recording and the
    settling of held moves both call this, so a candidate has one identity in either."""
    stated = {
        str(e.id): e.dependency
        for e in getattr(doc, "findings", None) or ()
        if getattr(e, "dependency", None) is not None
    }
    if not stated:
        return list(candidates)
    out = []
    for candidate in candidates:
        dependency = stated.get(str(candidate.label))
        if dependency is None or candidate.exposure is not None or not dependency.module:
            out.append(candidate)
            continue
        canonical = advisories.canonical(dependency.advisory)
        ecosystem = (
            str(dependency.ecosystem)
            if dependency.ecosystem
            else advisories.ecosystem_of(canonical.id, dependency.module)
            if canonical is not None and canonical.id is not None
            else None
        )
        if canonical is None or ecosystem is None:
            out.append(candidate)
            continue
        key = exposure_key(canonical, ecosystem, dependency.module)
        out.append(candidate.model_copy(update={"exposure": key}))
    return out
