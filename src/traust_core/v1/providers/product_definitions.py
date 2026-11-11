"""The product-definitions registry's pull-through cache (`traust feeds fetch-products` fills it):
`product_definitions.json` and its `feeds-meta.json` entry in the feeds cache directory."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from traust_core.v1.models.product_definitions import (
    CONTACT_FIELDS,
    DEFINITION_KEYS,
    ProductDefinitionsSnapshot,
    ProductSource,
    ProductSourceStatus,
)
from traust_core.v1.providers.clock import Clock

FEED = "product-definitions"
FILENAME = "product_definitions.json"
# Example URL only: operators point the fetch at their registry; nothing VPN-only ships.
URL = "https://example.com/product-definitions/products.json"
MAX_AGE_HOURS = 24.0 * 30


class ProductDefinitionsCache:
    def __init__(self, cache_dir: Path | None, clock: Clock) -> None:
        self._dir = cache_dir
        self._clock = clock

    def read(self) -> ProductDefinitionsSnapshot:
        """The cached registry and its freshness. A missing or malformed cache is `unavailable`
        with the reason: the registry is an optional corroborating source, never a failed run."""
        if self._dir is None:
            return _unavailable("feeds cache not configured")
        try:
            document = json.loads((self._dir / FILENAME).read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("product-definitions cache must be an object")
            missing = [k for k in DEFINITION_KEYS if not isinstance(document.get(k), dict)]
            if missing:
                raise ValueError(
                    "product-definitions cache is missing/malformed top-level key(s): "
                    + ", ".join(missing)
                )
            _validate_definitions(document)
        except (OSError, ValueError) as e:
            return _unavailable(str(e))
        retrieved_at, age = self._retrieved(self._dir)
        return ProductDefinitionsSnapshot(
            status=ProductSourceStatus.OK
            if age is not None and age <= MAX_AGE_HOURS
            else ProductSourceStatus.STALE,
            source=ProductSource(
                retrieved_at=retrieved_at,
                age_hours=None if age is None else round(age, 1),
                max_age_hours=MAX_AGE_HOURS,
                url=URL,
            ),
            document=document,
        )

    def _retrieved(self, cache_dir: Path) -> tuple[str | None, float | None]:
        try:
            meta = json.loads((cache_dir / "feeds-meta.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}
        if not isinstance(meta, dict) or not isinstance(entry := meta.get(FEED), dict):
            return None, None
        retrieved_at = entry.get("retrieved_at")
        if not isinstance(retrieved_at, str):
            return None, None
        try:
            at = datetime.strptime(retrieved_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except ValueError:
            return retrieved_at, None
        return retrieved_at, (self._clock.now() - at).total_seconds() / 3600


def _object(value: object, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"product-definitions cache {path} must be an object")
    return value


def _optional_string(value: object, path: str) -> None:
    if value is not None and not isinstance(value, str):
        raise ValueError(f"product-definitions cache {path} must be a string or null")


def _optional_list(value: object, path: str) -> list[object]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"product-definitions cache {path} must be an array or null")
    return value


def _links(value: object, path: str) -> None:
    if any(not isinstance(link, str) for link in _optional_list(value, path)):
        raise ValueError(f"product-definitions cache {path} must contain only strings")


def _validate_definitions(document: dict[str, object]) -> None:
    for pid, value in _object(document["ps_products"], "ps_products").items():
        path = f"ps_products.{pid}"
        product = _object(value, path)
        _optional_string(product.get("name"), f"{path}.name")
        _links(product.get("ps_modules"), f"{path}.ps_modules")
    for mid, value in _object(document["ps_modules"], "ps_modules").items():
        path = f"ps_modules.{mid}"
        module = _object(value, path)
        _links(module.get("ps_update_streams"), f"{path}.ps_update_streams")
        if (lifecycle := module.get("lifecycle")) is not None:
            lifecycle = _object(lifecycle, f"{path}.lifecycle")
            for field in ("supported_from", "supported_until"):
                _optional_string(lifecycle.get(field), f"{path}.lifecycle.{field}")
        for field, _, _ in CONTACT_FIELDS:
            if isinstance(contacts := module.get(field), dict):
                for component, members in contacts.items():
                    _optional_list(members, f"{path}.{field}.{component}")
    for sid, value in _object(document["ps_update_streams"], "ps_update_streams").items():
        path = f"ps_update_streams.{sid}"
        stream = _object(value, path)
        components = _optional_list(
            stream.get("managed_service_components"), f"{path}.managed_service_components"
        )
        for index, value in enumerate(components):
            component_path = f"{path}.managed_service_components[{index}]"
            component = _object(value, component_path)
            for field in ("name", "git_repo_url"):
                _optional_string(component.get(field), f"{component_path}.{field}")


def _unavailable(detail: str) -> ProductDefinitionsSnapshot:
    return ProductDefinitionsSnapshot(
        status=ProductSourceStatus.UNAVAILABLE, source=ProductSource(detail=detail)
    )
