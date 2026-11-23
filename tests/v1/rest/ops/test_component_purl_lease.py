"""REST regression tests for server-resolved component PURL lease admission and recording."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from tests.fixtures.component_purl.builder import PinnedFixture, build_spring_fixture
from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import ProcessConfig, RecordingConfig
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.operations import AssetName, OrderFilter, RecordingStartScope
from traust_core.v1.models.values import GitSha, LocalRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.local import LocalCheckout
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest, Workspace
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.rest.app import create_app
from traust_core.v1.services.identity import IdentityConfig


class _MappedLocalCheckouts:
    """Serves a fixture repo URL from a local pinned git checkout without touching the network."""

    def __init__(self, repo_url: str, local_path: Path) -> None:
        self._repo_url = repo_url
        self._origin = LocalRepoUrl.parse(local_path.as_uri())
        self._local = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(T0))

    def checkout(self, request: CheckoutRequest) -> Any:
        assert str(request.repo) == self._repo_url
        mapped = CheckoutRequest(
            repo=self._origin,
            ref=GitSha.parse(str(request.ref)),
            shared=request.shared,
            writable=request.writable,
        )
        return self._local.checkout(mapped)

    def release(self, workspace: Workspace) -> None:
        self._local.release(workspace)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _setup(
    engine: Engine, tmp_path: Path
) -> tuple[Context, TestClient, PinnedFixture, str, str, str, str]:
    spring = build_spring_fixture(tmp_path)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=spring.repo_url)
        seed.repository_ref(
            repository_id=repo.id, name="main", kind="branch", is_default=True, sha=spring.commit
        )
        ref = seed.repository_ref(
            repository_id=repo.id, name="v7.1.0", kind="tag", sha=spring.commit
        )
        uow.commit()
    assert repo.id is not None and ref.id is not None
    context = Context(
        Config(
            home=tmp_path / "home",
            identity=IdentityConfig(trust_local=True),
            process=ProcessConfig(allowed_binaries=("git",)),
            recording=RecordingConfig(
                assessment=(AssetName("sci_scan"),),
                start=(
                    RecordingStartScope(
                        principal="machine:runner-7",
                        assets=(AssetName("sci_scan"),),
                        repository_ids=(repo.id,),
                    ),
                ),
            ),
        ),
    )
    context.__dict__["database"] = engine
    context.__dict__["checkouts"] = _MappedLocalCheckouts(spring.repo_url, spring.path)
    assert context.identity is not None
    runner_tok = context.local_issuer.mint("runner-7", machine=True).token.get_secret_value()
    person_tok = context.local_issuer.mint(
        "alice@example.com", machine=False
    ).token.get_secret_value()
    return (
        context,
        TestClient(create_app(context)),
        spring,
        str(repo.id),
        str(ref.id),
        runner_tok,
        person_tok,
    )


def _report_json(repo_url: str, commit: str, purl: str, module_path: str, title: str) -> str:
    return json.dumps(
        {
            "title": title,
            "metadata": {
                "date": "2026-11-22",
                "scope": f"Component PURL audit of {purl} ({module_path})",
                "repository": repo_url,
                "commit": commit,
                "audit_profile": "code",
                "target": {
                    "purl": purl,
                    "repository": repo_url,
                    "commit": commit,
                    "module_path": module_path,
                    "release_ref": "v7.1.0",
                    "verification": {
                        "strategy": "shared_release",
                        "manifest_paths": [
                            "pom.xml",
                            f"{module_path}/pom.xml",
                        ],
                    },
                },
            },
            "executive_summary": {
                "prose": "Fresh initial source audit of pinned component target in monorepo.",
                "severity_counts": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "informational": 0,
                },
            },
            "severity_criteria": [
                {"level": "critical", "definition": "Remote compromise without authentication."},
                {"level": "high", "definition": "High-impact cross-tenant exposure or bypass."},
                {"level": "medium", "definition": "Scoped weakness under extra preconditions."},
                {"level": "low", "definition": "Defense-in-depth hardening gap."},
            ],
            "findings": [],
            "findings_summary": [
                {"severity": sev, "count": 0, "finding_ids": []}
                for sev in ("critical", "high", "medium", "low")
            ],
            "remediation_roadmap": [
                {
                    "priority": "p3",
                    "addresses": ["NONE"],
                    "action": "No remediation required for clean fixture report.",
                    "effort": "xs",
                }
            ],
        }
    )


def test_mismatched_purl_and_module_path_cannot_obtain_a_lease_or_queue(
    engine: Engine, tmp_path: Path
) -> None:
    context, client, spring, repo_id, ref_id, runner_tok, person_tok = _setup(engine, tmp_path)

    # 1. Mismatched (PURL, module_path) on POST /v1/orders/start -> 422, no lease created.
    bad_start = client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": "pkg:maven/org.springframework/spring-beans@7.1.0",
                "target_sha": spring.commit,
                "target_module_path": "spring-context",
            },
            "lease_seconds": 300,
        },
    )
    assert bad_start.status_code == 422, bad_start.text
    assert "supplied_path_conflict" in bad_start.text

    # 2. Mismatched (PURL, module_path) on POST /v1/orders -> 422, nothing queued.
    bad_submit = client.post(
        "/v1/orders",
        headers=_auth(person_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": "pkg:maven/org.springframework/spring-beans@7.1.0",
                "target_sha": spring.commit,
                "target_module_path": "spring-context",
            }
        },
    )
    assert bad_submit.status_code == 422, bad_submit.text
    assert "supplied_path_conflict" in bad_submit.text

    # 3. Unverified version -> 422, no lease created.
    bad_ver = client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": "pkg:maven/org.springframework/spring-beans@9.9.9",
                "target_sha": spring.commit,
            },
            "lease_seconds": 300,
        },
    )
    assert bad_ver.status_code == 422, bad_ver.text
    assert "version_mismatch" in bad_ver.text

    # Confirm ZERO orders were persisted by any refused request.
    listed = context.services().ops.list(
        OrderFilter(asset=AssetName("sci_scan"), repository_id=UUID(repo_id)), PageRequest()
    )
    assert listed.items == ()

    # 4. Valid PURL with omitted target_module_path -> server resolves "spring-beans" and leases.
    started = client.post(
        "/v1/orders/start",
        headers=_auth(runner_tok),
        json={
            "order": {
                "asset": "sci_scan",
                "priority": 1,
                "repository_id": repo_id,
                "target_purl": "pkg:maven/org.springframework/spring-beans@7.1.0",
                "target_sha": spring.commit,
            },
            "lease_seconds": 300,
        },
    )
    assert started.status_code == 200, started.text
    order = started.json()
    assert order["target_purl"] == "pkg:maven/org.springframework/spring-beans@7.1.0"
    assert order["target_sha"] == spring.commit
    assert order["target_module_path"] == "spring-beans"

    # 4b. GET /v1/orders/{id}/manifest exposes the full authoritative component_target
    # (including release_ref and verification.strategy / manifest_paths) for worker staging.
    manifest_resp = client.get(f"/v1/orders/{order['id']}/manifest", headers=_auth(runner_tok))
    assert manifest_resp.status_code == 200, manifest_resp.text
    manifest_target = manifest_resp.json()["component_target"]
    assert manifest_target["purl"] == "pkg:maven/org.springframework/spring-beans@7.1.0"
    assert manifest_target["release_ref"] == "v7.1.0"
    assert manifest_target["verification"]["strategy"] == "shared_release"
    assert manifest_target["verification"]["manifest_paths"] == ["pom.xml", "spring-beans/pom.xml"]

    # 4c. Tampering verification.strategy (reconstructed/altered target) is refused (403).
    tampered_doc = json.loads(
        _report_json(
            spring.repo_url,
            spring.commit,
            "pkg:maven/org.springframework/spring-beans@7.1.0",
            "spring-beans",
            "Spring Beans Security Audit",
        )
    )
    tampered_doc["metadata"]["target"]["verification"]["strategy"] = "package_release"
    tampered = client.post(
        "/v1/assessment-records",
        headers=_auth(runner_tok),
        json={
            "run_order_id": order["id"],
            "repository_ref_id": ref_id,
            "assessor_version": "1.0.0",
            "provenance": {
                "run_id": order["id"],
                "source": "vuln_scan_report",
                "occurred_at": T0.isoformat(),
            },
            "payload": json.dumps(tampered_doc),
        },
    )
    assert tampered.status_code == 403, tampered.text

    # 5. Sibling-B report at the same (repo, SHA) is refused on sibling-A's lease (403).
    swapped = client.post(
        "/v1/assessment-records",
        headers=_auth(runner_tok),
        json={
            "run_order_id": order["id"],
            "repository_ref_id": ref_id,
            "assessor_version": "1.0.0",
            "provenance": {
                "run_id": order["id"],
                "source": "vuln_scan_report",
                "occurred_at": T0.isoformat(),
            },
            "payload": _report_json(
                spring.repo_url,
                spring.commit,
                "pkg:maven/org.springframework/spring-context@7.1.0",
                "spring-context",
                "Spring Context Security Audit",
            ),
        },
    )
    assert swapped.status_code == 403, swapped.text

    # 6. Matching sibling-A report succeeds and stamps target_purl.
    ok = client.post(
        "/v1/assessment-records",
        headers=_auth(runner_tok),
        json={
            "run_order_id": order["id"],
            "repository_ref_id": ref_id,
            "assessor_version": "1.0.0",
            "provenance": {
                "run_id": order["id"],
                "source": "vuln_scan_report",
                "occurred_at": T0.isoformat(),
            },
            "payload": _report_json(
                spring.repo_url,
                spring.commit,
                "pkg:maven/org.springframework/spring-beans@7.1.0",
                "spring-beans",
                "Spring Beans Security Audit",
            ),
        },
    )
    assert ok.status_code == 200, ok.text
    latest = context.services().assessment.latest_recorded(
        UUID(repo_id),
        AssessmentKind.SECURE_CODE_CANONICAL,
        target_purl="pkg:maven/org.springframework/spring-beans@7.1.0",
    )
    assert latest.target_purl == "pkg:maven/org.springframework/spring-beans@7.1.0"
