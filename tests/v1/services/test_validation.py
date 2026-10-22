from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import UUID

import pytest

from traust_core.v1.models.artifacts import ValidationArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.vocabulary import SourceType, ValidationVerdict
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.validation import ValidationService


@pytest.fixture
def service() -> ValidationService:
    return ValidationService(Mock(spec=TraustUnitOfWork), Mock(spec=FindingDecisions), ())


@pytest.fixture
def provenance() -> Provenance:
    return Provenance(
        run_id=UUID("00000000-0000-4000-8000-000000000001"),
        source=SourceType.VALIDATION_REPORT,
        occurred_at=datetime(2026, 10, 22, tzinfo=UTC),
    )


def _artifact(
    verdict: ValidationVerdict, observed: str, flag: str | None = None
) -> ValidationArtifact:
    finding = {
        "source_id": "example:app/FIND-001",
        "source_report": "findings/example/app-security-audit.json",
        "verdict": verdict.value,
        "technique": "replay",
        "observed_impact": observed,
    }
    if flag is not None:
        finding["soundness_flag"] = flag
    return ValidationArtifact.from_document(
        {
            "title": "Live validation of example application",
            "metadata": {
                "date": "2026-10-22",
                "harness_version": "0.175.0",
                "scope_binding_mode": "explicit",
                "target_fingerprint": [],
            },
            "source_reports": [{"kind": "security-audit", "path": finding["source_report"]}],
            "summary": {
                "by_verdict": {v.value: int(v == verdict) for v in ValidationVerdict},
                "by_technique": {"replay": 1},
            },
            "validated_findings": [finding],
            "attack_chains": [],
            "novel_findings": [],
            "execution_log_ref": "validation-audit.jsonl",
        }
    )


@pytest.mark.todo(
    "validation-flow",
    legacy="traust/tests/test_refutation_soundness.py::TestReportRollup::test_backstop_gates_ungated_refuted",
)
def test_record_downgrades_an_ungated_unsound_refutation(
    service: ValidationService, provenance: Provenance
) -> None:
    doc = _artifact(ValidationVerdict.REFUTED, "no\nvf-rbac-tried:\nvf-rbac-probe: verb=delete")
    attempts = service.record(doc, provenance)
    assert len(attempts) == 1
    assert attempts[0].verdict == ValidationVerdict.INCONCLUSIVE
    assert attempts[0].soundness_flag == "rbac-zero-subjects"


@pytest.mark.todo(
    "validation-flow",
    legacy="traust/tests/test_refutation_soundness.py::TestReportRollup::test_sound_refutation_reported",
)
def test_record_preserves_a_sound_refutation(
    service: ValidationService, provenance: Provenance
) -> None:
    doc = _artifact(
        ValidationVerdict.REFUTED, "no\nvf-rbac-tried: system:serviceaccount:app:worker"
    )
    attempts = service.record(doc, provenance)
    assert len(attempts) == 1
    assert attempts[0].verdict == ValidationVerdict.REFUTED
    assert attempts[0].soundness_flag is None


@pytest.mark.todo(
    "validation-flow",
    legacy="traust/tests/test_refutation_soundness.py::TestReportRollup::test_gated_step_flag_travels_to_finding",
)
def test_record_preserves_a_producer_soundness_flag(
    service: ValidationService, provenance: Provenance
) -> None:
    doc = _artifact(ValidationVerdict.INCONCLUSIVE, "no", "target-not-deployed")
    attempts = service.record(doc, provenance)
    assert len(attempts) == 1
    assert attempts[0].verdict == ValidationVerdict.INCONCLUSIVE
    assert attempts[0].soundness_flag == "target-not-deployed"
