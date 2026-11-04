from __future__ import annotations

import pytest
from pydantic import ValidationError

from traust_core.v1.models.detection_quality import CheckPrecision, ComplianceCalibration
from traust_core.v1.models.vocabulary import ComplianceFramework


@pytest.mark.parametrize(
    ("fired", "dismissed", "gate", "precision", "flagged"),
    [
        (0, 0, 0.0, None, False),
        (0, 0, 1.0, None, False),
        (1, 1, 0.0, 0.0, True),
        (2, 1, 0.49, 0.5, False),
        (2, 1, 0.5, 0.5, True),
        (1, 0, 1.0, 1.0, True),
    ],
)
def test_precision_serialization_distinguishes_unknown_zero_and_inclusive_gate(
    fired: int, dismissed: int, gate: float, precision: float | None, flagged: bool
) -> None:
    check = CheckPrecision(check_id="tls", fired=fired, dismissed=dismissed, gate=gate)
    serialized = check.model_dump(mode="json")
    assert check.precision == serialized["precision"] == precision
    assert check.flagged is flagged
    assert serialized["flagged"] is flagged


@pytest.mark.parametrize("gate", [-0.1, 1.1, float("nan"), float("inf")])
def test_calibration_and_check_refuse_a_gate_outside_the_precision_range(gate: float) -> None:
    with pytest.raises(ValidationError):
        CheckPrecision(check_id="tls", fired=1, dismissed=0, gate=gate)
    with pytest.raises(ValidationError):
        ComplianceCalibration(
            framework=ComplianceFramework("nist-800-53-rev5"), assessments=0, gate=gate
        )
