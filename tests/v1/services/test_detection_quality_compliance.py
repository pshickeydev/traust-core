from __future__ import annotations

import pytest

from tests.v1.services.test_detection_quality_doors import (
    NIST,
    World,
    check,
    compliance,
    overridden,
)
from tests.v1.services.test_detection_quality_doors import engine as engine
from tests.v1.services.test_detection_quality_doors import world as world
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.vocabulary import ComplianceFramework

FRAMEWORK = ComplianceFramework(NIST)


@pytest.mark.parametrize("gate", [0.0, 0.49, 0.5, 1.0])
def test_compliance_precision_gate_is_configurable_inclusive_and_serialized(
    world: World, gate: float
) -> None:
    world.attach(
        compliance(check("tls", "not_satisfied"), overridden("tls")), AssessmentKind.COMPLIANCE
    )
    calibration = world.service().calibrate_compliance(FRAMEWORK, gate=gate)
    [precision] = calibration.checks
    assert calibration.gate == precision.gate == gate
    assert precision.precision == 0.5
    assert precision.flagged is (gate >= 0.5)
    [serialized] = calibration.model_dump(mode="json")["checks"]
    assert serialized["precision"] == 0.5
    assert serialized["flagged"] is (gate >= 0.5)
    assert serialized["gate"] == gate


def test_all_dismissed_firings_are_measured_zero_and_flagged_at_zero_gate(world: World) -> None:
    world.attach(compliance(overridden("tls")), AssessmentKind.COMPLIANCE)
    [check] = world.service().calibrate_compliance(FRAMEWORK, gate=0).checks
    assert (check.fired, check.dismissed, check.precision, check.flagged) == (1, 1, 0.0, True)


def test_satisfied_automatic_checks_do_not_invent_a_precision_population(world: World) -> None:
    world.attach(compliance(check("tls", "satisfied")), AssessmentKind.COMPLIANCE)
    calibration = world.service().calibrate_compliance(FRAMEWORK, gate=1)
    assert calibration.assessments == 1
    assert calibration.checks == ()
    assert calibration.gate == 1


@pytest.mark.parametrize("gate", [-0.1, 1.1, float("nan"), float("inf"), float("-inf")])
def test_invalid_precision_gate_is_refused_even_with_no_assessments(
    world: World, gate: float
) -> None:
    with pytest.raises(ValidationError, match="gate"):
        world.service().calibrate_compliance(FRAMEWORK, gate=gate)
