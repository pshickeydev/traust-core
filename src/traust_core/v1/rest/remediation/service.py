from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.remediation import RemediationService, VerificationService
from traust_core.v1.services.remediation_scheduling import RemediationSchedulingService


def verification(services: CoreServices) -> VerificationService:
    return services.verification


def remediation(services: CoreServices) -> RemediationService:
    return services.remediation


def scheduling(services: CoreServices) -> RemediationSchedulingService:
    return services.remediation_scheduling


Verifications = Annotated[VerificationService, Depends(verification)]
Remediation = Annotated[RemediationService, Depends(remediation)]
Scheduling = Annotated[RemediationSchedulingService, Depends(scheduling)]
