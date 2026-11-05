from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import SerializeAsAny

from traust_core.v1.models.common import TimeBucket
from traust_core.v1.models.insight import ViewFilter, ViewModel, ViewName
from traust_core.v1.rest.common.aware_datetime import UtcDatetime
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.insight.service import Insight

router = APIRouter()

Ids = Annotated[list[UUID] | None, Query()]
Labels = Annotated[list[str] | None, Query()]


@router.get("/v1/insights/{name}", responses=PROBLEMS(401, 404, 422))
def get_insight(
    name: ViewName,
    insight: Insight,
    _: Caller,
    product_id: Ids = None,
    team_id: Ids = None,
    as_of: UtcDatetime | None = None,
    bucket: TimeBucket = TimeBucket.MONTH,
    artifact_id: UUID | None = None,
    repository_id: UUID | None = None,
    category: Labels = None,
) -> SerializeAsAny[ViewModel]:
    """One insight (a dashboard, rollup or export such as SARIF) for a scope at `as_of`, built on
    demand; one route for every insight, so a new one needs no route or SDK release."""
    filter = ViewFilter(
        product_ids=tuple(product_id or ()),
        team_ids=tuple(team_id or ()),
        categories=tuple(category or ()),
        as_of=as_of,
        bucket=bucket,
        artifact_id=artifact_id,
        repository_id=repository_id,
    )
    return insight.build(name, filter)
