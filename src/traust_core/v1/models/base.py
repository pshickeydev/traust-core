from __future__ import annotations

from datetime import datetime
from uuid import UUID

import pydantic


class Model(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")


class Dto(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(frozen=True, extra="ignore")


class Entity(Model):
    # None until saved: the database generates id and both timestamps on insert.
    id: UUID | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AppendOnly(Model):
    # None until saved; append-only rows are never updated, so there is no updated_at.
    id: UUID | None = None
    created_at: datetime | None = None
