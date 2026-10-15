"""Concise idioms in traust-core shapes (reference only, not imported)."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class NotFoundError(LookupError): ...


class Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Status(StrEnum):
    OPEN = "open"
    DONE = "done"


@dataclass(frozen=True, slots=True)
class Slug:
    value: str

    @classmethod
    def parse(cls, raw: str) -> Self:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", raw):
            raise ValueError(f"not a slug: {raw!r}")
        return cls(raw)


class Task(Model):
    id: UUID | None = None
    slug: Slug
    status: Status
    done_at: datetime | None = None

    def complete(self, at: datetime) -> Task:
        if self.status is Status.DONE:
            return self
        return self.model_copy(update={"status": Status.DONE, "done_at": at})

    def is_open(self) -> bool:
        return self.status is Status.OPEN


def open_slugs(tasks: list[Task]) -> list[Slug]:
    return [t.slug for t in tasks if t.is_open()]


def by_status(tasks: list[Task]) -> dict[Status, int]:
    return dict(Counter(t.status for t in tasks))


def find(tasks: list[Task], task_id: UUID) -> Task:
    if (found := next((t for t in tasks if t.id == task_id), None)) is None:
        raise NotFoundError(f"task {task_id}")
    return found
