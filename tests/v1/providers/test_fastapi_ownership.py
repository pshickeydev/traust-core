"""Ownership of the object a FastAPI id route acts on: each allowed shape beside code that looks
protected but isn't, which must stay judged."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

AUTH = """
from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from typing import Annotated

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def get_current_user(token: str = Depends(oauth2_scheme)) -> "User":
    user = decode(token)
    if user is None:
        raise HTTPException(status_code=401)
    return user


def get_user_authorizer(required: bool = True):
    def inner(token: str = Depends(oauth2_scheme)):
        return decode(token)
    return inner


CurrentUser = Annotated["User", Depends(get_current_user)]
"""

MODELS = """
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: int = Field(primary_key=True)
    team: str
    is_superuser: bool = False


class Item(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int
    kind: str
    public: bool = False


class Holiday(SQLModel, table=True):
    id: int = Field(primary_key=True)
    name: str


class Tag(SQLModel, table=True):
    id: int = Field(primary_key=True)
    project_id: int
"""

STORE = """
from app.models import Item, Holiday

_SLOTS: dict[int, dict] = {}
_HOLIDAYS: dict[int, Holiday] = {}


def get_item(session, item_id):
    return session.get(Item, item_id)


def open_item(session, item_id):
    item = session.get(Item, item_id)
    item.kind = "opened"
    session.add(item)
    return item


def get_team_slot(team, slot_id):
    slot = _SLOTS.get(slot_id)
    return slot if slot is not None and slot["team"] == team else None


def get_any_slot(team, slot_id):
    slot = _SLOTS.get(slot_id)
    return slot if slot is not None or slot["team"] == team else None


def get_holiday(holiday_id):
    return _HOLIDAYS.get(holiday_id)


def get_slot(slot_id):
    return _SLOTS.get(slot_id)


def twice(item_id):
    return item_id


def twice(item_id):
    return None


class ItemService:
    def get(self, session, owner, item_id):
        statement = select(Item).where(Item.id == item_id, Item.owner_id == owner)
        return session.exec(statement).first()


item_service = ItemService()
"""

ROUTES = """
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlmodel import select, delete, or_

from app import store
from app.auth import CurrentUser, get_current_user, get_user_authorizer
from app.models import Item, Tag
from app.store import item_service

router = APIRouter(prefix="/items")


@router.get("/scoped/{item_id}")
def scoped(item_id: int, session, current_user: CurrentUser):
    statement = select(Item).where(Item.id == item_id, Item.owner_id == current_user.id)
    item = session.exec(statement).first()
    if item is None:
        raise HTTPException(status_code=404)
    return item


@router.delete("/scoped/{item_id}")
def scoped_delete(item_id: int, session, current_user: CurrentUser):
    item = session.exec(
        select(Item).where(Item.id == item_id, Item.owner_id == current_user.id)
    ).first()
    if not item:
        raise HTTPException(status_code=404)
    session.exec(delete(Item).where(Item.id == item_id))


@router.get("/one/{item_id}")
def one(item_id: int, session, current_user: CurrentUser):
    return session.query(Item).filter_by(id=item_id, owner_id=current_user.id).one()


@router.get("/either/{item_id}")
def either(item_id: int, session, current_user: CurrentUser):
    statement = select(Item).where(or_(Item.id == item_id, Item.owner_id == current_user.id))
    return session.exec(statement).first()


@router.get("/foreign/{item_id}")
def foreign(item_id: int, session, current_user: CurrentUser, owner: int):
    statement = select(Item).where(Item.id == item_id, Item.owner_id == owner)
    return session.exec(statement).first()


@router.get("/fallback/{item_id}")
def fallback(item_id: int, session, current_user: CurrentUser, owner: int | None = None):
    who = owner or current_user.id
    return session.exec(select(Item).where(Item.id == item_id, Item.owner_id == who)).first()


@router.delete("/unrefused/{item_id}")
def unrefused(item_id: int, session, current_user: CurrentUser):
    session.exec(select(Item).where(Item.id == item_id, Item.owner_id == current_user.id)).first()
    session.exec(delete(Item).where(Item.id == item_id))


@router.get("/template/{item_id}")
def template(item_id: int, session, current_user: CurrentUser):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404)
    if not current_user.is_superuser and (item.owner_id != current_user.id):
        raise HTTPException(status_code=403)
    return item


@router.delete("/template/{item_id}")
def template_delete(item_id: int, session, current_user: CurrentUser):
    item = session.get(Item, item_id)
    if item is None or item.owner_id != current_user.id:
        raise HTTPException(status_code=403)
    session.exec(delete(Item).where(Item.id == item_id))


@router.get("/public/{item_id}")
def public(item_id: int, session, current_user: CurrentUser):
    item = session.get(Item, item_id)
    if not item.public and item.owner_id != current_user.id:
        raise HTTPException(status_code=403)
    return item


@router.get("/flagged/{item_id}")
def flagged(item_id: int, session, current_user: CurrentUser):
    item = session.get(Item, item_id)
    if not item.is_superuser and item.owner_id != current_user.id:
        raise HTTPException(status_code=403)
    return item


@router.get("/logged/{item_id}")
def logged(item_id: int, session, current_user: CurrentUser):
    item = session.get(Item, item_id)
    if item.owner_id != current_user.id:
        print("not yours")
    return item


@router.get("/kind/{item_id}")
def kind(item_id: int, session, current_user: CurrentUser):
    item = session.get(Item, item_id)
    if item.kind != current_user.team:
        raise HTTPException(status_code=403)
    return item


@router.delete("/late/{item_id}")
def late(item_id: int, session, current_user: CurrentUser):
    item = session.get(Item, item_id)
    session.delete(item)
    session.exec(delete(Item).where(Item.id == item_id))
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403)


@router.get("/hop/{item_id}")
def hop(item_id: int, session, current_user: CurrentUser):
    item = store.get_item(session, item_id)
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403)
    return item


@router.get("/opened/{item_id}")
def opened(item_id: int, session, current_user: CurrentUser):
    item = store.open_item(session, item_id)
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403)
    return item


@router.get("/service/{item_id}")
def service(item_id: int, session, current_user: CurrentUser):
    item = item_service.get(session, current_user.id, item_id)
    if item is None:
        raise HTTPException(status_code=404)
    return item


@router.get("/ambiguous/{item_id}")
def ambiguous(item_id: int, current_user: CurrentUser):
    return store.twice(item_id)


@router.get("/slots/{slot_id}")
def slot(slot_id: int, user: dict = Depends(get_current_user)):
    found = store.get_team_slot(user["team"], slot_id)
    if found is None:
        raise HTTPException(status_code=404)
    return found


@router.get("/any-slots/{slot_id}")
def any_slot(slot_id: int, user: dict = Depends(get_current_user)):
    return store.get_any_slot(user["team"], slot_id)


@router.delete("/slots/{slot_id}")
def drop_slot(slot_id: int, user: dict = Depends(get_current_user)):
    store.get_team_slot(user["team"], slot_id)
    store._SLOTS.pop(slot_id)


@router.delete("/team-slots/{slot_id}")
def release_slot(slot_id: int, user: dict = Depends(get_current_user)):
    found = store.get_slot(slot_id)
    if found is None or found["team"] != user["team"]:
        raise HTTPException(status_code=403)
    store._SLOTS.pop(slot_id)


@router.get("/holidays/{holiday_id}", dependencies=[Depends(get_current_user)])
def holiday(holiday_id: int):
    return store.get_holiday(holiday_id)


@router.get("/tags/{tag_id}", dependencies=[Depends(get_current_user)])
def tag(tag_id: int, session):
    return session.get(Tag, tag_id)


@router.get("/request/{item_id}", dependencies=[Depends(get_current_user)])
def via_request(item_id: int, request: Request, session):
    item = session.get(Item, item_id)
    if item.owner_id != request.user.id:
        raise HTTPException(status_code=403)
    return item


@router.get("/optional/{item_id}")
def optional(item_id: int, session, user=Depends(get_user_authorizer(required=False))):
    return session.get(Item, item_id)


@router.get("/body/{item_id}")
def body(item_id: int, session, payload: dict, current_user: CurrentUser):
    item = session.get(Item, item_id)
    if item.owner_id != payload["owner_id"]:
        raise HTTPException(status_code=403)
    return item


@router.get("/swapped/{item_id}")
def swapped(item_id: int, session, current_user: CurrentUser, other: int):
    me = current_user.id
    me = other
    return session.exec(select(Item).where(Item.id == item_id, Item.owner_id == me)).first()


@router.get("/mutated/{item_id}")
def mutated(item_id: int, session, current_user: CurrentUser, other: int):
    current_user.id = other
    item = session.get(Item, item_id)
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403)
    return item


@router.get("/converted/{item_id}")
def converted(item_id: str, session, current_user: CurrentUser):
    key = int(item_id)
    item = session.get(Item, key)
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403)
    return item


@router.delete("/built/{item_id}")
def built(item_id: str, session, current_user: CurrentUser, probe: str | None = None):
    item = session.get(Item, probe or item_id)
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403)
    session.exec(delete(Item).where(Item.id == item_id))
"""

DEPENDENCIES = """
from fastapi import APIRouter, Depends, HTTPException

from app.auth import CurrentUser
from app.models import Item

router = APIRouter(prefix="/deps")


def owned_item(item_id: int, session, current_user: CurrentUser):
    item = session.get(Item, item_id)
    if item is None or item.owner_id != current_user.id:
        raise HTTPException(status_code=404)
    return item


def any_item(item_id: int, session):
    return session.get(Item, item_id)


@router.delete("/owned/{item_id}")
def owned(item_id: int, session, item=Depends(owned_item)):
    session.delete(item)


@router.delete("/any/{item_id}")
def any_(item=Depends(any_item), current_user: CurrentUser = None):
    return item


class Permissions:
    def __init__(self, checks):
        self.checks = checks

    def __call__(self, request):
        return request.path_params["item_id"]


@router.get("/checked-elsewhere/{item_id}", dependencies=[Depends(Permissions([]))])
def elsewhere(item_id: int, session, current_user: CurrentUser):
    return session.get(Item, item_id)
"""

MAIN = """
from fastapi import FastAPI
from app import routes, dependencies

app = FastAPI()
app.include_router(routes.router)
app.include_router(dependencies.router)
"""


def _tree(root: Path, files: dict[str, str]) -> dict:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))
    return route_guards(tree_files(root)).model_dump(mode="json")


def _row(result: dict, method: str, pattern: str) -> dict:
    [row] = [
        r
        for r in result["routes"]
        if r["family"] == "fastapi" and r["method"] == method and r["pattern"] == pattern
    ]
    return row


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _tree(
        tmp_path_factory.mktemp("app"),
        {
            "app/__init__.py": "",
            "app/auth.py": AUTH,
            "app/models.py": MODELS,
            "app/store.py": STORE,
            "app/routes.py": ROUTES,
            "app/dependencies.py": DEPENDENCIES,
            "app/main.py": MAIN,
        },
    )


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/items/scoped/{item_id}", "scoped"),  # shape 1, refused when absent
        ("DELETE", "/items/scoped/{item_id}", "checked"),  # the id is verified for the delete
        ("GET", "/items/one/{item_id}", "scoped"),  # `filter_by` and `.one()`
        ("GET", "/items/either/{item_id}", "unchecked"),  # `or_` doesn't narrow to the caller
        ("GET", "/items/foreign/{item_id}", "caller-blind"),  # a query parameter as the owner
        ("GET", "/items/fallback/{item_id}", "unchecked"),  # `owner or current_user.id`
        ("DELETE", "/items/unrefused/{item_id}", "unchecked"),  # nothing refused when absent
        ("GET", "/items/template/{item_id}", "checked"),  # shape 2, superusers by design
        ("DELETE", "/items/template/{item_id}", "checked"),
        ("GET", "/items/public/{item_id}", "unchecked"),  # `and` on the record's own flag
        ("GET", "/items/flagged/{item_id}", "unchecked"),  # the privilege flag isn't the caller's
        ("GET", "/items/logged/{item_id}", "unchecked"),  # the condition doesn't refuse
        ("GET", "/items/kind/{item_id}", "unchecked"),  # `kind` is no owner
        ("DELETE", "/items/late/{item_id}", "unchecked"),  # deleted before the check
        ("GET", "/items/hop/{item_id}", "checked"),  # a hop that only reads
        ("GET", "/items/opened/{item_id}", "unchecked"),  # a hop that writes before the check
        ("GET", "/items/service/{item_id}", "scoped"),  # an instance's method, caller handed in
        ("GET", "/items/ambiguous/{item_id}", "unknown"),  # two definitions of one name
        ("GET", "/items/slots/{slot_id}", "checked"),  # shape 5, refused when absent
        ("GET", "/items/any-slots/{slot_id}", "unknown"),  # `or`: returned whenever present
        ("DELETE", "/items/slots/{slot_id}", "unknown"),  # the owned result is ignored
        ("DELETE", "/items/team-slots/{slot_id}", "checked"),  # dict records, `record["team"]`
        ("GET", "/items/holidays/{holiday_id}", "none"),  # a typed store of ownerless records
        ("GET", "/items/tags/{tag_id}", "caller-blind"),  # `project_id` ties it to a project
        ("GET", "/items/request/{item_id}", "checked"),  # `request.user` is the caller
        ("GET", "/items/optional/{item_id}", "n/a"),  # a caller that may be missing
        ("GET", "/items/body/{item_id}", "caller-blind"),  # compared with the request body
        ("GET", "/items/swapped/{item_id}", "unchecked"),  # the caller local overwritten
        ("GET", "/items/mutated/{item_id}", "caller-blind"),  # the caller object written to
        ("GET", "/items/converted/{item_id}", "checked"),  # a converted id is the id
        ("DELETE", "/items/built/{item_id}", "unchecked"),  # verified another value than the id
        ("DELETE", "/deps/owned/{item_id}", "checked"),  # a dependency that loads and refuses
        ("DELETE", "/deps/any/{item_id}", "caller-blind"),  # a dependency that only loads
        ("GET", "/deps/checked-elsewhere/{item_id}", "unknown"),  # a check we can't read
    ],
)
def test_only_the_allowed_shapes_count_as_protection(
    app: dict, method: str, pattern: str, ownership: str
) -> None:
    row = _row(app, method, pattern)
    assert row["ownership"] == ownership
    if ownership in ("caller-blind", "unchecked"):
        assert row["judgement_required"]


def test_the_evidence_names_the_record_and_its_owner(app: dict) -> None:
    evidence = _row(app, "GET", "/items/kind/{item_id}")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Item", "owner_id")


@pytest.mark.parametrize(
    ("middleware", "dependency", "guarded"),
    [
        # a database-session middleware authenticates nothing
        (
            "@app.middleware('http')\nasync def db_session_middleware(request, call_next):\n"
            "    if bad(request):\n        return error()\n    return await call_next(request)\n",
            "",
            False,
        ),
        # a dependency named for the caller that refuses a missing one
        (
            "",
            "def get_current_user(request):\n    if not request.headers:\n"
            "        raise HTTPException(status_code=401)\n    return 1\n",
            True,
        ),
        # an instance of a guard class used as a dependency
        (
            "",
            "class Authenticator:\n    def __call__(self, request):\n        return 1\n\n"
            "get_current_user = Authenticator()\n",
            True,
        ),
    ],
)
def test_what_authenticates_a_fastapi_route(
    tmp_path, middleware: str, dependency: str, guarded: bool
) -> None:
    code = (
        "from fastapi import FastAPI, Depends, HTTPException\n"
        f"{dependency}\n"
        "app = FastAPI()\n"
        f"{middleware}\n"
        "@app.get('/things/{thing_id}'"
        + (", dependencies=[Depends(get_current_user)]" if dependency else "")
        + ")\ndef thing(thing_id: int, session):\n    return session.get(Thing, thing_id)\n"
    )
    result = route_guards(tree_files(_write(tmp_path, code))).model_dump(mode="json")
    row = _row(result, "GET", "/things/{thing_id}")
    assert bool(row["guards"] or row["scope_guards"]) is guarded


def _write(root: Path, code: str) -> Path:
    (root / "main.py").write_text(code)
    return root


# Invented FastAPI apps from an independent review: code credited as protected while another user's
# object stays reachable (each must stay judged or unknown), beside twins that are protected.
_REVIEW = Path(__file__).parents[2] / "fixtures/code_facts/fastapi_ownership_review.json"
_CASES = json.loads(_REVIEW.read_text())


@pytest.mark.parametrize(
    ("case", "method", "pattern", "ownership"),
    [(c["case"], e["method"], e["pattern"], e["ownership"]) for c in _CASES for e in c["expect"]],
)
def test_holes_a_review_found_stay_closed(
    tmp_path: Path, case: str, method: str, pattern: str, ownership: str
) -> None:
    files = next(c["files"] for c in _CASES if c["case"] == case)
    base = {
        "app/__init__.py": "",
        "app/auth.py": AUTH,
        "app/models.py": MODELS,
        "app/main.py": "from fastapi import FastAPI\nfrom app import r\n"
        "app = FastAPI()\napp.include_router(r.router)\n",
    }
    result = _tree(tmp_path, {**base, **files})
    assert _row(result, method, pattern)["ownership"] == ownership


def test_route_matrix_guards_are_what_they_claim(tmp_path: Path) -> None:
    raw = {
        "app/__init__.py": "",
        "app/main.py": dedent(
            """
            from fastapi import FastAPI, APIRouter, Depends, HTTPException
            from fastapi.security import HTTPBearer

            app = FastAPI()
            optional_bearer = HTTPBearer(auto_error=False)


            def principal(cred=Depends(optional_bearer)):
                return cred


            def items_service():
                return object()


            class Authenticator:
                def __init__(self, required=True):
                    self.required = required

                def __call__(self, request):
                    return 1


            maybe_user = Authenticator(required=False)


            @app.delete("/things/{thing_id}")
            def thing(thing_id: int, session, p=Depends(principal)):
                session.delete(session.get(Thing, thing_id))


            @app.get("/svc/{thing_id}")
            def svc(thing_id: int, items=Depends(items_service)):
                return thing_id


            @app.get("/maybe/{thing_id}")
            def maybe(thing_id: int, u=Depends(maybe_user)):
                return thing_id
            """
        ),
        "app/elsewhere.py": dedent(
            """
            def unrelated(identity, credential, ctx):
                principal = identity.authenticate(credential)
                items_service = ctx.require_items()
                return principal, items_service
            """
        ),
    }
    result = _tree(tmp_path, raw)
    # a local `principal = …authenticate(…)` elsewhere doesn't make these guards
    assert any(
        "fail-open" in u for u in _row(result, "DELETE", "/things/{thing_id}")["unguard_markers"]
    )
    assert _row(result, "GET", "/svc/{thing_id}")["guards"] == []
    # an instance asked not to refuse fails open
    assert any(
        "fail-open" in u for u in _row(result, "GET", "/maybe/{thing_id}")["unguard_markers"]
    )


def test_deep_inheritance_neither_crashes_nor_crawls(tmp_path: Path) -> None:
    chain = "".join(f"class C{k}(C{k - 1}):\n    f{k}: int\n\n\n" for k in range(1, 1200))
    models = (
        "from sqlmodel import SQLModel\n\n\nclass C0(SQLModel):\n    owner_id: int\n\n\n" + chain
    )
    routes = dedent(
        """
        from fastapi import FastAPI, Depends
        from app.models import C1199
        from app.auth import CurrentUser

        app = FastAPI()


        @app.get("/c/{c_id}")
        def c(c_id: int, session, current_user: CurrentUser):
            return session.get(C1199, c_id)
        """
    )
    result = _tree(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/auth.py": AUTH,
            "app/models.py": models,
            "app/main.py": routes,
        },
    )
    assert _row(result, "GET", "/c/{c_id}")["ownership"] == "caller-blind"


def test_a_path_id_only_a_no_op_dependency_takes_acts_on_nothing(tmp_path: Path) -> None:
    routes = dedent(
        """
        from fastapi import APIRouter, Depends, FastAPI
        from sqlmodel import delete
        from app.auth import get_current_user
        from app.models import Item

        app = FastAPI()


        def tenant_path(tenant: str):
            pass


        tenant_router = APIRouter(prefix="/{tenant}", dependencies=[Depends(tenant_path)])


        @tenant_router.post("/notes")
        def create_note(session):
            session.add(object())


        @tenant_router.delete("/notes/{note_id}")
        def drop_note(note_id: int, session):
            session.exec(delete(Item).where(Item.id == note_id))


        app.include_router(tenant_router, dependencies=[Depends(get_current_user)])
        """
    )
    result = _tree(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/auth.py": AUTH,
            "app/models.py": MODELS,
            "app/main.py": routes,
        },
    )
    assert _row(result, "POST", "/{tenant}/notes")["ownership"] == "n/a"
    assert _row(result, "DELETE", "/{tenant}/notes/{note_id}")["ownership"] == "caller-blind"
