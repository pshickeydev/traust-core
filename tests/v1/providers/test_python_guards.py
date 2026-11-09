"""Which decorators, mixins, permission classes and hooks count as authentication guards: a
known library guard, or checkout code that refuses an anonymous caller (D36)."""

from __future__ import annotations

import ast
from textwrap import dedent

import pytest

from traust_core.v1.providers.python_guards import GuardReader, refuses_anonymous


def _reader(code: str) -> GuardReader:
    defs = {
        n.name: n
        for n in ast.parse(dedent(code)).body
        if isinstance(n, ast.FunctionDef | ast.ClassDef)
    }
    return GuardReader(lambda name: defs.get(name.split(".")[-1]))


CHECKOUT = """
from functools import wraps

def admin_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return inner

def staff_only(f):
    return login_required(f)

def ajax_required(f):
    def inner(request, *args, **kwargs):
        if not request.headers.get("X-Requested-With"):
            return HttpResponseBadRequest()
        return f(request, *args, **kwargs)
    return inner

def exempting(f):
    def inner(*args, **kwargs):
        if request.endpoint in OPEN:
            return f(*args, **kwargs)
        if current_user.is_anonymous:
            abort(401)
        return f(*args, **kwargs)
    return inner

def logged_in_away(f):
    def inner(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect("/home")
        return f(*args, **kwargs)
    return inner

def scoped(scope):
    def deco(f):
        def inner(*args, **kwargs):
            if get_jwt_identity() is None:
                abort(401)
            return f(*args, **kwargs)
        return inner
    return deco

class MemberMixin:
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

class IsOwnerOrReadOnly(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user

class IsMember(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

class IsAnyone(BasePermission):
    def has_permission(self, request, view):
        return not request.user.is_authenticated or True

class StrictAuth(IsAuthenticated):
    pass
"""


@pytest.mark.parametrize(
    ("name", "guards"),
    [
        ("login_required", True),  # a library guard
        ("flask_login.login_required", True),
        ("LoginRequiredMixin", True),
        ("token_required", False),  # a name we can't read
        ("admin_required", True),  # its wrapper refuses an anonymous caller first
        ("staff_only", True),  # it returns a known guard around the view
        ("ajax_required", False),  # refuses on a header, not on who the caller is
        ("exempting", False),  # an endpoint allow-list runs first
        ("logged_in_away", False),  # refuses the authenticated, not the anonymous
        ("scoped", True),  # a decorator factory's wrapper
        ("MemberMixin", True),  # its `dispatch` refuses before calling on
    ],
)
def test_a_guard_is_a_known_guard_or_code_that_refuses_the_anonymous(
    name: str, guards: bool
) -> None:
    assert _reader(CHECKOUT).guards(name) is guards


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("IsAuthenticated", "guard"),
        ("rest_framework.permissions.IsAdminUser", "guard"),
        ("IsAuthenticatedOrReadOnly", "read-only"),
        ("IsOwnerOrReadOnly", "none"),  # only an object check; `has_permission` admits anyone
        ("IsMember", "guard"),
        ("IsAnyone", "none"),
        ("StrictAuth", "guard"),  # inherits a known guard's `has_permission`
        ("HasScope", "none"),  # a library class we don't know
    ],
)
def test_a_permission_class_is_read_by_what_it_admits(name: str, kind: str) -> None:
    assert _reader(CHECKOUT).permission(name) == kind


def test_a_hook_guards_only_by_refusing_first() -> None:
    hooks = ast.parse(
        dedent(
            """
            def require_login():
                if not current_user.is_authenticated:
                    abort(401)

            def jwt_hook():
                verify_jwt_in_request()

            def optional_jwt():
                verify_jwt_in_request(optional=True)

            def selective():
                if request.path.startswith("/public"):
                    return None
                if not g.user:
                    abort(401)

            def maintenance():
                if MAINTENANCE:
                    abort(503)
            """
        )
    ).body
    assert [refuses_anonymous(h) for h in hooks] == [True, True, False, False, False]


def test_a_cycle_between_checkout_decorators_reads_as_no_guard() -> None:
    reader = _reader("def a(f):\n    return b(f)\n\ndef b(f):\n    return a(f)\n")
    assert reader.guards("a") is False
