"""What counts as an authentication guard for Django, DRF and Flask routes (D36): a known
guard of those frameworks' auth libraries, or checkout code that refuses an unauthenticated
caller before the view runs. A name that only looks like a guard is none."""

from __future__ import annotations

import ast
import re
from collections.abc import Callable

# library decorators and mixins that refuse an anonymous caller
KNOWN_GUARDS = {
    "login_required", "permission_required", "staff_member_required", "superuser_required",
    "fresh_login_required", "jwt_required", "auth_required", "roles_required", "roles_accepted",
    "permissions_required", "permissions_accepted", "http_auth_required", "token_auth_required",
    "auth_token_required", "LoginRequiredMixin", "PermissionRequiredMixin",
}  # fmt: skip
# DRF permission classes that refuse an anonymous caller, and those that let one read
KNOWN_PERMISSIONS = {
    "IsAuthenticated", "IsAdminUser", "DjangoModelPermissions", "DjangoObjectPermissions",
    "TokenHasScope", "TokenHasReadWriteScope", "TokenHasResourceScope", "HasAPIKey",
}  # fmt: skip
READ_ONLY_PERMISSIONS = {"IsAuthenticatedOrReadOnly", "DjangoModelPermissionsOrAnonReadOnly"}
# what an authenticated caller is read from
_IDENTITY = re.compile(
    r"\b(current_user|request\.user|g\.user|get_jwt_identity|verify_jwt_in_request|"
    r"get_current_user|is_authenticated)\b"
)
_REFUSALS = {"abort", "redirect", "redirect_to_login", "HttpResponseForbidden", "Response"}

Resolve = Callable[[str], ast.AST | None]


def known(name: str) -> bool:
    return name.split(".")[-1] in KNOWN_GUARDS


class GuardReader:
    """Reads checkout decorators, mixins, permission classes and hooks; `resolve` finds a
    checkout definition by the name used for it, or None for a library's."""

    def __init__(self, resolve: Resolve) -> None:
        self.resolve = resolve
        self._seen: dict[str, bool] = {}

    def guards(self, name: str) -> bool:
        """A decorator or mixin named `name` refuses an unauthenticated caller."""
        if known(name):
            return True
        if name in self._seen:
            return self._seen[name]
        self._seen[name] = False  # a cycle reads as no guard
        found = self.resolve(name)
        if isinstance(found, ast.FunctionDef | ast.AsyncFunctionDef):
            result = self.decorator(found)
        elif isinstance(found, ast.ClassDef):
            result = self.mixin(found)
        else:
            result = False
        self._seen[name] = result
        return result

    def decorator(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """`def admin_required(f): @wraps(f) def inner(*a): if not current_user.is_authenticated:
        abort(401) ...; return f(*a)`, or one that returns a known guard around `f`."""
        for stmt in fn.body:
            if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
                inner = stmt.value
                if self.guards(_dotted(inner.func)):
                    return True  # `return login_required(f)`
        # the wrapper, or a factory's (`require_scope("read")`): its nested functions
        inner = [
            n
            for n in ast.walk(fn)
            if n is not fn and isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        return any(refuses_anonymous(w) for w in inner)

    def mixin(self, cls: ast.ClassDef) -> bool:
        """A checkout mixin whose `dispatch` refuses first, or one built on a known guard
        mixin it doesn't override."""
        dispatch = next(
            (n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "dispatch"), None
        )
        if dispatch is not None:
            return refuses_anonymous(dispatch)
        return any(self.guards(_dotted(b)) for b in cls.bases)

    def permission(self, name: str) -> str:
        """`guard`, `read-only` (lets an anonymous caller read) or `none`."""
        last = name.split(".")[-1]
        if last in KNOWN_PERMISSIONS:
            return "guard"
        if last in READ_ONLY_PERMISSIONS:
            return "read-only"
        found = self.resolve(name)
        if not isinstance(found, ast.ClassDef):
            return "none"
        method = next(
            (
                n
                for n in found.body
                if isinstance(n, ast.FunctionDef) and n.name == "has_permission"
            ),
            None,
        )
        if method is None:
            # inherits `has_permission`: as its base does
            kinds = {self.permission(_dotted(b)) for b in found.bases}
            return (
                "guard" if kinds == {"guard"} else "read-only" if "read-only" in kinds else "none"
            )
        return "guard" if _requires_identity(method) else "none"


def refuses_anonymous(fn: ast.AST) -> bool:
    """Code that, at its top level and on no other condition, refuses a caller it can't
    identify: `if not current_user.is_authenticated: abort(401)`, `verify_jwt_in_request()`."""
    for stmt in getattr(fn, "body", []):
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Call)
            and _dotted(stmt.value.func).split(".")[-1] == "verify_jwt_in_request"
            and not stmt.value.keywords
        ):
            return True
        if isinstance(stmt, ast.If) and _anonymous(stmt.test) and _refuses(stmt.body):
            return True
        if isinstance(stmt, ast.Return) or (
            # `if request.endpoint in OPEN: return` lets some callers past what follows
            isinstance(stmt, ast.If) and any(isinstance(n, ast.Return) for n in ast.walk(stmt))
        ):
            return False
    return False


def _anonymous(test: ast.AST) -> bool:
    """A test true for a caller no one identified: `not current_user.is_authenticated`,
    `g.user is None`, `request.user.is_anonymous`, `not a or b` with such a side."""
    if isinstance(test, ast.BoolOp):
        sides = [_anonymous(v) for v in test.values]
        return any(sides) if isinstance(test.op, ast.Or) else all(sides)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return bool(_IDENTITY.search(ast.unparse(test.operand)))
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        none = isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None
        return (
            none
            and isinstance(test.ops[0], ast.Is | ast.Eq)
            and bool(_IDENTITY.search(ast.unparse(test.left)))
        )
    return isinstance(test, ast.Attribute) and test.attr == "is_anonymous"


def _refuses(body: list[ast.stmt]) -> bool:
    last = body[-1] if body else None
    if isinstance(last, ast.Raise):
        return True
    if isinstance(last, ast.Expr | ast.Return) and isinstance(last.value, ast.Call):
        return _dotted(last.value.func).split(".")[-1] in _REFUSALS | {"abort"}
    return (
        isinstance(last, ast.Return)
        and last.value is not None
        and not (isinstance(last.value, ast.Constant) and last.value.value is None)
    )


def _requires_identity(method: ast.FunctionDef) -> bool:
    """`return bool(request.user and request.user.is_authenticated and ..)`: one return, an
    `and` of terms one of which says the caller is authenticated."""
    body = [
        s
        for s in method.body
        if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
    ]
    if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
        return False
    value = body[0].value
    if isinstance(value, ast.Call) and _dotted(value.func) == "bool" and value.args:
        value = value.args[0]
    terms = (
        value.values if isinstance(value, ast.BoolOp) and isinstance(value.op, ast.And) else [value]
    )
    return any(
        isinstance(t, ast.Attribute) and t.attr in ("is_authenticated", "is_staff", "is_superuser")
        for t in terms
    )


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""
