"""What counts as an authentication guard for Django, DRF and Flask routes (D37): a known
guard of those frameworks' auth libraries, and only when no checkout definition shadows its
name. Checkout decorators, mixins, permission classes and hooks are no guards."""

from __future__ import annotations

import ast
from collections.abc import Callable

# library decorators and mixins that refuse an anonymous caller
KNOWN_GUARDS = {
    "login_required", "permission_required", "staff_member_required", "superuser_required",
    "fresh_login_required", "jwt_required", "auth_required", "roles_required", "roles_accepted",
    "permissions_required", "permissions_accepted", "http_auth_required", "token_auth_required",
    "auth_token_required", "LoginRequiredMixin", "PermissionRequiredMixin",
}  # fmt: skip
# flask-login's guards, which `LOGIN_DISABLED` turns off
FLASK_LOGIN_GUARDS = frozenset({"login_required", "fresh_login_required"})
# DRF permission classes that refuse an anonymous caller, and those that let one read
KNOWN_PERMISSIONS = {
    "IsAuthenticated", "IsAdminUser", "DjangoModelPermissions", "DjangoObjectPermissions",
    "TokenHasScope", "TokenHasReadWriteScope", "TokenHasResourceScope", "HasAPIKey",
}  # fmt: skip
READ_ONLY_PERMISSIONS = {"IsAuthenticatedOrReadOnly", "DjangoModelPermissionsOrAnonReadOnly"}

Resolve = Callable[[str], ast.AST | None]


class GuardReader:
    """Whether a name is a known guard; `resolve` finds a checkout definition by the name used
    for it (None for a library's), which makes the name no known guard."""

    def __init__(self, resolve: Resolve, *, disabled: frozenset[str] = frozenset()) -> None:
        self.resolve = resolve
        self.disabled = disabled  # known guards configured off (flask-login's `LOGIN_DISABLED`)

    def guards(self, name: str) -> bool:
        """A decorator or mixin named `name` is a known guard the checkout doesn't redefine."""
        last = name.split(".")[-1]
        return last in KNOWN_GUARDS - self.disabled and self.resolve(name) is None

    def permission(self, name: str) -> str:
        """`guard`, `read-only` (lets an anonymous caller read) or `none`."""
        last = name.split(".")[-1]
        if self.resolve(name) is not None:
            return "none"  # a checkout class, whatever its name
        if last in KNOWN_PERMISSIONS:
            return "guard"
        return "read-only" if last in READ_ONLY_PERMISSIONS else "none"
