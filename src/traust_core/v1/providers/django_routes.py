"""Django and Django REST framework routes, read with `ast`: the `urlpatterns` of each urlconf
and the `include()` chains that mount them, DRF routers and the viewsets they register, and each
view's methods and guards."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass, field, replace

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.providers.route_guards import (
    _const_str,
    _dotted,
    _guards_in,
    _mark,
    _PyIndex,
    _resolve_import,
    _Row,
    _row,
    _unguards_in,
    _unique,
)

_PATH_CALLS = {"path", "re_path", "url"}
_HTTP = ("get", "post", "put", "patch", "delete", "head", "options")
# what a library view or viewset answers when the checkout doesn't say
_GENERIC_METHODS = {
    "ListAPIView": ("GET",),
    "CreateAPIView": ("POST",),
    "RetrieveAPIView": ("GET",),
    "DestroyAPIView": ("DELETE",),
    "UpdateAPIView": ("PUT", "PATCH"),
    "ListCreateAPIView": ("GET", "POST"),
    "RetrieveUpdateAPIView": ("GET", "PUT", "PATCH"),
    "RetrieveDestroyAPIView": ("GET", "DELETE"),
    "RetrieveUpdateDestroyAPIView": ("GET", "PUT", "PATCH", "DELETE"),
    "TemplateView": ("GET",),
    "ListView": ("GET",),
    "DetailView": ("GET",),
    "RedirectView": ("GET",),
    "CreateView": ("GET", "POST"),
    "UpdateView": ("GET", "POST"),
    "FormView": ("GET", "POST"),
    "DeleteView": ("GET", "POST"),
}
_VIEWSET_ACTIONS = {
    "ModelViewSet": ("list", "create", "retrieve", "update", "partial_update", "destroy"),
    "ReadOnlyModelViewSet": ("list", "retrieve"),
    "ListModelMixin": ("list",),
    "CreateModelMixin": ("create",),
    "RetrieveModelMixin": ("retrieve",),
    "UpdateModelMixin": ("update", "partial_update"),
    "DestroyModelMixin": ("destroy",),
}
_LIST_ACTIONS = {"list": "GET", "create": "POST"}
_ALL_ACTIONS = _VIEWSET_ACTIONS["ModelViewSet"]
# library bases that answer no action of their own
_NO_ACTIONS = {"GenericViewSet", "ViewSet", "ViewSetMixin", "GenericAPIView", "APIView", "object"}
_DETAIL_ACTIONS = {
    "retrieve": "GET",
    "update": "PUT",
    "partial_update": "PATCH",
    "destroy": "DELETE",
}
_DECORATOR_METHODS = {
    "require_GET": ("GET",),
    "require_POST": ("POST",),
    "require_safe": ("GET", "HEAD"),
}
_MAX_DEPTH = 12
_LIST_CALLS = {"format_suffix_patterns", "i18n_patterns", "list", "reduce", "sum"}
_DRF_BASES = re.compile(r"APIView|ViewSet")
# CSRF protection (and its exemption) is about forged browser requests, and the method decorators
# about verbs: neither says who the caller is
_NOT_GUARDS = re.compile(r"(?i)csrf|^require_(GET|POST|safe|http_methods)$")
# decorators that set how a view runs, not who may call it
_INERT_DECORATORS = re.compile(
    r"^(api_view|action|detail_route|list_route|cache_page|cache_control|never_cache|vary_on_\w+|"
    r"condition|etag|last_modified|sensitive_\w+|xframe_options_\w+|gzip_page|atomic|"
    r"non_atomic_requests|extend_schema\w*|swagger_auto_schema|ensure_csrf_cookie)$"
)
# DRF's policy decorators: what they name is read as a permission list, or not at all
_POLICY_DECORATORS = {
    "permission_classes", "authentication_classes", "throttle_classes", "renderer_classes",
    "parser_classes", "schema", "versioning_class", "metadata_class",
}  # fmt: skip
_PERMISSION_METHODS = {"get_permissions", "check_permissions"}
# a library view: its `dispatch` runs before any mixin after it in the method order
_LIBRARY_VIEW = re.compile(r"(View|ViewSet)$")
# permissions that admit any caller, or any caller to read
_ANONYMOUS = re.compile(r"^(AllowAny|IsAnonymous\w*)$")
_READ_ONLY = re.compile(r"(^|Or)(Anon)?ReadOnly$")
_SAFE = {"GET", "HEAD", "OPTIONS", "any"}


@dataclass
class _View:
    """What a view answers: (method, handler name, definition) per route, and its guards."""

    methods: list[tuple[str, str, ast.AST | None]]
    guards: list[str]
    unguards: list[str]
    # its permission classes, each read per method; None: DRF's defaults apply to a DRF view
    permissions: list[ast.AST] | None
    drf: bool = False
    # the methods whose own decorators guard them: a class view's, not a function view's
    methods_of: set[str] = field(default_factory=set)
    # `@method_decorator(login_required, name="post")` on the class: (guards, unguards) by method
    named: dict[str, tuple[list[str], list[str]]] = field(default_factory=dict)


@dataclass
class _Router:
    """A DRF router: what is registered on it, and where it sits."""

    registered: list[tuple[str, ast.Call]] = field(default_factory=list)
    extends: list[tuple[str, str]] = field(default_factory=list)
    # a nested router's parent and the part of its routes the parent adds
    parent: tuple[tuple[str, str] | None, str] | None = None
    default: bool = False
    slash: str = "/"
    dynamic: bool = False


@dataclass
class _Django:
    index: _PyIndex
    consts: dict[str, str]
    # the settings guards of the root urlconf being mounted
    current: tuple[list[str], list[ast.AST]] = ([], [])
    rows: list[_Row] = field(default_factory=list)
    included: set[str] = field(default_factory=set)
    mounted: set[str] = field(default_factory=set)
    seen: set[int] = field(default_factory=set)
    trees: dict[str, ast.Module] = field(default_factory=dict)
    _lists: dict[str, dict[str, list[ast.AST]]] = field(default_factory=dict)
    _routers: dict[tuple[str, str], _Router] | None = None

    def __post_init__(self) -> None:
        self.trees = {s.file.rel: s.tree for s in self.index.sources}
        self.projects = self.settings()

    def file(self, module: str, rel: str) -> str | None:
        return self.index.modules.near(module, rel)

    # ---- settings
    def settings(self) -> dict[str, tuple[list[str], list[ast.AST]]]:
        """Each root urlconf's project-wide guards (`LoginRequiredMiddleware`, DRF's
        `DEFAULT_PERMISSION_CLASSES`) from the settings that name it: read as code, only where
        set unconditionally, and only those every settings module of the project agrees on."""
        found: dict[str, list[tuple[list[str], list[ast.AST]]]] = {}
        for rel in self.trees:
            values = self.setting_values(rel, frozenset())
            if not values.keys() & {"ROOT_URLCONF", "MIDDLEWARE", "REST_FRAMEWORK"}:
                continue
            middleware = [
                "LoginRequiredMiddleware"
                for v in _strings(values.get("MIDDLEWARE"))
                if v.endswith("LoginRequiredMiddleware")
            ]
            drf = values.get("REST_FRAMEWORK")
            permissions = (
                next(
                    (
                        v
                        for k, v in zip(drf.keys, drf.values, strict=False)
                        if _const_str(k) == "DEFAULT_PERMISSION_CLASSES"
                    ),
                    None,
                )
                if isinstance(drf, ast.Dict)
                else None
            )
            entry = (middleware, _elements(permissions) if permissions is not None else [])
            root = _const_str(values.get("ROOT_URLCONF"))
            where = self.file(root, rel) if root else None
            if where is not None:
                found.setdefault(where, []).append(entry)
            elif root is None:
                # no ROOT_URLCONF: the urlconfs beside the settings
                home = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
                for conf in self.trees:
                    if conf.startswith(home) and "urlpatterns" in self.lists(conf):
                        found.setdefault(conf, []).append(entry)
        return {
            root: (
                [m for m in entries[0][0] if all(m in e[0] for e in entries)],
                [
                    d
                    for d in entries[0][1]
                    if all(_label(d) in {_label(x) for x in e[1]} for e in entries)
                ],
            )
            for root, entries in found.items()
        }

    def setting_values(self, rel: str, seen: frozenset[str]) -> dict[str, ast.AST]:
        """A settings module's unconditional top-level values, over the ones it star-imports."""
        tree = self.trees.get(rel)
        if tree is None or rel in seen:
            return {}
        values: dict[str, ast.AST] = {}
        for n in tree.body:
            if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names):
                module = _resolve_import(rel, n.module, n.level)
                if (where := self.file(module, rel)) is not None:
                    values.update(self.setting_values(where, seen | {rel}))
            elif isinstance(n, ast.Assign | ast.AnnAssign) and n.value is not None:
                for t in _targets(n):
                    if isinstance(t, ast.Name) and t.id.isupper():
                        values[t.id] = n.value
        return values

    # ---- urlconfs
    def run(self) -> list[_Row]:
        confs = [rel for rel in self.trees if "urlpatterns" in self.lists(rel)]
        # what each urlconf includes, so the ones nothing includes are the roots
        for rel in confs:
            for n in ast.walk(self.trees[rel]):
                if self.is_path(rel, n):
                    target = self.include_target(rel, n)
                    if isinstance(target, str):
                        self.included.add(target)
        roots = [r for r in confs if r not in self.included or r in self.projects]
        for rel in roots:
            self.current = self.projects.get(rel, ([], []))
            self.mount(rel, "", False, frozenset())
        self.current = ([], [])  # what can't be placed takes no project's settings
        # what the walk couldn't place (a urlconf mounted from code it can't read, a route list
        # built by a function) is listed with its prefix unknown, never dropped
        for rel in confs:
            if rel not in self.mounted:
                self.mount(rel, "", True, frozenset())
        for rel, tree in self.trees.items():
            if rel in confs or any(
                m.startswith(("django.urls", "django.conf.urls"))
                for m in self.index.modules.imported.get(rel, {}).values()
            ):
                forwarded = _forwarded(tree)
                for n in ast.walk(tree):
                    if self.is_path(rel, n) and id(n) not in self.seen | forwarded:
                        self.entry(rel, n, "", True, frozenset())
        return self.rows

    def is_path(self, rel: str, node: ast.AST) -> bool:
        """A path() call, or a call to the checkout's own helper that builds one
        (`opt_slash_path("_health", health)`)."""
        if not isinstance(node, ast.Call):
            return False
        origin = self.index.modules.imported.get(rel, {}).get(_dotted(node.func), "")
        if _name(node) in _PATH_CALLS or (
            # `from django.urls import path as dj_path`
            origin.startswith(("django.urls.", "django.conf.urls."))
            and origin.rsplit(".", 1)[-1] in _PATH_CALLS
        ):
            return True
        if _route_args(node) == (None, None):
            return False
        fn = self.index.callee(_dotted(node.func), rel)
        return (
            fn is not None
            and fn.node is not None
            and any(isinstance(n, ast.Call) and _name(n) in _PATH_CALLS for n in ast.walk(fn.node))
        )

    def lists(self, rel: str) -> dict[str, list[ast.AST]]:
        """What each module-level list is built from: its assignment, then every `+=`,
        `.append`, `.extend` and `.insert`; a conditional assignment adds to it."""
        if rel in self._lists:
            return self._lists[rel]
        out: dict[str, list[ast.AST]] = {}
        for n, conditional in _module_statements(self.trees[rel].body, False):
            if isinstance(n, ast.Assign | ast.AnnAssign) and n.value is not None:
                for t in _targets(n):
                    name = _dotted(t)
                    # `urlpatterns = format_suffix_patterns(urlpatterns)` keeps what it held
                    again = any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(n.value))
                    kept = out.get(name, []) if conditional or again else []
                    out[name] = [*kept, n.value]
            elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                out.setdefault(n.target.id, []).append(n.value)
            elif (
                isinstance(n, ast.Expr)
                and isinstance(n.value, ast.Call)
                and isinstance(n.value.func, ast.Attribute)
                and isinstance(n.value.func.value, ast.Name)
                and n.value.func.attr in ("append", "extend", "insert")
                and n.value.args
            ):
                arg = n.value.args[-1]
                added = arg if n.value.func.attr == "extend" else ast.List(elts=[arg])
                out.setdefault(n.value.func.value.id, []).append(added)
        self._lists[rel] = out
        return out

    def flatten(self, rel: str, node: ast.AST | None, stack: frozenset[str]) -> list[ast.AST]:
        """The path() calls and `router.urls` a urlpatterns expression stands for, in order."""
        if isinstance(node, ast.List | ast.Tuple):
            out: list[ast.AST] = []
            for e in node.elts:
                e = e.value if isinstance(e, ast.Starred) else e
                nested = isinstance(e, ast.Name | ast.List | ast.Tuple | ast.BinOp) or (
                    isinstance(e, ast.Call) and _name(e) in _LIST_CALLS
                )
                out += self.flatten(rel, e, stack) if nested else [e]
            return out
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.flatten(rel, node.left, stack) + self.flatten(rel, node.right, stack)
        if isinstance(node, ast.Name) and node.id not in stack:
            return [
                e
                for part in self.lists(rel).get(node.id, [])
                for e in self.flatten(rel, part, stack | {node.id})
            ]
        if isinstance(node, ast.Attribute) and node.attr == "urls":
            return [node]  # `router.urls`
        if isinstance(node, ast.Call) and _name(node) == "i18n_patterns":
            # its routes sit under the language code: `[language]/about/`
            inner = ast.List(elts=self.flatten(rel, ast.List(elts=node.args), stack))
            prefix = ast.JoinedStr(
                values=[
                    ast.FormattedValue(value=ast.Name(id="language"), conversion=-1),
                    ast.Constant("/"),
                ]
            )
            mounted = ast.Call(
                func=ast.Name(id="path"),
                args=[prefix, ast.Call(func=ast.Name(id="include"), args=[inner], keywords=[])],
                keywords=[],
            )
            return [ast.fix_missing_locations(ast.copy_location(mounted, node))]
        if isinstance(node, ast.Call) and _name(node) in _LIST_CALLS:
            # `reduce(add, groups)` folds its second argument
            args = node.args[1:] if _name(node) == "reduce" else node.args
            return [e for a in args for e in self.flatten(rel, a, stack)]
        return []

    def include_target(
        self, rel: str, call: ast.Call
    ) -> str | ast.Attribute | tuple[str, ast.AST] | None:
        """What a path() includes: a urlconf's file, `router.urls`, or a list of entries."""
        view = _route_args(call)[1]
        if not (isinstance(view, ast.Call) and _name(view) == "include" and view.args):
            return None
        arg = view.args[0]
        if isinstance(arg, ast.Tuple) and arg.elts:
            arg = arg.elts[0]  # `include(("app.urls", "app"))`
        if (module := _const_str(arg)) is not None:
            return self.file(module, rel) or ""
        if isinstance(arg, ast.Attribute) and arg.attr == "urls":
            return arg
        name = _dotted(arg)
        target = self.index.modules.imported.get(rel, {}).get(name.split(".")[0])
        if target is not None and not isinstance(arg, ast.Call):
            module = ".".join([target, *name.split(".")[1:]])
            home, _, local = module.rpartition(".")
            where = self.file(home, rel) if home else None
            if where is not None and local in self.lists(where):
                return where, ast.Name(id=local)  # a list another module builds
            return self.file(module, rel) or self.file(f"{module}.urls", rel) or ""
        return rel, arg  # a list, or a name bound in this module

    # ---- mounting
    def mount(self, rel: str, prefix: str, dynamic: bool, stack: frozenset[str]) -> None:
        if rel in stack or len(stack) > _MAX_DEPTH:
            return
        self.mounted.add(rel)
        for entry in self.flatten(rel, ast.Name(id="urlpatterns"), frozenset()):
            self.entry(rel, entry, prefix, dynamic, stack | {rel})

    def entry(
        self, rel: str, entry: ast.AST, prefix: str, dynamic: bool, stack: frozenset[str]
    ) -> None:
        self.seen.add(id(entry))
        if isinstance(entry, ast.Attribute) and entry.attr == "urls":
            self.router(rel, entry, prefix, dynamic)
            return
        if not (isinstance(entry, ast.Call) and self.is_path(rel, entry)):
            return
        route, view = _route_args(entry)
        if route is None:
            return
        part, computed = self.part(route)
        pattern, dynamic = _join(prefix, part), dynamic or computed
        target = self.include_target(rel, entry)
        if target == "":
            # a library's urlconf: its routes and guards aren't in the checkout
            text = ast.unparse(view)[:200] if view is not None else ""
            self.emit(rel, entry.lineno, dynamic, _UNREAD, [("any", pattern, text, None)])
            return
        if isinstance(target, str):
            self.mount(target, pattern, dynamic, stack)
            return
        if isinstance(target, ast.Attribute):
            self.router(rel, target, pattern, dynamic)
            return
        if target is not None:
            where, entries = target
            for e in self.flatten(where, entries, frozenset()):
                self.entry(where, e, pattern, dynamic, stack)
            return
        self.view_rows(rel, view, pattern, dynamic, entry.lineno)

    def part(self, node: ast.AST) -> tuple[str, bool]:
        """A path() pattern's text, and whether it's computed: what isn't a literal or a
        module constant is kept as `[expr]`, which no path parameter looks like."""
        if (text := _const_str(node)) is not None:
            return text, False
        if isinstance(node, ast.Name) and node.id in self.consts:
            return self.consts[node.id], False
        if isinstance(node, ast.JoinedStr):
            parts = [
                v.value if isinstance(v, ast.Constant) else f"[{ast.unparse(v.value)}]"
                for v in node.values
            ]
            return "".join(str(p) for p in parts)[:160], True
        return f"[{ast.unparse(node)[:160]}]", True

    def view_rows(
        self, rel: str, view: ast.AST | None, pattern: str, dynamic: bool, line: int
    ) -> None:
        # decorators applied in the urlconf: `login_required(views.page)`, `cache_page(60)(view)`
        wrappers: list[ast.AST] = []
        while (
            isinstance(view, ast.Call)
            and not (isinstance(view.func, ast.Attribute) and view.func.attr == "as_view")
            and len(view.args) == 1
            and isinstance(view.args[0], ast.Name | ast.Attribute | ast.Call)
        ):
            wrappers.append(view.func)
            view = view.args[0]
        info = self.view(rel, view)
        if info is None:
            text = ast.unparse(view)[:200] if view is not None else ""
            info, routes = replace(_UNREAD), [("any", pattern, text, None)]
        else:
            routes = [(m, pattern, h, n) for m, h, n in info.methods]
        for w in wrappers:
            guards, unguards = _decorator_guards(w)
            info.guards = _unique([*info.guards, *guards])
            info.unguards = sorted({*info.unguards, *unguards})
        self.emit(rel, line, dynamic, info, routes)

    def emit(
        self,
        rel: str,
        line: int,
        dynamic: bool,
        info: _View,
        routes: list[tuple[str, str, str, ast.AST | None]],
    ) -> None:
        middleware, defaults = self.current
        for verb, pattern, handler, node in routes:
            guards, unguards, permissions = self.method_guards(node, info)
            named_guards, named_unguards = info.named.get(handler.rsplit(".", 1)[-1], ([], []))
            guards, unguards = [*guards, *named_guards], [*unguards, *named_unguards]
            inherited = permissions is None
            granted, open_ = _permitted(
                (defaults if inherited else permissions) if info.drf else [], verb
            )
            # `login_not_required` exempts a view from `LoginRequiredMiddleware`
            scope = [] if "login_not_required" in unguards else list(middleware)
            row = _row(
                RouteFamily.DJANGO_DRF,
                verb,
                pattern or "/",
                handler,
                rel,
                line,
                _unique([*guards, *([] if inherited else granted)]),
                _unique([*scope, *(granted if inherited else [])]),
                sorted({*unguards, *open_}),
            )
            if node is not None:
                self.index.locate(row, node)
            self.rows.append(_mark(row, None, dynamic, rel))

    def method_guards(
        self, node: ast.AST | None, info: _View
    ) -> tuple[list[str], list[str], list[ast.AST] | None]:
        """A view's guards with its method's decorators; an `@action(permission_classes=..)`
        replaces the viewset's permissions."""
        guards, unguards, permissions = list(info.guards), list(info.unguards), info.permissions
        if (
            not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            or node.name not in info.methods_of
        ):
            return guards, unguards, permissions
        for d in node.decorator_list:
            override = (
                next((k.value for k in d.keywords if k.arg == "permission_classes"), None)
                if isinstance(d, ast.Call) and _name(d) == "action"
                else None
            )
            if override is not None:
                permissions = _elements(override)
                continue
            more, fewer = _decorator_guards(d)
            guards, unguards = [*guards, *more], [*unguards, *fewer]
        return _unique(guards), sorted(set(unguards)), permissions

    # ---- views
    def view(self, rel: str, node: ast.AST | None) -> _View | None:
        """The view a path() names: `View.as_view()`, `ViewSet.as_view({..})`, a function."""
        if node is None:
            return None
        mapping: dict[str, str] | None = None
        init: dict[str | None, ast.AST] = {}
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "as_view"
        ):
            if node.args and isinstance(node.args[0], ast.Dict):
                mapping = {
                    k.value.upper(): v.value
                    for k, v in zip(node.args[0].keys, node.args[0].values, strict=False)
                    if isinstance(k, ast.Constant) and isinstance(v, ast.Constant)
                }
            init = {k.arg: k.value for k in node.keywords}
            node = node.func.value
        found = self.definition(_dotted(node), rel)
        if found is None:
            return None
        def_rel, definition = found
        if not isinstance(definition, ast.ClassDef):
            return self.function_view(definition)
        info = self.class_view(def_rel, definition, mapping)
        if "permission_classes" in init:
            # `as_view(permission_classes=[AllowAny])` replaces the class attribute
            info.permissions = _elements(init["permission_classes"])
        return info

    def definition(
        self, dotted: str, rel: str
    ) -> tuple[str, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef] | None:
        """The class or function a name from `rel` is, through its imports."""
        if not dotted:
            return None
        index = self.index
        name = dotted.split(".")[-1]
        target = index.modules.imported.get(rel, {}).get(dotted.split(".")[0])
        candidates: list[str] = []
        if target is not None:
            full = ".".join([target, *dotted.split(".")[1:]])
            where = self.file(full.rpartition(".")[0], rel) or self.file(full, rel)
            if where is not None:
                candidates.append(where)
        candidates.append(rel)
        for where in candidates:
            tree = self.trees.get(where)
            for n in tree.body if tree is not None else []:
                if (
                    isinstance(n, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
                    and n.name == name
                ):
                    return where, n
        if target is not None:
            return None  # imported from a library
        # a name the urlconf never imports (a star import): the checkout's one definition of it
        found = [
            (where, n)
            for where, tree in ((s.file.rel, s.tree) for s in index.sources)
            for n in tree.body
            if isinstance(n, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
            and n.name == name
        ]
        return found[0] if len(found) == 1 else None

    def mro(self, rel: str, cls: ast.ClassDef) -> list[tuple[str, ast.ClassDef | str]]:
        """A class's method resolution order (C3), the checkout's classes resolved, a library's
        by name; depth-first where C3 can't be built."""
        return self.linearize(rel, cls, frozenset()) or self.depth_first(rel, cls, 0)

    def linearize(
        self, rel: str, cls: ast.ClassDef, seen: frozenset[int]
    ) -> list[tuple[str, ast.ClassDef | str]] | None:
        if id(cls) in seen or len(seen) > _MAX_DEPTH:
            return None
        lines: list[list[tuple[str, ast.ClassDef | str]]] = []
        for base in cls.bases:
            name = _dotted(base)
            found = self.definition(name, rel)
            if found is not None and isinstance(found[1], ast.ClassDef) and found[1] is not cls:
                line = self.linearize(found[0], found[1], seen | {id(cls)})
                if line is None:
                    return None
                lines.append(line)
            else:
                lines.append([(rel, name.split(".")[-1])])
        lines.append([line[0] for line in lines])
        out: list[tuple[str, ast.ClassDef | str]] = [(rel, cls)]
        key = _class_key
        while any(lines):
            head = next(
                (
                    line[0]
                    for line in lines
                    if line
                    and not any(key(line[0]) in {key(x) for x in other[1:]} for other in lines)
                ),
                None,
            )
            if head is None:
                return None  # an order Python would refuse too
            out.append(head)
            lines = [[x for x in line if key(x) != key(head)] for line in lines]
        return out

    def depth_first(
        self, rel: str, cls: ast.ClassDef, depth: int
    ) -> list[tuple[str, ast.ClassDef | str]]:
        out: list[tuple[str, ast.ClassDef | str]] = [(rel, cls)]
        for base in cls.bases if depth <= _MAX_DEPTH else []:
            name = _dotted(base)
            found = self.definition(name, rel)
            if found is not None and isinstance(found[1], ast.ClassDef) and found[1] is not cls:
                out += self.depth_first(found[0], found[1], depth + 1)
            else:
                out.append((rel, name.split(".")[-1]))
        return out

    def class_view(self, rel: str, cls: ast.ClassDef, mapping: dict[str, str] | None) -> _View:
        mro = self.mro(rel, cls)
        names = [c if isinstance(c, str) else c.name for _, c in mro]
        defined: dict[str, tuple[str, ast.AST]] = {}
        aliases: dict[str, str] = {}
        for where, c in mro:
            if isinstance(c, ast.ClassDef):
                for n in c.body:
                    if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef):
                        defined.setdefault(n.name, (where, n))
                    elif isinstance(n, ast.Assign) and isinstance(n.value, ast.Name):
                        for t in n.targets:  # `post = get`
                            aliases.setdefault(_dotted(t), n.value.id)
        for alias, name in aliases.items():
            if alias not in defined and name in defined:
                defined[alias] = defined[name]
        policy = self.class_policy(mro)
        methods: list[tuple[str, str, ast.AST | None]] = []
        if mapping is not None:
            for verb, action in mapping.items():
                node = defined.get(action, (None, cls))[1]
                methods.append((verb, f"{cls.name}.{action}", node))
        else:
            # what the checkout defines, and what a library generic still answers for itself
            generic = next((_GENERIC_METHODS[n] for n in names if n in _GENERIC_METHODS), ())
            for http in _HTTP:
                if http in defined:
                    methods.append((http.upper(), f"{cls.name}.{http}", defined[http][1]))
                elif http.upper() in generic:
                    methods.append((http.upper(), f"{cls.name}.{http}", cls))
            if not methods:
                methods = [("any", cls.name, cls)]
        policy.methods = methods
        policy.methods_of = {
            n.name for _, _, n in methods if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        policy.drf = any(_DRF_BASES.search(n) for n in names)
        return policy

    def class_policy(self, mro: list[tuple[str, ast.ClassDef | str]]) -> _View:
        """A class view's guards, in method resolution order: auth mixins only ahead of the
        library view whose `dispatch` would run first; the nearest `permission_classes`, unless
        a library DRF view (whose default it is) comes first; `get_permissions` read as code we
        don't follow; `method_decorator(name=)` only where no earlier class defines the method."""
        guards: list[str] = []
        unguards: list[str] = []
        named: dict[str, tuple[list[str], list[str]]] = {}
        permissions: list[ast.AST] | None = None
        settled = viewed = False
        earlier: set[str] = set()  # the methods a class earlier in the order defines
        for _, c in mro:
            if isinstance(c, str):
                if _LIBRARY_VIEW.search(c):
                    viewed = True
                    settled = settled or bool(_DRF_BASES.search(c))
                elif c.endswith("Mixin") and not viewed:
                    more, fewer = _decorator_guards(ast.Name(id=c))
                    guards, unguards = [*guards, *more], [*unguards, *fewer]
                continue
            own = {n.name for n in c.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}
            for d in c.decorator_list:
                method = (
                    _const_str(next((k.value for k in d.keywords if k.arg == "name"), None))
                    if isinstance(d, ast.Call) and _name(d) == "method_decorator"
                    else None
                )
                more, fewer = _decorator_guards(d)
                if method is not None and method != "dispatch":
                    if method not in earlier:
                        held = named.setdefault(method, ([], []))
                        held[0].extend(more)
                        held[1].extend(fewer)
                elif "dispatch" not in earlier:
                    guards, unguards = [*guards, *more], [*unguards, *fewer]
            if not settled and own & _PERMISSION_METHODS:
                # which permissions apply is decided by code: never shown as a guard
                unguards.append(sorted(own & _PERMISSION_METHODS)[0])
                permissions, settled = [], True
            if not settled:
                for n in c.body:
                    if (
                        isinstance(n, ast.Assign | ast.AnnAssign)
                        and n.value is not None
                        and any(_dotted(t) == "permission_classes" for t in _targets(n))
                    ):
                        permissions, settled = _elements(n.value), True
            earlier |= own
        return _View([], _unique(guards), sorted(set(unguards)), permissions, named=named)

    def function_view(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> _View:
        methods: tuple[str, ...] = ("any",)
        guards: list[str] = []
        unguards: list[str] = []
        permissions: list[ast.AST] | None = None
        names = [_dotted(d).split(".")[-1] for d in fn.decorator_list]
        # DRF's policy decorators only count below `@api_view`, which reads what they set
        api_view = names.index("api_view") if "api_view" in names else None
        for i, (d, name) in enumerate(zip(fn.decorator_list, names, strict=True)):
            if name in _DECORATOR_METHODS:
                methods = _DECORATOR_METHODS[name]
            elif (
                name in ("require_http_methods", "api_view") and isinstance(d, ast.Call) and d.args
            ):
                methods = tuple(m.upper() for m in _strings(d.args[0])) or methods
            if name in _POLICY_DECORATORS:
                if (
                    name == "permission_classes"
                    and api_view is not None
                    and i > api_view
                    and isinstance(d, ast.Call)
                    and d.args
                ):
                    permissions = _elements(d.args[0])
                continue
            more, fewer = _decorator_guards(d)
            guards, unguards = [*guards, *more], [*unguards, *fewer]
        return _View(
            [(m, fn.name, fn) for m in methods],
            _unique(guards),
            sorted(set(unguards)),
            permissions,
            drf=api_view is not None,
        )

    # ---- DRF routers
    def routers(self) -> dict[tuple[str, str], _Router]:
        """Every module-level DRF router (`DefaultRouter()`, drf-nested-routers' nested ones),
        with the viewsets registered on it from any module."""
        if self._routers is not None:
            return self._routers
        found: dict[tuple[str, str], _Router] = {}
        for rel, tree in self.trees.items():
            for n, _ in _module_statements(tree.body, False):
                value = n.value if isinstance(n, ast.Assign | ast.AnnAssign) else None
                if isinstance(value, ast.IfExp):  # `DefaultRouter() if DEBUG else SimpleRouter()`
                    value = value.body
                if not (isinstance(value, ast.Call) and _name(value).endswith("Router")):
                    continue
                kw = {k.arg: k.value for k in value.keywords}
                slash = kw.get("trailing_slash")
                router = found.setdefault((rel, _dotted(_targets(n)[0])), _Router())
                router.default |= "Default" in _name(value)
                router.slash = (
                    "" if isinstance(slash, ast.Constant) and slash.value is False else "/"
                )
                router.dynamic |= slash is not None and not isinstance(slash, ast.Constant)
                if _name(value).startswith("Nested") and len(value.args) >= 2:
                    # `NestedSimpleRouter(parent, r"notes", lookup="note")`
                    parent = self.router_key(rel, _dotted(value.args[0]))
                    route, computed = self.part(value.args[1])
                    lookup = _const_str(kw.get("lookup")) or "parent"
                    router.parent = (parent, f"{route.strip('^$').strip('/')}/<{lookup}_pk>/")
                    router.dynamic |= computed or parent is None
        self._routers = found
        for rel, tree in self.trees.items():
            for n in ast.walk(tree):
                if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
                    continue
                if n.func.attr == "register" and len(n.args) >= 2:
                    key = self.router_key(rel, _dotted(n.func.value))
                    if key in found:
                        found[key].registered.append((rel, n))
                elif (
                    n.func.attr == "extend"
                    and isinstance(n.func.value, ast.Attribute)
                    and n.func.value.attr == "registry"
                    and n.args
                ):
                    # `router.registry.extend(other.registry)`
                    key = self.router_key(rel, _dotted(n.func.value.value))
                    other = self.router_key(rel, _dotted(n.args[0]).removesuffix(".registry"))
                    if key in found and other in found:
                        found[key].extends.append(other)
        return found

    def router_key(self, rel: str, name: str) -> tuple[str, str] | None:
        """The (module, name) a router named in `rel` is bound at, through its imports."""
        if (rel, name) in (self._routers or {}) or (
            "." not in name
            and any(
                isinstance(n, ast.Assign | ast.AnnAssign)
                and name in {_dotted(t) for t in _targets(n)}
                for n, _ in _module_statements(self.trees.get(rel, ast.Module([], [])).body, False)
            )
        ):
            return rel, name
        target = self.index.modules.imported.get(rel, {}).get(name.split(".")[0])
        if target is None:
            return None
        full = ".".join([target, *name.split(".")[1:]])
        module, _, local = full.rpartition(".")
        where = self.file(module, rel)
        return (where, local) if where else None

    def router(self, rel: str, urls: ast.Attribute, prefix: str, dynamic: bool) -> None:
        """The routes `router.urls` stands for: each registered viewset's list and detail routes
        and its `@action`s."""
        key = self.router_key(rel, _dotted(urls.value))
        routers = self.routers()
        if key not in routers:  # `admin.site.urls`, a library's router
            self.emit(
                rel, urls.lineno, dynamic, _UNREAD, [("any", prefix, ast.unparse(urls), None)]
            )
            return
        router = routers[key]
        base, base_dynamic = self.router_base(key, frozenset())
        dynamic = dynamic or base_dynamic or router.dynamic
        if router.default:
            # DefaultRouter's API root view
            self.emit(
                rel,
                urls.lineno,
                dynamic,
                _View([], [], [], None, True),
                [("GET", prefix or "/", "APIRootView", None)],
            )
        for k in [key, *router.extends]:
            for where, n in routers[k].registered:
                route, computed = self.part(n.args[0])
                route = route.strip("^$").strip("/")
                self.viewset_rows(
                    where,
                    n.args[1],
                    _join(prefix, base + route),
                    dynamic or computed,
                    n.lineno,
                    router.slash,
                )

    def router_base(
        self, key: tuple[str, str] | None, seen: frozenset[tuple[str, str]]
    ) -> tuple[str, bool]:
        """A nested router's routes sit under its parents': `notes/<note_pk>/comments/..`."""
        router = self.routers().get(key) if key is not None else None
        if router is None or router.parent is None or key in seen or key is None:
            return "", key in seen
        parent, own = router.parent
        above, dynamic = self.router_base(parent, seen | {key})
        return above + own, dynamic

    def viewset_rows(
        self, rel: str, node: ast.AST, prefix: str, dynamic: bool, line: int, slash: str = "/"
    ) -> None:
        found = self.definition(_dotted(node), rel)
        if found is None or not isinstance(found[1], ast.ClassDef):
            self.view_rows(rel, node, prefix + slash, dynamic, line)
            return
        where, cls = found
        mro = self.mro(where, cls)
        actions: dict[str, ast.AST] = {}
        extra: list[tuple[str, str, ast.AST, bool, list[str]]] = []
        for _, c in reversed(mro):
            if isinstance(c, str):
                # a library base whose actions we don't know may answer any of them
                known = _VIEWSET_ACTIONS.get(c)
                for a in known if known is not None else (() if c in _NO_ACTIONS else _ALL_ACTIONS):
                    actions.setdefault(a, cls)
                continue
            mapped: dict[str, list[tuple[str, ast.AST]]] = {}
            for n in c.body:
                if not isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                if n.name in _LIST_ACTIONS or n.name in _DETAIL_ACTIONS:
                    actions[n.name] = n
                for d in n.decorator_list:
                    # `@share.mapping.delete`: another verb of the `share` action
                    if (
                        isinstance(d, ast.Attribute)
                        and isinstance(d.value, ast.Attribute)
                        and d.value.attr == "mapping"
                    ):
                        mapped.setdefault(_dotted(d.value.value), []).append((d.attr.upper(), n))
                deco = next(
                    (
                        d
                        for d in n.decorator_list
                        if _dotted(d).split(".")[-1] in ("action", "detail_route", "list_route")
                    ),
                    None,
                )
                if deco is None:
                    continue
                kw = {k.arg: k.value for k in deco.keywords} if isinstance(deco, ast.Call) else {}
                detail = _dotted(deco).endswith("detail_route") or (
                    isinstance(kw.get("detail"), ast.Constant) and kw["detail"].value is True
                )
                methods = [
                    e.value.upper()
                    for e in getattr(kw.get("methods"), "elts", [])
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                ] or ["GET"]
                url_path = _const_str(kw.get("url_path")) or n.name
                extra.append((n.name, url_path, n, detail, methods))
            extra += [
                (fn.name, url_path, fn, detail, [verb])
                for action, url_path, _, detail, _ in list(extra)
                for verb, fn in mapped.get(action, [])
            ]
        policy = self.class_policy(mro)
        detail_prefix = f"{prefix}/<{self.lookup(mro)}>"
        routes = [
            (verb, f"{prefix}{slash}", f"{cls.name}.{action}", actions[action])
            for action, verb in _LIST_ACTIONS.items()
            if action in actions
        ]
        routes += [
            (verb, f"{detail_prefix}{slash}", f"{cls.name}.{action}", actions[action])
            for action, verb in _DETAIL_ACTIONS.items()
            if action in actions
        ]
        for name, url_path, n, detail, methods in extra:
            base = detail_prefix if detail else prefix
            routes += [
                (m, f"{base}/{url_path.strip('/')}{slash}", f"{cls.name}.{name}", n)
                for m in methods
            ]
        if not routes:
            routes = [("any", f"{prefix}{slash}", cls.name, cls)]
        methods_of = {
            n.name for _, _, _, n in routes if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        self.emit(
            rel,
            line,
            dynamic,
            _View(
                [],
                policy.guards,
                policy.unguards,
                policy.permissions,
                True,
                methods_of,
                policy.named,
            ),
            routes,
        )

    def lookup(self, mro: list[tuple[str, ast.ClassDef | str]]) -> str:
        """The detail route's URL keyword: `lookup_url_kwarg`, `lookup_field`, else `pk`."""
        for attr in ("lookup_url_kwarg", "lookup_field"):
            for _, c in mro:
                if isinstance(c, ast.ClassDef):
                    for n in c.body:
                        if (
                            isinstance(n, ast.Assign)
                            and attr in {_dotted(t) for t in n.targets}
                            and (value := _const_str(n.value)) is not None
                        ):
                            return value
        return "pk"


_UNREAD = _View([], [], [], None)


def _forwarded(tree: ast.Module) -> set[int]:
    """The path() calls inside a helper that passes its own parameters on: the helper's callers
    are the routes."""
    out: set[int] = set()
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            params = {a.arg for a in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]}
            out |= {
                id(n)
                for n in ast.walk(fn)
                if isinstance(n, ast.Call)
                and len(n.args) >= 2
                and any(isinstance(a, ast.Name) and a.id in params for a in n.args[:2])
            }
    return out


def _module_statements(body: list[ast.stmt], conditional: bool) -> Iterator[tuple[ast.stmt, bool]]:
    """A module's statements, through the `if`/`try`/`with`/`for` blocks around them."""
    for n in body:
        if isinstance(n, ast.If | ast.Try | ast.For | ast.While):
            for block in ("body", "orelse", "finalbody"):
                yield from _module_statements(getattr(n, block, []), True)
            for h in getattr(n, "handlers", []):
                yield from _module_statements(h.body, True)
        elif isinstance(n, ast.With):
            yield from _module_statements(n.body, conditional)
        else:
            yield n, conditional


def _targets(node: ast.Assign | ast.AugAssign | ast.AnnAssign) -> list[ast.AST]:
    if isinstance(node, ast.Assign):
        return list(node.targets)
    return [node.target]


def _route_args(call: ast.Call) -> tuple[ast.AST | None, ast.AST | None]:
    """A path() call's route and view, positional or by keyword (`path(route=.., view=..)`)."""
    kw = {k.arg: k.value for k in call.keywords}
    route = call.args[0] if call.args else kw.get("route", kw.get("regex"))
    view = call.args[1] if len(call.args) > 1 else kw.get("view")
    return route, view


def _name(call: ast.Call) -> str:
    return _dotted(call.func).split(".")[-1]


def _join(prefix: str, pattern: str) -> str:
    """Django joins an included urlconf's patterns to the prefix that mounts it; a regex keeps
    one `^` at the front and drops the prefix's `$`."""
    if not prefix:
        return pattern
    return prefix.rstrip("$") + pattern.lstrip("^")


def _decorator_guards(d: ast.AST) -> tuple[list[str], list[str]]:
    """The guards and unguards a decorator (or an auth mixin) is, by what it does: the name of
    the decorator itself, never its module's or its arguments' (`extend_schema(request=..)`)."""
    name = _dotted(d).split(".")[-1]
    if name == "method_decorator" and isinstance(d, ast.Call) and d.args:
        inner = d.args[0]
        out = [_decorator_guards(x) for x in _elements(inner)]
        return _unique([g for x, _ in out for g in x]), sorted({u for _, x in out for u in x})
    if name == "login_not_required":
        return [], [name]
    if _INERT_DECORATORS.match(name) or name in _POLICY_DECORATORS or _NOT_GUARDS.search(name):
        return [], []
    label = _dotted(d)
    if _unguards_in(name):
        return [], [label]
    if isinstance(d, ast.Call) and any(
        k.arg == "optional" and isinstance(k.value, ast.Constant) and k.value.value is True
        for k in d.keywords
    ):
        return [], [f"optional:{label}"]  # `login_required(optional=True)` lets anyone through
    return ([label] if _guards_in(name) else []), []


def _elements(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return [
            ast.Name(id=e.value) if isinstance(e, ast.Constant) and isinstance(e.value, str) else e
            for e in node.elts
        ]
    return [node]


def _label(node: ast.AST) -> str:
    return node.id if isinstance(node, ast.Name) else ast.unparse(node)[:120]


def _allows(node: ast.AST, verb: str) -> str:
    """Whether a permission class refuses an anonymous caller of `verb`: `guard`, `open`, or
    `none` for one whose name says neither. `A | B` is as weak as its weakest side, `A & B` as
    strong as its strongest; `~A` may admit anyone."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr | ast.BitAnd):
        sides = {_allows(node.left, verb), _allows(node.right, verb)}
        order = (
            ("open", "none", "guard")
            if isinstance(node.op, ast.BitOr)
            else ("guard", "none", "open")
        )
        return next(k for k in order if k in sides)
    if isinstance(node, ast.UnaryOp):
        return "open"
    name = _label(node).split(".")[-1].split("(")[0]
    if _ANONYMOUS.match(name) or _unguards_in(name):
        return "open"
    if _READ_ONLY.search(name):
        return "open" if verb in _SAFE else "guard"
    return "guard" if _guards_in(name) else "none"


def _permitted(permissions: list[ast.AST], verb: str) -> tuple[list[str], list[str]]:
    """(guards, unguards) of a permission list for one method: DRF requires every class."""
    kinds = [(_label(p), _allows(p, verb)) for p in permissions]
    if any(k == "guard" for _, k in kinds):
        return [label for label, k in kinds if k == "guard"], []
    return [], [label for label, k in kinds if k == "open"]


def _class_key(entry: tuple[str, ast.ClassDef | str]) -> object:
    return id(entry[1]) if isinstance(entry[1], ast.ClassDef) else entry[1]


def _strings(node: ast.AST | None) -> list[str]:
    return [
        e.value
        for e in getattr(node, "elts", [])
        if isinstance(e, ast.Constant) and isinstance(e.value, str)
    ]


def _guards(expr: str) -> list[str]:
    return [g for g in _guards_in(expr) if not _NOT_GUARDS.search(g)]


def _code(node: ast.AST) -> str:
    """A decorator or class attribute's source without its string literals, so a setting's name
    passed as an argument isn't read as a guard's."""
    return " ".join(_dotted(n) for n in ast.walk(node) if isinstance(n, ast.Name | ast.Attribute))


def django_rows(index: _PyIndex, consts: dict[str, str]) -> list[_Row]:
    """The Django and DRF rows of a checkout's parsed Python sources."""
    return _Django(index, consts).run()
