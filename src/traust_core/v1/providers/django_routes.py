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
    _DRF_DEFAULTS,
    _const_str,
    _dotted,
    _guards_in,
    _mark,
    _PyIndex,
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


@dataclass
class _View:
    """What a view answers: (method, handler name, definition) per route, and its guards."""

    methods: list[tuple[str, str, ast.AST | None]]
    guards: list[str]
    unguards: list[str]
    has_permissions: bool
    drf: bool = False
    # the methods whose own decorators guard them: a class view's, not a function view's
    methods_of: set[str] = field(default_factory=set)
    # `@method_decorator(login_required, name="post")` on the class: (guards, unguards) by method
    named: dict[str, tuple[list[str], list[str]]] = field(default_factory=dict)


@dataclass
class _Django:
    index: _PyIndex
    consts: dict[str, str]
    defaults: list[str] = field(default_factory=list)
    middleware: list[str] = field(default_factory=list)
    root: str | None = None
    rows: list[_Row] = field(default_factory=list)
    included: set[str] = field(default_factory=set)
    mounted: set[str] = field(default_factory=set)
    seen: set[int] = field(default_factory=set)
    trees: dict[str, ast.Module] = field(default_factory=dict)
    _lists: dict[str, dict[str, list[ast.AST]]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.trees = {s.file.rel: s.tree for s in self.index.sources}
        for src in self.index.sources:
            text = src.file.text
            if "ROOT_URLCONF" in text and (
                m := re.search(r"ROOT_URLCONF\s*=\s*['\"]([\w.]+)['\"]", text)
            ):
                self.root = self.root or self.index.modules.file(m.group(1))
            if "DEFAULT_PERMISSION_CLASSES" in text and (m := _DRF_DEFAULTS.search(text)):
                self.defaults = self.defaults or _guards(m["perms"])
            if "LoginRequiredMiddleware" in text and re.search(r"MIDDLEWARE\s*=", text):
                self.middleware = ["LoginRequiredMiddleware"]

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
        roots = [r for r in confs if r not in self.included]
        if self.root in confs and self.root not in roots:
            roots.append(self.root)
        for rel in roots:
            self.mount(rel, "", False, frozenset())
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
        if _name(node) in _PATH_CALLS:
            return True
        if len(node.args) < 2:
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
                    kept = out.get(_dotted(t), []) if conditional else []
                    out[_dotted(t)] = [*kept, n.value]
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
        if isinstance(node, ast.Call) and _name(node) in _LIST_CALLS:
            # `reduce(add, groups)` folds its second argument
            args = node.args[1:] if _name(node) == "reduce" else node.args
            return [e for a in args for e in self.flatten(rel, a, stack)]
        return []

    def include_target(self, rel: str, call: ast.Call) -> str | ast.AST | None:
        """What a path() includes: a urlconf's file, `router.urls`, or a list of entries."""
        view = call.args[1] if len(call.args) > 1 else None
        if not (isinstance(view, ast.Call) and _name(view) == "include" and view.args):
            return None
        arg = view.args[0]
        if isinstance(arg, ast.Tuple) and arg.elts:
            arg = arg.elts[0]  # `include(("app.urls", "app"))`
        if (module := _const_str(arg)) is not None:
            return self.index.modules.file(module) or ""
        if isinstance(arg, ast.Attribute) and arg.attr == "urls":
            return arg
        name = _dotted(arg)
        target = self.index.modules.imported.get(rel, {}).get(name.split(".")[0])
        if target is not None and not isinstance(arg, ast.Call):
            module = ".".join([target, *name.split(".")[1:]])
            return (
                self.index.modules.file(module) or self.index.modules.file(f"{module}.urls") or ""
            )
        return arg  # a list, or a name bound in this module

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
        part, computed = self.part(entry.args[0])
        pattern, dynamic = _join(prefix, part), dynamic or computed
        target = self.include_target(rel, entry)
        if target == "":
            # a library's urlconf: its routes and guards aren't in the checkout
            view = ast.unparse(entry.args[1])[:200]
            self.emit(rel, entry.lineno, dynamic, _UNREAD, [("any", pattern, view, None)])
            return
        if isinstance(target, str):
            self.mount(target, pattern, dynamic, stack)
            return
        if isinstance(target, ast.Attribute):
            self.router(rel, target, pattern, dynamic)
            return
        if target is not None:
            for e in self.flatten(rel, target, frozenset()):
                self.entry(rel, e, pattern, dynamic, stack)
            return
        view = entry.args[1] if len(entry.args) > 1 else None
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
            info.guards = _unique([*info.guards, *_guards(_code(w))])
            info.unguards = sorted({*info.unguards, *_unguards_in(_code(w))})
        self.emit(rel, line, dynamic, info, routes)

    def emit(
        self,
        rel: str,
        line: int,
        dynamic: bool,
        info: _View,
        routes: list[tuple[str, str, str, ast.AST | None]],
    ) -> None:
        for verb, pattern, handler, node in routes:
            guards, unguards, has_permissions = self.method_guards(node, info)
            named_guards, named_unguards = info.named.get(handler.rsplit(".", 1)[-1], ([], []))
            guards, unguards = (
                _unique([*guards, *named_guards]),
                sorted({*unguards, *named_unguards}),
            )
            row = _row(
                RouteFamily.DJANGO_DRF,
                verb,
                pattern or "/",
                handler,
                rel,
                line,
                guards,
                self.scope(has_permissions, info.drf),
                unguards,
            )
            if node is not None:
                self.index.locate(row, node)
            self.rows.append(_mark(row, None, dynamic, rel))

    def method_guards(self, node: ast.AST | None, info: _View) -> tuple[list[str], list[str], bool]:
        """A view's guards with its method's decorators; an `@action(permission_classes=..)`
        replaces the viewset's permissions."""
        guards, unguards, has_permissions = (
            list(info.guards),
            list(info.unguards),
            info.has_permissions,
        )
        if (
            not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            or node.name not in info.methods_of
        ):
            return guards, unguards, has_permissions
        for d in node.decorator_list:
            override = (
                next((k.value for k in d.keywords if k.arg == "permission_classes"), None)
                if isinstance(d, ast.Call) and _name(d) == "action"
                else None
            )
            if override is not None:
                guards, unguards, has_permissions = (
                    _guards(_code(override)),
                    _unguards_in(_code(override)),
                    True,
                )
            guards += _guards(_code(d)) if override is None else []
            unguards += _unguards_in(_code(d)) if override is None else []
        return _unique(guards), sorted(set(unguards)), has_permissions

    def scope(self, has_permissions: bool, drf: bool) -> list[str]:
        """The project-wide guards a view inherits: DRF's default permissions (a DRF view that
        names none), Django's `LoginRequiredMiddleware`."""
        return [*self.middleware, *([] if has_permissions or not drf else self.defaults)]

    # ---- views
    def view(self, rel: str, node: ast.AST | None) -> _View | None:
        """The view a path() names: `View.as_view()`, `ViewSet.as_view({..})`, a function."""
        if node is None:
            return None
        mapping: dict[str, str] | None = None
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
            node = node.func.value
        found = self.definition(_dotted(node), rel)
        if found is None:
            return None
        def_rel, definition = found
        if isinstance(definition, ast.ClassDef):
            return self.class_view(def_rel, definition, mapping)
        return self.function_view(definition)

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
            where = index.modules.file(full.rpartition(".")[0]) or index.modules.file(full)
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

    def mro(
        self, rel: str, cls: ast.ClassDef, depth: int = 0
    ) -> list[tuple[str, ast.ClassDef | str]]:
        """A class and its bases, the checkout's resolved, a library's by name."""
        out: list[tuple[str, ast.ClassDef | str]] = [(rel, cls)]
        if depth > _MAX_DEPTH:
            return out
        for base in cls.bases:
            name = _dotted(base)
            found = self.definition(name, rel)
            if found is not None and isinstance(found[1], ast.ClassDef) and found[1] is not cls:
                out += self.mro(found[0], found[1], depth + 1)
            else:
                out.append((rel, name.split(".")[-1]))
        return out

    def class_view(self, rel: str, cls: ast.ClassDef, mapping: dict[str, str] | None) -> _View:
        mro = self.mro(rel, cls)
        names = [c if isinstance(c, str) else c.name for _, c in mro]
        defined: dict[str, tuple[str, ast.AST]] = {}
        for where, c in mro:
            if isinstance(c, ast.ClassDef):
                for n in c.body:
                    if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef):
                        defined.setdefault(n.name, (where, n))
        guards, unguards, has_permissions, named = self.class_guards(mro)
        methods: list[tuple[str, str, ast.AST | None]] = []
        if mapping is not None:
            for verb, action in mapping.items():
                node = defined.get(action, (None, cls))[1]
                methods.append((verb, f"{cls.name}.{action}", node))
        else:
            for http in _HTTP:
                if http in defined:
                    methods.append((http.upper(), f"{cls.name}.{http}", defined[http][1]))
            if not methods:
                for name in names:
                    if name in _GENERIC_METHODS:
                        methods = [
                            (m, f"{cls.name}.{m.lower()}", cls) for m in _GENERIC_METHODS[name]
                        ]
                        break
            if not methods:
                methods = [("any", cls.name, cls)]
        methods_of = {
            n.name for _, _, n in methods if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        drf = any(_DRF_BASES.search(n) for n in names)
        return _View(methods, guards, unguards, has_permissions, drf, methods_of, named)

    def class_guards(
        self, mro: list[tuple[str, ast.ClassDef | str]]
    ) -> tuple[list[str], list[str], bool, dict[str, tuple[list[str], list[str]]]]:
        """`permission_classes` (the nearest), auth mixins among the bases, and decorators like
        `@method_decorator(login_required, name="dispatch")`; one naming another method guards
        only that method."""
        guards: list[str] = []
        unguards: list[str] = []
        named: dict[str, tuple[list[str], list[str]]] = {}
        has_permissions = False
        for _, c in mro:
            if isinstance(c, str):
                # a library's auth mixin (`LoginRequiredMixin`); a view (`LoginView`) isn't one
                if c.endswith("Mixin"):
                    guards += _guards(c)
                unguards += _unguards_in(c)
                continue
            for d in c.decorator_list:
                method = (
                    _const_str(next((k.value for k in d.keywords if k.arg == "name"), None))
                    if isinstance(d, ast.Call) and _name(d) == "method_decorator"
                    else None
                )
                if method is not None and method != "dispatch":
                    held = named.setdefault(method, ([], []))
                    held[0].extend(_guards(_code(d)))
                    held[1].extend(_unguards_in(_code(d)))
                    continue
                guards += _guards(_code(d))
                unguards += _unguards_in(_code(d))
            if not has_permissions:
                # `authentication_classes` only says how a caller is read: it refuses no one
                for n in c.body:
                    if isinstance(n, ast.Assign) and any(
                        _dotted(t) == "permission_classes" for t in n.targets
                    ):
                        has_permissions = True
                        guards += _guards(_code(n.value))
                        unguards += _unguards_in(_code(n.value))
        return _unique(guards), sorted(set(unguards)), has_permissions, named

    def function_view(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> _View:
        decorators = [_code(d) for d in fn.decorator_list]
        methods: tuple[str, ...] = ("any",)
        for d in fn.decorator_list:
            name = _dotted(d).split(".")[-1]
            if name in _DECORATOR_METHODS:
                methods = _DECORATOR_METHODS[name]
            elif (
                name in ("require_http_methods", "api_view") and isinstance(d, ast.Call) and d.args
            ):
                listed = [
                    e.value.upper()
                    for e in getattr(d.args[0], "elts", [])
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                ]
                methods = tuple(listed) or methods
        text = " ".join(decorators)
        drf = "api_view" in text
        return _View(
            [(m, fn.name, fn) for m in methods],
            _guards(text),
            _unguards_in(text),
            "permission_classes" in text,
            drf=drf,
        )

    # ---- DRF routers
    def router(self, rel: str, urls: ast.Attribute, prefix: str, dynamic: bool) -> None:
        """The routes `router.urls` stands for: each registered viewset's list and detail routes
        and its `@action`s."""
        found = self.router_module(rel, _dotted(urls.value))
        if found is None:  # `admin.site.urls`, a library's router
            self.emit(
                rel, urls.lineno, dynamic, _UNREAD, [("any", prefix, ast.unparse(urls), None)]
            )
            return
        where, tree, local = found
        nested: dict[str, str] = {}
        for n in tree.body:
            # drf-nested-routers: `NestedSimpleRouter(parent, r"notes", lookup="note")`
            if (
                isinstance(n, ast.Assign)
                and isinstance(n.value, ast.Call)
                and _name(n.value).startswith("Nested")
                and len(n.value.args) >= 2
            ):
                parent_prefix = _const_str(n.value.args[1]) or ""
                lookup = next(
                    (_const_str(k.value) for k in n.value.keywords if k.arg == "lookup"),
                    "parent",
                )
                for t in n.targets:
                    nested[_dotted(t)] = f"{parent_prefix.strip('/')}/<{lookup}_pk>/"
        for n in ast.walk(tree):
            if not (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "register"
                and _dotted(n.func.value) in {local, *nested}
                and len(n.args) >= 2
            ):
                continue
            base = nested.get(_dotted(n.func.value), "")
            route, computed = self.part(n.args[0])
            route = route.strip("^$").strip("/")
            self.viewset_rows(
                where, n.args[1], _join(prefix, base + route), dynamic or computed, n.lineno
            )

    def router_module(self, rel: str, name: str) -> tuple[str, ast.Module, str] | None:
        tree = self.trees.get(rel)
        if tree is not None and any(
            isinstance(n, ast.Assign) and name in {_dotted(t) for t in n.targets} for n in tree.body
        ):
            return rel, tree, name
        target = self.index.modules.imported.get(rel, {}).get(name.split(".")[0])
        if target is None:
            return None
        module, _, local = (
            ".".join([target, *name.split(".")[1:]]).rpartition(".")
            if "." in target or "." in name
            else (target, "", name)
        )
        where = self.index.modules.file(module)
        tree = self.trees.get(where) if where else None
        return (where, tree, local) if where and tree is not None else None

    def viewset_rows(self, rel: str, node: ast.AST, prefix: str, dynamic: bool, line: int) -> None:
        found = self.definition(_dotted(node), rel)
        if found is None or not isinstance(found[1], ast.ClassDef):
            self.view_rows(rel, node, prefix + "/", dynamic, line)
            return
        where, cls = found
        mro = self.mro(where, cls)
        actions: dict[str, ast.AST] = {}
        extra: list[tuple[str, str, ast.AST, bool, list[str]]] = []
        for _, c in reversed(mro):
            if isinstance(c, str):
                for a in _VIEWSET_ACTIONS.get(c, ()):
                    actions.setdefault(a, cls)
                continue
            for n in c.body:
                if not isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                if n.name in _LIST_ACTIONS or n.name in _DETAIL_ACTIONS:
                    actions[n.name] = n
                deco = next(
                    (
                        d
                        for d in n.decorator_list
                        if isinstance(d, ast.Call) and _name(d) == "action"
                    ),
                    None,
                )
                if deco is not None:
                    kw = {k.arg: k.value for k in deco.keywords}
                    detail = (
                        isinstance(kw.get("detail"), ast.Constant) and kw["detail"].value is True
                    )
                    methods = [
                        e.value.upper()
                        for e in getattr(kw.get("methods"), "elts", [])
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    ] or ["GET"]
                    url_path = _const_str(kw.get("url_path")) or n.name
                    extra.append((n.name, url_path, n, detail, methods))
        guards, unguards, has_permissions, named = self.class_guards(mro)
        detail_prefix = f"{prefix}/<{self.lookup(mro)}>"
        routes = [
            (verb, f"{prefix}/", f"{cls.name}.{action}", actions[action])
            for action, verb in _LIST_ACTIONS.items()
            if action in actions
        ]
        routes += [
            (verb, f"{detail_prefix}/", f"{cls.name}.{action}", actions[action])
            for action, verb in _DETAIL_ACTIONS.items()
            if action in actions
        ]
        for name, url_path, n, detail, methods in extra:
            base = detail_prefix if detail else prefix
            routes += [
                (m, f"{base}/{url_path.strip('/')}/", f"{cls.name}.{name}", n) for m in methods
            ]
        methods_of = {
            n.name for _, _, _, n in routes if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        self.emit(
            rel,
            line,
            dynamic,
            _View([], guards, unguards, has_permissions, True, methods_of, named),
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


_UNREAD = _View([], [], [], False)


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


def _name(call: ast.Call) -> str:
    return _dotted(call.func).split(".")[-1]


def _join(prefix: str, pattern: str) -> str:
    """Django joins an included urlconf's patterns to the prefix that mounts it; a regex keeps
    one `^` at the front and drops the prefix's `$`."""
    if not prefix:
        return pattern
    return prefix.rstrip("$") + pattern.lstrip("^")


def _guards(expr: str) -> list[str]:
    return [g for g in _guards_in(expr) if not _NOT_GUARDS.search(g)]


def _code(node: ast.AST) -> str:
    """A decorator or class attribute's source without its string literals, so a setting's name
    passed as an argument isn't read as a guard's."""
    return " ".join(_dotted(n) for n in ast.walk(node) if isinstance(n, ast.Name | ast.Attribute))


def django_rows(index: _PyIndex, consts: dict[str, str]) -> list[_Row]:
    """The Django and DRF rows of a checkout's parsed Python sources."""
    return _Django(index, consts).run()
