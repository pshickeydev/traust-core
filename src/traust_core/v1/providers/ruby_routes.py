"""Rails and Sinatra routes in Ruby and the guards on each, parsed with tree-sitter. Rails
routes come from `config/routes.rb` and their guards from each controller's `before_action`
chain (inherited, `only`/`except`, and `skip_before_action`, which is judged); Sinatra guards
are `before` filters, `use Rack::Auth::*` and guard calls in the route body."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from traust_core.v1.models.code_facts import RouteAsymmetry, RouteFamily
from traust_core.v1.models.common import RepoPath
from traust_core.v1.providers.route_guards import (
    GUARD_RX,
    NON_ENFORCING_RX,
    UNGUARD_RX,
    _mark,
    _Row,
    _row,
    _unique,
)
from traust_core.v1.providers.route_ownership import path_params
from traust_core.v1.providers.syntax import Node, Parsed, walk
from traust_core.v1.providers.syntax import ruby_parser as parser
from traust_core.v1.providers.tree import TreeFile

SINATRA_USE = re.compile(r"""require\s+['"]sinatra|Sinatra::(?:Base|Application)""")
VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
_ACTIONS = {
    "index": ("GET", ""),
    "create": ("POST", ""),
    "new": ("GET", "/new"),
    "edit": ("GET", "/:id/edit"),
    "show": ("GET", "/:id"),
    "update": ("PATCH", "/:id"),
    "destroy": ("DELETE", "/:id"),
}
_SINGULAR_ACTIONS = ("create", "new", "edit", "show", "update", "destroy")
_BEFORE = ("before_action", "prepend_before_action", "append_before_action", "before_filter")
_SKIP = ("skip_before_action", "skip_before_filter")
_AFTER = ("after_action", "append_after_action", "prepend_after_action", "after_filter")
_AROUND = ("around_action", "append_around_action", "prepend_around_action", "around_filter")
_SKIP_AFTER = ("skip_after_action", "skip_after_filter")
_LITERAL_NAMES = ("array", "symbol_array", "string_array", "simple_symbol", "string")
# `unless: -> { current_user.admin? }`: skipped only for an admin (D10)
_ADMIN_ONLY = re.compile(
    r"^->\s*(\(\s*\))?\s*\{\s*(current_user|Current\.user|@current_user)\.(is_)?"
    r"(admin|administrator|superuser|super_admin|staff|moderator)\?\s*\}$"
)
# what's left of `load_and_authorize_resource` once one half is skipped
_SPLIT = {"authorize_resource": "load_resource", "load_resource": "authorize_resource"}
_CANCAN_SKIPS = {
    "skip_authorize_resource": "authorize_resource",
    "skip_load_resource": "load_resource",
    "skip_load_and_authorize_resource": "load_and_authorize_resource",
}
# callbacks that guard whatever their name says
_GUARD_CALLBACKS = (
    "http_basic_authenticate_with",
    "load_and_authorize_resource",
    "authorize_resource",
)
SKIPPED = "skip_before_action"


def _is_guard(name: str) -> bool:
    if UNGUARD_RX.search(name):
        return False
    return bool(GUARD_RX.search(NON_ENFORCING_RX.sub("", name)))


class _Source(Parsed):
    def string(self, node: Node | None) -> str | None:
        if node is None:
            return None
        if node.type in ("simple_symbol", "hash_key_symbol"):
            return self.text(node).lstrip(":")
        if node.type in ("bare_symbol", "bare_string") and node.named_children:
            return "".join(self.text(c) for c in node.named_children if c.type == "string_content")
        interpolated = any(c.type == "interpolation" for c in node.named_children)
        if node.type == "string" and not interpolated:
            return "".join(self.text(c) for c in node.named_children if c.type == "string_content")
        return None


def _args(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return [a for a in args.named_children if a.type != "comment"] if args else []


def _method(src: _Source, call: Node) -> str:
    return src.text(call.child_by_field_name("method"))


def _body(call: Node) -> list[Node]:
    block = call.child_by_field_name("block")
    if block is None:
        return []
    body = block.child_by_field_name("body") or next(
        (c for c in block.named_children if c.type in ("body_statement", "block_body")), None
    )
    return list(body.named_children) if body is not None else []


def _options(src: _Source, call: Node) -> dict[str, Node]:
    """A call's `key: value` and `"path" => "c#a"` pairs, by key (`=>` under its own key)."""
    found = {}
    for a in _args(call):
        for p in [a] if a.type == "pair" else (a.named_children if a.type == "hash" else []):
            if p.type == "pair":
                key = p.child_by_field_name("key")
                symbol = key.type in ("hash_key_symbol", "simple_symbol")
                found[src.string(key) if symbol else "=>"] = p.child_by_field_name("value")
    return found


def _names(src: _Source, node: Node | None) -> list[str]:
    """Symbol or string values, one or an array of them."""
    if node is None:
        return []
    arrays = ("array", "symbol_array", "string_array")
    items = node.named_children if node.type in arrays else [node]
    return [v for i in items if (v := src.string(i)) is not None]


def _plural(name: str) -> str:
    if name.endswith("s"):
        return name
    if name.endswith("y") and name[-2:-1] not in "aeiou":
        return name[:-1] + "ies"
    return name + "s"


def _singular(name: str) -> str:
    if name.endswith("ies"):
        return name[:-3] + "y"
    return name[:-1] if name.endswith("s") else name


@dataclass(frozen=True)
class _Scope:
    path: str = ""
    module: str = ""
    controller: str | None = None
    member: str | None = None  # the resource's member path, `/posts/:id`
    guards: tuple[str, ...] = ()


@dataclass
class _Route:
    method: str
    pattern: str
    controller: str
    action: str
    src: _Source
    node: Node
    scope_guards: tuple[str, ...] = ()


def _join(*parts: str) -> str:
    segments = [p.strip("/") for p in parts if p.strip("/")]
    return "/" + "/".join(segments)


class _RailsRoutes:
    """`config/routes.rb` (and the files it `draw`s) as (verb, path, controller#action) rows."""

    def __init__(self, sources: dict[str, _Source]) -> None:
        self.sources = sources
        self.routes: list[_Route] = []
        self.drawn: set[str] = set()  # `draw :api` files, read once
        for rel, src in sources.items():
            if rel.endswith("config/routes.rb"):
                for n in walk(src.root):
                    if (
                        n.type == "call"
                        and _method(src, n) == "draw"
                        and "routes" in src.text(n.child_by_field_name("receiver"))
                    ):
                        self._block(src, _body(n), _Scope(), rel.removesuffix("routes.rb"))

    def _block(self, src: _Source, calls: list[Node], scope: _Scope, config: str) -> None:
        for c in calls:
            if c.type == "call":
                self._call(src, c, scope, config)

    def _controller(self, scope: _Scope, name: str) -> str:
        return f"{scope.module}{name}" if "/" not in name else name

    def _call(self, src: _Source, call: Node, scope: _Scope, config: str) -> None:
        name = _method(src, call)
        args = _args(call)
        opts = _options(src, call)
        first = src.string(args[0]) if args else None
        if name in ("resources", "resource"):
            for res in [v for a in args if (v := src.string(a)) is not None and a.type != "pair"]:
                self._resource(src, call, scope, config, res, name == "resource", opts)
        elif name == "namespace" and first:
            module = f"{scope.module}{first}/"
            inner = replace(scope, path=_join(scope.path, first), module=module)
            self._block(src, _body(call), inner, config)
        elif name == "scope":
            positional = first is not None and args[0].type != "pair"
            path = first if positional else src.string(opts.get("path"))
            module = src.string(opts.get("module"))
            inner = replace(
                scope,
                path=_join(scope.path, path or ""),
                module=f"{scope.module}{module}/" if module else scope.module,
            )
            self._block(src, _body(call), inner, config)
        elif name in ("member", "collection") and scope.member is not None:
            path = scope.member if name == "member" else scope.member.rsplit("/:", 1)[0]
            self._block(src, _body(call), replace(scope, path=path, member=None), config)
        elif name in ("authenticate", "authenticated"):
            who = first or "user"
            guarded = replace(scope, guards=(*scope.guards, f"devise:{name}({who})"))
            self._block(src, _body(call), guarded, config)
        elif name in ("constraints", "defaults", "controller", "concern"):
            inner = scope if name != "controller" or not first else replace(scope, controller=first)
            if name != "concern":
                self._block(src, _body(call), inner, config)
        elif name in (*VERBS, "match"):
            self._verb(src, call, scope, name, first, opts)
        elif name == "root":
            positional = first is not None and args[0].type != "pair"
            target = first if positional else src.string(opts.get("to"))
            self._add(src, call, scope, "GET", scope.path or "/", target)
        elif name == "mount" and args:
            at = src.string(opts.get("at")) or src.string(opts.get("=>"))
            mounted = args[0].child_by_field_name("key") if args[0].type == "pair" else args[0]
            path = _join(scope.path, at or "")
            self.routes.append(_Route("ALL", path, src.text(mounted), "", src, call, scope.guards))
        elif name == "draw" and first:
            rel = f"{config}routes/{first}.rb"
            included = self.sources.get(rel)
            if included is not None and rel not in self.drawn:
                self.drawn.add(rel)
                self._block(included, list(included.root.named_children), scope, config)

    def _resource(
        self,
        src: _Source,
        call: Node,
        scope: _Scope,
        config: str,
        name: str,
        singular: bool,
        opts: dict[str, Node],
    ) -> None:
        path = _join(scope.path, src.string(opts.get("path")) or name)
        if module := src.string(opts.get("module")):
            scope = replace(scope, module=f"{scope.module}{module}/")
        named = src.string(opts.get("controller")) or (_plural(name) if singular else name)
        controller = self._controller(scope, named)
        actions = list(_SINGULAR_ACTIONS if singular else _ACTIONS)
        if "only" in opts:
            actions = [a for a in actions if a in _names(src, opts["only"])]
        if "except" in opts:
            actions = [a for a in actions if a not in _names(src, opts["except"])]
        for action in actions:
            verb, suffix = _ACTIONS[action]
            suffix = suffix.replace("/:id", "") if singular else suffix
            for v in (verb, "PUT") if action == "update" else (verb,):
                route = _Route(v, path + suffix, controller, action, src, call, scope.guards)
                self.routes.append(route)
        member = path if singular else f"{path}/:id"
        nested = f"{path}/:{_singular(name)}_id" if not singular else path
        self._block(
            src,
            _body(call),
            replace(scope, path=nested, controller=controller, member=member),
            config,
        )

    def _verb(
        self,
        src: _Source,
        call: Node,
        scope: _Scope,
        name: str,
        first: str | None,
        opts: dict[str, Node],
    ) -> None:
        target = src.string(opts.get("to")) or src.string(opts.get("=>"))
        if first is None:  # `get "a/:id" => "notes#show"`
            first = next(
                (
                    src.string(a.child_by_field_name("key"))
                    for a in _args(call)
                    if a.type == "pair" and a.child_by_field_name("key").type == "string"  # type: ignore[union-attr]
                ),
                None,
            )
        if target is None and "controller" in opts:
            target = f"{src.string(opts['controller'])}#{src.string(opts.get('action')) or first}"
        if target is None and first and scope.controller:
            target = f"{scope.controller}#{first}"  # `get :preview` inside a resource
        path = _join(scope.path, first or "")
        verbs = (
            [name.upper()]
            if name != "match"
            else [v.upper() for v in _names(src, opts.get("via"))] or ["ALL"]
        )
        for v in verbs:
            self._add(src, call, scope, "ALL" if v == "ALL" else v, path, target)

    def _add(
        self, src: _Source, call: Node, scope: _Scope, verb: str, path: str, target: str | None
    ) -> None:
        controller, _, action = (target or "").partition("#")
        self.routes.append(
            _Route(verb, path, self._controller(scope, controller), action, src, call, scope.guards)
        )


@dataclass
class _Callback:
    name: str
    only: list[str] | None
    skip: bool
    except_: list[str] = field(default_factory=list)
    conditional: bool = False  # `if:`/`unless:`: may not run
    prepend: bool = False  # `prepend_before_action`: runs before those declared earlier
    after: bool = False  # an `after_action`
    body: Node | None = None  # `before_action { … }`, `before_action -> { … }`
    src: _Source | None = None  # where the block is written
    around: bool = False  # an `around_action`
    # a point in the chain, not a callback: `include:<M>`, `prepend:<M>`, `reset`
    marker: str = ""

    def applies(self, action: str) -> bool:
        return (self.only is None or action in self.only) and action not in self.except_


@dataclass
class _Controller:
    name: str
    parent: str | None
    callbacks: list[_Callback]
    actions: dict[str, Node]
    src: _Source
    # the qualified names the superclass may be, innermost namespace first
    # (`BaseController` inside `module Admin`: `Admin::BaseController`, then `BaseController`)
    parents: tuple[str, ...] = ()
    includes: tuple[str, ...] = ()  # the modules it includes, the last one looked up first
    prepends: tuple[str, ...] = ()  # the modules it prepends, looked up before the class
    aliases: dict[str, str] = field(default_factory=dict)  # `alias_method :new, :old`


def _controllers(sources: dict[str, _Source]) -> dict[str, _Controller]:
    """Controllers by route name (`admin/users`) and by class name (`ApplicationController`)."""
    found: dict[str, _Controller] = {}
    for rel, src in sources.items():
        for n in walk(src.root):
            if n.type != "class":
                continue
            name = src.text(n.child_by_field_name("name"))
            if not name.endswith("Controller"):
                continue
            sup = n.child_by_field_name("superclass")
            base = sup.named_children[0] if sup is not None and sup.named_children else None
            parent = src.text(base).rsplit("::", 1)[-1] if base is not None else None
            # a superclass resolves in the lexical scope: `class Api::X < Base` looks up `::Base`
            lexical = _lexical(src, n)
            qualified = "::".join([*lexical, name])
            written = src.text(base).removeprefix("::") if base is not None else ""
            parents = (
                tuple("::".join([*lexical[:k], written]) for k in range(len(lexical), -1, -1))
                if base is not None and not src.text(base).startswith("::")
                else (written,)
            )
            callbacks: list[_Callback] = []
            actions: dict[str, Node] = {}
            includes: list[str] = []
            prepends: list[str] = []
            aliases: dict[str, str] = {}
            body = n.child_by_field_name("body")
            for stmt in body.named_children if body is not None else []:
                wrapped = False
                if stmt.type in ("if_modifier", "unless_modifier"):
                    # `skip_before_action :x unless ENV[…]`: declared on some boots only
                    stmt, wrapped = stmt.child_by_field_name("body") or stmt, True
                if stmt.type == "call" and _method(src, stmt) in ("private", "protected", "public"):
                    defs = [a for a in _args(stmt) if a.type == "method"]
                    stmt = defs[0] if defs else stmt  # `private def require_owner`
                if stmt.type == "method":
                    actions[src.text(stmt.child_by_field_name("name"))] = stmt
                    aliases.pop(src.text(stmt.child_by_field_name("name")), None)
                elif stmt.type in ("call", "identifier"):
                    method = _method(src, stmt) if stmt.type == "call" else src.text(stmt)
                    declared = _callbacks(src, stmt, method)
                    callbacks += (
                        [replace(x, conditional=True) for x in declared] if wrapped else declared
                    )
                    modules = [src.text(a).removeprefix("::") for a in _args(stmt)]
                    # `include A, B` puts A first in the lookup, like `include B; include A`
                    if method == "include" and stmt.type == "call":
                        includes += reversed(modules)
                        callbacks += [
                            _Callback("", None, False, marker=f"include:{m}")
                            for m in reversed(modules)
                        ]
                    if method == "prepend" and stmt.type == "call":
                        prepends += reversed(modules)
                        callbacks += [
                            _Callback("", None, False, marker=f"include:{m}")
                            for m in reversed(modules)
                        ]
                    names = [src.string(a) for a in _args(stmt)]
                    if method == "alias_method" and len(names) == 2 and None not in names:
                        aliases[names[0]] = names[1]  # type: ignore[index]
            controller = _Controller(
                name,
                parent,
                callbacks,
                actions,
                src,
                parents,
                tuple(includes),
                tuple(prepends),
                aliases,
            )
            found[qualified] = controller
            if m := re.search(r"app/controllers/(.+)_controller\.rb$", rel):
                found[m.group(1)] = controller
    return found


def _callbacks(src: _Source, stmt: Node, method: str) -> list[_Callback]:
    kinds = (*_BEFORE, *_SKIP, *_AFTER, *_SKIP_AFTER, *_AROUND, *_GUARD_CALLBACKS, *_CANCAN_SKIPS)
    if method not in (*kinds, "skip_callback", "reset_callbacks"):
        return []
    args = _args(stmt) if stmt.type == "call" else []
    if method == "reset_callbacks":
        return [_Callback("", None, False, marker="reset")]
    if method == "skip_callback":  # `skip_callback :process_action, :before, :require_owner`
        names = [src.string(a) for a in args if a.type != "pair"]
        if len(names) >= 3 and names[0] == "process_action" and names[1] in ("before", "after"):
            return [_Callback(n, None, True, after=names[1] == "after") for n in names[2:] if n]
        return []
    opts = _options(src, stmt) if stmt.type == "call" else {}
    # `only: SHARED`, `except: [:show, *OPEN]`: a list we can't read may name the action
    unread = any(
        k in opts
        and (
            opts[k].type not in _LITERAL_NAMES
            or (
                opts[k].type == "array"
                and any(c.type not in ("simple_symbol", "string") for c in opts[k].named_children)
            )
        )
        for k in ("only", "except")
    )
    only = _names(src, opts.get("only")) if "only" in opts and not unread else None
    except_ = _names(src, opts.get("except")) if not unread else []
    conditional = (
        unread
        or "if" in opts
        or ("unless" in opts and not _ADMIN_ONLY.match(src.text(opts["unless"]).strip()))
    )
    if method in _GUARD_CALLBACKS:
        return [_Callback(method, only, False, except_, conditional)]
    if method in _CANCAN_SKIPS:
        return [_Callback(_CANCAN_SKIPS[method], only, True, except_, conditional)]
    after = method in (*_AFTER, *_SKIP_AFTER)
    around = method in _AROUND
    skip = method in (*_SKIP, *_SKIP_AFTER)
    prepend = method in ("prepend_before_action", "prepend_after_action") or (
        "prepend" in opts and src.text(opts["prepend"]) == "true"
    )
    block = stmt.child_by_field_name("block") if stmt.type == "call" else None
    lambdas = [a for a in args if a.type == "lambda"]
    if not skip and (block is not None or lambdas):
        body = block if block is not None else lambdas[0]
        name = f"<block:{src.file.rel}:{src.line(stmt)}>"
        return [
            _Callback(name, only, False, except_, conditional, prepend, after, body, src, around)
        ]
    names = [v for a in args if a.type != "pair" and (v := src.string(a))]
    return [
        _Callback(n, only, skip, except_, conditional, prepend, after, around=around) for n in names
    ]


def _chain(controllers: dict[str, _Controller], c: _Controller) -> list[_Controller]:
    chain, seen = [c], {id(c)}
    while True:
        last = chain[-1]
        found = next((controllers[q] for q in last.parents if q in controllers), None)
        if found is None or id(found) in seen:
            break
        chain.append(found)
        seen.add(id(found))
    return chain[::-1]


def _callback_body(node: Node) -> list[Node]:
    """A callback method's statements, or a callback block's (`before_action { … }`)."""
    from traust_core.v1.providers.ruby_ownership import method_body, statements

    if node.type == "method":
        return method_body(node)
    block = node if node.type != "lambda" else node.child_by_field_name("body") or node
    body = block.child_by_field_name("body") or next(
        (c for c in block.named_children if c.type in ("block_body", "body_statement")), None
    )
    return statements(body)


def _lexical(src: _Source, node: Node) -> list[str]:
    """The modules and classes a class is written inside (`module Admin; class X`)."""
    out = []
    parent = node.parent
    while parent is not None:
        if parent.type in ("module", "class"):
            out[:0] = src.text(parent.child_by_field_name("name")).split("::")
        parent = parent.parent
    return out


def _rails_guards(
    controllers: dict[str, _Controller], c: _Controller, action: str
) -> tuple[list[str], list[str]]:
    """(guards, unguards): the before_action guards that run for the action, base class first;
    a skip that removes one is an unguard, judged."""
    active: list[str] = []
    skipped: list[str] = []
    for ctrl in _chain(controllers, c):
        for cb in ctrl.callbacks:
            if not cb.applies(action) or cb.after or cb.around or cb.marker:
                continue
            if cb.skip:
                if cb.name in active:
                    active.remove(cb.name)
                    skipped.append(f"{SKIPPED}:{cb.name}")
            elif (_is_guard(cb.name) or cb.name in _GUARD_CALLBACKS) and cb.name not in active:
                active.append(cb.name)
    return active, skipped


def _body_guard_calls(src: _Source, stmts: list[Node]) -> list[str]:
    names = [
        src.text(s.child_by_field_name("method")) if s.type == "call" else src.text(s)
        for s in stmts
        if s.type in ("call", "identifier")
    ]
    return [f"call:{n}" for n in names if _is_guard(n)]


def _rails_rows(sources: dict[str, _Source]) -> list[_Row]:
    controllers = _controllers(sources)
    ownership: _Ownership | None = None
    rows = []
    for r in _RailsRoutes(sources).routes:
        c = controllers.get(r.controller)
        guards: list[str] = []
        unguards: list[str] = []
        handler_path, handler_line = r.src.file.rel, r.src.line(r.node)
        if c is not None:
            guards, unguards = _rails_guards(controllers, c, r.action)
            if (action := c.actions.get(r.action)) is not None:
                body = action.child_by_field_name("body")
                guards += _body_guard_calls(c.src, list(body.named_children) if body else [])
                handler_path, handler_line = c.src.file.rel, c.src.line(action)
        row = _row(
            RouteFamily.RAILS,
            r.method,
            r.pattern,
            f"{r.controller}#{r.action}" if r.action else r.controller,
            r.src.file.rel,
            r.src.line(r.node),
            _unique(guards),
            list(r.scope_guards),
            unguards,
        )
        row.handler_path, row.handler_line = handler_path, handler_line
        if path_params(row.pattern):
            ownership = ownership or _Ownership(sources, controllers)
            ownership.own(row, c, r)
        _mark(row, None, False, r.src.file.rel)
        row.view_class = c.name if c is not None else r.controller
        rows.append(row)
    return rows


class _Ownership:
    """Reads each Rails id route's action for ownership (`providers.ruby_ownership`)."""

    def __init__(self, sources: dict[str, _Source], controllers: dict[str, _Controller]) -> None:
        from traust_core.v1.providers.ruby_ownership import RubyCode

        self.controllers = controllers
        self.code = RubyCode(dict(sources))
        self.concern_methods: dict[str, list[tuple[Parsed, Node]]] = {}
        for found in self.code.modules.values():
            for src, module in found:
                if "/concerns/" not in f"/{src.file.rel}":
                    continue  # elsewhere, a module counts only where it's included
                for name, m in self.code.module_methods(src, module).items():
                    self.concern_methods.setdefault(name, []).append((src, m))

    def methods(self, c: _Controller) -> Callable[[str], tuple[Parsed, Node] | None]:
        chain = _chain(self.controllers, c)

        unread = object()

        def module(name: str, method: str) -> tuple[Parsed, Node] | object | None:
            found = self.code.module(name)
            if found is None:
                return None
            if found is unread:
                return unread
            ms = self.code.module_methods(*found)  # type: ignore[misc]
            return (found[0], ms[method]) if method in ms else None  # type: ignore[index]

        def find(name: str, depth: int = 0, upto: int | None = None) -> tuple[Parsed, Node] | None:
            # Ruby's lookup: prepended modules, the class, its modules (the last included
            # first), then its parent; an alias copies the method where it's declared
            for i in reversed(range(len(chain) if upto is None else upto)):
                ctrl = chain[i]
                for m in [*reversed(ctrl.prepends), None, *reversed(ctrl.includes)]:
                    if m is None:
                        if name in ctrl.aliases and depth < 4:
                            return find(ctrl.aliases[name], depth + 1, i + 1)
                        if name in ctrl.actions:
                            return ctrl.src, ctrl.actions[name]
                        continue
                    found = module(m, name)
                    if found is unread:
                        return None  # a module we can't name may define it: fail closed
                    if found is not None:
                        return found  # type: ignore[return-value]
            candidates = self.concern_methods.get(name, [])
            return candidates[0] if len(candidates) == 1 else None

        return find

    def included(self, name: str) -> list[_Callback]:
        """Callbacks a module declares in `included do … end` or `prepended do … end`."""
        out: list[_Callback] = []
        found = self.code.module(name)
        if not isinstance(found, tuple):
            return out
        src, module = found
        for n in walk(module):
            if n.type == "call" and _method(src, n) in ("included", "prepended"):  # type: ignore[arg-type]
                for stmt in _body(n):
                    if stmt.type in ("call", "identifier"):
                        method = _method(src, stmt) if stmt.type == "call" else src.text(stmt)  # type: ignore[arg-type]
                        out += _callbacks(src, stmt, method)  # type: ignore[arg-type]
        return out

    def callbacks(self, c: _Controller, action: str) -> list[_Callback]:
        """The callbacks that run for an action, in the order Rails runs them."""
        out: list[_Callback] = []
        pending = [cb for ctrl in _chain(self.controllers, c) for cb in ctrl.callbacks]
        while pending:
            cb = pending.pop(0)
            if cb.marker == "reset":
                out = []
                continue
            if cb.marker:  # an included module's own callbacks, where it's included
                pending[:0] = self.included(cb.marker.removeprefix("include:"))
                continue
            if not cb.skip:
                out = [x for x in out if x.name != cb.name]  # declared again: replaced
            if not cb.applies(action):
                continue
            if cb.skip:
                kept = []
                for x in out:
                    if x.name == cb.name and cb.conditional:
                        kept.append(replace(x, conditional=True))
                    elif x.name == "load_and_authorize_resource" and cb.name in _SPLIT:
                        kept.append(replace(x, name=_SPLIT[cb.name]))
                    elif x.name != cb.name:
                        kept.append(x)
                out = kept
            elif cb.prepend:
                out.insert(0, cb)
            else:
                out.append(cb)
        return out

    def own(self, row: _Row, c: _Controller | None, r: _Route) -> None:
        from traust_core.v1.models.common import CodeSpan
        from traust_core.v1.providers.route_ownership import HandlerFacts, privileged_only
        from traust_core.v1.providers.ruby_ownership import (
            Kind,
            action_facts,
            admin_gate,
            caller_forged,
            early_return,
            inert,
            keeps_going,
            method_body,
            rescues,
            swallows,
        )

        ids = set(path_params(row.pattern))
        span = CodeSpan(path=RepoPath(r.src.file.rel), line=r.src.line(r.node))
        if c is None or not r.action:
            row.own(HandlerFacts(handoff=span, takes_id=True), self.code.fields)
            return
        find = self.methods(c)
        callbacks = self.callbacks(c, r.action)
        guards = [*row.guards, *row.scope_guards]
        steps: list[tuple[Parsed, Node, Kind]] = []
        load = authorize = False
        gates: list[str] = []
        afters = [cb for cb in callbacks if cb.after]
        for cb in [cb for cb in callbacks if not cb.after]:
            if cb.name in ("load_and_authorize_resource", "load_resource"):
                load = True
            if cb.name in ("load_and_authorize_resource", "authorize_resource"):
                authorize = authorize or not cb.conditional
            if cb.body is not None:
                found = (cb.src or c.src, cb.body)
            elif cb.name in _GUARD_CALLBACKS or (found := find(cb.name)) is None:  # type: ignore[assignment]
                continue
            if cb.body is None and admin_gate(*found) and not cb.conditional and not cb.around:
                gates.append(cb.name)
            # an `around_action` wraps the action: read, but it refuses nothing
            conditional = cb.conditional or cb.around or swallows(*found)
            kind = Kind.CONDITIONAL if conditional else Kind.CALLBACK
            body = _callback_body(found[1])
            for i, s in enumerate(body):
                # a response doesn't stop the callback: what it runs next still runs
                rest = [x for x in body[i + 1 :] if not inert(found[0], x)]
                steps.append(
                    (found[0], s, Kind.CONDITIONAL if keeps_going(found[0], s) and rest else kind)
                )
                if early_return(found[0], s):
                    kind = Kind.CONDITIONAL  # the rest of this callback may not run
            steps += [(found[0], s, Kind.CONDITIONAL) for s in rescues(found[1])]
        action = find(r.action)
        forged = caller_forged(self.code, steps, find, action)
        # an admin-named callback that, read, refuses no unprivileged caller is no admin gate;
        # nor is one that trusts a caller the app builds from the request
        for g in list(guards):
            if privileged_only(g) and (
                forged or ((found := find(g)) is not None and g not in gates)
            ):
                guards.remove(g)
        if gates and not forged and not any(privileged_only(g) for g in guards):
            guards.append(f"admin_gate:{gates[0]}")  # refuses every non-admin caller
        if action is None:
            row.own(HandlerFacts(handoff=span, takes_id=True), self.code.fields, guards=guards)
            return
        # an action's own `rescue` may swallow the raise that refused
        kind = Kind.CONDITIONAL if swallows(*action) else Kind.ACTION
        steps += [(action[0], s, kind) for s in method_body(action[1])]
        steps += [(action[0], s, Kind.CONDITIONAL) for s in rescues(action[1])]
        for cb in afters:
            found = (cb.src or c.src, cb.body) if cb.body is not None else find(cb.name)
            if found is not None:
                steps += [(found[0], s, Kind.AFTER) for s in _callback_body(found[1])]
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", c.name.removesuffix("Controller").split("::")[-1])
        model = "".join(p.capitalize() for p in _singular(snake.lower()).split("_"))
        facts = action_facts(
            self.code,
            steps,
            ids,
            guarded=bool(guards),
            methods=find,
            action=r.action,
            model=model,
            cancan=(load, authorize),
        )
        row.own(facts, self.code.fields, guards=guards)


def callback_asymmetries(rows: list[_Row]) -> list[RouteAsymmetry]:
    """Within one controller, actions missing a guard callback its other actions run (the
    `before_action :x, except: [...]` shape): each is judged."""
    groups: dict[tuple[str, str], list[_Row]] = {}
    for r in rows:
        if r.family is RouteFamily.RAILS and r.view_class:
            groups.setdefault((r.handler_path, r.view_class), []).append(r)
    found = []
    for (path, controller), members in sorted(groups.items()):
        for guard in _unique(g for r in members for g in r.guards if not g.startswith("call:")):
            lack = [r for r in members if guard not in r.guards]
            if not lack or len(lack) == len(members):
                continue
            found.append(
                RouteAsymmetry(
                    family=RouteFamily.RAILS,
                    path=RepoPath(path),
                    group=controller,
                    guarded=tuple(r.label for r in members if guard in r.guards),
                    unguarded=tuple(r.label for r in lack),
                )
            )
            for r in lack:
                r.mark()
    return found


def _sinatra_pattern(path: str) -> re.Pattern[str]:
    out = re.escape(path).replace(r"\*", ".*")
    return re.compile(re.sub(r":\w+", "[^/]+", out))


def _sinatra_rows(src: _Source) -> list[_Row]:
    rows: list[_Row] = []
    scope: list[str] = []
    filters: list[tuple[re.Pattern[str] | None, list[str]]] = []
    calls = [
        n for n in walk(src.root) if n.type == "call" and n.child_by_field_name("receiver") is None
    ]
    for call in calls:
        name = _method(src, call)
        args = _args(call)
        if name == "use" and args:
            scope += [t for t in re.findall(r"[A-Za-z_][\w:]*", src.text(args[0])) if _is_guard(t)]
        elif name == "before":
            path = src.string(args[0]) if args else None
            names = [
                src.text(n.child_by_field_name("method")) if n.type == "call" else src.text(n)
                for n in walk(call.child_by_field_name("block") or call)
                if n.type in ("call", "identifier")
            ]
            guards = [f"before:{n}" for n in _unique(names) if _is_guard(n)]
            if guards:
                filters.append((_sinatra_pattern(path) if path else None, guards))
    namespaces = [
        (ns.start_byte, ns.end_byte, src.string(_args(ns)[0]) or "")
        for ns in calls
        if _method(src, ns) == "namespace" and _args(ns)
    ]
    for call in calls:
        name = _method(src, call)
        args = _args(call)
        if name not in VERBS or not args or call.child_by_field_name("block") is None:
            continue
        literal = src.string(args[0])
        prefix = [p for start, end, p in namespaces if start < call.start_byte < end]
        pattern = _join(*prefix, literal) if literal is not None else src.text(args[0])[:160]
        scoped = [
            g for rx, gs in filters if rx is None or (literal and rx.fullmatch(pattern)) for g in gs
        ]
        row = _row(
            RouteFamily.SINATRA,
            name.upper(),
            pattern,
            "<block>",
            src.file.rel,
            src.line(call),
            _body_guard_calls(src, _body(call)),
            _unique([*scope, *scoped]),
            [],
        )
        rows.append(_mark(row, None, literal is None, src.file.rel))
    return rows


@dataclass
class RubyRoutes:
    rows: list[_Row]
    evidence: dict[RouteFamily, str]  # a file per family that uses it
    parsed: bool  # whether the Ruby parser was available


def ruby_rows(files: list[TreeFile]) -> RubyRoutes:
    """The Rails and Sinatra rows of a checkout's Ruby sources."""
    ruby = [f for f in files if f.path.suffix == ".rb"]
    evidence: dict[RouteFamily, str] = {}
    for f in ruby:
        if RouteFamily.RAILS not in evidence and f.rel.endswith("config/routes.rb"):
            evidence[RouteFamily.RAILS] = f.rel
        if RouteFamily.SINATRA not in evidence and SINATRA_USE.search(f.text):
            evidence[RouteFamily.SINATRA] = f.rel
    if not evidence:
        return RubyRoutes([], {}, True)
    available = parser()
    if available is None:
        return RubyRoutes([], evidence, False)
    sources = {}
    for f in ruby:
        data = f.text.encode("utf-8")
        sources[f.rel] = _Source(f, available.parse(data).root_node, data)
    rows = _rails_rows(sources) if RouteFamily.RAILS in evidence else []
    for src in sources.values():
        if SINATRA_USE.search(src.file.text):
            rows += _sinatra_rows(src)
    return RubyRoutes(rows, evidence, True)
