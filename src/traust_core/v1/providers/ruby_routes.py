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
# class-body calls that are no app macro
# class-body statements that declare nothing an action runs
_CLASS_INERT = {
    "comment",
    "heredoc_body",
    "empty_statement",
    "class",
    "module",
    "string",
    "simple_symbol",
    "constant",
    "integer",
    "nil",
    "true",
    "false",
}
_KNOWN_MACROS = {
    "include",
    "prepend",
    "extend",
    "alias_method",
    "helper_method",
    "helper",
    "layout",
    "respond_to",
    "protect_from_forgery",
    "attr_reader",
    "attr_accessor",
    "attr_writer",
    "private",
    "protected",
    "public",
    "skip_forgery_protection",
    "wrap_parameters",
    "require",
    "require_relative",
    "rate_limit",
    "add_flash_types",
    "etag",
    "content_security_policy",
    "permissions_policy",
    "allow_browser",
    "http_basic_authenticate_with",
}
_SKIP_AFTER = ("skip_after_action", "skip_after_filter")
_MAX_ROUTE_NESTING = 100
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


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


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
    depth: int = 0


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
        self.concerns: dict[str, tuple[_Source, list[Node]]] = {}  # `concern :commentable`
        for rel, src in sources.items():
            if rel.endswith("config/routes.rb"):
                for n in walk(src.root):
                    if (
                        n.type == "call"
                        and _method(src, n) == "draw"
                        and "routes" in src.text(n.child_by_field_name("receiver"))
                    ):
                        root = rel.removesuffix("config/routes.rb")
                        module = self._isolated(root)
                        self._block(
                            src, _body(n), _Scope(module=module), rel.removesuffix("routes.rb")
                        )

    def _isolated(self, root: str) -> str:
        """`isolate_namespace Billing` in an engine: its routes name `billing/…` controllers."""
        for rel, src in self.sources.items():
            found = re.search(r"isolate_namespace\s+([\w:]+)", src.file.text)
            if rel.startswith(root) and found:
                return f"{_snake(found.group(1).replace('::', '/'))}/"
        return ""

    def _block(self, src: _Source, calls: list[Node], scope: _Scope, config: str) -> None:
        if scope.depth > _MAX_ROUTE_NESTING:
            return  # nested past any real routes file
        inner = replace(scope, depth=scope.depth + 1)
        for c in calls:
            if c.type == "call":
                self._call(src, c, inner, config)

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
            module = f"{scope.module}{src.string(opts.get('module')) or first}/"
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
        elif name == "concern" and first:
            self.concerns[first] = (src, _body(call))  # expanded where `concerns` names it
        elif name == "concerns":
            self._concerns(_names(src, args[0]) if args else [], scope, config)
        elif name in ("constraints", "defaults", "controller"):
            inner = scope if name != "controller" or not first else replace(scope, controller=first)
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
        key = src.string(opts.get("param")) or "id"  # `resources :articles, param: :slug`
        controller = self._controller(scope, named)
        actions = list(_SINGULAR_ACTIONS if singular else _ACTIONS)
        if "only" in opts:
            actions = [a for a in actions if a in _names(src, opts["only"])]
        if "except" in opts:
            actions = [a for a in actions if a not in _names(src, opts["except"])]
        for action in actions:
            verb, suffix = _ACTIONS[action]
            suffix = suffix.replace("/:id", "" if singular else f"/:{key}")
            for v in (verb, "PUT") if action == "update" else (verb,):
                route = _Route(v, path + suffix, controller, action, src, call, scope.guards)
                self.routes.append(route)
        member = path if singular else f"{path}/:{key}"
        nested = f"{path}/:{_singular(name)}_{key}" if not singular else path
        inner = replace(scope, path=nested, controller=controller, member=member)
        self._block(src, _body(call), inner, config)
        self._concerns(_names(src, opts.get("concerns")), inner, config)

    def _concerns(self, names: list[str], scope: _Scope, config: str) -> None:
        for name in names:
            if name in self.concerns and scope.depth <= _MAX_ROUTE_NESTING:
                csrc, body = self.concerns[name]
                self._block(csrc, body, scope, config)

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
    # a point in the chain, not a callback: `include:<M>`, `macro:<m>`, `reset`
    marker: str = ""
    node: Node | None = None  # the declaration (`load_and_authorize_resource class: "Memo"`)

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
    root: str = ""  # the app it belongs to (`spec/dummy/`), where several share a checkout
    singletons: dict[str, Node] = field(default_factory=dict)  # `def self.shared_actions`
    rescues: list[tuple[_Source, str | Node]] = field(default_factory=list)  # `rescue_from`
    dynamic: bool = False  # defines methods whose names we can't read (`define_method(name)`)
    sources: dict[str, _Source] = field(default_factory=dict)  # where each method is written
    extends: tuple[str, ...] = ()  # `extend SharingMacros`: class macros


def _app_root(rel: str) -> str:
    """The app a file belongs to: `spec/dummy/` for `spec/dummy/app/…`, '' for the top one."""
    for part in ("app/", "config/", "lib/"):
        at = f"/{rel}".find(f"/{part}")
        if at >= 0:
            return rel[:at]
    return ""


def _controllers(sources: dict[str, _Source]) -> dict[str, _Controller]:
    """Controllers by `<root>|<route name>` (`|admin/users`) and `<root>|<class name>`; a class
    reopened in another file or by `class_eval` is one controller."""
    found: dict[str, _Controller] = {}
    for rel, src in sources.items():
        root = _app_root(rel)
        for n in walk(src.root):
            if n.type != "class" or not n.is_named:
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
            key = f"{root}|{qualified}"
            controller = found.get(key)
            if controller is None:
                controller = _Controller(name, parent, [], {}, src, parents, root=root)
                found[key] = controller
            elif base is not None:
                controller.parent, controller.parents = parent, parents
            body = n.child_by_field_name("body")
            _read_class(src, list(body.named_children) if body is not None else [], controller)
            if m := re.search(r"app/controllers/(.+)_controller\.rb$", rel):
                # the class the file is named for (`notes_controller.rb`: NotesController)
                camel = "".join(w.capitalize() for w in m.group(1).rsplit("/", 1)[-1].split("_"))
                if name.rsplit("::", 1)[-1] == f"{camel}Controller":
                    found[f"{root}|route:{m.group(1)}"] = controller
                else:
                    found.setdefault(f"{root}|route:{m.group(1)}", controller)
    for src in sources.values():
        for n in walk(src.root):
            if n.type == "call" and _method(src, n) in ("class_eval", "class_exec"):
                target = src.text(n.child_by_field_name("receiver")).removeprefix("::")
                for c in {id(c): c for k, c in found.items() if k.endswith(f"|{target}")}.values():
                    _read_class(src, _body(n), c)  # `NotesController.class_eval { … }`
    return found


def _read_class(
    src: _Source,
    stmts: list[Node],
    controller: _Controller,
    extra: dict[str, Node] | None = None,
    wrapped: bool = False,
) -> None:
    """A class body's methods, callbacks, modules, aliases and macros, in order."""
    for stmt in stmts:
        conditional = wrapped
        if stmt.type in ("if_modifier", "unless_modifier"):
            # `skip_before_action :x unless ENV[…]`: declared on some boots only
            stmt, conditional = stmt.child_by_field_name("body") or stmt, True
        if stmt.type == "call" and _method(src, stmt) in ("private", "protected", "public"):
            defs = [a for a in _args(stmt) if a.type == "method"]
            stmt = defs[0] if defs else stmt  # `private def require_owner`
        if stmt.type == "method":
            name = src.text(stmt.child_by_field_name("name"))
            controller.actions[name] = stmt
            controller.sources[name] = src
            controller.aliases.pop(name, None)
            continue
        if stmt.type == "singleton_method":
            name = src.text(stmt.child_by_field_name("name"))
            controller.singletons[name] = stmt
            controller.sources[f"self.{name}"] = src
            continue
        if stmt.type == "singleton_class":  # `class << self; def shared_actions…`
            for m in walk(stmt):
                if m.type == "method":
                    name = src.text(m.child_by_field_name("name"))
                    controller.singletons[name] = m
                    controller.sources[f"self.{name}"] = src
            continue
        if stmt.type in ("if", "unless", "case"):
            # `if ENV[…] … end`: what it declares holds on some boots only
            for branch in stmt.named_children:
                if branch.type in ("then", "else", "elsif", "when"):
                    inner = [b for b in branch.named_children if b.type != "pattern"]
                    _read_class(src, inner, controller, extra, True)
            continue
        # constants and class attributes (`self.responder = …`) declare no callback or method
        if stmt.type in _CLASS_INERT or stmt.type in ("assignment", "operator_assignment"):
            continue
        if stmt.type == "alias" and len(stmt.named_children) == 2:
            new, old = (src.text(a).lstrip(":") for a in stmt.named_children)
            controller.aliases[new] = old  # `alias require_owner log_access`
            continue
        if stmt.type not in ("call", "identifier"):
            controller.dynamic = True  # a class body we can't read: fail closed
            continue
        method = _method(src, stmt) if stmt.type == "call" else src.text(stmt)
        args = _args(stmt) if stmt.type == "call" else []
        if method in ("concerning", "included") and stmt.type == "call":
            _read_class(src, _body(stmt), controller, extra, conditional)
            continue
        if method == "with_options" and stmt.type == "call":
            opts = {**(extra or {}), **_options(src, stmt)}
            _read_class(src, _body(stmt), controller, opts, conditional)
            continue
        if method == "define_method" and args and (name := src.string(args[0])):
            block = stmt.child_by_field_name("block")
            if block is not None:
                controller.actions[name] = block
                controller.sources[name] = src
            continue
        if method == "extend" and stmt.type == "call":
            controller.extends += tuple(src.text(a).removeprefix("::") for a in args)
            continue
        if stmt.type == "call" and any(
            n.type == "call" and _method(src, n) == "define_method" for n in walk(stmt) if n != stmt
        ):
            controller.dynamic = True  # `%i[a b].each { |m| define_method(m) { … } }`
        if method == "rescue_from":
            value = _options(src, stmt).get("with")
            handler = src.string(value)
            block = stmt.child_by_field_name("block") or (
                value if value is not None and handler is None else None
            )  # `with: :name`, `with: ->(e) { … }`, or a block
            controller.rescues.append((src, handler or block))  # type: ignore[arg-type]
            continue
        declared = _callbacks(src, stmt, method, extra)
        if conditional:
            declared = [replace(x, conditional=True) for x in declared]
        controller.callbacks += declared
        modules = [src.text(a).removeprefix("::") for a in args]
        # `include A, B` puts A first in the lookup, like `include B; include A`
        if method in ("include", "prepend") and stmt.type == "call":
            if method == "include":
                controller.includes += tuple(reversed(modules))
            else:
                controller.prepends += tuple(reversed(modules))
            controller.callbacks += [
                _Callback("", None, False, marker=f"include:{m}") for m in reversed(modules)
            ]
        names = [src.string(a) for a in args]
        if method == "alias_method" and len(names) == 2 and None not in names:
            controller.aliases[names[0]] = names[1]  # type: ignore[index]
        if not declared and method not in _KNOWN_MACROS and stmt.type == "call":
            # a class macro the app may define (`def self.shared_actions`): read where called
            controller.callbacks.append(_Callback("", None, False, marker=f"macro:{method}"))


def _callbacks(
    src: _Source, stmt: Node, method: str, extra: dict[str, Node] | None = None
) -> list[_Callback]:
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
    opts = {**(extra or {}), **(_options(src, stmt) if stmt.type == "call" else {})}
    # `only: SHARED`, `except: [:show, *OPEN]`: a list we can't read may name the action
    unread = any(
        k in opts
        and (
            opts[k] is None
            or opts[k].type not in _LITERAL_NAMES
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
        or (
            "unless" in opts
            and not (
                opts["unless"] is not None and _ADMIN_ONLY.match(src.text(opts["unless"]).strip())
            )
        )
    )
    if method in _GUARD_CALLBACKS:
        return [_Callback(method, only, False, except_, conditional, node=stmt, src=src)]
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


def _lookup(controllers: dict[str, _Controller], root: str, name: str) -> _Controller | None:
    """A controller by name, in its app first, else the one app that defines it."""
    if (found := controllers.get(f"{root}|{name}")) is not None:
        return found
    if root and name.startswith("route:"):
        return None  # an engine's route never runs the host app's controller
    others = {
        id(c): c
        for k, c in controllers.items()
        if k.endswith(f"|{name}") and k.split("|")[0] != root
    }
    return next(iter(others.values())) if len(others) == 1 else None


def _chain(controllers: dict[str, _Controller], c: _Controller) -> list[_Controller]:
    chain, seen = [c], {id(c)}
    while True:
        last = chain[-1]
        found = next(
            (x for q in last.parents if (x := _lookup(controllers, last.root, q)) is not None),
            None,
        )
        if found is None or id(found) in seen:
            break
        chain.append(found)
        seen.add(id(found))
    return chain[::-1]


def _cancan_model(src: _Source, node: Node | None) -> str | None:
    """The model `load_and_authorize_resource` loads: "" for the controller's own, a named
    one (`:note`, `class: "Memo"`), or None for options we don't read (`through:`)."""
    if node is None or node.type != "call":
        return ""
    opts = _options(src, node)
    if set(opts) - {"only", "except", "if", "unless", "class", "parent"}:
        return None
    if "class" in opts:
        named = src.string(opts["class"]) or src.text(opts["class"])
        return named.rsplit("::", 1)[-1] if named else None
    names = [src.string(a) for a in _args(node) if a.type != "pair"]
    if names and names[0]:
        return "".join(w.capitalize() for w in _singular(names[0]).split("_"))
    return ""


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
    parts: list[list[str]] = []
    parent = node.parent
    while parent is not None:
        if parent.type in ("module", "class"):
            parts.append(src.text(parent.child_by_field_name("name")).split("::"))
        parent = parent.parent
    return [p for names in reversed(parts) for p in names]


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
        rel = r.src.file.rel
        root = rel[: f"/{rel}".find("/config/")] if "/config/" in f"/{rel}" else ""
        c = _lookup(controllers, root, f"route:{r.controller}")
        guards: list[str] = []
        unguards: list[str] = []
        handler_path, handler_line = r.src.file.rel, r.src.line(r.node)
        if c is not None:
            guards, unguards = _rails_guards(controllers, c, r.action)
            if (action := c.actions.get(r.action)) is not None:
                asrc = c.sources.get(r.action, c.src)
                body = action.child_by_field_name("body")
                guards += _body_guard_calls(asrc, list(body.named_children) if body else [])
                handler_path, handler_line = asrc.file.rel, asrc.line(action)
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


_OPAQUE = _Callback("", None, False, marker="opaque")


class _Ownership:
    """Reads each Rails id route's action for ownership (`providers.ruby_ownership`)."""

    def __init__(self, sources: dict[str, _Source], controllers: dict[str, _Controller]) -> None:
        from traust_core.v1.providers.ruby_ownership import RubyCode

        self.controllers = controllers
        self.code = RubyCode(dict(sources))
        self.blocks: dict[str, _Controller] = {}

    def methods(self, c: _Controller) -> Callable[[str], tuple[Parsed, Node] | None]:
        chain = _chain(self.controllers, c)

        from traust_core.v1.providers.ruby_ownership import UNREAD as unread

        def module(name: str, method: str, depth: int = 0) -> tuple[Parsed, Node] | object | None:
            found = self.code.module(name)
            if found is None:
                return None
            if found is unread or depth > 4:
                return unread
            ms = self.code.module_methods(*found)  # type: ignore[misc]
            if method in ms:
                return found[0], ms[method]  # type: ignore[index]
            # a module's own includes, the last first (`module Sharing; include Lenient`)
            for inner in reversed(self.code.module_includes(*found)):  # type: ignore[misc]
                if (hit := module(inner, method, depth + 1)) is not None:
                    return hit
            return None

        memo: dict[tuple[str, int, int | None], tuple[Parsed, Node] | None] = {}

        def find(name: str, depth: int = 0, upto: int | None = None) -> tuple[Parsed, Node] | None:
            key = (name, depth, upto)
            if key not in memo:
                memo[key] = lookup(name, depth, upto)
            return memo[key]

        def lookup(
            name: str, depth: int = 0, upto: int | None = None
        ) -> tuple[Parsed, Node] | None:
            # Ruby's lookup: prepended modules, the class, its modules (the last included
            # first), then its parent; an alias copies the method where it's declared
            for i in reversed(range(len(chain) if upto is None else upto)):
                ctrl = chain[i]
                for m in [*reversed(ctrl.prepends), None, *reversed(ctrl.includes)]:
                    if m is None:
                        if name in ctrl.aliases and depth < 4:
                            return find(ctrl.aliases[name], depth + 1, i + 1)
                        if name in ctrl.actions:
                            return ctrl.sources.get(name, ctrl.src), ctrl.actions[name]
                        continue
                    found = module(m, name)
                    if found is unread:
                        return None  # a module we can't name may define it: fail closed
                    if found is not None:
                        return found  # type: ignore[return-value]
                if ctrl.dynamic:
                    return None  # it may define the method under a name we can't read
                # modules its included modules include (`included do include Translatable`)
                for m in reversed([i for inc in ctrl.includes for i in self.body(inc).includes]):
                    found = module(m, name)
                    if found is unread:
                        return None
                    if found is not None:
                        return found  # type: ignore[return-value]
            return None  # a method nothing on its chain defines: a gem's, not read

        return find

    def body(self, name: str) -> _Controller:
        """What a module's `included do … end` / `prepended do … end` declares, read as a
        class body."""
        if name in self.blocks:
            return self.blocks[name]
        out = _Controller(name, None, [], {}, None)  # type: ignore[arg-type]
        self.blocks[name] = out
        found = self.code.module(name)
        if isinstance(found, tuple):
            src, module = found
            for n in walk(module):
                if n.type == "call" and _method(src, n) in ("included", "prepended"):  # type: ignore[arg-type]
                    _read_class(src, _body(n), out)  # type: ignore[arg-type]
        return out

    def included(self, name: str) -> list[_Callback]:
        """Callbacks a module declares in `included do … end` or `prepended do … end`."""
        found = self.body(name)
        return [*found.callbacks, *([_OPAQUE] if found.dynamic else [])]

    def handled(self, c: _Controller, find: Callable[[str], tuple[Parsed, Node] | None]) -> bool:
        """Whether a `rescue_from` handler (its own, a module's, or a helper it calls) may use
        the record (`render json: @note`, `e.record`): then a raise that refused hands it on."""
        from traust_core.v1.providers.ruby_ownership import uses_record

        for ctrl in _chain(self.controllers, c):
            rescues = [*ctrl.rescues, *(r for m in ctrl.includes for r in self.body(m).rescues)]
            for src, handler in rescues:
                found = find(handler) if isinstance(handler, str) else (src, handler)
                if found is None or uses_record(found[0], found[1], find):
                    return True
        return False

    def macro(self, c: _Controller, name: str) -> list[_Callback]:
        """The callbacks an app-defined class macro declares; its arguments aren't read, so
        they may or may not name the action."""
        from traust_core.v1.providers.ruby_ownership import method_body

        for ctrl in reversed(_chain(self.controllers, c)):
            found = None
            if name in ctrl.singletons:
                found = (ctrl.sources.get(f"self.{name}", ctrl.src), ctrl.singletons[name])
            for m in [*ctrl.extends, *ctrl.includes]:
                mod = self.code.module(m)
                if found is None and isinstance(mod, tuple):
                    found = self.code.class_macro(mod[0], mod[1], name, m in ctrl.extends)  # type: ignore[arg-type]
            if found is not None:
                out: list[_Callback] = []
                for stmt in method_body(found[1]):
                    if stmt.type == "call":
                        out += [
                            replace(x, conditional=True)
                            for x in _callbacks(found[0], stmt, _method(found[0], stmt))  # type: ignore[arg-type]
                        ]
                return out
        # a concern's `class_methods` macro defined once in the checkout (its module included
        # where we can't follow it); else an app-defined macro we can't place fails closed
        defs = [
            hit
            for mods in self.code.modules.values()
            for msrc, mod in mods
            if (hit := self.code.class_macro(msrc, mod, name, False)) is not None
        ]
        if len(defs) == 1:
            return [
                replace(x, conditional=True)
                for stmt in method_body(defs[0][1])
                if stmt.type == "call"
                for x in _callbacks(defs[0][0], stmt, _method(defs[0][0], stmt))  # type: ignore[arg-type]
            ]
        return [_OPAQUE] if name in self.code.defined else []

    def callbacks(self, c: _Controller, action: str) -> list[_Callback]:
        """The callbacks that run for an action, in the order Rails runs them."""
        out: list[_Callback] = []
        chain = _chain(self.controllers, c)
        pending = [
            cb for ctrl in chain for cb in [*ctrl.callbacks, *([_OPAQUE] if ctrl.dynamic else [])]
        ]
        opaque = False
        while pending:
            cb = pending.pop(0)
            if cb.marker == "reset":
                out = []
                continue
            if cb.marker.startswith("include:"):  # a module's own callbacks, where included
                pending[:0] = self.included(cb.marker.removeprefix("include:"))
                continue
            if cb.marker.startswith("macro:"):  # a class macro's callbacks, where called
                pending[:0] = self.macro(c, cb.marker.removeprefix("macro:"))
                continue
            if cb.marker == "opaque":
                opaque = True
                continue
            if not cb.skip and cb.name not in _GUARD_CALLBACKS:
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
        # a declaration we couldn't read may have skipped or replaced any of them
        return [replace(x, conditional=True) for x in out] if opaque else out

    def own(self, row: _Row, c: _Controller | None, r: _Route) -> None:
        from traust_core.v1.models.common import CodeSpan
        from traust_core.v1.providers.route_ownership import HandlerFacts, privileged_only
        from traust_core.v1.providers.ruby_ownership import (
            Kind,
            action_facts,
            admin_gate,
            caller_forged,
            early_return,
            ensures,
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
        cancan_model: str | None = ""
        for cb in [cb for cb in callbacks if not cb.after]:
            if cb.name in ("load_and_authorize_resource", "load_resource", "authorize_resource"):
                cancan_model = _cancan_model(c.src if cb.node is None else cb.src or c.src, cb.node)
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
            steps += [(found[0], s, Kind.ENSURE) for s in ensures(found[1])]
        action = find(r.action)
        forged = caller_forged(self.code, steps, find, action)
        # an admin-named callback that, read, refuses no unprivileged caller is no admin gate;
        # nor is one that trusts a caller the app builds from the request
        for g in list(guards):
            # defined in the checkout but not where we can place it (`on_load`, a module
            # several share a name with): not read, so not trusted
            if privileged_only(g) and (
                forged
                or ((found := find(g)) is not None and g not in gates)
                or (found is None and g in self.code.defined)
            ):
                guards.remove(g)
        if gates and not forged and not any(privileged_only(g) for g in guards):
            guards.append(f"admin_gate:{gates[0]}")  # refuses every non-admin caller
        if action is None:
            row.own(HandlerFacts(handoff=span, takes_id=True), self.code.fields, guards=guards)
            return
        # an action's own `rescue` may swallow the raise that refused; its `ensure` runs anyway
        kind = Kind.CONDITIONAL if swallows(*action) else Kind.ACTION
        steps += [(action[0], s, kind) for s in method_body(action[1])]
        steps += [(action[0], s, Kind.CONDITIONAL) for s in rescues(action[1])]
        steps += [(action[0], s, Kind.ENSURE) for s in ensures(action[1])]
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
            model=model if cancan_model == "" else cancan_model,
            cancan=(load, authorize),
            raises=not self.handled(c, find),
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
