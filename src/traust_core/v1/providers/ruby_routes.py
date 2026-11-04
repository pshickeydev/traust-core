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
from traust_core.v1.providers.ruby_ownership import app_roots, root_of
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
_MAX_CLASS_NESTING = 64
_VISIBILITY = {"private", "protected", "public", "module_function", "private_class_method"}
# calls that run code we don't read (`send(:skip_before_action, …)`)
_DYNAMIC = {
    "send",
    "public_send",
    "__send__",
    "instance_eval",
    "instance_exec",
    "class_eval",
    "class_exec",
    "module_eval",
    "method_missing",
    "eval",
}
# macros whose block declares nothing an action runs
_BLOCK_MACROS = {"respond_to", "helper", "rescue_from", "content_security_policy", "rate_limit"}
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
# calls that declare what an action runs, or run code we don't read
_DECLARING = {
    *_BEFORE,
    *_SKIP,
    *_AFTER,
    *_SKIP_AFTER,
    *_AROUND,
    *_GUARD_CALLBACKS,
    *_CANCAN_SKIPS,
    *_DYNAMIC,
    "skip_callback",
    "reset_callbacks",
    "define_method",
    "alias_method",
    "include",
    "prepend",
    "extend",
}
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
    collection: str | None = None  # its collection path, `/posts`
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
        self.drawn: set[str] = set()  # `draw :api` files being expanded
        # `concern :commentable`, by the routes directory that declares it
        self.concerns: dict[tuple[str, str], tuple[_Source, list[Node]]] = {}
        self.expanding: set[tuple[str, str]] = set()
        for rel, src in sources.items():
            if rel.endswith("config/routes.rb"):
                for n in walk(src.root):
                    receiver = n.child_by_field_name("receiver") if n.type == "call" else None
                    if (
                        n.type == "call"
                        and _method(src, n) == "draw"
                        and "routes" in src.text(receiver)
                    ):
                        module = self._isolated(src.text(receiver))
                        self._block(
                            src, _body(n), _Scope(module=module), rel.removesuffix("routes.rb")
                        )

    def _isolated(self, drawn_on: str) -> str:
        """`Billing::Engine.routes.draw` of an engine whose class calls `isolate_namespace
        Billing`: its routes name `billing/…`. The host's `Rails.application.routes.draw` never
        does."""
        engine = re.fullmatch(r"((?:\w+::)*\w+)::Engine\.routes", drawn_on.removeprefix("::"))
        if engine is None:
            return ""
        for src in self.sources.values():
            if "isolate_namespace" not in src.file.text:
                continue
            for n in walk(src.root):
                if n.type != "class" or not n.is_named:
                    continue
                name = "::".join([*_lexical(src, n), src.text(n.child_by_field_name("name"))])
                if name.removeprefix("::") != f"{engine.group(1)}::Engine":
                    continue
                for c in walk(n):
                    if c.type == "call" and _method(src, c) == "isolate_namespace" and _args(c):
                        return f"{_snake(src.text(_args(c)[0]).replace('::', '/'))}/"
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
            # expanded where `concerns` names it, within the same app's routes
            self.concerns[(config, first)] = (src, _body(call))
        elif name == "concerns":
            names = [n for a in args if a.type != "pair" for n in _names(src, a)]
            self._concerns(names, scope, config)
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
                self.drawn.add(rel)  # drawing itself again (a cycle) stops; another scope doesn't
                self._block(included, list(included.root.named_children), scope, config)
                self.drawn.discard(rel)

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
        inner = replace(scope, path=nested, controller=controller, member=member, collection=path)
        self._block(src, _body(call), inner, config)
        self._concerns(_names(src, opts.get("concerns")), inner, config)

    def _concerns(self, names: list[str], scope: _Scope, config: str) -> None:
        for name in names:
            key = (config, name)
            if key in self.concerns and key not in self.expanding:
                csrc, body = self.concerns[key]
                self.expanding.add(key)  # a concern naming itself expands once
                self._block(csrc, body, scope, config)
                self.expanding.discard(key)

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
        base = scope.path
        on = src.string(opts.get("on"))
        if on == "member" and scope.member is not None:
            base = scope.member
        elif on == "collection" and scope.collection is not None:
            base = scope.collection
        path = _join(base, first or "")
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
    skipped: bool = False  # a skip with `if:`/`unless:` may take it out

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
    unread: set[str] = field(default_factory=set)  # methods defined with a body we don't read
    sources: dict[str, _Source] = field(default_factory=dict)  # where each method is written
    extends: tuple[str, ...] = ()  # `extend SharingMacros`: class macros
    lexical: tuple[str, ...] = ()  # the modules it's written inside, for its includes
    delegated: set[str] = field(default_factory=set)  # `delegate :authorize, to: …`


def _app_root(rel: str, roots: list[str]) -> str:
    """The app a file belongs to (`spec/dummy/` for `spec/dummy/app/…`): see `app_roots`."""
    return root_of(rel, roots)


def _controllers(sources: dict[str, _Source]) -> dict[str, _Controller]:
    """Controllers by `<root>|<route name>` (`|admin/users`) and `<root>|<class name>`; a class
    reopened in another file or by `class_eval` is one controller."""
    found: dict[str, _Controller] = {}
    roots = app_roots(list(sources))
    for rel, src in sources.items():
        root = _app_root(rel, roots)
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
            # `class ::NotesController` is top level wherever it's written
            qualified = name[2:] if name.startswith("::") else "::".join([*lexical, name])
            name = name.removeprefix("::")
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
                controller.lexical = tuple(qualified.split("::")[:-1])
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
            if n.type != "call" or n.child_by_field_name("receiver") is None:
                continue
            target = src.text(n.child_by_field_name("receiver")).removeprefix("::")
            here = _app_root(src.file.rel, roots)
            if re.search(r"(^|/)(spec|test)/", src.file.rel[len(here) :]):
                continue  # a test's `NotesController.class_eval { … }` changes no app
            owners = {id(c): c for k, c in found.items() if k == f"{here}|{target}"}.values()
            if _method(src, n) in ("class_eval", "class_exec"):
                for c in owners:
                    _read_class(src, _body(n), c)  # `NotesController.class_eval { … }`
            elif owners:  # `TabsController.skip_before_action …` from an initializer
                for c in owners:
                    c.callbacks += [
                        replace(x, conditional=True) for x in _callbacks(src, n, _method(src, n))
                    ]
    return found


def _read_class(
    src: _Source,
    stmts: list[Node],
    controller: _Controller,
    extra: dict[str, Node] | None = None,
    wrapped: bool = False,
    depth: int = 0,
) -> None:
    """A class body's methods, callbacks, modules, aliases and macros, in order; whatever it
    can't read makes the class dynamic (fail closed)."""
    if depth > _MAX_CLASS_NESTING:
        controller.dynamic = True
        return
    for stmt in stmts:
        conditional = wrapped
        if stmt.type in ("if_modifier", "unless_modifier"):
            # `skip_before_action :x unless ENV[…]`: declared on some boots only
            stmt, conditional = stmt.child_by_field_name("body") or stmt, True
        if stmt.type == "call" and _method(src, stmt) in _VISIBILITY:
            defs = [a for a in _args(stmt) if a.type in ("method", "singleton_method")]
            if defs:
                stmt = defs[0]  # `private def require_owner`, `module_function def …`
            elif all(a.type in ("simple_symbol", "string") for a in _args(stmt)):
                continue  # `private`, `private :x`
        if stmt.type == "method":
            name = src.text(stmt.child_by_field_name("name"))
            controller.actions[name] = stmt
            controller.sources[name] = src
            controller.aliases.pop(name, None)
            controller.unread.discard(name)
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
                    _read_class(src, inner, controller, extra, True, depth + 1)
            continue
        literal = stmt.type in ("string", "heredoc_body")
        if stmt.type in _CLASS_INERT and not (
            literal and any(c.type == "interpolation" for c in walk(stmt))
        ):
            continue  # a literal or a nested definition; an interpolated string runs code
        if stmt.type in ("assignment", "operator_assignment") and _plain(
            src, stmt.child_by_field_name("right")
        ):
            continue  # `DEFAULT_LIMIT = 40`, `self.responder = ApplicationResponder`
        if stmt.type == "alias" and len(stmt.named_children) == 2:
            new, old = (src.text(a).lstrip(":") for a in stmt.named_children)
            _alias(controller, src, new, old)  # `alias require_owner log_access`
            continue
        if stmt.type not in ("call", "identifier"):
            controller.dynamic = True  # a class body we can't read: fail closed
            continue
        method = _method(src, stmt) if stmt.type == "call" else src.text(stmt)
        args = _args(stmt) if stmt.type == "call" else []
        block = stmt.child_by_field_name("block") if stmt.type == "call" else None
        if method in _DYNAMIC or (
            stmt.type == "call" and (stmt.child_by_field_name("receiver") is not None)
        ):
            controller.dynamic = True  # `send(:skip_before_action, …)`, `%i[a].each { … }`
            continue
        if method in ("concerning", "included") and stmt.type == "call":
            _read_class(src, _body(stmt), controller, extra, conditional, depth + 1)
            continue
        if method == "with_options" and stmt.type == "call":
            opts = {**(extra or {}), **_options(src, stmt)}
            _read_class(src, _body(stmt), controller, opts, conditional, depth + 1)
            continue
        if method == "define_method" and args and (name := src.string(args[0])):
            if block is not None and len(args) == 1:
                controller.actions[name] = block
                controller.sources[name] = src
                controller.unread.discard(name)
            else:  # `define_method(:x, proc {})`, `instance_method(:y)`: a body we don't read
                controller.actions.pop(name, None)
                controller.aliases.pop(name, None)
                controller.unread.add(name)
            continue
        if method == "extend" and stmt.type == "call":
            controller.extends += tuple(src.text(a).removeprefix("::") for a in args)
            continue
        if method == "delegate":
            controller.delegated |= {n for a in args if a.type != "pair" and (n := src.string(a))}
            continue
        if method == "rescue_from":
            value = _options(src, stmt).get("with")
            handler = src.string(value)
            handler_block = block or (value if value is not None and handler is None else None)
            controller.rescues.append((src, handler or handler_block))  # type: ignore[arg-type]
            continue
        declared = _callbacks(src, stmt, method, extra)
        if block is not None and not declared and method not in _BLOCK_MACROS:
            controller.dynamic = True  # a block a macro we don't know runs
            continue
        if conditional:
            declared = [replace(x, conditional=True) for x in declared]
        controller.callbacks += declared
        if method in ("include", "prepend") and stmt.type == "call":
            if not all(a.type in ("constant", "scope_resolution") for a in args):
                controller.dynamic = True  # `include(Module.new { … })`
                continue
            # `include A, B` puts A first in the lookup, like `include B; include A`; an
            # unqualified name resolves in the class's lexical scope first
            modules = [_candidates(src.text(a), controller.lexical) for a in reversed(args)]
            if method == "include":
                controller.includes += tuple(modules)
            else:
                controller.prepends += tuple(modules)
            controller.callbacks += [
                _Callback("", None, False, marker=f"include:{m}") for m in modules
            ]
            continue
        names = [src.string(a) for a in args]
        if method == "alias_method" and len(names) == 2 and None not in names:
            _alias(controller, src, names[0], names[1])  # type: ignore[arg-type]
            continue
        if not declared and stmt.type == "call":
            # a class macro the app may define (`def self.shared_actions`), even one named
            # like a framework's (`def self.helper_method`): read where called
            controller.callbacks.append(_Callback("", None, False, marker=f"macro:{method}"))


def _alias(controller: _Controller, src: _Source, new: str, old: str) -> None:
    """`alias_method :new, :old` copies the method `old` names at that point; one it doesn't
    define yet (a parent's, a module's) is looked up by name."""
    controller.unread.discard(new)
    if old in controller.actions:
        controller.actions[new] = controller.actions[old]
        controller.sources[new] = controller.sources.get(old, src)
        controller.aliases.pop(new, None)
    elif old in controller.unread:
        controller.actions.pop(new, None)
        controller.unread.add(new)
    else:
        controller.actions.pop(new, None)
        controller.aliases[new] = old


def _candidates(written: str, lexical: tuple[str, ...]) -> str:
    """The names an `include` may mean, innermost scope first (`Api::Sharing|Sharing`)."""
    if written.startswith("::"):
        return written[2:]
    return "|".join("::".join([*lexical[:k], written]) for k in range(len(lexical), -1, -1))


def _plain(src: _Source, node: Node | None) -> bool:
    """A value that declares nothing an action runs: no callback, method definition, module
    or dynamic send in it (`SHARED = skip_before_action(…)` declares one; `%i[a].freeze`
    doesn't)."""
    return node is not None and not any(
        n.type == "call" and _method(src, n) in _DECLARING for n in walk(node)
    )


def _callbacks(
    src: _Source, stmt: Node, method: str, extra: dict[str, Node] | None = None
) -> list[_Callback]:
    kinds = (*_BEFORE, *_SKIP, *_AFTER, *_SKIP_AFTER, *_AROUND, *_GUARD_CALLBACKS, *_CANCAN_SKIPS)
    if method not in (*kinds, "skip_callback", "reset_callbacks"):
        return []
    args = _args(stmt) if stmt.type == "call" else []
    if method == "reset_callbacks":
        chain = src.string(args[0]) if args else None
        if chain == "process_action":
            return [_Callback("", None, False, marker="reset")]
        return [] if chain else [_Callback("", None, False, marker="opaque")]  # unread
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
    # never a test app's (`spec/dummy/`) for the host's routes
    others = {
        id(c): c
        for k, c in controllers.items()
        if k.endswith(f"|{name}")
        and k.split("|")[0] != root
        and not re.search(r"(^|/)(spec|test)/", k.split("|")[0])
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


def _cancan_model(src: _Source, node: Node | None) -> tuple[str | None, str, str]:
    """What `load_and_authorize_resource` loads: the model ("" for the controller's own, a
    named one: `:note`, `class: "Memo"`; None for options we don't read: `through:`), the
    parameter it reads (`id_param:`) and the column it finds by (`find_by:`)."""
    if node is None or node.type != "call":
        return "", "id", "pk"
    opts = _options(src, node)
    if set(opts) - {"only", "except", "if", "unless", "class", "parent", "id_param", "find_by"}:
        return None, "id", "pk"
    key = src.string(opts.get("id_param")) or "id"
    field_ = src.string(opts.get("find_by")) or "pk"
    if ("id_param" in opts and key == "id" and src.string(opts["id_param"]) is None) or (
        "find_by" in opts and src.string(opts["find_by"]) is None
    ):
        return None, "id", "pk"  # an option we can't read
    if "class" in opts:
        named = src.string(opts["class"]) or src.text(opts["class"])
        return (named.rsplit("::", 1)[-1] if named else None), key, field_
    names = [src.string(a) for a in _args(node) if a.type != "pair"]
    if names and names[0]:
        return "".join(w.capitalize() for w in _singular(names[0]).split("_")), key, field_
    return "", key, field_


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
    ownership: _Ownership, c: _Controller, action: str
) -> tuple[list[str], list[str]]:
    """(guards, unguards): the before_action guards that run for the action, in the order
    Rails runs them, including those included modules declare; a skip that removes one is an
    unguard, judged."""
    removed: list[str] = []
    callbacks = ownership.callbacks(c, action, removed)
    guarding = [
        cb
        for cb in callbacks
        if not cb.after
        and not cb.around
        and cb.body
        is None  # a block's synthetic name (`<block:admin_controller.rb:3>`) names no guard
        and (_is_guard(cb.name) or cb.name in _GUARD_CALLBACKS)
    ]
    guard = [cb.name for cb in guarding if not cb.skipped]
    # a skip that may take a guard out (`skip_before_action :x, if: :public?`) is an unguard
    removed += [cb.name for cb in guarding if cb.skipped]
    skipped = [
        f"{SKIPPED}:{n}"
        for n in removed
        if not n.startswith("<") and (_is_guard(n) or n in _GUARD_CALLBACKS)
    ]
    return _unique(guard), _unique(skipped)


def _body_guard_calls(src: _Source, stmts: list[Node]) -> list[str]:
    names = [
        src.text(s.child_by_field_name("method")) if s.type == "call" else src.text(s)
        for s in stmts
        if s.type in ("call", "identifier")
    ]
    return [f"call:{n}" for n in names if _is_guard(n)]


def _rails_rows(sources: dict[str, _Source]) -> list[_Row]:
    controllers = _controllers(sources)
    ownership = _Ownership(sources, controllers)
    rows = []
    roots = app_roots(list(sources))
    for r in _RailsRoutes(sources).routes:
        c = _lookup(controllers, _app_root(r.src.file.rel, roots), f"route:{r.controller}")
        guards: list[str] = []
        unguards: list[str] = []
        handler_path, handler_line = r.src.file.rel, r.src.line(r.node)
        if c is not None:
            guards, unguards = _rails_guards(ownership, c, r.action)
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
            ownership.own(row, c, r)
        _mark(row, None, False, r.src.file.rel)
        row.view_class = c.name if c is not None else r.controller
        rows.append(row)
    return rows


_OPAQUE = _Callback("", None, False, marker="opaque")


def _same(x: _Callback, cb: _Callback) -> bool:
    """The same callback: name and kind (`after_action :x` never replaces `before_action :x`)."""
    return x.name == cb.name and x.after == cb.after and x.around == cb.around


class _Ownership:
    """Reads each Rails id route's action for ownership (`providers.ruby_ownership`)."""

    def __init__(self, sources: dict[str, _Source], controllers: dict[str, _Controller]) -> None:
        from traust_core.v1.providers.ruby_ownership import RubyCode

        self.controllers = controllers
        self.code = RubyCode(dict(sources))
        self.blocks: dict[str, _Controller] = {}
        self.classes: dict[str, _Controller | None] = {}
        for c in {id(x): x for x in controllers.values()}.values():
            self.code.defined |= c.delegated

    def defs(self, name: str) -> list[tuple[_Source, Node]] | object | None:
        """A module's definitions by the name it's included as (`Api::Sharing|Sharing`):
        None when the checkout doesn't define it, UNREAD when it can't be told apart."""
        candidates = name.split("|")
        for candidate in candidates[:-1]:
            if candidate in self.code.qualified:
                return self.code.module_defs(candidate)
        return self.code.module_defs(candidates[-1])

    def module_class(self, name: str) -> _Controller | None:
        """A module's own body (outside `included do`), read as a class body; a module we
        can't tell apart reads as dynamic."""
        from traust_core.v1.providers.ruby_ownership import UNREAD

        if name in self.classes:
            return self.classes[name]
        found = self.defs(name)
        if found is None:
            self.classes[name] = None
            return None
        out = _Controller(name, None, [], {}, None, lexical=tuple(name.split("|")[-1].split("::")))  # type: ignore[arg-type]
        self.classes[name] = out
        if found is UNREAD:
            out.dynamic = True
            return out
        for src, module in found:  # type: ignore[union-attr]
            stmts = [
                s
                for s in (
                    module.child_by_field_name("body").named_children
                    if module.child_by_field_name("body")
                    else []
                )
                if not (
                    s.type == "call"
                    and _method(src, s) in ("included", "prepended", "class_methods")
                )
                and s.type not in ("module", "class")
                and not (
                    s.type == "singleton_method"
                    and src.text(s.child_by_field_name("name")) == "included"
                )
            ]
            _read_class(src, stmts, out)
        return out

    def body(self, name: str) -> _Controller:
        """What a module runs on the class that includes it: its `included do … end` and
        `prepended do … end` blocks, and a `def self.included(base)` hook, read as a class
        body."""
        if name in self.blocks:
            return self.blocks[name]
        out = _Controller(name, None, [], {}, None)  # type: ignore[arg-type]
        self.blocks[name] = out
        found = self.defs(name)
        if not isinstance(found, list):
            return out
        for src, module in found:
            for s in (
                module.child_by_field_name("body").named_children
                if module.child_by_field_name("body")
                else []
            ):
                if s.type == "call" and _method(src, s) in ("included", "prepended"):
                    _read_class(src, _body(s), out)
                if (
                    s.type == "singleton_method"
                    and src.text(s.child_by_field_name("name")) == "included"
                ):
                    self._hook(src, s, out)
        return out

    def _hook(self, src: _Source, hook: Node, out: _Controller) -> None:
        """`def self.included(base)`: `base.extend(ClassMethods)`, `base.class_eval { … }` and
        callbacks declared on `base` are read; anything else fails closed."""
        from traust_core.v1.providers.ruby_ownership import method_body

        params = hook.child_by_field_name("parameters")
        base = (
            src.text(params.named_children[0])
            if params is not None and params.named_children
            else ""
        )
        for stmt in method_body(hook):
            receiver = stmt.child_by_field_name("receiver") if stmt.type == "call" else None
            method = _method(src, stmt) if stmt.type == "call" else ""
            if stmt.type in ("super", "zsuper"):
                continue
            if receiver is None or src.text(receiver) != base:
                out.dynamic = True
                continue
            if method == "extend":
                out.extends += tuple(src.text(a).removeprefix("::") for a in _args(stmt))
            elif method in ("class_eval", "class_exec", "included"):
                _read_class(src, _body(stmt), out)
            elif method in ("include", "prepend"):
                modules = [src.text(a).removeprefix("::") for a in reversed(_args(stmt))]
                if method == "include":
                    out.includes += tuple(modules)
                else:
                    out.prepends += tuple(modules)
                out.callbacks += [
                    _Callback("", None, False, marker=f"include:{m}") for m in modules
                ]
            elif declared := _callbacks(src, stmt, method):
                out.callbacks += declared
            else:
                out.dynamic = True

    def included(self, name: str) -> list[_Callback]:
        """What a module runs where it's included: the modules it includes first, then its
        own `included do` callbacks."""
        cls = self.module_class(name)
        found = self.body(name)
        inner = [
            _Callback("", None, False, marker=f"include:{m}")
            for m in (cls.includes if cls is not None else ())
        ]
        # module-level code runs where the module is defined, not on the class: only its
        # included block or hook can add callbacks
        return [*inner, *found.callbacks, *([_OPAQUE] if found.dynamic else [])]

    def methods(self, c: _Controller) -> Callable[[str], tuple[Parsed, Node] | None]:
        chain = _chain(self.controllers, c)
        unread_names: set[str] = set()

        from traust_core.v1.providers.ruby_ownership import UNREAD as unread

        def module(name: str, method: str, depth: int = 0) -> tuple[Parsed, Node] | object | None:
            cls = self.module_class(name)
            if cls is None:
                return None
            if depth > 4:
                return unread
            body = self.body(name)
            for part in (body, cls):  # `included do def …` lands on the class itself
                if method in part.unread:
                    return unread
                if method in part.aliases:
                    return module(name, part.aliases[method], depth + 1) if part is cls else unread
                if method in part.actions:
                    return part.sources.get(method, part.src), part.actions[method]
            if cls.dynamic or body.dynamic:
                return unread  # it may define the method under a name we can't read
            # a module's own includes, the last first (`module Sharing; include Lenient`)
            for inner in reversed([*cls.includes, *body.includes]):
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
                        if name in ctrl.delegated or name in ctrl.unread or ctrl.dynamic:
                            # `delegate :authorize`, `define_method(:x, proc)`, or a class body
                            # that may define it ahead of its modules: not read
                            unread_names.add(name)
                            return None
                        continue
                    found = module(m, name)
                    if found is unread:
                        unread_names.add(name)
                        return None  # a module we can't read may define it: fail closed
                    if found is not None:
                        return found  # type: ignore[return-value]
            return None  # a method nothing on its chain defines: a gem's, not read

        def is_unread(name: str) -> bool:
            find(name)
            return name in unread_names

        find.unread = is_unread  # type: ignore[attr-defined]
        return find

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

    def class_macro(
        self, name: str, macro: str, extended: bool, depth: int = 0
    ) -> tuple[Parsed, Node] | None:
        """A class macro a module adds: its own methods when extended; its `class_methods do`
        or `ClassMethods` methods when included, through the modules it includes."""
        found = self.defs(name)
        if not isinstance(found, list) or depth > 4:
            return None
        for src, module in found:
            if (hit := self.code.class_macro(src, module, macro, extended)) is not None:
                return hit
        if extended:
            cls = self.module_class(name)
            if cls is not None and macro in cls.actions:
                return cls.sources.get(macro, cls.src), cls.actions[macro]
            return None
        cls, body = self.module_class(name), self.body(name)
        for inner in reversed([*(cls.includes if cls else ()), *body.includes]):
            if (hit := self.class_macro(inner, macro, False, depth + 1)) is not None:
                return hit
        for inner in reversed(body.extends):
            if (hit := self.class_macro(inner, macro, True, depth + 1)) is not None:
                return hit
        return None

    def macro(self, c: _Controller, name: str) -> list[_Callback]:
        """The callbacks a class macro declares; its arguments aren't read, so they may or
        may not name the action. A framework's (`helper_method`) declares none; an
        app-defined one we can't place fails closed."""
        from traust_core.v1.providers.ruby_ownership import method_body

        found = None
        for ctrl in reversed(_chain(self.controllers, c)):
            if name in ctrl.singletons:
                found = (ctrl.sources.get(f"self.{name}", ctrl.src), ctrl.singletons[name])
                break
            for m, extended in [
                *((x, True) for x in reversed(ctrl.extends)),
                *((x, False) for x in reversed(ctrl.includes)),
            ]:
                if (found := self.class_macro(m, name, extended)) is not None:
                    break
            if found is not None:
                break
        if found is None:
            known = name in _KNOWN_MACROS or name not in self.code.defined
            return [] if known else [_OPAQUE]
        return [
            replace(x, conditional=True)
            for stmt in method_body(found[1])
            if stmt.type == "call"
            for x in _callbacks(found[0], stmt, _method(found[0], stmt))  # type: ignore[arg-type]
        ]

    def callbacks(
        self, c: _Controller, action: str, removed: list[str] | None = None
    ) -> list[_Callback]:
        """The callbacks that run for an action, in the order Rails runs them; `removed`
        collects the ones a skip took out."""
        out: list[_Callback] = []
        chain = _chain(self.controllers, c)
        pending = [
            cb for ctrl in chain for cb in [*ctrl.callbacks, *([_OPAQUE] if ctrl.dynamic else [])]
        ]
        opaque = False
        seen: set[str] = set()  # a module included twice (or in a cycle) runs once
        while pending:
            cb = pending.pop(0)
            if cb.marker == "reset":
                out = []
                continue
            if cb.marker.startswith("include:"):  # a module's own callbacks, where included
                if cb.marker not in seen:
                    seen.add(cb.marker)
                    pending[:0] = self.included(cb.marker.removeprefix("include:"))
                continue
            if cb.marker.startswith("macro:"):  # a class macro's callbacks, where called
                pending[:0] = self.macro(c, cb.marker.removeprefix("macro:"))
                continue
            if cb.marker == "opaque":
                opaque = True
                continue
            if not cb.skip and cb.name not in _GUARD_CALLBACKS:
                out = [x for x in out if not _same(x, cb)]  # declared again: replaced
            if not cb.applies(action):
                continue
            if cb.skip:
                kept = []
                for x in out:
                    if _same(x, cb) and cb.conditional:
                        kept.append(replace(x, conditional=True, skipped=True))
                    elif x.name == "load_and_authorize_resource" and cb.name in _SPLIT:
                        kept.append(replace(x, name=_SPLIT[cb.name]))
                    elif not _same(x, cb):
                        kept.append(x)
                    elif removed is not None:
                        removed.append(x.name)
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
            admin_gate,
            early_return,
            ensures,
            inert,
            keeps_going,
            method_body,
            prepare,
            rescues,
            swallows,
        )

        ids = set(path_params(row.pattern))
        span = CodeSpan(path=RepoPath(r.src.file.rel), line=r.src.line(r.node))
        if c is None or not r.action:
            # a controller the checkout doesn't hold: unread, never unauthenticated (n/a)
            row.own(
                HandlerFacts(handoff=span, takes_id=True), self.code.fields, guards=["<unread>"]
            )
            return
        find = self.methods(c)
        callbacks = self.callbacks(c, r.action)
        guards = [*row.guards, *row.scope_guards]
        steps: list[tuple[Parsed, Node, Kind]] = []
        load = authorize = False
        gates: list[str] = []
        afters = [cb for cb in callbacks if cb.after]
        cancan_model: str | None = ""
        cancan_key = ("id", "pk")
        for cb in [cb for cb in callbacks if not cb.after]:
            if cb.name in ("load_and_authorize_resource", "load_resource", "authorize_resource"):
                cancan_model, *key = _cancan_model(
                    c.src if cb.node is None else cb.src or c.src, cb.node
                )
                cancan_key = (key[0], key[1])
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
            # `def require_owner(current_user = @note.user)`: a parameter shadows the caller
            parameters = (
                found[1].child_by_field_name("parameters") if found[1].type == "method" else None
            )
            shadowed = parameters is not None and bool(parameters.named_children)
            conditional = cb.conditional or cb.around or shadowed or swallows(*found)
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
        if action is not None:
            # an action's own `rescue` may swallow the raise that refused; its `ensure` runs
            kind = Kind.CONDITIONAL if swallows(*action) else Kind.ACTION
            steps += [(action[0], s, kind) for s in method_body(action[1])]
            steps += [(action[0], s, Kind.CONDITIONAL) for s in rescues(action[1])]
            steps += [(action[0], s, Kind.ENSURE) for s in ensures(action[1])]
            for cb in afters:
                found = (cb.src or c.src, cb.body) if cb.body is not None else find(cb.name)
                if found is not None:
                    steps += [(found[0], s, Kind.AFTER) for s in _callback_body(found[1])]
                    if found[1].type == "method":
                        steps += [(found[0], s, Kind.AFTER) for s in rescues(found[1])]
                        steps += [(found[0], s, Kind.AFTER) for s in ensures(found[1])]
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", c.name.removesuffix("Controller").split("::")[-1])
        model = "".join(p.capitalize() for p in _singular(snake.lower()).split("_"))
        walk_ = prepare(
            self.code,
            steps,
            ids,
            methods=find,
            action=r.action,
            model=model if cancan_model == "" else cancan_model,
            cancan=(load, authorize),
            cancan_key=cancan_key,
            raises=not self.handled(c, find),
        )
        forged = bool(walk_.forged & {"current_user", "current_admin"})
        # an admin-named callback that, read, refuses no unprivileged caller is no admin gate;
        # nor is one that trusts a caller the app builds from the request
        for g in list(guards):
            # defined in the checkout but not where we can place it (`on_load`, a module
            # several share a name with): not read, so not trusted
            sometimes = any(cb.name == g and cb.conditional for cb in callbacks)
            if privileged_only(g) and (
                forged
                or sometimes  # `before_action :authenticate_admin!, if: :x`
                or ((found := find(g)) is not None and g not in gates)
                or (found is None and g in self.code.defined)
            ):
                guards.remove(g)
        if gates and not forged and not any(privileged_only(g) for g in guards):
            guards.append(f"admin_gate:{gates[0]}")  # refuses every non-admin caller
        if action is None:
            row.own(HandlerFacts(handoff=span, takes_id=True), self.code.fields, guards=guards)
            return
        facts = walk_.facts(guarded=bool(guards))
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
