"""Ownership of the object a Rails action acts on, read from its `before_action` callbacks, its
body and the same-repository methods, models, policies and abilities they use. Protection
counts only from allow-listed shapes (D8, D15-D18)."""

from __future__ import annotations

import itertools
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum

from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_ownership import (
    OWNER_CHECK_RX,
    OWNER_FIELD_RX,
    HandlerFacts,
    Lookup,
)
from traust_core.v1.providers.syntax import Node, Parsed, walk

# Rails' 401-404 statuses (D16)
_REFUSING_STATUS = {"unauthorized", "payment_required", "forbidden", "not_found"}
_REFUSING_CODES = {"401", "402", "403", "404"}
# ActiveRecord: the reads that raise on a miss, those that return nil, and the writes
_RAISING = {"find", "find_by!", "first!", "take!", "last!", "sole", "find_sole_by", "find!"}
_NIL_READS = {"find_by", "first", "take", "last", "find_by_id"}
_WRITES = {
    "update_attribute",
    "update_attributes",
    "update_attributes!",
    "increment!",
    "decrement!",
    "toggle!",
    "save",
    "save!",
    "update",
    "update!",
    "update_all",
    "update_columns",
    "update_column",
    "destroy",
    "destroy!",
    "destroy_all",
    "destroy_by",
    "delete",
    "delete_all",
    "delete_by",
    "touch",
}
_READS = _RAISING | _NIL_READS | {"exists?", "find_each", "pluck", "count"}
# reads and writes of the one record a key names
_ONE = _RAISING | _NIL_READS | {"exists?"}
# query methods that drop conditions, so a relation reaches past the caller's records
_WIDENING = {
    "or",
    "unscope",
    "unscoped",
    "rewhere",
    "merge",
    "invert_where",
    "except",
    "only",
    "klass",  # `current_user.notes.klass`: the bare class
    "find_by_sql",
    "from",
    "extending",
    "model",
    "base_class",
}
# query methods that narrow nothing and change nothing (`includes`, `order`)
_NEUTRAL = {
    "includes",
    "preload",
    "eager_load",
    "joins",
    "left_joins",
    "left_outer_joins",
    "references",
    "order",
    "reorder",
    "limit",
    "offset",
    "select",
    "readonly",
    "lock",
    "distinct",
    "kept",
    "with_attached_file",
    "strict_loading",
}
_CALLERS = {"current_user", "current_account", "current_member", "current_admin"}
_CALLER_IVARS = {f"@{c}" for c in _CALLERS}
_PRIVILEGE = re.compile(r"^(is_)?(admin|administrator|superuser|super_admin|staff|moderator)\??$")
# what a caller set by an authentication callback may come from (D17, D20): the session, a
# cookie, a verified token; never the request's parameters
_CREDENTIAL = re.compile(
    r"\b(session|cookies|warden|\w*authenticat\w*|verif\w*|decode\w*|\w*bearer\w*|\w*token\w*|"
    r"jwt\w*)\b",
    re.I,
)
_UNTRUSTED = re.compile(
    r"\bparams\b|\brequest\.(params|parameters|query_parameters|request_parameters|"
    r"path_parameters|GET|POST|query_string|raw_post|body)\b|"
    # D20 amended: a plain cookie is set by the client; `cookies.signed`/`.encrypted` aren't
    r"\bcookies(\.permanent)?\s*(\[|\.fetch\b|\.dig\b|\.to_h(ash)?\b|\.each\b)|"
    r"\brequest\.(cookie_jar|cookies)\b"
)
_STRING = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'")
# the caller's own tenant (`current_user.account_id`); never another user it names
_TENANT = re.compile(
    r"(?i)^(account|customer|org|organi[sz]ation|workspace|team|client|group|company|realm|"
    r"tenant|project)(_?id)?$"
)
_BY_USER = re.compile(r"(?i)_by(_id)?$|_user_id$")
_TOKEN_KEY = re.compile(r"(?i)token|api_key|digest|secret|jti")
_PARAMS = {"params", "request.path_parameters", "request.params", "request.parameters"}
# a `render` naming a view (`render :show`, `template:`) may print the record
_VIEW_KEYS = {"action", "template"}
# what a `render` sends instead of a view
_BODY_KEYS = {"json", "plain", "html", "body", "xml", "js", "text", "nothing", "inline", "partial"}
# `JWT.decode(token, nil, false)`: a token read without its signature
_UNVERIFIED = re.compile(r"\bdecode\s*\([^)]*,\s*(false|nil)\s*(,|\))|verify(_signature)?:\s*false")
_SIGN_IN = {"sign_in", "bypass_sign_in", "login", "log_in", "auto_login", "set_user"}
_CONVERSIONS = {"to_i", "to_s", "to_param", "presence"}
_INERT = {"logger", "Rails", "puts", "p", "pp", "flash", "notice", "alert", "t", "I18n"}
_MAX_DEPTH = 64
_MAX_NESTING = 64  # alternating `&&`/`||` levels a condition may nest
_MAX_HELPERS = 6  # argument-free helpers followed inside one another
_Key = tuple[str, str, str]  # (the id, the model, the field); "*" for unknown


def call_name(src: Parsed, node: Node) -> str:
    return src.text(node.child_by_field_name("method")) if node.type == "call" else ""


def args(node: Node) -> list[Node]:
    a = node.child_by_field_name("arguments") if node.type in ("call", "return") else None
    if node.type == "return" and a is None:
        a = next((c for c in node.named_children if c.type == "argument_list"), None)
    return [x for x in a.named_children if x.type != "comment"] if a is not None else []


def unwrap(node: Node | None) -> Node | None:
    while node is not None and node.type == "parenthesized_statements" and node.named_children:
        if len(node.named_children) != 1:
            return node
        node = node.named_children[0]
    return node


def chain_text(src: Parsed, node: Node | None) -> str:
    """`current_user.account.id` for a chain of argument-free calls on a name, else ''."""
    parts: list[str] = []
    node = unwrap(node)
    for _ in range(_MAX_DEPTH):
        if node is None:
            return ""
        if node.type in ("identifier", "instance_variable", "constant", "self"):
            return ".".join([src.text(node), *reversed(parts)])
        if node.type == "scope_resolution":
            return ".".join([src.text(node), *reversed(parts)])
        if node.type != "call" or args(node) or node.child_by_field_name("block") is not None:
            return ""
        receiver = node.child_by_field_name("receiver")
        if receiver is None:
            return ".".join([call_name(src, node), *reversed(parts)])
        parts.append(call_name(src, node))
        node = unwrap(receiver)
    return ""


def symbol(src: Parsed, node: Node | None) -> str | None:
    node = unwrap(node)
    if node is None:
        return None
    if node.type in ("simple_symbol", "hash_key_symbol"):
        return src.text(node).lstrip(":")
    if node.type == "string" and not any(c.type == "interpolation" for c in node.named_children):
        return "".join(src.text(c) for c in node.named_children if c.type == "string_content")
    return None


def pairs(src: Parsed, nodes: list[Node]) -> list[tuple[str, Node]] | None:
    """The `key: value` equalities of a hash argument; None for anything else (a string
    condition, a splat, a computed key, a nested hash or a range)."""
    out: list[tuple[str, Node]] = []
    for a in nodes:
        items = a.named_children if a.type == "hash" else [a]
        for p in items:
            if p.type == "comment":
                continue
            if p.type != "pair":
                return None
            key = symbol(src, p.child_by_field_name("key"))
            value = unwrap(p.child_by_field_name("value"))
            if key is None or value is None or value.type in ("hash", "range", "array"):
                return None
            out.append((key, value))
    names = [k for k, _ in out]
    return out if len(names) == len(set(names)) else None


def statements(body: Node | None) -> list[Node]:
    if body is None:
        return []
    return [
        s
        for s in body.named_children
        if s.type not in ("comment", "empty_statement", "rescue", "ensure", "else")
    ]


def method_body(method: Node) -> list[Node]:
    """A method's statements; an endless method (`def a? = x`) is its one expression."""
    body = method.child_by_field_name("body")
    if body is None:
        return []
    return statements(body) if body.type in ("body_statement", "block_body") else [body]


def code_text(src: Parsed, node: Node | None) -> str:
    """A node's text with its string literals emptied (a header named "X-Session" is no
    session)."""
    return _STRING.sub('""', src.text(node)) if node is not None else ""


# ---- the checkout's models, schema, policies and abilities


@dataclass
class _Model:
    name: str
    associations: dict[str, str] = field(default_factory=dict)  # has_many/one name -> class
    belongs: dict[str, str] = field(default_factory=dict)  # belongs_to name -> class
    members: list[str] = field(default_factory=list)  # users held through a join (`through:`)
    linked: bool = False  # fields we can't all read
    policy: str | None = None  # `def self.policy_class`
    base: str = ""  # the class it inherits from
    users: list[str] = field(default_factory=list)  # `belongs_to :uploader, class_name: "User"`
    children: list[str] = field(default_factory=list)  # the classes its `has_many`s hold
    scopes: dict[str, Node] = field(default_factory=dict)  # `scope :x, -> { … }`, `def self.x`
    polymorphic: set[str] = field(default_factory=set)  # `belongs_to :owner, polymorphic: true`
    qualified: set[str] = field(default_factory=set)  # `Note`, `Archive::Note`


class RubyCode:
    """A checkout's ActiveRecord models (associations from the model, columns from
    `db/schema.rb`), Pundit policies and the CanCanCan `Ability`."""

    def __init__(self, sources: dict[str, Parsed]) -> None:
        self.sources = sources
        self.models: dict[str, _Model] = {}
        self.columns: dict[str, list[str]] = {}  # table -> columns
        self.policies: dict[str, Node] = {}  # class name -> class node
        self.policy_src: dict[str, Parsed] = {}
        self.modules: dict[str, list[tuple[Parsed, Node]]] = {}  # module name -> definitions
        self.ability: tuple[Parsed, Node] | None = None
        self.qualified: dict[str, tuple[Parsed, Node]] = {}  # `Api::Relaxed` -> module
        self.method_cache: dict[tuple[str, int, int], dict[str, Node]] = {}
        self.defined: set[str] = set()  # every method name the checkout defines
        for rel, src in sources.items():
            self._index(rel, src)
            self.defined |= {
                src.text(m.child_by_field_name("name"))
                for m in walk(src.root)
                if m.type in ("method", "singleton_method")
            }
        self.fields = self._fields()

    def _index(self, rel: str, src: Parsed) -> None:
        if rel.endswith("db/schema.rb"):
            self._schema(src)
        for n in walk(src.root):
            if n.type == "module" and n.is_named:
                written = src.text(n.child_by_field_name("name"))
                self.modules.setdefault(written.rsplit("::", 1)[-1], []).append((src, n))
                self.qualified["::".join([*_lexical(src, n), written])] = (src, n)
            if n.type != "class" or not n.is_named:
                continue
            name = src.text(n.child_by_field_name("name")).rsplit("::", 1)[-1]
            sup = n.child_by_field_name("superclass")
            base = src.text(sup.named_children[0]) if sup is not None and sup.named_children else ""
            body = statements(n.child_by_field_name("body"))
            if name.endswith("Policy") or base.endswith("Policy") or name == "Scope":
                if name.endswith("Policy"):
                    self.policies[name] = n
                    self.policy_src[name] = src
            elif (
                name == "Ability"
                and any(s.type == "call" and call_name(src, s) == "include" for s in body)
            ) or (name == "Ability" and "CanCan" in src.text(n)):
                self.ability = (src, n)
            elif "/app/" in f"/{rel}" and (
                base in ("ApplicationRecord", "ActiveRecord::Base") or "/app/models/" in f"/{rel}"
            ):  # never a migration's or a task's stub (`db/migrate`: `class Account < …`)
                if (
                    not base
                    or base.endswith(("Controller", "CurrentAttributes"))
                    or name.endswith("Controller")
                ):
                    continue
                model = self.models.setdefault(name, _Model(name))
                model.qualified.add(
                    "::".join([*_lexical(src, n), src.text(n.child_by_field_name("name"))])
                )
                model.base = base.rsplit("::", 1)[-1]
                if base not in ("ApplicationRecord", "ActiveRecord::Base"):
                    model.linked = True  # inherited associations (STI)
                defined = {
                    src.text(s.child_by_field_name("name")) for s in body if s.type == "method"
                }
                for s in body:
                    if (
                        s.type in ("singleton_method", "method")
                        and src.text(s.child_by_field_name("name")) == "policy_class"
                    ):
                        found = method_body(s)
                        model.policy = src.text(found[-1]) if found else None
                    if s.type == "singleton_method":
                        model.scopes[src.text(s.child_by_field_name("name"))] = s
                    if s.type != "call" or not args(s):
                        continue
                    kind, first = call_name(src, s), symbol(src, args(s)[0])
                    if kind == "scope" and first is not None:
                        model.scopes[first] = s
                        continue
                    opts = dict(pairs(src, [a for a in args(s)[1:] if a.type != "lambda"]) or [])
                    if first is None:
                        continue
                    target = symbol(src, opts.get("class_name")) or _class_of(first)
                    if kind in ("has_many", "has_one", "has_and_belongs_to_many"):
                        held = symbol(src, opts.get("source"))
                        if (_class_of(held) if held else target) == "User":
                            model.members.append(first)  # its users: owned through a join
                        if any(
                            a.type == "lambda"
                            and any(call_name(src, c) in _WIDENING for c in walk(a))
                            for a in args(s)
                        ):
                            continue  # `-> { unscope(where: :user_id) }`: not the caller's own
                        # `def notes` overrides it; `through:` reaches records through others
                        # (a membership, D22, or other users), so it is never the caller's own;
                        # an extension block may widen it
                        block = s.child_by_field_name("block")
                        widened = block is not None and any(
                            call_name(src, c) in _WIDENING for c in walk(block)
                        )
                        if first not in defined and "through" not in opts and not widened:
                            model.associations[first] = target
                        if "through" not in opts:
                            model.children.append(target)
                    elif kind == "belongs_to":
                        model.belongs[first] = target
                        if src.text(opts.get("polymorphic")) == "true":
                            model.polymorphic.add(first)
                        if target == "User":
                            model.users.append(first)
                    elif kind in ("include", "acts_as_tenant", "delegated_type", "store"):
                        model.linked = True

    def _schema(self, src: Parsed) -> None:
        for n in walk(src.root):
            if n.type != "call" or call_name(src, n) != "create_table" or not args(n):
                continue
            table = symbol(src, args(n)[0])
            if table is None:
                continue
            block = n.child_by_field_name("block")
            columns = self.columns.setdefault(table, [])
            for c in walk(block) if block is not None else []:
                if c.type == "call" and args(c) and (col := symbol(src, args(c)[0])):
                    kind = call_name(src, c)
                    if kind in ("references", "belongs_to"):
                        columns.append(f"{col}_id")
                    elif kind not in ("index",):
                        columns.append(col)

    def _fields(self) -> dict[str, tuple[str, ...]]:
        """A model's fields (columns and associations), only for models we can fully read."""
        out = {}
        user = self.models.get("User")
        users_hold = set(user.belongs.values()) if user is not None else set()
        if user is not None:
            users_hold |= set(user.associations.values()) | set(user.children)
        for other in self.models.values():
            owner_cols = [
                c for c in self.columns.get(_table_of(other.name), []) if OWNER_FIELD_RX.match(c)
            ]
            if owner_cols or any(OWNER_FIELD_RX.match(b) for b in other.belongs):
                users_hold |= set(other.belongs.values())
        # what a held record holds is held too (`User` → `Account` → `BillingProfile`)
        queue = list(users_hold)
        while queue:
            held = self.models.get(queue.pop())
            for target in held.belongs.values() if held is not None else ():
                if target not in users_hold:
                    users_hold.add(target)
                    queue.append(target)
        for name, model in self.models.items():
            table = _table_of(name)
            # owned through a join (`has_many :users, through: :memberships`), or by a user
            # under a name we don't read as an owner (`belongs_to :uploader`): not readable
            if model.linked or model.members or table not in self.columns:
                continue
            fields = tuple(dict.fromkeys([*self.columns[table], *model.belongs]))
            owned = any(OWNER_FIELD_RX.match(f) for f in fields)
            # owned in ways no field of its own names: a user column we don't read as an owner
            # (`submitted_by`), the user holding the link (`users.wallet_id`), or rows that
            # hold users (`has_many :permissions` with `permissions.user_id`)
            if not owned and (
                model.users
                or any(_BY_USER.search(f) for f in fields)
                or name in users_hold
                or any(self._owned(child) for child in model.children)
            ):
                continue
            if len(model.qualified) > 1:
                continue  # `Note` and `Archive::Note`: which one a name means isn't read
            out[name] = fields
        return out

    def descendants(self, model: str) -> list[str]:
        """A model and every model that inherits from it (STI)."""
        out, queue = [model], [model]
        while queue:
            base = queue.pop()
            for m in self.models.values():
                if m.base == base and m.name not in out:
                    out.append(m.name)
                    queue.append(m.name)
        return out

    def module(self, name: str) -> tuple[Parsed, Node] | object | None:
        """A module by the name it's included as: its definition, None when the checkout
        doesn't define it, or UNREAD when several share the name."""
        if name in self.qualified:
            return self.qualified[name]
        if "::" in name and not any(q.endswith(f"::{name}") for q in self.qualified):
            return None  # `Pundit::Authorization`: a gem's, not the app's `Authorization`
        found = self.modules.get(name.rsplit("::", 1)[-1], [])
        if not found:
            return None
        return found[0] if len(found) == 1 else UNREAD

    def _owned(self, model: str) -> bool:
        cols = self.columns.get(_table_of(model), [])
        found = self.models.get(model)
        return any(OWNER_CHECK_RX.match(c) for c in [*cols, *(found.belongs if found else ())])

    def narrows(self, model: str | None, name: str) -> bool:
        """Whether a model's own scope only narrows (`scope :recent, -> { order(…) }`); an
        unread one, or one that drops conditions, may reach past the caller's records."""
        found = self.models.get(model or "")
        scope = found.scopes.get(name) if found is not None else None
        return scope is not None and not any(
            n.type == "call"
            and n.child_by_field_name("method") is not None
            and n.child_by_field_name("method").text.decode() in _WIDENING  # type: ignore[union-attr]
            for n in walk(scope)
        )

    def module_includes(self, src: Parsed, module: Node) -> list[str]:
        return [
            src.text(a).removeprefix("::")
            for m in statements(module.child_by_field_name("body"))
            if m.type == "call" and call_name(src, m) == "include"
            for a in args(m)
        ]

    def class_macro(
        self, src: Parsed, module: Node, name: str, extended: bool
    ) -> tuple[Parsed, Node] | None:
        """A class macro a module adds: its methods when extended, its `class_methods do`
        methods when included."""
        if extended:
            found = self.module_methods(src, module).get(name)
            return (src, found) if found is not None else None
        for n in walk(module):
            if n.type == "call" and call_name(src, n) == "class_methods":
                for m in walk(n):
                    if m.type == "method" and src.text(m.child_by_field_name("name")) == name:
                        return src, m
        return None

    def module_methods(self, src: Parsed, module: Node) -> dict[str, Node]:
        key = (src.file.rel, module.start_byte, module.end_byte)
        if key in self.method_cache:
            return self.method_cache[key]
        found = self._module_methods(src, module)
        self.method_cache[key] = found
        return found

    def _module_methods(self, src: Parsed, module: Node) -> dict[str, Node]:
        return {
            src.text(m.child_by_field_name("name")): m
            for m in statements(module.child_by_field_name("body"))
            if m.type == "method"
        }

    def held(self, name: str) -> str | None:
        """The class an association name holds, when every model naming it agrees."""
        found = {m.associations[name] for m in self.models.values() if name in m.associations}
        return next(iter(found)) if len(found) == 1 else None

    def association(self, model: str | None, name: str) -> str | None:
        """The class a model's `has_many`/`has_one` association holds."""
        found = self.models.get(model or "")
        return found.associations.get(name) if found is not None else None

    def owner_columns(self, model: str | None) -> set[str]:
        found = self.models.get(model or "")
        cols = set(self.columns.get(_table_of(model or ""), []))
        if found is not None:
            cols |= set(found.belongs) | {f"{b}_id" for b in found.belongs}
        return {c for c in cols if OWNER_CHECK_RX.match(c)}

    def policy_name(self, model: str, policy: str | None = None) -> str:
        """The policy Pundit uses: the one named, a `policy_class` the model or a class it
        inherits from defines, else `<Model>Policy`."""
        found, seen = self.models.get(model), set()
        while policy is None and found is not None and found.name not in seen:
            seen.add(found.name)
            policy = found.policy
            found = self.models.get(found.base)
        return (policy or f"{model}Policy").removeprefix("::")

    def policy_method(
        self, model: str, query: str, policy: str | None = None
    ) -> tuple[Parsed, Node] | None:
        """`NotePolicy#destroy?` (through aliases and policy inheritance); None when it
        can't be read."""
        name = self.policy_name(model, policy)
        cls = self.policies.get(name.rsplit("::", 1)[-1])
        seen: set[tuple[str, str]] = set()
        while cls is not None and (name, query) not in seen:
            seen.add((name, query))
            src = self.policy_src[name.rsplit("::", 1)[-1]]
            # the last definition wins: a `def`, or an alias made after it
            last: Node | str | None = None
            for m in statements(cls.child_by_field_name("body")):
                if m.type == "method" and src.text(m.child_by_field_name("name")) == query:
                    last = m
                if m.type == "call" and call_name(src, m) == "alias_method" and len(args(m)) == 2:
                    new, old = (symbol(src, a) for a in args(m))
                    last = old if new == query else last
                if m.type == "alias" and len(m.named_children) == 2:
                    new, old = (src.text(a).lstrip(":") for a in m.named_children)
                    last = old if new == query else last
            if isinstance(last, str):
                query = last
                continue
            if last is not None:
                return src, last
            sup = cls.child_by_field_name("superclass")
            name = (
                src.text(sup.named_children[0]).rsplit("::", 1)[-1]
                if sup is not None and sup.named_children
                else ""
            )
            cls = self.policies.get(name)
        return None

    def policy_scope(self, model: str, scope: str | None = None) -> tuple[Parsed, Node] | None:
        """`NotePolicy::Scope#resolve`, or the `policy_scope_class:` named."""
        policy, _, inner = (scope or f"{self.policy_name(model)}::Scope").rpartition("::")
        cls = self.policies.get(policy.rsplit("::", 1)[-1])
        if cls is None:
            return None
        src = self.policy_src[policy.rsplit("::", 1)[-1]]
        for n in walk(cls):
            if n.type == "class" and src.text(n.child_by_field_name("name")) == inner:
                for m in statements(n.child_by_field_name("body")):
                    if m.type == "method" and src.text(m.child_by_field_name("name")) == "resolve":
                        return src, m
        return None


UNREAD = object()  # a module several definitions share a name with


def _lexical(src: Parsed, node: Node) -> list[str]:
    """The modules and classes a node is written inside."""
    parts: list[list[str]] = []
    parent = node.parent
    while parent is not None:
        if parent.type in ("module", "class"):
            parts.append(src.text(parent.child_by_field_name("name")).split("::"))
        parent = parent.parent
    return [p for names in reversed(parts) for p in names]


def _class_of(association: str) -> str:
    singular = (
        association[:-3] + "y" if association.endswith("ies") else association.removesuffix("s")
    )
    return "".join(p.capitalize() for p in singular.split("_"))


def _table_of(model: str) -> str:
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", model).lower()
    if snake.endswith("y") and snake[-2:-1] not in "aeiou":
        return snake[:-1] + "ies"
    return snake if snake.endswith("s") else snake + "s"


# ---- truth tables: what a condition refuses


_Atom = str  # "own", "present", "admin", or a free atom's text
_Env = dict[str, bool]
_Cond = tuple[Parsed, Node | None, bool]  # a condition and whether it must fail (`unless`)


def _boolean(
    src: Parsed, node: Node | None, atom: Callable[[Node], _Atom | None], depth: int = 0
) -> Callable[[_Env], bool] | None:
    """A condition as a function of its atoms; None when it isn't a plain boolean (or nests
    past reading)."""
    node = unwrap(node)
    negate = False
    while (
        node is not None
        and node.type == "unary"
        and src.text(node.child_by_field_name("operator")) in ("!", "not")
    ):
        negate, node = not negate, unwrap(node.child_by_field_name("operand"))
    if node is None or depth > _MAX_NESTING:
        return None
    fn: Callable[[_Env], bool] | None
    op = src.text(node.child_by_field_name("operator")) if node.type == "binary" else ""
    if node.type == "true":
        fn = lambda env: True  # noqa: E731
    elif node.type in ("false", "nil"):
        fn = lambda env: False  # noqa: E731
    elif op in ("&&", "and", "||", "or"):
        same = ("&&", "and") if op in ("&&", "and") else ("||", "or")
        operands: list[Node | None] = []
        stack: list[Node | None] = [node]
        while stack:
            n = unwrap(stack.pop())
            if (
                n is not None
                and n.type == "binary"
                and (src.text(n.child_by_field_name("operator")) in same)
            ):
                stack += [n.child_by_field_name("right"), n.child_by_field_name("left")]
            else:
                operands.append(n)
        fns = [_boolean(src, o, atom, depth + 1) for o in operands]
        if any(f is None for f in fns):
            return None
        both = same[0] == "&&"
        fn = (
            (lambda env: all(f(env) for f in fns))  # type: ignore[misc]
            if both
            else (lambda env: any(f(env) for f in fns))  # type: ignore[misc]
        )
    else:
        found = atom(node)
        if found is None:
            return None
        name = found.removeprefix("!")
        flip = found.startswith("!")
        fn = lambda env: env[name] is not flip  # noqa: E731
    return (lambda env: not fn(env)) if negate else fn


def _atoms(src: Parsed, node: Node | None, atom: Callable[[Node], _Atom | None]) -> set[str]:
    out: set[str] = set()
    stack = [unwrap(node)]
    while stack:
        n = unwrap(stack.pop())
        if n is None:
            continue
        if n.type == "unary" and src.text(n.child_by_field_name("operator")) in ("!", "not"):
            stack.append(n.child_by_field_name("operand"))
        elif n.type == "binary" and src.text(n.child_by_field_name("operator")) in (
            "&&",
            "and",
            "||",
            "or",
        ):
            stack += [n.child_by_field_name("left"), n.child_by_field_name("right")]
        elif n.type not in ("true", "false", "nil") and (a := atom(n)) is not None:
            out.add(a.removeprefix("!"))
    return out


def holds(
    src: Parsed,
    node: Node | None,
    atom: Callable[[Node], _Atom | None],
    when: _Env,
    value: bool,
) -> bool:
    """Whether a condition is `value` in every state matching `when` (the other atoms free)."""
    fn = _boolean(src, node, atom)
    if fn is None:
        return False
    free = sorted(_atoms(src, node, atom) - set(when))
    if len(free) > 8:
        return False
    for combo in itertools.product((False, True), repeat=len(free)):
        env = {**dict.fromkeys(("own", "present", "admin", "caller"), True), **when}
        env.update(zip(free, combo, strict=True))
        if fn(env) is not value:
            return False
    return True


def holds_all(
    conds: list[_Cond], atom: Callable[[Parsed], Callable[[Node], _Atom | None]], when: _Env
) -> bool:
    """Whether every condition holds (an `unless` one: fails) in every state matching `when`."""
    fns = []
    free: set[str] = set()
    for src, node, negated in conds:
        fn = _boolean(src, node, atom(src))
        if fn is None:
            return False
        fns.append((fn, negated))
        free |= _atoms(src, node, atom(src))
    names = sorted(free - set(when))
    if len(names) > 8:
        return False
    for combo in itertools.product((False, True), repeat=len(names)):
        env = {**dict.fromkeys(("own", "present", "admin", "caller"), True), **when}
        env.update(zip(names, combo, strict=True))
        if not all(fn(env) is not negated for fn, negated in fns):
            return False
    return True


# ---- one action


@dataclass
class _Record:
    lookup: int  # the lookup that loaded it
    model: str | None
    used: bool = False  # acted on or sent before any check


class Kind(Enum):
    ACTION = "action"
    CALLBACK = "callback"  # a `before_action`: a response there halts the chain
    CONDITIONAL = "conditional"  # a callback that may not run (`if:`, after an early `return`)
    AFTER = "after"  # an `after_action`: runs even when the action refused
    ENSURE = "ensure"  # an `ensure` clause: runs even after the raise that refused


@dataclass
class _Step:
    src: Parsed
    node: Node
    kind: Kind

    @property
    def callback(self) -> bool:
        return self.kind is not Kind.ACTION


class _Action:
    """A Rails action as the statements it runs in order: its `before_action` callbacks'
    bodies, then its own. `path_ids`: the route's params; `guarded`: an authenticating
    callback runs before it (D17)."""

    def __init__(
        self,
        code: RubyCode,
        steps: list[_Step],
        path_ids: set[str],
        guarded: bool,
        methods: Callable[[str], tuple[Parsed, Node] | None],
        action: str,
        model: str | None,
        cancan: tuple[bool, bool],
        raises: bool = True,
    ) -> None:
        self.raise_refuses = raises
        self.code, self.steps, self.path_ids = code, steps, path_ids
        self.methods, self.action, self.model = methods, action, model
        self.lookups: list[Lookup] = []
        self.terminals: list[str] = []
        self.nodes: list[Node] = []
        self.cover: list[set[_Key] | None] = []
        self.starts: list[int] = []
        self.raising: set[int] = set()
        self.reads: list[bool] = []
        self.handoffs: list[tuple[CodeSpan, set[_Key] | None, int]] = []
        self.verified: dict[_Key, int] = {}
        self.records: dict[str, _Record] = {}
        self.roots: dict[str, str] = {}  # local -> the path id it holds
        self.unstable: set[str] = set()
        self.hop: CodeSpan | None = None
        self.caller_span: CodeSpan | None = None
        self.reached = _reachable(steps, methods)
        self.local_values: dict[str, list[tuple[Parsed, Node]]] = {}
        literal: dict[str, bool] = {}
        for step in self.reached:
            for n in walk(step.node):
                left = n.child_by_field_name("left") if n.type == "assignment" else None
                if left is not None and left.type == "identifier":
                    right = n.child_by_field_name("right")
                    self.local_values.setdefault(step.src.text(left), []).append((step.src, right))
                    literal[step.src.text(left)] = literal.get(step.src.text(left), True) and (
                        _is_literal(right)
                    )
        self.literals = {name for name, ok in literal.items() if ok}
        self.guarded = guarded
        self.taint: dict[tuple[str, int, int], bool] = {}
        self.credentials: dict[tuple[str, int, int, int], bool] = {}
        self.caller_ivars = self._caller_ivars()
        # what each caller ivar stands for: the user, or the caller's tenant (`@account =
        # current_user.account`)
        kinds = self._ivar_kinds()
        self.ivar_kind = {
            name: next(iter(kinds[name])) if len(kinds.get(name, ())) == 1 else "user"
            for name in self.caller_ivars
        }
        self.forged = self._forged()
        self.cancan = cancan
        self.position = 0
        self.inlined: set[str] = set()
        self.kind = Kind.ACTION
        self.deferred: set[int] = set()  # lookups an unreadable policy decides (D15: unknown)
        self.verified_kind: dict[_Key, Kind] = {}
        self.checked_in: dict[int, Kind] = {}
        self.after: set[int] = set()  # lookups an `after_action` makes
        self.ensured: set[int] = set()  # lookups an `ensure` clause makes
        self.raises = False  # whether the last refusal read raises
        # a name a method assigns is its local there, never a call (`note = Note.find(…)`)
        self.locals = {
            step.src.text(n.child_by_field_name("left"))
            for step in steps
            for n in walk(step.node)
            if n.type in ("assignment", "operator_assignment")
            and n.child_by_field_name("left") is not None
            and n.child_by_field_name("left").type == "identifier"
        }

    # -- the caller
    def _untrusted(self, src: Parsed, node: Node | None, depth: int = 0) -> bool:
        """Built from the request's parameters, directly, through a local or an app helper, or
        from a token decoded without its signature (`JWT.decode(t, nil, false)`)."""
        if node is None:
            return False
        key = (src.file.rel, node.start_byte, node.end_byte)
        if key not in self.taint:
            self.taint[key] = False  # a cycle through locals reads as clean until resolved
            text = code_text(src, node)
            self.taint[key] = bool(_UNTRUSTED.search(text) or _UNVERIFIED.search(text)) or (
                depth < 3
                and any(self._untrusted(s, v, depth + 1) for s, v in self._values(src, node))
            )
        return self.taint[key]

    def _values(self, src: Parsed, node: Node) -> list[tuple[Parsed, Node | None]]:
        """What the locals and the app's own argument-free helpers an expression names
        return."""
        out: list[tuple[Parsed, Node | None]] = []
        for n in walk(node):
            name = _helper_name(src, n) if n.type in ("identifier", "call") else ""
            if not name:
                continue
            if name in self.local_values:
                out += self.local_values[name]
            elif name not in _CALLERS and (found := self.methods(name)) is not None:
                body = method_body(found[1])
                out += [(found[0], body[-1])] if body else []
        return out

    def _credential(self, src: Parsed, node: Node | None, ivars: set[str], depth: int = 0) -> bool:
        """From the session, a cookie, a verified token or the caller (D17, D20); an app
        helper counts by what it returns, never by its name (`decoded_token`)."""
        if node is None or self._untrusted(src, node):
            return False
        key = (src.file.rel, node.start_byte, node.end_byte, len(ivars))
        if key in self.credentials:
            return self.credentials[key]
        self.credentials[key] = False
        found = (
            bool(_CREDENTIAL.search(self._words(src, node)))
            or _own_chain(chain_text(src, node)) is not None
            or _own_chain(chain_text(src, node), ivars) is not None
            or (
                depth < 3
                and any(
                    self._credential(s, v, ivars, depth + 1) for s, v in self._values(src, node)
                )
            )
        )
        self.credentials[key] = found
        return found

    def _words(self, src: Parsed, node: Node) -> str:
        """The names an expression calls or reads, not its locals, its strings or the keys it
        filters by (`find_by(id: …, verified: true)`), except a token's (`find_by(token: …)`)."""
        out = []
        for n in walk(node):
            parent = n.parent
            token_key = n.type == "hash_key_symbol" and _TOKEN_KEY.search(src.text(n))
            if token_key or n.type in ("constant", "instance_variable"):
                out.append(src.text(n))
            elif n.type == "identifier":
                named = (
                    parent is not None
                    and parent.type == "call"
                    and (parent.child_by_field_name("method") == n)
                )
                name = src.text(n)
                bare = not named or parent.child_by_field_name("receiver") is None  # type: ignore[union-attr]
                if bare and (name in self.local_values or self.methods(name) is not None):
                    continue  # read through what it holds or returns
                out.append(name)
        return " ".join(out)

    def _ivar_kinds(self) -> dict[str, set[str]]:
        kinds: dict[str, set[str]] = {}
        for step in self.reached:
            for n in walk(step.node):
                if n.type not in ("assignment", "operator_assignment"):
                    continue
                left = n.child_by_field_name("left")
                if left is not None and left.type == "instance_variable":
                    right = n.child_by_field_name("right")
                    kind = _own_chain(chain_text(step.src, right)) or "user"
                    kinds.setdefault(step.src.text(left), set()).add(kind)
        return kinds

    def _caller_ivars(self) -> set[str]:
        """Instance variables an authentication callback sets from a credential (`@user =
        User.find_by(session_token: session[:u])`, D20): the caller too, unless set anywhere
        from the request's parameters or in the action."""
        assigned: dict[str, list[tuple[Kind, Parsed, Node | None]]] = {}
        for step in self.reached:
            for n in walk(step.node):
                if n.type in ("assignment", "operator_assignment"):
                    left = n.child_by_field_name("left")
                    if left is not None and left.type == "instance_variable":
                        assigned.setdefault(step.src.text(left), []).append(
                            (step.kind, step.src, n.child_by_field_name("right"))
                        )
        found: set[str] = set()
        for _ in range(2):  # `@resource = @token.owner` after `@token = …`
            found = {
                name
                for name, values in assigned.items()
                if name not in _CALLER_IVARS
                and all(
                    kind is not Kind.ACTION and self._credential(src, value, found | {name})
                    for kind, src, value in values
                )
            }
        return found

    def _forged(self) -> set[str]:
        """The callers the request may choose (D17): one the action assigns or a callback sets
        from anything but a credential, a `sign_in` of such a user, or the app's own
        `current_user` built from the request's parameters."""
        out: set[str] = set()
        for name in _CALLERS:
            found = self.methods(name)
            if found is not None and any(
                self._untrusted(s.src, s.node)
                for s in _reachable(
                    [_Step(found[0], b, Kind.CALLBACK) for b in method_body(found[1])],
                    self.methods,
                )
            ):
                out.add(name)
        for step in self.reached:
            for n in walk(step.node):
                if n.type in ("assignment", "operator_assignment"):
                    group = _caller_group(chain_text(step.src, n.child_by_field_name("left")))
                    if group is not None and (
                        step.kind is Kind.ACTION
                        or not self._credential(
                            step.src, n.child_by_field_name("right"), self.caller_ivars
                        )
                    ):
                        out.add(group)
                elif (
                    n.type == "call"
                    and call_name(step.src, n) == "instance_variable_set"
                    and len(args(n)) == 2
                    and _caller_group(step.src.text(args(n)[0]).lstrip(":"))
                ):
                    if step.kind is Kind.ACTION or not self._credential(
                        step.src, args(n)[1], self.caller_ivars
                    ):
                        out.add(_caller_group(step.src.text(args(n)[0]).lstrip(":")))  # type: ignore[arg-type]
                elif n.type == "call" and _signs_in(step.src, n):
                    if step.kind is Kind.ACTION or not all(
                        self._credential(step.src, a, self.caller_ivars) for a in args(n)
                    ):
                        out.add("current_user")
        return out

    def is_caller(self, src: Parsed, node: Node | None) -> bool:
        node = unwrap(node)
        if node is None or not self.guarded:
            return False
        text = chain_text(src, node)
        group = _caller_group(text)
        return group not in self.forged if group is not None else text in self.caller_ivars

    def derived(self, src: Parsed, node: Node | None) -> bool:
        return self.caller_kind(src, node) is not None

    def caller_kind(self, src: Parsed, node: Node | None) -> str | None:
        """What a value built from the caller alone stands for: the user (`current_user`,
        `current_user.id`) or its tenant (`current_user.account_id`: "account"); None for
        anything else, such as another user it names (`current_user.manager`)."""
        node = unwrap(node)
        tenant: str | None = None
        for _ in range(_MAX_DEPTH):
            if node is None:
                return None
            if self.is_caller(src, node):
                group = _caller_group(chain_text(src, node))
                kind = (
                    self.ivar_kind.get(chain_text(src, node), "user")
                    if group is None
                    else "user"
                    if group in ("current_user", "current_admin")
                    else group[8:]
                )
                return tenant or kind
            name = call_name(src, node)
            if node.type != "call" or args(node) or src.text(node).endswith(f"&.{name}"):
                return None
            if _TENANT.match(name):
                if tenant is not None:
                    return None
                tenant = _owner_kind(name)
            elif name != "id" and name not in _CONVERSIONS:
                return None
            node = unwrap(node.child_by_field_name("receiver"))
        return None

    # -- the id
    def path_id(self, src: Parsed, node: Node | None) -> str | None:
        node = unwrap(node)
        if node is None:
            return None
        if node.type == "element_reference":
            obj = node.child_by_field_name("object")
            keys = [c for c in node.named_children if c != obj]
            permitted = obj is not None and re.fullmatch(
                r"params(\.(require|permit|expect)\([^()]*\))+", src.text(obj)
            )
            if obj is not None and (src.text(obj) in _PARAMS or permitted) and len(keys) == 1:
                key = symbol(src, keys[0])
                return key if key in self.path_ids else None
        if node.type == "call" and call_name(src, node) in ("fetch", "require", "expect", "dig"):
            receiver = node.child_by_field_name("receiver")
            a = args(node)
            if receiver is not None and src.text(receiver) in _PARAMS and len(a) >= 1:
                key = symbol(src, a[0])
                return key if key in self.path_ids else None
        return None

    def exact(self, src: Parsed, node: Node | None) -> str | None:
        node = unwrap(node)
        for _ in range(_MAX_DEPTH):
            if node is None:
                return None
            if node.type == "identifier" and src.text(node) in self.roots:
                return self.roots[src.text(node)]
            if (pid := self.path_id(src, node)) is not None:
                return pid
            if node.type == "call" and call_name(src, node) in _CONVERSIONS and not args(node):
                node = unwrap(node.child_by_field_name("receiver"))
                continue
            if node.type == "call" and call_name(src, node) == "Integer" and len(args(node)) == 1:
                node = unwrap(args(node)[0])
                continue
            return None
        return None

    def mentions(self, src: Parsed, node: Node | None) -> bool:
        return node is not None and any(
            self.path_id(src, n) is not None
            or (n.type == "identifier" and src.text(n) in self.roots)
            for n in walk(node)
        )

    def keys(self, src: Parsed, values: list[Node], model: str, field_: str) -> set[_Key] | None:
        roots = [self.exact(src, v) for v in values if self.mentions(src, v)]
        return None if not roots or None in roots else {(r, model, field_) for r in roots if r}

    # -- recording
    def span(self, src: Parsed, node: Node) -> CodeSpan:
        return CodeSpan(path=RepoPath(src.file.rel), line=src.line(node))

    def add(
        self, src: Parsed, node: Node, lookup: Lookup, cover: set[_Key] | None, read: bool
    ) -> int:
        self.position += 1
        if self.kind is Kind.AFTER:
            self.after.add(len(self.lookups))
        if self.kind is Kind.ENSURE:
            self.ensured.add(len(self.lookups))
        self.lookups.append(lookup)
        self.nodes.append(node)
        self.terminals.append(call_name(src, node))
        self.cover.append(cover)
        self.starts.append(self.position)
        self.reads.append(read)
        return len(self.lookups) - 1

    def handoff(self, src: Parsed, node: Node, cover: set[_Key] | None = None) -> None:
        self.position += 1
        self.handoffs.append((self.span(src, node), cover, self.position))

    def verify(self, keys: set[_Key] | None) -> None:
        self.position += 1
        if self.kind in (Kind.CONDITIONAL, Kind.AFTER, Kind.ENSURE):
            return  # a check that may not run, or runs after the response, protects nothing
        for k in keys or set():
            if k[0] not in self.unstable:
                self.verified.setdefault(k, self.position)
                self.verified_kind.setdefault(k, self.kind)

    # -- queries
    def query(self, src: Parsed, call: Node) -> tuple[int | None, bool]:
        """The lookup a query chain is (`Note.where(…).find(id)`, `current_user.notes.find(id)`,
        `policy_scope(Note).find(id)`); (None, False) when it isn't one by a path id."""
        chain: list[Node] = []
        node: Node | None = call
        while node is not None and node.type == "call":
            chain.append(node)
            node = unwrap(node.child_by_field_name("receiver"))
        chain.reverse()
        root = node
        model: str | None = None
        scoped = False
        start = 0
        caller = next((i + 1 for i, c in enumerate(chain) if self.is_caller(src, c)), None)
        if self.is_caller(src, root) or caller is not None:
            # `current_user.notes.find(id)`, `Current.user.notes.find(id)`: a caller
            # association (D18)
            start = 0 if self.is_caller(src, root) else caller  # type: ignore[assignment]
            if start >= len(chain):
                return None, False
            assoc = call_name(src, chain[start])
            holder = chain[start - 1] if start else root
            kind = self.caller_kind(src, holder) or "user"
            model = self.code.association("".join(w.capitalize() for w in kind.split("_")), assoc)
            if model is None:
                return None, False
            scoped, start = True, start + 1
        elif root is not None and root.type in ("constant", "scope_resolution"):
            model = src.text(root).rsplit("::", 1)[-1]
            found = self.code.models.get(model)
            written = src.text(root).removeprefix("::")
            if (
                found is None
                or len(found.qualified) > 1
                or ("::" in written and written not in found.qualified)
            ):
                return None, False  # `Archive::Note` beside `Note`: not the model we read
        elif root is None and chain and call_name(src, chain[0]) == "policy_scope":
            a = args(chain[0])
            model = src.text(a[0]).rsplit("::", 1)[-1] if a else None
            if model not in self.code.models:
                return None, False
            options = dict(pairs(src, [x for x in a if x.type == "pair"]) or [])
            scope = (
                src.text(options["policy_scope_class"]) if "policy_scope_class" in options else None
            )
            scoped = self.policy_scoped(model, scope)  # D15
            if not scoped and self.code.policy_scope(model, scope) is None:
                self.handoff(src, chain[0])
            start = 1
        elif (
            root is not None
            and root.type in ("identifier", "instance_variable")
            and (record := self.records.get(src.text(root))) is not None
            and chain
        ):
            # `@project.tasks.find(id)`: through a record the caller owns
            model = self.code.association(record.model, call_name(src, chain[0]))
            if model is None:
                return None, False
            parent = self.lookups[record.lookup]
            scoped, start = parent.scoped or parent.checked, 1
        elif chain and (
            model := self.code.held(
                call_name(src, chain[0] if root is not None else chain[min(1, len(chain) - 1)])
            )
        ):
            # `x.notes.find(id)` on a receiver that isn't the caller (an untrusted `current_user`,
            # a user loaded from params): a lookup, scoped by nothing
            start = 1 if root is not None else 2
        else:
            return None, False
        if not chain[start:] or not any(self.mentions(src, c) for c in chain[start:]):
            if any(
                _finder(call_name(src, c)) and any(self._untrusted(src, a) for a in args(c))
                for c in chain[start:]
            ):
                # a record the request names some other way (`Note.find(note_params[:id])`):
                # handed on, so nothing else in the action vouches for it
                self.handoff(src, call)
                return None, True
            return None, False
        cover: set[_Key] = set()
        plain = True
        terminal = call_name(src, chain[-1])
        for c in chain[start:]:
            name = call_name(src, c)
            a = args(c)
            if name in _NEUTRAL:
                continue
            if (
                name in ("find", "find!", "exists?")
                and len(a) == 1
                and a[0].type not in ("pair", "hash")
            ):
                keys = self.keys(src, a, model, "pk")
                if keys is None:
                    return self.record_lookup(src, call, model, False, None, terminal), True
                cover |= keys
            elif name in (
                "where",
                "find_by",
                "find_by!",
                "find_sole_by",
                "destroy_by",
                "delete_by",
                "rewhere",
                "exists?",
            ):
                found = pairs(src, a) if name != "rewhere" else None
                if found is None:
                    plain = False
                    continue
                for k, v in found:
                    if self.mentions(src, v):
                        keys = self.keys(src, [v], model, "pk" if k == "id" else k)
                        if keys is None:
                            plain = False
                        else:
                            cover |= keys
                    elif (
                        OWNER_CHECK_RX.match(k)
                        and self.caller_kind(src, v) == _owner_kind(k)
                        and plain
                        and not self.polymorphic_id(model, k)
                    ):
                        scoped = True  # shape 1: `where(user: current_user)`
            elif name in _READS or name in _WRITES or name in ("first", "last", "take"):
                continue
            else:
                plain = False  # `or`, `not`, `merge`, `unscope`, a scope we can't read
                if not self.code.narrows(model, name):
                    scoped = False  # `current_user.notes.including_archived`: may widen
        if any(call_name(src, c) in _WIDENING for c in chain):
            # widened past the caller's records, and past the ids it was read by
            return self.record_lookup(src, call, model, False, None, terminal), True
        return self.record_lookup(src, call, model, scoped, cover or None, terminal), True

    def polymorphic_id(self, model: str | None, field_: str) -> bool:
        """`owner_id` of a polymorphic `owner`: an id alone matches another type's row too."""
        found = self.code.models.get(model or "")
        return found is not None and field_.endswith("_id") and field_[:-3] in found.polymorphic

    def record_lookup(
        self,
        src: Parsed,
        call: Node,
        model: str,
        scoped: bool,
        cover: set[_Key] | None,
        terminal: str,
    ) -> int:
        k = self.add(
            src,
            call,
            Lookup(self.span(src, call), scoped, record_type=model),
            cover,
            terminal in _READS or terminal in _NIL_READS,
        )
        if terminal in _RAISING:
            self.raising.add(k)
        return k

    def policy_scoped(self, model: str, scope: str | None = None) -> bool:
        """`NotePolicy::Scope#resolve` narrows by the user on every return (D15); an early
        `return scope.all if user.admin?` is the admin's (D10)."""
        found = self.code.policy_scope(model, scope)
        if found is None:
            return False
        src, method = found
        body = method_body(method)
        if not body:
            return False
        for s in body[:-1]:
            if not any(n.type == "return" for n in walk(s)):
                continue
            ret = unwrap(s.child_by_field_name("body"))
            if (
                s.type not in ("if_modifier", "unless_modifier")
                or ret is None
                or ret.type != "return"
            ):
                return False
            admin = s.type == "if_modifier" and _privileged_test(
                src, s.child_by_field_name("condition"), "user"
            )
            if not admin and not (args(ret) and _narrows(self.code, src, args(ret)[0], model)):
                return False
        last = body[-1]
        if last.type == "return" and args(last):
            last = args(last)[0]
        return _narrows(self.code, src, last, model)

    # -- the walk
    def run(self) -> HandlerFacts:
        if self.cancan[0] and self.model is not None and self.path_ids:
            self.cancan_load()
        for index, step in enumerate(self.steps):
            self.position = index * 1000
            self.statement(step)
        verified = {k: at for k, at in self.verified.items() if k[0] not in self.unstable}

        def held(
            keys: set[_Key] | None,
            at: int,
            after: bool = False,
            one: bool = True,
            ensured: bool = False,
        ) -> bool:
            # an `after_action` runs even when the action refused: only a callback's check holds;
            # a key other than the primary one pins only the record read by it
            if any(f != "pk" for _, _, f in keys or ()):
                return False  # `slug` is unique per user at most: it pins no one record
            if ensured:
                return False
            return bool(keys) and all(
                any(
                    v[0] == r
                    and v[1] == s
                    and f in (v[2], "*")
                    and pos < at
                    and not (after and self.verified_kind.get(v) is Kind.ACTION)
                    for v, pos in verified.items()
                )
                for r, s, f in keys  # type: ignore[union-attr]
            )

        seen = {
            r
            for keys in [*self.cover, *(k for _, k, _ in self.handoffs)]
            for r in (["*"] if keys is None else [r for r, _, _ in keys])
        }
        unheld = [span for span, keys, at in self.handoffs if not held(keys, at)]
        if self.path_ids and "*" not in seen and not self.path_ids <= seen:
            span = self.span(self.steps[-1].src, self.steps[-1].node) if self.steps else None
            return HandlerFacts(handoff=span, takes_id=True)
        return HandlerFacts(
            lookups=tuple(
                Lookup(
                    x.span,
                    x.scoped,
                    x.checked
                    or (
                        not x.scoped
                        and held(
                            self.cover[k],
                            self.starts[k],
                            k in self.after,
                            self.terminals[k] in _ONE,
                            k in self.ensured,
                        )
                    ),
                    x.record_type,
                )
                for k, x in enumerate(self.lookups)
                if k not in self.deferred
            ),
            caller=self.caller_span,
            hop=self.hop,
            handoff=unheld[0] if unheld else None,
            takes_id=bool(self.path_ids),
        )

    def cancan_load(self) -> None:
        """`load_and_authorize_resource`: `@note = Note.find(params[:id])`, then
        `authorize!(action, @note)` against `Ability` (D15)."""
        if "id" not in self.path_ids:
            return
        step = self.steps[0] if self.steps else None
        if step is None:
            return
        lookup = Lookup(self.span(step.src, step.node), record_type=self.model)
        k = self.add(step.src, step.node, lookup, {("id", self.model, "pk")}, True)  # type: ignore[arg-type]
        self.records[f"@{_snake(self.model)}"] = _Record(k, self.model)  # type: ignore[arg-type]
        if not self.cancan[1]:
            return  # loaded, never authorized (`skip_authorize_resource`)
        verdict = (
            False  # `Ability.new(current_user)` with a user the request names
            if "current_user" in self.forged
            else _ability(self.code, self.action, self.model)  # type: ignore[arg-type]
            if self.model in self.code.models and self.methods("current_ability") is None
            else None  # a model we can't name, or an ability the controller picks
        )
        if verdict and not self.raise_refuses:
            verdict = False  # `rescue_from CanCan::AccessDenied` answers with the record
        if verdict is None:
            self.deferred.add(k)
            self.handoff(step.src, step.node)
        elif verdict:
            self.checked(k)

    def checked(self, k: int) -> None:
        x = self.lookups[k]
        self.lookups[k] = Lookup(x.span, x.scoped, True, x.record_type)
        self.checked_in.setdefault(k, self.kind)
        self.verify(self.cover[k])

    def inline(self, src: Parsed, node: Node, depth: int) -> None:
        """Argument-free private helpers a statement uses (`note.destroy` with `def note;
        @note ||= Note.find(params[:id]); end`): their statements run first, once, and the
        helper's name stands for the record it returns."""
        for n in walk(node):
            name = _helper_name(src, n)
            if not name or name in self.inlined or name in self.locals or name in self.records:
                continue
            found = self.methods(name)
            if found is None or depth > _MAX_HELPERS:
                continue
            if name.endswith("?") and not self.mentions(*found):
                continue  # a predicate (`owner?`): read where it's tested
            self.inlined.add(name)
            hsrc, method = found
            if self.hop is None:
                self.hop = self.span(src, n)
            body = method_body(method)
            kind = Kind.CONDITIONAL if _conditional_at(src, n, node) else self.kind
            if swallows(hsrc, method):
                kind = Kind.CONDITIONAL
            for s in body:
                self.statement(_Step(hsrc, s, kind), depth + 1)
            last = unwrap(body[-1]) if body else None
            if last is not None and last.type in ("assignment", "operator_assignment"):
                target = hsrc.text(last.child_by_field_name("left"))
                if target in self.records:
                    self.records[name] = self.records[target]
            elif last is not None and last.type == "call":
                k, handled = self.query(hsrc, last)
                if handled and k is not None:
                    self.records[name] = _Record(k, self.lookups[k].record_type)
                    if k in self.raising:
                        self.raised(k)

    def statement(self, step: _Step, depth: int = 0) -> None:
        src, node = step.src, step.node
        self.kind = step.kind
        self.inline(src, node, depth)
        self.kind = step.kind
        conditional = step.kind is Kind.CONDITIONAL
        self.rebinds(src, node)
        if self.caller_span is None:
            caller = next((n for n in walk(node) if self.is_caller(src, n)), None)
            if caller is not None:
                self.caller_span = self.span(src, caller)
        # bindings: `note = Note.find(…)`, `id = params[:id]`
        if node.type in ("assignment", "operator_assignment"):
            left = node.child_by_field_name("left")
            right = unwrap(node.child_by_field_name("right"))
            name = src.text(left) if left is not None else ""
            k = self.calls(src, right) if right is not None else None
            if left is not None and left.type in ("identifier", "instance_variable"):
                if name in self.roots:
                    self.unstable.add(self.roots[name])
                if k is not None:
                    self.records[name] = _Record(k, self.lookups[k].record_type)
                    if k in self.raising:
                        self.raised(k)
                elif (alias := self.records.get(chain_text(src, right))) is not None:
                    self.records[name] = alias  # `note = @note`
                elif self.foreign(src, right):
                    self.records.pop(name, None)  # `source = @note.original`
                elif name in self.records and node.type == "assignment":
                    del self.records[name]  # `note = note.original`: another record
                    self.handoff(src, node)
                elif right is not None and (pid := self.exact(src, right)) is not None:
                    self.roots[name] = pid
                elif right is not None and self.mentions(src, right):
                    self.handoff(src, node)  # the id under a name we don't read
            if k is None and right is not None:
                self.use(src, right)
            return
        # refusals; in a helper the action calls, a `return` leaves only the helper
        helper = depth > 0 and step.kind is Kind.ACTION
        refusal = (
            None
            if conditional or step.kind in (Kind.AFTER, Kind.ENSURE)
            else self.refusal(src, node, step.callback, helper)
        )
        if refusal is not None:
            start = len(self.lookups)
            for csrc, condition, _ in refusal:
                if condition is not None:
                    self.inline(csrc, condition, depth)  # `owner?`'s own helpers (`note`)
                    self.kind = step.kind
                self.calls(csrc, condition)
            # a raise stops the `after_action`s too; a response doesn't
            self.kind = Kind.CALLBACK if self.raises else step.kind
            self.exists(refusal, start)
            for name, record in list(self.records.items()):
                self.refuses(record, name, refusal)
            self.kind = step.kind
            return
        if (
            not conditional
            and node.type == "call"
            and call_name(src, node) in ("authorize", "authorize!")
            and node.child_by_field_name("receiver") is None
            and self.library(call_name(src, node))  # an app's own `authorize` is a helper
            and args(node)
        ):
            self.authorize(src, node)
            return
        self.foreign(src, node)
        self.use(src, node)
        k = self.calls(src, node)
        if k is not None and k in self.raising:
            self.raised(k)

    def foreign(self, src: Parsed, node: Node | None, bound: bool = False) -> bool:
        """Another record a loaded one names (`@note.original`, not its owner), bound to a name
        or written: handed on, since it may be anyone's."""
        found = False
        for n in walk(node) if node is not None else []:
            if n.type != "call" or args(n):
                continue
            record = self.records.get(chain_text(src, n.child_by_field_name("receiver")))
            model = self.code.models.get(record.model or "") if record is not None else None
            name = call_name(src, n).removesuffix("_id")
            if model is None or name not in model.belongs or OWNER_CHECK_RX.match(name):
                continue
            self.handoff(src, n)  # sent, written, bound or looked up by: may be anyone's
            found = True
        return found

    def rebinds(self, src: Parsed, node: Node) -> None:
        """What a statement rebinds below its top (`@note = Note.find(other) if x`) or the
        path id itself (`params[:id] = …`, `params.merge!(…)`): no longer what was checked."""
        for n in walk(node):
            if (
                n.type == "call"
                and call_name(src, n) in _PARAMS_MUTATORS
                and src.text(n.child_by_field_name("receiver")) == "params"
            ):
                self.unstable |= self.path_ids
            if n.type not in ("assignment", "operator_assignment"):
                continue
            left = n.child_by_field_name("left")
            if left is None:
                continue
            if left.type == "element_reference" and (pid := self.path_id(src, left)) is not None:
                self.unstable.add(pid)
            elif n != node and left.type in ("identifier", "instance_variable"):
                name = src.text(left)
                if name in self.roots:
                    self.unstable.add(self.roots[name])
                if name in self.records:
                    del self.records[name]
                    self.handoff(src, n)

    def raised(self, k: int) -> None:
        """A raising read refused when missing: its id is verified if it was scoped."""
        if self.lookups[k].scoped:
            self.verify(self.cover[k])

    def calls(self, src: Parsed, node: Node | None) -> int | None:
        """Lookups, hops and hand-offs in an expression; the lookup it is, if it is one."""
        if node is None:
            return None
        made: int | None = None
        outer = [n for n in walk(node) if n.type == "call" and not _is_receiver(n)]
        for c in outer:
            k, handled = self.query(src, c)
            if handled:
                if c == unwrap(node):
                    made = k
                continue
            if self.mentions(src, c) and self.exact(src, c) is None:
                self.other_call(src, c)
        if made is None and unwrap(node) is not None and unwrap(node).type == "call":
            return None
        return made

    def other_call(self, src: Parsed, call: Node) -> None:
        name = call_name(src, call)
        receiver = call.child_by_field_name("receiver")
        root = chain_text(src, receiver).split(".", 1)[0] if receiver is not None else ""
        if root in _INERT or name in (
            "render",
            "redirect_to",
            "head",
            "respond_to",
            "send_data",
            "send_file",
        ):
            for a in args(call):
                if self.mentions(src, a):
                    pass
            return
        if receiver is None and self.methods(name) is not None:
            self.hop = self.hop or self.span(src, call)
            self.handoff(
                src,
                call,
                self.keys(src, [a for a in args(call) if self.mentions(src, a)], "*", "*"),
            )
            return  # a helper handed the id: not followed
        self.handoff(
            src, call, self.keys(src, [a for a in args(call) if self.mentions(src, a)], "*", "*")
        )

    def refusal(
        self, src: Parsed, node: Node, callback: bool = False, helper: bool = False
    ) -> list[_Cond] | None:
        """A statement refusing the request (D16) and the conditions under which it does, all
        of them: `head :forbidden and return if c`, `raise X unless c`, `if c; render …,
        status: :not_found; return; end`, `if admin?; elsif c; head :forbidden; end`."""
        if node.type in ("if_modifier", "unless_modifier"):
            body = node.child_by_field_name("body")
            if body is not None and self.refuses_request(src, body, callback, helper):
                condition = node.child_by_field_name("condition")
                return [self.predicate(src, condition, node.type == "unless_modifier")]
            return None
        if node.type not in ("if", "unless"):
            return None
        body = node.child_by_field_name("consequence")
        other = node.child_by_field_name("alternative")
        condition = node.child_by_field_name("condition")
        if other is None:
            if body is not None and self.refuses_request(src, body, callback, helper):
                return [self.predicate(src, condition, node.type == "unless")]
            return None
        if (
            node.type == "if"
            and other.type == "elsif"
            and other.child_by_field_name("alternative") is None
            and all(_inert(src, s) for s in statements(body))
        ):
            inner = other.child_by_field_name("consequence")
            if inner is not None and self.refuses_request(src, inner, callback, helper):
                elsif = other.child_by_field_name("condition")
                return [(src, condition, True), self.predicate(src, elsif, False)]
        return None

    def predicate(self, src: Parsed, condition: Node | None, negated: bool) -> _Cond:
        """A condition, read through an argument-free predicate helper (`unless owner?`)."""
        node = unwrap(condition)
        flip = False
        if (
            node is not None
            and node.type == "unary"
            and src.text(node.child_by_field_name("operator")) in ("!", "not")
        ):
            node, flip = unwrap(node.child_by_field_name("operand")), True
        name = _helper_name(src, node) if node is not None else ""
        if name.endswith("?") and (found := self.methods(name)) is not None:
            body = method_body(found[1])
            if len(body) == 1 and body[0].type not in ("assignment", "operator_assignment"):
                return found[0], body[0], negated != flip
        return src, condition, negated

    def refuses_request(
        self, src: Parsed, body: Node, callback: bool = False, helper: bool = False
    ) -> bool:
        """D16; in a `before_action`, any response halts the action, so a `redirect_to` or a
        `render` refuses too (D19), unless it sends a value. In a helper the action calls,
        only a `raise` stops the action."""
        stmts = statements(body) if body.type == "then" else [body]
        if not stmts:
            return False
        self.raises = len(stmts) == 1 and _raises(src, stmts[0])
        if self.raises and not self.raise_refuses:
            return False  # a `rescue_from` handler uses the record
        if helper:
            return self.raises
        if (
            callback
            and any(_halts(src, s) for s in stmts)
            and all(_halts(src, s) or _raises(src, s) or _inert(src, s) for s in stmts)
            and not any(
                _render_leaks(src, n, self.literals, self.action)
                if call_name(src, n) == "render"
                else _redirect_leaks(src, n, self.literals)
                for s in stmts
                for n in walk(s)
                if n.type == "call"
                and call_name(src, n) in ("render", "redirect_to", "redirect_back")
            )
        ):
            return True
        last = stmts[-1]
        if len(stmts) == 1 and _raises(src, last):
            return self.raise_refuses
        if len(stmts) == 1 and last.type == "return":
            a = args(last)
            return len(a) == 1 and _responds(src, a[0], self.literals, self.action)
        if (
            len(stmts) == 1
            and last.type == "binary"
            and src.text(last.child_by_field_name("operator")) in ("and", "&&")
        ):
            return (
                _responds(src, last.child_by_field_name("left"), self.literals, self.action)
                and unwrap(last.child_by_field_name("right")).type == "return"
            )
        if len(stmts) == 2 and last.type == "return" and not args(last):
            return _responds(src, stmts[0], self.literals, self.action)
        return False

    def exists(self, conds: list[_Cond], start: int) -> None:
        """`head :forbidden unless Note.exists?(id: params[:id], user: current_user)`: a
        scoped existence test, refused when false, verifies the id."""
        for k in range(start, len(self.lookups)):
            if not self.lookups[k].scoped or self.terminals[k] != "exists?":
                continue
            tested = self.nodes[k]

            def atom(s: Parsed, tested: Node = tested) -> Callable[[Node], _Atom | None]:
                return lambda n: "exists" if n == tested else self.atom(s, n, "\0", None)

            if holds_all(conds, atom, {"exists": False}):
                self.verify(self.cover[k])

    def use(self, src: Parsed, node: Node) -> None:
        """Records a statement acts on or sends: a later check no longer protects them; in an
        `after_action`, nor does a check the action made."""
        names = {src.text(n) for n in walk(node) if n.type in ("identifier", "instance_variable")}
        for name, record in self.records.items():
            if name in names:
                record.used = True
                after = (
                    self.kind is Kind.AFTER and self.checked_in.get(record.lookup) is Kind.ACTION
                )
                if after or self.kind is Kind.ENSURE:
                    x = self.lookups[record.lookup]
                    self.lookups[record.lookup] = Lookup(x.span, x.scoped, False, x.record_type)

    def refuses(self, record: _Record, name: str, conds: list[_Cond]) -> None:
        """Shape 2 / shape 1's refusal of a missing record, on a statement refusing when all
        its conditions hold."""
        if record.used:
            return
        if any(_writes(s, c) for s, c, _ in conds):
            record.used = True  # `unless note.update(user: me) && note.user == me`
            return
        lookup = self.lookups[record.lookup]

        def atom(s: Parsed) -> Callable[[Node], _Atom | None]:
            return lambda node: self.atom(s, node, name, record.model)

        # refused whenever missing: a nil read becomes a raising one
        if holds_all(conds, atom, {"present": False}):
            if lookup.scoped:
                self.verify(self.cover[record.lookup])
            missing_refused = True
        else:
            missing_refused = record.lookup in self.raising
        # refused whenever foreign (and the caller isn't an admin, D10)
        if (
            missing_refused
            and holds_all(conds, atom, {"present": True, "own": False, "admin": False})
            and "own" in {a for s, c, _ in conds for a in _atoms(s, c, atom(s))}
        ):
            self.checked(record.lookup)

    def atom(self, src: Parsed, node: Node, record: str, model: str | None) -> _Atom | None:
        """`note.user == current_user` (own), `note.nil?` (!present), `current_user.admin?`
        (admin); another expression is a free atom (its text), unless it's unreadable."""
        node = unwrap(node)
        if node is None:
            return None
        text = chain_text(src, node)
        if text == record:
            return "present"
        if (
            node.type == "call"
            and call_name(src, node) in ("nil?", "blank?")
            and chain_text(src, node.child_by_field_name("receiver")) == record
        ):
            return "!present"
        if (
            node.type == "call"
            and call_name(src, node) == "present?"
            and chain_text(src, node.child_by_field_name("receiver")) == record
        ):
            return "present"
        if node.type == "binary" and src.text(node.child_by_field_name("operator")) in ("==", "!="):
            op = src.text(node.child_by_field_name("operator"))
            sides = [unwrap(node.child_by_field_name(x)) for x in ("left", "right")]
            for a, b in (sides, sides[::-1]):
                owner = self.owner_of(src, a, record, model)
                if owner is not None and self.polymorphic_id(model, owner):
                    owner = None  # `note.owner_id == current_user.id` on a polymorphic owner
                if (
                    owner is not None
                    and self.caller_kind(src, b) == _owner_kind(owner)
                    and _same_kind(src, a, b)
                ):
                    return "own" if op == "==" else "!own"
        if (
            node.type == "call"
            and not args(node)
            and _PRIVILEGE.match(call_name(src, node))
            and self.caller_kind(src, node.child_by_field_name("receiver")) == "user"
        ):
            return "admin"
        if node.type in ("call", "identifier", "binary", "instance_variable", "constant"):
            if any(n.type in ("assignment", "operator_assignment") for n in walk(node)):
                return None
            return f"?{src.text(node)}"
        return None

    def owner_of(
        self, src: Parsed, node: Node | None, record: str, model: str | None
    ) -> str | None:
        """`note.user`, `note.user_id`, `note.user.id`: the record's owner field."""
        node = unwrap(node)
        for _ in range(2):
            if node is None or node.type != "call" or args(node):
                return None
            name = call_name(src, node)
            receiver = unwrap(node.child_by_field_name("receiver"))
            if chain_text(src, receiver) == record:
                return name if OWNER_CHECK_RX.match(name) else None
            if name != "id":
                return None
            node = receiver
        return None

    def library(self, name: str) -> bool:
        """Whether `authorize`/`authorize!` is the library's: the app doesn't define it, or
        only wraps it (`def authorize(*) = super`)."""
        found = self.methods(name)
        if found is None:
            return True
        body = method_body(found[1])
        return len(body) == 1 and body[0].type in ("super", "zsuper") and not args(body[0])

    def pundit_user_forged(self) -> bool:
        found = self.methods("pundit_user")
        return found is not None and any(
            self._untrusted(s.src, s.node)
            for s in _reachable(
                [_Step(found[0], b, Kind.CALLBACK) for b in method_body(found[1])], self.methods
            )
        )

    def authorize(self, src: Parsed, call: Node) -> None:
        """`authorize note` (Pundit, D15): checked when the policy's query method refuses a
        foreign record; unknown when it can't be read."""
        a = [x for x in args(call) if x.type != "pair"]
        options = dict(pairs(src, [x for x in args(call) if x.type == "pair"]) or [])
        cancan = call_name(src, call) == "authorize!"
        first = a[1] if cancan and len(a) > 1 else a[0] if a else None
        namespaced = first is not None and first.type == "array"
        if namespaced:
            first = first.named_children[-1] if first.named_children else None  # type: ignore[union-attr]
        record = self.records.get(chain_text(src, first))
        if record is None:
            if self.mentions(src, call):
                self.handoff(src, call)
            return
        if record.used:
            return
        query = symbol(src, a[1]) if len(a) > 1 else f"{self.action}?"
        policy = src.text(options["policy_class"]) if "policy_class" in options else None
        if "current_user" in self.forged and not (
            not cancan and self.methods("pundit_user") is not None
        ):
            verdict: bool | None = False  # asked about a user the request names
        elif not cancan and (self.methods("policy") or self.methods("policy_scope")):
            verdict = None  # the controller picks the policy itself
        elif cancan:
            action = symbol(src, a[0]) or ""
            verdict = (
                _ability(self.code, action, record.model)
                if record.model and self.methods("current_ability") is None
                else None
            )
        elif namespaced:
            verdict = None  # `authorize [:admin, note]`: `Admin::NotePolicy`, not read
        elif self.pundit_user_forged():
            verdict = False  # Pundit asks about a user the request names
        else:
            # a row of an STI subclass is asked of its own policy (`Draft < Note`)
            verdicts = (
                [
                    _policy_refuses(self.code, m, query or "", policy)
                    for m in self.code.descendants(record.model)
                ]
                if record.model
                else [None]
            )
            verdict = (
                None if None in verdicts else all(verdicts)  # type: ignore[arg-type]
            )
        if verdict and not self.raise_refuses:
            verdict = False  # `rescue_from Pundit::NotAuthorizedError` answers with the record
        if verdict is None:
            self.deferred.add(record.lookup)
            self.handoff(src, call)
        elif verdict:
            self.checked(record.lookup)


_PARAMS_MUTATORS = {
    "merge!",
    "delete",
    "store",
    "update",
    "reverse_merge!",
    "deep_merge!",
    "replace",
}
_LITERAL = {
    "hash",
    "pair",
    "hash_key_symbol",
    "simple_symbol",
    "string",
    "string_content",
    "escape_sequence",
    "integer",
    "float",
    "true",
    "false",
    "nil",
    "array",
    "symbol_array",
    "string_array",
    "bare_symbol",
    "bare_string",
}


def _helper_name(src: Parsed, node: Node) -> str:
    """The method a bare name or an argument-free call without a receiver may be."""
    parent = node.parent
    if node.type == "identifier":
        # `x.destroy`'s `destroy` is the call's name, not a reference
        named = (
            parent is not None
            and parent.type == "call"
            and (parent.child_by_field_name("method") == node)
        )
        return "" if named else src.text(node)
    if node.type == "call" and node.child_by_field_name("receiver") is None and not args(node):
        return call_name(src, node)
    return ""


def _reachable(
    steps: list[_Step], methods: Callable[[str], tuple[Parsed, Node] | None], limit: int = 2000
) -> list[_Step]:
    """The steps and the bodies of the helpers they call, transitively; a caller's own
    definition (`def current_user`) is an authentication step."""
    out: list[_Step] = []
    seen: set[str] = set()
    queue = list(steps)
    while queue and len(out) < limit:
        step = queue.pop(0)
        out.append(step)
        for n in walk(step.node):
            name = _helper_name(step.src, n)
            if not name or name in seen:
                continue
            seen.add(name)
            found = methods(name)
            if found is not None:
                kind = Kind.CALLBACK if name in _CALLERS else step.kind
                queue += [_Step(found[0], s, kind) for s in method_body(found[1])]
    return out


def _policy_user_kind(text: str) -> str | None:
    """In a policy or ability: `user`/`user.id` stands for the user, `user.account_id` for its
    tenant."""
    head, _, rest = text.removeprefix("@").partition(".")
    if head != "user":
        return None
    parts = [p for p in rest.split(".") if p and p != "id"]
    if not parts:
        return "user"
    return _owner_kind(parts[0]) if len(parts) == 1 and _TENANT.match(parts[0]) else None


def _owner_kind(field_: str) -> str:
    """What an owner field holds: a tenant (`account_id`: "account") or a user."""
    base = re.sub(r"(?i)_?(id|uuid|key)$", "", field_) or field_
    return base.lower() if _TENANT.match(base) or base.lower() == "member" else "user"


def _own_chain(text: str, ivars: set[str] | None = None) -> str | None:
    """What `current_user`, `current_user.id` or `current_user&.account` stands for: the user
    or its own tenant ("account"); None for anything else, such as another user it names."""
    head, _, rest = text.removeprefix("self.").partition(".")
    if head == "Current" and rest:
        head, _, rest = f"Current.{rest}".partition(".")
        head, rest = f"{head}.{rest.split('.', 1)[0]}", rest.partition(".")[2]
    group = _caller_group(head)
    if group is None and head in (ivars or ()):
        group = "current_user"  # an ivar the authenticating callback set
    if group is None:
        return None
    kind = "user" if group in ("current_user", "current_admin") else group[8:]
    for part in (p for p in rest.split(".") if p):
        if _TENANT.match(part) and kind == "user":
            kind = _owner_kind(part)
        elif part != "id" and part not in _CONVERSIONS:
            return None
    return kind


def _conditional_at(src: Parsed, node: Node, stop: Node) -> bool:
    """Whether a node, inside `stop`, runs only on some paths (`check! if x`, `x || check!`)."""
    child, parent = node, node.parent
    while parent is not None and child != stop:
        if parent.type in (
            "if",
            "unless",
            "if_modifier",
            "unless_modifier",
            "while_modifier",
            "until_modifier",
            "conditional",
            "case",
            "when",
            "elsif",
            "else",
            "rescue_modifier",
            "rescue",
            "ensure",
            "case_match",
            "in_clause",
            "while",
            "until",
            "for",
        ) and child != parent.child_by_field_name("condition"):
            return True
        if parent.type == "binary" and (
            src.text(parent.child_by_field_name("operator")) in ("&&", "||", "and", "or")
            and child == parent.child_by_field_name("right")
        ):
            return True
        if parent.type in ("block", "do_block") and child != parent:
            return True  # a block may run any number of times, or never
        child, parent = parent, parent.parent
    return False


def _caller_group(text: str) -> str | None:
    """`current_user` for `current_user`, `@current_user` and `Current.user`."""
    name = text.removeprefix("@").removeprefix("self.")
    if name.startswith("Current."):
        name = "current_" + name.removeprefix("Current.")
    return name if name in _CALLERS else None


def _signs_in(src: Parsed, node: Node) -> bool:
    name = call_name(src, node)
    receiver = node.child_by_field_name("receiver")
    if name == "set_user":
        return receiver is not None and src.text(receiver) == "warden"
    return name in _SIGN_IN and receiver is None


def _is_literal(node: Node | None) -> bool:
    return node is not None and all(n.type in _LITERAL for n in walk(node) if n.is_named)


def _writes(src: Parsed, node: Node | None) -> bool:
    return node is not None and any(
        n.type in ("assignment", "operator_assignment")
        or (
            n.type == "call"
            and (
                call_name(src, n) in _WRITES
                or call_name(src, n) in ("save", "update_attribute")
                or call_name(src, n).endswith("!")
            )
        )
        for n in walk(node)
    )


def _finder(name: str) -> bool:
    """An ActiveRecord read of a record by a value (`find`, `find_by_slug!`, `where`)."""
    return name in ("find", "find!", "where", "find_sole_by", "exists?") or name.startswith(
        ("find_by", "destroy_by", "delete_by")
    )


def _is_receiver(node: Node) -> bool:
    parent = node.parent
    return (
        parent is not None
        and parent.type == "call"
        and parent.child_by_field_name("receiver") == node
    )


def _same_kind(src: Parsed, owner: Node, caller: Node) -> bool:
    """`note.user == current_user` or `note.user_id == current_user.id`, not `note.user_id ==
    current_user` (a record against an id is never equal)."""
    owner_id = src.text(owner).endswith(("_id", ".id"))
    caller_id = src.text(caller).endswith((".id", "_id"))
    return owner_id == caller_id


def _snake(model: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", model).lower()


def _responds(
    src: Parsed, node: Node | None, safe: set[str] | None = None, action: str = ""
) -> bool:
    """`head :forbidden`, `head 404`, `render …, status: :not_found` (401-404) sending no value
    but literals (`safe`: locals only ever assigned literals)."""
    node = unwrap(node)
    if node is None or node.type != "call" or node.child_by_field_name("receiver") is not None:
        return False
    name = call_name(src, node)
    a = args(node)
    if name == "head" and a:
        status = symbol(src, a[0]) or src.text(a[0])
        return status in _REFUSING_STATUS or status in _REFUSING_CODES
    if name == "render":
        statuses = [
            symbol(src, p.child_by_field_name("value")) or src.text(p.child_by_field_name("value"))
            for x in a
            for p in (x.named_children if x.type == "hash" else [x])
            if p.type == "pair"
            and symbol(src, p.child_by_field_name("key")) == "status"
            and p.child_by_field_name("value") is not None
        ]
        return (
            bool(statuses)
            and statuses[0] in (*_REFUSING_STATUS, *_REFUSING_CODES)
            and not _render_leaks(src, node, safe or set(), action)
        )
    return False


def _render_leaks(src: Parsed, node: Node, safe: set[str], action: str = "") -> bool:
    """A `render` whose body names a value, which may be the record (`render json: note`), or
    that renders a view showing it (`render :show`)."""
    items = [p for x in args(node) for p in (x.named_children if x.type == "hash" else [x])]
    keys = {symbol(src, p.child_by_field_name("key")) for p in items if p.type == "pair"}
    if not keys & _BODY_KEYS and not any(p.type != "pair" for p in items):
        return True  # `render status: :forbidden`: the action's own view, which may show it
    for p in items:
        key = symbol(src, p.child_by_field_name("key")) if p.type == "pair" else None
        if key in (*_VIEW_KEYS, "partial", "inline", "layout") or (
            p.type != "pair" and (symbol(src, p) is not None)
        ):
            return True  # a view, a partial or a template may print the record
        if p.type != "pair":
            if p.type not in _LITERAL and not (p.type == "identifier" and src.text(p) in safe):
                return True
            continue
        key = symbol(src, p.child_by_field_name("key"))
        value = p.child_by_field_name("value")
        if key == "status":
            continue
        if value is None:  # `render json:`, the local or method of that name
            if key not in safe:
                return True
            continue
        for n in walk(value):
            method = (
                n.parent is not None
                and n.parent.type == "call"
                and (n.parent.child_by_field_name("method") == n)
            )
            if n.type == "instance_variable" or (
                n.type == "identifier" and not method and src.text(n) not in safe
            ):
                return True
            if n.type == "call" and not (
                call_name(src, n) in ("t", "translate")
                and chain_text(src, n.child_by_field_name("receiver")) in ("", "I18n")
                and all(_is_literal(a) for a in args(n))
            ):
                return True
    return False


def _redirect_leaks(src: Parsed, node: Node, safe: set[str]) -> bool:
    """A redirect carrying a value in its flash (`alert: "#{@note.body}"`, `flash: {…}`)."""
    for x in args(node):
        for p in x.named_children if x.type == "hash" else [x]:
            key = symbol(src, p.child_by_field_name("key")) if p.type == "pair" else None
            if p.type != "pair" or key in ("status", "fallback_location"):
                continue
            value = p.child_by_field_name("value")
            if value is None or not (
                _is_literal(value)
                or (value.type == "identifier" and src.text(value) in safe)
                or (
                    value.type == "call"
                    and call_name(src, value) in ("t", "translate")
                    and all(_is_literal(a) for a in args(value))
                )
            ):
                return True
    return False


def uses_record(
    src: Parsed, node: Node, methods: Callable[[str], tuple[Parsed, Node] | None], depth: int = 0
) -> bool:
    """Whether code may send or act on a record: an instance variable, an exception's record
    (`e.record`, `exception.subject`), or a helper doing so."""
    for n in walk(node):
        if n.type == "instance_variable":
            return True
        if n.type == "call" and call_name(src, n) in ("record", "subject", "resource", "object"):
            return True
        name = _helper_name(src, n)
        if (
            name
            and depth < 3
            and (found := methods(name)) is not None
            and found[1] != node
            and uses_record(found[0], found[1], methods, depth + 1)
        ):
            return True
    return False


def _inert(src: Parsed, node: Node) -> bool:
    """A statement that acts on nothing: `return`, a literal, a flash message, a log line."""
    node = unwrap(node) or node
    if node.type in ("return", "true", "false", "nil"):
        return not args(node) if node.type == "return" else True
    if node.type == "assignment":
        target = src.text(node.child_by_field_name("left"))
        right = node.child_by_field_name("right")
        literal = _is_literal(right) or (
            right is not None
            and right.type == "call"
            and call_name(src, right) in ("t", "translate")
            and all(_is_literal(a) for a in args(right))
        )
        return target.startswith(("flash", "flash.now")) and literal
    return node.type == "call" and chain_text(src, node.child_by_field_name("receiver")).split(".")[
        0
    ] in (
        "logger",
        "Rails",
    )


def _raises(src: Parsed, node: Node | None) -> bool:
    node = unwrap(node)
    return (
        node is not None
        and node.type == "call"
        and node.child_by_field_name("receiver") is None
        and call_name(src, node) in ("raise", "fail")
    )


def _narrows(code: RubyCode, src: Parsed, expr: Node | None, model: str, depth: int = 0) -> bool:
    """A policy Scope's `resolve` narrows by the user: `scope.where(user: user)`,
    `scope.where(user_id: user.id)`, `user.notes`; under `user.admin? ? scope.all : …` the
    non-admin branch (D10)."""
    expr = unwrap(expr)
    if expr is None or depth > _MAX_NESTING:
        return False
    if expr.type in ("conditional", "if"):
        cond = expr.child_by_field_name("condition")
        yes = expr.child_by_field_name("consequence")
        no = expr.child_by_field_name("alternative")

        def last(n: Node | None) -> Node | None:
            body = statements(n) if n is not None and n.type in ("then", "else") else []
            return body[-1] if body else n

        if _privileged_test(src, cond, "user"):
            return _narrows(code, src, last(no), model, depth + 1)
        return _narrows(code, src, last(yes), model, depth + 1) and _narrows(
            code, src, last(no), model, depth + 1
        )
    chain: list[Node] = []
    node: Node | None = expr
    while node is not None and node.type == "call":
        chain.append(node)
        node = unwrap(node.child_by_field_name("receiver"))
    chain.reverse()
    if any(call_name(src, c) in _WIDENING for c in chain):
        return False
    if (
        node is not None
        and src.text(node) == "user"
        and chain
        and code.association("User", call_name(src, chain[0]))
    ):
        return True
    if node is None or src.text(node) != "scope":
        return False
    for c in chain:
        if call_name(src, c) == "where":
            for k, v in pairs(src, args(c)) or []:
                text = src.text(v)
                if OWNER_CHECK_RX.match(k) and _policy_user_kind(text) == _owner_kind(k):
                    return True
    return False


def _privileged_test(src: Parsed, node: Node | None, user: str) -> bool:
    """`user.admin?`: the user's own flag, never `user.membership.admin?` (D21)."""
    head, _, flag = chain_text(src, node).partition(".")
    return head == user and "." not in flag and bool(_PRIVILEGE.match(flag))


def _owner_atom(src: Parsed, node: Node | None, records: tuple[str, ...]) -> _Atom | None:
    """In a policy or an ability block: `record.user == user` (own), `user.admin?` (admin);
    another expression is a free atom."""
    node = unwrap(node)
    if node is None:
        return None
    if node.type == "binary" and src.text(node.child_by_field_name("operator")) in ("==", "!="):
        op = src.text(node.child_by_field_name("operator"))
        sides = [unwrap(node.child_by_field_name(x)) for x in ("left", "right")]
        for a, b in (sides, sides[::-1]):
            head, _, rest = chain_text(src, a).partition(".")
            if (
                head in records
                and OWNER_CHECK_RX.match(rest.removesuffix(".id"))
                and _policy_user_kind(chain_text(src, b)) == _owner_kind(rest.split(".")[0])
                and _same_kind(src, a, b)  # type: ignore[arg-type]
            ):
                return "own" if op == "==" else "!own"
    if _privileged_test(src, node, "user") or _privileged_test(src, node, "@user"):
        return "admin"
    if node.type in ("call", "identifier", "binary"):
        return f"?{src.text(node)}"
    return None


def _policy_refuses(
    code: RubyCode, model: str, query: str, policy: str | None = None, depth: int = 0
) -> bool | None:
    """Whether `<Model>Policy#<query>` is false for every user who doesn't own the record
    (an admin aside, D10): `record.user == user`, `record.user_id == user.id`; None when the
    policy can't be read."""
    found = code.policy_method(model, query, policy)
    if not found:
        return None
    src, method = found
    body = method_body(method)
    if not body:
        return True  # returns nil: Pundit refuses
    expr = body[-1]
    if expr.type == "return" and args(expr):
        expr = args(expr)[0]
    if len(body) > 1:
        return None  # more than one expression: not read
    if expr.type == "identifier" and src.text(expr).endswith("?") and depth < 3:
        return _policy_refuses(code, model, src.text(expr), policy, depth + 1)  # `= update?`
    return holds(
        src,
        expr,
        lambda n: _owner_atom(src, n, ("record", "@record")),
        {"own": False, "admin": False},
        False,
    )


_CANCAN_ALIASES = {
    "read": {"show", "index"},
    "update": {"edit", "update"},
    "create": {"new", "create"},
    "destroy": {"destroy"},
}


def _ability(code: RubyCode, action: str, model: str) -> bool | None:
    """CanCanCan (D15): whether `Ability` refuses `action` on a `model` the user doesn't own;
    None when it can't be read. Rules under an admin test are the admin's (D10)."""
    if code.ability is None:
        return None
    src, cls = code.ability
    if any(n.type == "call" and call_name(src, n) == "merge" for n in walk(cls)) or any(
        s.type == "call"
        and call_name(src, s) == "include"
        and not all(src.text(a).startswith("CanCan::") for a in args(s))
        for s in statements(cls.child_by_field_name("body"))
    ):
        return None  # `merge(OtherAbility.new(user))`, `include Shared`: rules we don't read
    if any(
        n.type == "self" and n.parent is not None and n.parent.type == "argument_list"
        for n in walk(cls)
    ):
        return None  # `NoteSharing.grant(self, user)`: rules added elsewhere
    rules = [n for n in walk(cls) if n.type == "call" and n.child_by_field_name("receiver") is None]
    aliases = {k: set(v) for k, v in _CANCAN_ALIASES.items()}
    for rule in rules:
        if call_name(src, rule) == "alias_action":
            options = dict(pairs(src, [x for x in args(rule) if x.type == "pair"]) or [])
            target = symbol(src, options.get("to"))
            if target is None:
                return None
            aliases.setdefault(target, set()).update(
                s for x in args(rule) if x.type != "pair" and (s := symbol(src, x))
            )
    for rule in rules:
        if call_name(src, rule) != "can":
            continue
        a = args(rule)
        if len(a) < 2:
            return None
        actions = [
            symbol(src, x) for x in (a[0].named_children if a[0].type == "array" else [a[0]])
        ]
        subjects = a[1].named_children if a[1].type == "array" else [a[1]]
        if None in actions or any(
            s.type not in ("constant", "scope_resolution") and src.text(s) != ":all"
            for s in subjects
        ):
            return None  # a subject or an action we can't name
        names = [src.text(s).rsplit("::", 1)[-1] for s in subjects]
        applies = any(
            x == "manage" or x == action or action in aliases.get(x or "", set()) for x in actions
        ) and (model in names or ":all" in names)
        if not applies or _under_admin(src, rule, cls):
            continue
        conditions = pairs(src, a[2:]) if len(a) > 2 else []
        if conditions and any(
            OWNER_CHECK_RX.match(k) and _policy_user_kind(src.text(v)) == _owner_kind(k)
            for k, v in conditions
        ):
            continue
        block = rule.child_by_field_name("block")
        if block is not None and _block_refuses(src, block):
            continue
        return False
    return True


def _block_refuses(src: Parsed, block: Node) -> bool:
    """`can :destroy, Note do |note| note.user == user end`: false for every foreign record."""
    params = block.child_by_field_name("parameters")
    names = [src.text(c) for c in params.named_children] if params is not None else []
    body = block.child_by_field_name("body") or next(
        (c for c in block.named_children if c.type in ("block_body", "body_statement")), None
    )
    stmts = statements(body)
    if not names or len(stmts) != 1:
        return False
    return holds(
        src,
        stmts[0],
        lambda n: _owner_atom(src, n, (names[0],)),
        {"own": False, "admin": False},
        False,
    )


def _under_admin(src: Parsed, node: Node, stop: Node) -> bool:
    """Inside the branch an admin test takes (`if user.admin?` then, `unless user.admin?`
    else)."""
    child, parent = node, node.parent
    while parent is not None and parent != stop:
        if parent.type in ("if", "if_modifier", "unless", "unless_modifier"):
            condition = parent.child_by_field_name("condition")
            then = parent.child_by_field_name("consequence") or parent.child_by_field_name("body")
            if child != condition and _privileged_test(src, condition, "user"):
                positive = parent.type in ("if", "if_modifier")
                if (child == then) == positive:
                    return True
        child, parent = parent, parent.parent
    return False


def iter_methods(src: Parsed, cls: Node) -> Iterator[Node]:
    for m in statements(cls.child_by_field_name("body")):
        if m.type == "method":
            yield m


def admin_gate(src: Parsed, method: Node) -> bool:
    """Whether a callback refuses every caller who isn't an admin: its first statement halts
    (a response or a raise; a callback that renders or redirects stops the action) unless
    the caller is an admin."""
    body = method_body(method)
    if (
        len(body) >= 2
        and body[0].type == "if_modifier"
        and unwrap(body[0].child_by_field_name("body")).type == "return"  # type: ignore[union-attr]
        and _user_flag(src, body[0].child_by_field_name("condition"))
        and (_halts(src, body[1]) or _raises(src, body[1]))
    ):
        return True  # `return if current_user.admin?`, then `head :forbidden`
    if not body:
        return False
    first = body[0]
    if first.type not in ("if_modifier", "unless_modifier", "if", "unless"):
        return False
    inner = first.child_by_field_name("body") or first.child_by_field_name("consequence")
    if inner is None or (
        first.type in ("if", "unless") and first.child_by_field_name("alternative") is not None
    ):
        return False
    stmts = statements(inner) if inner.type == "then" else [inner]
    if (
        not stmts
        or not all(_raises(src, s) or _halts(src, s) or s.type == "return" for s in stmts)
        or not any(_raises(src, s) or _halts(src, s) for s in stmts)
    ):
        return False

    def atom(node: Node) -> _Atom | None:
        node = unwrap(node)
        text = chain_text(src, node)
        if _user_flag(src, node):
            return "admin"
        if text in _CALLERS or text in _CALLER_IVARS:
            return "caller"
        if node is not None and node.type in ("call", "identifier", "binary"):
            return f"?{src.text(node)}"
        return None

    refuse = first.type in ("if_modifier", "if")
    cond = first.child_by_field_name("condition")
    return "admin" in _atoms(src, cond, atom) and holds(src, cond, atom, {"admin": False}, refuse)


def _user_flag(src: Parsed, node: Node | None) -> bool:
    """`current_user.admin?`: the signed-in user's own flag (D10, D21), never a membership's
    (`current_member.admin?`: a tenant admin isn't an admin)."""
    owner, _, flag = chain_text(src, node).rpartition(".")
    return _caller_group(owner) in ("current_user", "current_admin") and bool(
        _PRIVILEGE.match(flag)
    )


def ensures(method: Node) -> list[Node]:
    """The statements of a method's `ensure` clause."""
    body = method.child_by_field_name("body")
    return [
        s
        for r in (body.named_children if body is not None and body.type == "body_statement" else [])
        if r.type == "ensure"
        for s in statements(r)
    ]


def rescues(method: Node) -> list[Node]:
    """The statements of a method's `rescue` clauses."""
    body = method.child_by_field_name("body")
    return [
        s
        for r in (body.named_children if body is not None and body.type == "body_statement" else [])
        if r.type == "rescue"
        for c in r.named_children
        if c.type == "then"
        for s in statements(c)
    ]


def _halts(src: Parsed, node: Node | None) -> bool:
    node = unwrap(node)
    if node is None:
        return False
    if node.type == "binary" and src.text(node.child_by_field_name("operator")) == "and":
        return _halts(src, node.child_by_field_name("left"))
    return (
        node.type == "call"
        and node.child_by_field_name("receiver") is None
        and call_name(src, node)
        in (
            "head",
            "render",
            "redirect_to",
            "redirect_back",
        )
    )


def swallows(src: Parsed, method: Node) -> bool:
    """A method-level `rescue` that neither re-raises nor responds: what it rescues goes on."""
    body = method.child_by_field_name("body")
    for r in body.named_children if body is not None and body.type == "body_statement" else []:
        if r.type == "rescue":
            stmts = [s for c in r.named_children if c.type == "then" for s in statements(c)]
            if not any(_raises(src, s) or _halts(src, s) for s in stmts):
                return True
    return False


def inert(src: Parsed, node: Node) -> bool:
    return _inert(src, node)


def keeps_going(src: Parsed, node: Node) -> bool:
    """A conditional response in a callback with no `return` or raise after it: the callback
    runs on after responding (`head :forbidden unless own`)."""
    if node.type not in ("if_modifier", "unless_modifier", "if", "unless"):
        return False
    found = list(walk(node))
    return any(_halts(src, n) for n in found) and not any(
        n.type == "return" or _raises(src, n) for n in found
    )


def early_return(src: Parsed, node: Node) -> bool:
    """A statement that may leave a callback without a response (`return if preview?`); one
    that lets only an admin through (`return if current_user.admin?`) is D10's bypass."""
    found = list(walk(node))
    if node.type == "if_modifier" and _user_flag(src, node.child_by_field_name("condition")):
        return False
    return any(n.type == "return" for n in found) and not any(
        _halts(src, n) or _raises(src, n) for n in found
    )


def caller_forged(
    code: RubyCode,
    steps: list[tuple[Parsed, Node, Kind]],
    methods: Callable[[str], tuple[Parsed, Node] | None],
    action: tuple[Parsed, Node] | None,
) -> bool:
    """Whether the request may choose `current_user` for this action (D17)."""
    body = [(action[0], s, Kind.ACTION) for s in method_body(action[1])] if action else []
    walk_ = _Action(
        code,
        [_Step(s, n, kind) for s, n, kind in [*steps, *body]],
        set(),
        True,
        methods,
        "",
        None,
        (False, False),
    )
    return bool(walk_.forged & {"current_user", "current_admin"})


def action_facts(
    code: RubyCode,
    steps: list[tuple[Parsed, Node, Kind]],
    path_ids: set[str],
    *,
    guarded: bool,
    methods: Callable[[str], tuple[Parsed, Node] | None],
    action: str,
    model: str | None,
    cancan: tuple[bool, bool],
    raises: bool = True,
) -> HandlerFacts:
    """An action's ownership facts from the statements it runs in order (its callbacks', then
    its own). `cancan`: whether `load_resource` and `authorize_resource` run for it."""
    walk_ = _Action(
        code,
        [_Step(s, n, kind) for s, n, kind in steps],
        path_ids,
        guarded,
        methods,
        action,
        model,
        cancan,
        raises,
    )
    return walk_.run()
