"""Ownership of the object a Rails action acts on, read from its `before_action` callbacks, its
body and the same-repository methods, models, policies and abilities they use. Protection
counts only from allow-listed shapes (D8, D15-D18)."""

from __future__ import annotations

import itertools
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_ownership import (
    OWNER_CHECK_RX,
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
# what a caller set by an authentication callback may come from (D17): the session, a cookie,
# a verified token; never `params`
_CREDENTIAL = re.compile(
    r"\b(session|cookies|warden|authenticat\w*|verify\w*|decode\w*|bearer)\b", re.I
)
_CONVERSIONS = {"to_i", "to_s", "to_param", "presence"}
_INERT = {"logger", "Rails", "puts", "p", "pp", "flash", "notice", "alert", "t", "I18n"}
_MAX_DEPTH = 64
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


# ---- the checkout's models, schema, policies and abilities


@dataclass
class _Model:
    name: str
    associations: dict[str, str] = field(default_factory=dict)  # has_many/one name -> class
    belongs: dict[str, str] = field(default_factory=dict)  # belongs_to name -> class
    linked: bool = False  # fields we can't all read


class RubyCode:
    """A checkout's ActiveRecord models (associations from the model, columns from
    `db/schema.rb`), Pundit policies and the CanCanCan `Ability`."""

    def __init__(self, sources: dict[str, Parsed]) -> None:
        self.sources = sources
        self.models: dict[str, _Model] = {}
        self.columns: dict[str, list[str]] = {}  # table -> columns
        self.policies: dict[str, Node] = {}  # class name -> class node
        self.policy_src: dict[str, Parsed] = {}
        self.modules: dict[str, tuple[Parsed, Node]] = {}  # concern name -> module
        self.ability: tuple[Parsed, Node] | None = None
        for rel, src in sources.items():
            self._index(rel, src)
        self.fields = self._fields()

    def _index(self, rel: str, src: Parsed) -> None:
        if rel.endswith("db/schema.rb"):
            self._schema(src)
        for n in walk(src.root):
            if n.type == "module" and "/concerns/" in rel:
                self.modules[src.text(n.child_by_field_name("name")).rsplit("::", 1)[-1]] = (src, n)
            if n.type != "class":
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
            elif base in ("ApplicationRecord", "ActiveRecord::Base") or "/app/models/" in f"/{rel}":
                if not base or base.endswith("Controller") or name.endswith("Controller"):
                    continue
                model = self.models.setdefault(name, _Model(name))
                if base not in ("ApplicationRecord", "ActiveRecord::Base"):
                    model.linked = True  # inherited associations (STI)
                for s in body:
                    if s.type != "call" or not args(s):
                        continue
                    kind, first = call_name(src, s), symbol(src, args(s)[0])
                    opts = dict(pairs(src, args(s)[1:]) or [])
                    if first is None:
                        continue
                    target = symbol(src, opts.get("class_name")) or _class_of(first)
                    if kind in ("has_many", "has_one", "has_and_belongs_to_many"):
                        model.associations[first] = target
                    elif kind == "belongs_to":
                        model.belongs[first] = target
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
        for name, model in self.models.items():
            table = _table_of(name)
            if model.linked or table not in self.columns:
                continue
            out[name] = tuple(dict.fromkeys([*self.columns[table], *model.belongs]))
        return out

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

    def policy_method(self, model: str, query: str) -> tuple[Parsed, Node] | bool | None:
        """`NotePolicy#destroy?` (through policy inheritance); None when the policy can't be
        read, False when no policy names the model."""
        cls = self.policies.get(f"{model}Policy")
        if cls is None:
            return None
        seen: set[str] = set()
        name = f"{model}Policy"
        while cls is not None and name not in seen:
            seen.add(name)
            src = self.policy_src[name]
            for m in statements(cls.child_by_field_name("body")):
                if m.type == "method" and src.text(m.child_by_field_name("name")) == query:
                    return src, m
            sup = cls.child_by_field_name("superclass")
            name = (
                src.text(sup.named_children[0]).rsplit("::", 1)[-1]
                if sup is not None and sup.named_children
                else ""
            )
            cls = self.policies.get(name)
        return None

    def policy_scope(self, model: str) -> tuple[Parsed, Node] | None:
        """`NotePolicy::Scope#resolve`."""
        cls = self.policies.get(f"{model}Policy")
        if cls is None:
            return None
        src = self.policy_src[f"{model}Policy"]
        for n in walk(cls):
            if n.type == "class" and src.text(n.child_by_field_name("name")) == "Scope":
                for m in statements(n.child_by_field_name("body")):
                    if m.type == "method" and src.text(m.child_by_field_name("name")) == "resolve":
                        return src, m
        return None


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


def _boolean(
    src: Parsed, node: Node | None, atom: Callable[[Node], _Atom | None]
) -> Callable[[_Env], bool] | None:
    """A condition as a function of its atoms; None when it isn't a plain boolean."""
    node = unwrap(node)
    if node is None:
        return None
    if node.type == "true":
        return lambda env: True
    if node.type in ("false", "nil"):
        return lambda env: False
    if node.type == "unary" and src.text(node.child_by_field_name("operator")) in ("!", "not"):
        inner = _boolean(src, node.child_by_field_name("operand"), atom)
        return (lambda env: not inner(env)) if inner is not None else None
    if node.type == "binary":
        op = src.text(node.child_by_field_name("operator"))
        if op in ("&&", "and", "||", "or"):
            left = _boolean(src, node.child_by_field_name("left"), atom)
            right = _boolean(src, node.child_by_field_name("right"), atom)
            if left is None or right is None:
                return None
            if op in ("&&", "and"):
                return lambda env: left(env) and right(env)
            return lambda env: left(env) or right(env)
    found = atom(node)
    if found is None:
        return None
    negated = found.startswith("!")
    name = found.removeprefix("!")
    return (lambda env: not env[name]) if negated else (lambda env: env[name])


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


# ---- one action


@dataclass
class _Record:
    lookup: int  # the lookup that loaded it
    model: str | None
    used: bool = False  # acted on or sent before any check


@dataclass
class _Step:
    src: Parsed
    node: Node
    callback: bool  # part of a `before_action` (a response there halts the chain)


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
        load_and_authorize: bool,
    ) -> None:
        self.code, self.steps, self.path_ids = code, steps, path_ids
        self.methods, self.action, self.model = methods, action, model
        self.lookups: list[Lookup] = []
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
        self.caller_ivars = self._caller_ivars()
        self.guarded = guarded and not self._forged()
        self.load_and_authorize = load_and_authorize
        self.position = 0
        self.inlined: set[str] = set()
        self.callback_now = False
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
    def _caller_ivars(self) -> set[str]:
        """Instance variables an authentication callback sets from a credential (`@user =
        User.find_by(session_token: session[:u])`): the caller too, unless set anywhere from
        `params` or outside the callbacks."""
        assigned: dict[str, list[tuple[bool, str]]] = {}
        for step in self.steps:
            for n in walk(step.node):
                if n.type in ("assignment", "operator_assignment"):
                    left = n.child_by_field_name("left")
                    if left is not None and left.type == "instance_variable":
                        value = step.src.text(n.child_by_field_name("right"))
                        assigned.setdefault(step.src.text(left), []).append((step.callback, value))
        return {
            name
            for name, values in assigned.items()
            if name not in _CALLER_IVARS
            and all(callback for callback, _ in values)
            and all(_CREDENTIAL.search(v) and "params" not in v for _, v in values)
        }

    def _forged(self) -> bool:
        """Whether a step assigns who is calling (`@current_user = …`, `Current.user = …`), or
        the app's own `current_user` is built from `params`."""
        for name in _CALLERS:
            found = self.methods(name)
            if found is not None and "params" in found[0].text(found[1]):
                return True
        for step in self.steps:
            for n in walk(step.node):
                if n.type in ("assignment", "operator_assignment"):
                    left = chain_text(step.src, n.child_by_field_name("left"))
                    if left in _CALLER_IVARS or left in _CALLERS or left == "Current.user":
                        return True
        return False

    def is_caller(self, src: Parsed, node: Node | None) -> bool:
        node = unwrap(node)
        if node is None or not self.guarded:
            return False
        text = chain_text(src, node)
        return (
            text in _CALLERS
            or text in _CALLER_IVARS
            or text == "Current.user"
            or text in self.caller_ivars
        )

    def derived(self, src: Parsed, node: Node | None) -> bool:
        """Built from the caller alone: `current_user`, `current_user.id`, `.account`."""
        node = unwrap(node)
        for _ in range(_MAX_DEPTH):
            if node is None:
                return False
            if self.is_caller(src, node):
                return True
            if node.type != "call" or args(node):
                return False
            if call_name(src, node) == "&.":
                return False
            node = unwrap(node.child_by_field_name("receiver"))
        return False

    # -- the id
    def path_id(self, src: Parsed, node: Node | None) -> str | None:
        node = unwrap(node)
        if node is None:
            return None
        if node.type == "element_reference":
            obj = node.child_by_field_name("object")
            keys = [c for c in node.named_children if c != obj]
            if obj is not None and src.text(obj) == "params" and len(keys) == 1:
                key = symbol(src, keys[0])
                return key if key in self.path_ids else None
        if node.type == "call" and call_name(src, node) in ("fetch", "require"):
            receiver = node.child_by_field_name("receiver")
            a = args(node)
            if receiver is not None and src.text(receiver) == "params" and len(a) >= 1:
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
        self.lookups.append(lookup)
        self.cover.append(cover)
        self.starts.append(self.position)
        self.reads.append(read)
        return len(self.lookups) - 1

    def handoff(self, src: Parsed, node: Node, cover: set[_Key] | None = None) -> None:
        self.position += 1
        self.handoffs.append((self.span(src, node), cover, self.position))

    def verify(self, keys: set[_Key] | None) -> None:
        self.position += 1
        for k in keys or set():
            if k[0] not in self.unstable:
                self.verified.setdefault(k, self.position)

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
        if root is not None and root.type in ("constant", "scope_resolution"):
            model = src.text(root).rsplit("::", 1)[-1]
            if model not in self.code.models:
                return None, False
        elif root is None and chain and call_name(src, chain[0]) == "policy_scope":
            a = args(chain[0])
            model = src.text(a[0]).rsplit("::", 1)[-1] if a else None
            if model not in self.code.models:
                return None, False
            scoped = self.policy_scoped(model)  # D15
            if not scoped and self.code.policy_scope(model) is None:
                self.handoff(src, chain[0])
            start = 1
        elif self.is_caller(src, root) or (
            root is None and chain and self.is_caller(src, chain[0])
        ):
            # `current_user.notes.find(id)`: a caller association (D18)
            start = 0 if root is not None else 1
            if start >= len(chain):
                return None, False
            assoc = call_name(src, chain[start])
            model = self.code.association("User", assoc) or self.code.association("Account", assoc)
            if model is None:
                return None, False
            scoped, start = True, start + 1
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
            return None, False
        cover: set[_Key] = set()
        plain = True
        terminal = call_name(src, chain[-1])
        for c in chain[start:]:
            name = call_name(src, c)
            a = args(c)
            if name in _NEUTRAL:
                continue
            if name in ("find", "find!") and len(a) == 1:
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
                    elif OWNER_CHECK_RX.match(k) and self.derived(src, v) and plain:
                        scoped = True  # shape 1: `where(user: current_user)`
            elif name in _READS or name in _WRITES or name in ("first", "last", "take"):
                continue
            else:
                plain = False  # `or`, `not`, `merge`, `unscope`, a scope we can't read
        if any(
            call_name(src, c) in ("or", "unscope", "unscoped", "rewhere", "merge", "invert_where")
            for c in chain
        ):
            scoped = False  # widened past the caller's records
        return self.record_lookup(src, call, model, scoped, cover or None, terminal), True

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

    def policy_scoped(self, model: str) -> bool:
        """`NotePolicy::Scope#resolve` narrows by the user (D15)."""
        found = self.code.policy_scope(model)
        if found is None:
            return False
        src, method = found
        body = statements(method.child_by_field_name("body"))
        return bool(body) and _narrows(self.code, src, body[-1], model)

    # -- the walk
    def run(self) -> HandlerFacts:
        if self.load_and_authorize and self.model is not None and self.path_ids:
            self.cancan_load()
        for index, step in enumerate(self.steps):
            self.position = index * 1000
            self.statement(step)
        verified = {k: at for k, at in self.verified.items() if k[0] not in self.unstable}

        def held(keys: set[_Key] | None, at: int) -> bool:
            return bool(keys) and all(
                any(
                    v[0] == r and v[1] == s and f in (v[2], "*") and pos < at
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
                    x.checked or (not x.scoped and held(self.cover[k], self.starts[k])),
                    x.record_type,
                )
                for k, x in enumerate(self.lookups)
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
        verdict = (
            _ability(self.code, self.action, self.model)  # type: ignore[arg-type]
            if self.model in self.code.models
            else None  # a model we can't name: the Ability can't be read for it
        )
        if verdict is None:
            self.handoff(step.src, step.node)
        elif verdict:
            self.checked(k)

    def checked(self, k: int) -> None:
        x = self.lookups[k]
        self.lookups[k] = Lookup(x.span, x.scoped, True, x.record_type)
        self.verify(self.cover[k])

    def inline(self, src: Parsed, node: Node, depth: int) -> None:
        """Argument-free private helpers a statement uses (`note.destroy` with `def note;
        @note ||= Note.find(params[:id]); end`): their statements run first, once, and the
        helper's name stands for the record it returns."""
        for n in walk(node):
            name = (
                src.text(n)
                if n.type == "identifier"
                else call_name(src, n)
                if n.type == "call" and n.child_by_field_name("receiver") is None and not args(n)
                else ""
            )
            if not name or name in self.inlined or name in self.locals or name in self.records:
                continue
            found = self.methods(name)
            if found is None or depth > 1:
                continue
            self.inlined.add(name)
            hsrc, method = found
            if self.hop is None:
                self.hop = self.span(src, n)
            body = statements(method.child_by_field_name("body"))
            for s in body:
                self.statement(_Step(hsrc, s, self.callback_now), depth + 1)
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
        self.callback_now = step.callback
        self.inline(src, node, depth)
        self.callback_now = step.callback
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
                if name in self.roots or name in self.records:
                    self.unstable.add(self.roots.get(name, name))
                if k is not None:
                    self.records[name] = _Record(k, self.lookups[k].record_type)
                    if k in self.raising:
                        self.raised(k)
                elif right is not None and (pid := self.exact(src, right)) is not None:
                    self.roots[name] = pid
                elif right is not None and self.mentions(src, right):
                    self.handoff(src, node)  # the id under a name we don't read
            if k is None and right is not None:
                self.use(src, right)
            return
        # refusals
        refusal = self.refusal(src, node, step.callback)
        if refusal is not None:
            _, condition, negated = refusal
            self.calls(src, condition) if condition is not None else None
            for name, record in list(self.records.items()):
                self.refuses(src, record, name, condition, negated)
            return
        if node.type == "call" and call_name(src, node) == "authorize" and args(node):
            self.authorize(src, node)
            return
        self.use(src, node)
        k = self.calls(src, node)
        if k is not None and k in self.raising:
            self.raised(k)

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
            if self.mentions(src, c):
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
        self, src: Parsed, node: Node, callback: bool = False
    ) -> tuple[Node, Node | None, bool] | None:
        """A statement refusing the request (D16): `head :forbidden and return if c`, `raise X
        unless c`, `if c; render …, status: :not_found; return; end`. (body, condition,
        negated: an `unless`)."""
        if node.type in ("if_modifier", "unless_modifier"):
            body = node.child_by_field_name("body")
            if body is not None and self.refuses_request(src, body, callback):
                return body, node.child_by_field_name("condition"), node.type == "unless_modifier"
            return None
        if node.type in ("if", "unless") and node.child_by_field_name("alternative") is None:
            body = node.child_by_field_name("consequence")
            if body is not None and self.refuses_request(src, body, callback):
                return body, node.child_by_field_name("condition"), node.type == "unless"
        return None

    def refuses_request(self, src: Parsed, body: Node, callback: bool = False) -> bool:
        """D16; in a `before_action`, any response halts the action, so a `redirect_to` or a
        `render` refuses too (owner decision 2026-11-03)."""
        stmts = statements(body) if body.type == "then" else [body]
        if not stmts:
            return False
        if (
            callback
            and any(_halts(src, s) for s in stmts)
            and all(_halts(src, s) or _raises(src, s) or _inert(src, s) for s in stmts)
        ):
            return True
        last = stmts[-1]
        if len(stmts) == 1 and _raises(src, last):
            return True
        if len(stmts) == 1 and last.type == "return":
            a = args(last)
            return len(a) == 1 and _responds(src, a[0])
        if (
            len(stmts) == 1
            and last.type == "binary"
            and src.text(last.child_by_field_name("operator")) == "and"
        ):
            return (
                _responds(src, last.child_by_field_name("left"))
                and unwrap(last.child_by_field_name("right")).type == "return"
            )
        if len(stmts) == 2 and last.type == "return" and not args(last):
            return _responds(src, stmts[0])
        return False

    def use(self, src: Parsed, node: Node) -> None:
        """Records a statement acts on or sends: a later check no longer protects them."""
        names = {src.text(n) for n in walk(node) if n.type in ("identifier", "instance_variable")}
        for name, record in self.records.items():
            if name in names:
                record.used = True

    def refuses(
        self, src: Parsed, record: _Record, name: str, condition: Node | None, negated: bool
    ) -> None:
        """Shape 2 / shape 1's refusal of a missing record, on a statement refusing when the
        condition (`unless`: its negation) holds."""
        if condition is None or record.used:
            return
        lookup = self.lookups[record.lookup]
        refuse_value = not negated

        def atom(node: Node) -> _Atom | None:
            return self.atom(src, node, name, record.model)

        # refused whenever missing: a nil read becomes a raising one
        if holds(src, condition, atom, {"present": False}, refuse_value):
            if lookup.scoped:
                self.verify(self.cover[record.lookup])
            missing_refused = True
        else:
            missing_refused = record.lookup in self.raising
        # refused whenever foreign (and the caller isn't an admin, D10)
        if (
            missing_refused
            and holds(
                src, condition, atom, {"present": True, "own": False, "admin": False}, refuse_value
            )
            and "own" in _atoms(src, condition, atom)
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
                if (
                    self.owner_of(src, a, record, model)
                    and self.derived(src, b)
                    and _same_kind(src, a, b)
                ):
                    return "own" if op == "==" else "!own"
        if (
            text
            and text.rsplit(".", 1)[0] in (*_CALLERS, *_CALLER_IVARS, "Current.user")
            and _PRIVILEGE.match(text.rsplit(".", 1)[-1])
        ):
            return "admin" if self.guarded else None
        if node.type in ("call", "identifier", "binary", "instance_variable", "constant"):
            if any(n.type in ("assignment", "operator_assignment") for n in walk(node)):
                return None
            return f"?{src.text(node)}"
        return None

    def owner_of(self, src: Parsed, node: Node | None, record: str, model: str | None) -> bool:
        """`note.user`, `note.user_id`, `note.user.id`: the record's owner."""
        node = unwrap(node)
        if node is None or node.type != "call" or args(node):
            return False
        name = call_name(src, node)
        receiver = unwrap(node.child_by_field_name("receiver"))
        if chain_text(src, receiver) == record:
            return bool(OWNER_CHECK_RX.match(name))
        return name == "id" and self.owner_of(src, receiver, record, model)

    def authorize(self, src: Parsed, call: Node) -> None:
        """`authorize note` (Pundit, D15): checked when the policy's query method refuses a
        foreign record; unknown when it can't be read."""
        a = args(call)
        target = chain_text(src, a[0])
        record = self.records.get(target)
        if record is None:
            if self.mentions(src, call):
                self.handoff(src, call)
            return
        if record.used:
            return
        query = symbol(src, a[1]) if len(a) > 1 else f"{self.action}?"
        verdict = _policy_refuses(self.code, record.model, query or "") if record.model else None
        if verdict is None:
            self.handoff(src, call, self.cover[record.lookup])
        elif verdict:
            self.checked(record.lookup)


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


def _responds(src: Parsed, node: Node | None) -> bool:
    """`head :forbidden`, `head 404`, `render …, status: :not_found` (401-404)."""
    node = unwrap(node)
    if node is None or node.type != "call" or node.child_by_field_name("receiver") is not None:
        return False
    name = call_name(src, node)
    a = args(node)
    if name == "head" and a:
        status = symbol(src, a[0]) or src.text(a[0])
        return status in _REFUSING_STATUS or status in _REFUSING_CODES
    if name == "render":
        options = [
            p
            for x in a
            for p in (x.named_children if x.type == "hash" else [x])
            if p.type == "pair"
        ]
        statuses = [
            symbol(src, p.child_by_field_name("value")) or src.text(p.child_by_field_name("value"))
            for p in options
            if symbol(src, p.child_by_field_name("key")) == "status"
        ]
        # a body naming a value may send the record (`render json: note, status: :forbidden`)
        leaks = any(
            n.type in ("identifier", "instance_variable", "call")
            for p in options
            if symbol(src, p.child_by_field_name("key")) != "status"
            for n in walk(p.child_by_field_name("value"))
        )
        return bool(statuses) and statuses[0] in (*_REFUSING_STATUS, *_REFUSING_CODES) and not leaks
    return False


def _inert(src: Parsed, node: Node) -> bool:
    """A statement that acts on nothing: `return`, a literal, a flash message, a log line."""
    node = unwrap(node) or node
    if node.type in ("return", "true", "false", "nil"):
        return not args(node) if node.type == "return" else True
    if node.type == "assignment":
        target = src.text(node.child_by_field_name("left"))
        return target.startswith(("flash", "flash.now"))
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


def _narrows(code: RubyCode, src: Parsed, expr: Node | None, model: str) -> bool:
    """A policy Scope's `resolve` narrows by the user: `scope.where(user: user)`,
    `scope.where(user_id: user.id)`, `user.notes`; under `user.admin? ? scope.all : …` the
    non-admin branch (D10)."""
    expr = unwrap(expr)
    if expr is None:
        return False
    if expr.type in ("conditional", "if"):
        cond = expr.child_by_field_name("condition")
        yes = expr.child_by_field_name("consequence")
        no = expr.child_by_field_name("alternative")

        def last(n: Node | None) -> Node | None:
            body = statements(n) if n is not None and n.type in ("then", "else") else []
            return body[-1] if body else n

        if _privileged_test(src, cond, "user"):
            return _narrows(code, src, last(no), model)
        return _narrows(code, src, last(yes), model) and _narrows(code, src, last(no), model)
    chain: list[Node] = []
    node: Node | None = expr
    while node is not None and node.type == "call":
        chain.append(node)
        node = unwrap(node.child_by_field_name("receiver"))
    chain.reverse()
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
                if OWNER_CHECK_RX.match(k) and text in ("user", "user.id"):
                    return True
    return False


def _privileged_test(src: Parsed, node: Node | None, user: str) -> bool:
    text = chain_text(src, node)
    return text.startswith(f"{user}.") and bool(_PRIVILEGE.match(text.rsplit(".", 1)[-1]))


def _policy_refuses(code: RubyCode, model: str, query: str, depth: int = 0) -> bool | None:
    """Whether `<Model>Policy#<query>` is false for every user who doesn't own the record
    (an admin aside, D10): `record.user == user`, `record.user_id == user.id`; None when the
    policy can't be read."""
    found = code.policy_method(model, query)
    if not found:
        return None
    src, method = found
    body = statements(method.child_by_field_name("body"))
    if not body:
        return False
    expr = body[-1]
    if expr.type == "return" and args(expr):
        expr = args(expr)[0]
    if len(body) > 1:
        return None  # more than one expression: not read
    if expr.type == "identifier" and src.text(expr).endswith("?") and depth < 3:
        return _policy_refuses(code, model, src.text(expr), depth + 1)  # `def edit? = update?`

    def atom(node: Node) -> _Atom | None:
        node = unwrap(node)
        if node is None:
            return None
        if node.type == "binary" and src.text(node.child_by_field_name("operator")) in ("==", "!="):
            op = src.text(node.child_by_field_name("operator"))
            sides = [unwrap(node.child_by_field_name(x)) for x in ("left", "right")]
            for a, b in (sides, sides[::-1]):
                owner = chain_text(src, a)
                head, _, rest = owner.partition(".")
                if (
                    head in ("record", "@record")
                    and OWNER_CHECK_RX.match(rest.removesuffix(".id"))
                    and chain_text(src, b) in ("user", "@user", "user.id", "@user.id")
                    and _same_kind(src, a, b)
                ):
                    return "own" if op == "==" else "!own"
        if _privileged_test(src, node, "user") or _privileged_test(src, node, "@user"):
            return "admin"
        if node.type in ("call", "identifier", "binary"):
            return f"?{src.text(node)}"
        return None

    return holds(src, expr, atom, {"own": False, "admin": False}, False)


def _ability(code: RubyCode, action: str, model: str) -> bool | None:
    """CanCanCan (D15): whether `Ability` refuses `action` on a `model` the user doesn't own;
    None when it can't be read. Rules under an admin test are the admin's (D10)."""
    if code.ability is None:
        return None
    src, cls = code.ability
    init = next(
        (
            m
            for m in walk(cls)
            if m.type == "method" and src.text(m.child_by_field_name("name")) == "initialize"
        ),
        None,
    )
    if init is None:
        return None
    aliases = {
        "read": {"show", "index"},
        "update": {"edit", "update"},
        "create": {"new", "create"},
        "destroy": {"destroy"},
    }
    for rule in walk(init):
        if (
            rule.type != "call"
            or call_name(src, rule) != "can"
            or rule.child_by_field_name("receiver") is not None
        ):
            continue
        a = args(rule)
        if len(a) < 2:
            return None
        actions = [
            symbol(src, x) for x in (a[0].named_children if a[0].type == "array" else [a[0]])
        ]
        subjects = [src.text(x) for x in (a[1].named_children if a[1].type == "array" else [a[1]])]
        if None in actions:
            return None
        applies = any(
            x == "manage" or x == action or action in aliases.get(x or "", set()) for x in actions
        ) and (model in subjects or ":all" in subjects)
        if not applies or _under_admin(src, rule, init):
            continue
        conditions = pairs(src, a[2:]) if len(a) > 2 else []
        block = rule.child_by_field_name("block")
        if conditions and any(
            OWNER_CHECK_RX.match(k) and src.text(v) in ("user", "user.id") for k, v in conditions
        ):
            continue
        if block is not None and re.search(
            r"\.(user|owner|author)(_id)?\s*==\s*user(\.id)?\b", src.text(block)
        ):
            continue
        return False
    return True


def _under_admin(src: Parsed, node: Node, stop: Node) -> bool:
    parent = node.parent
    while parent is not None and parent != stop:
        if parent.type in ("if", "if_modifier") and _privileged_test(
            src, parent.child_by_field_name("condition"), "user"
        ):
            return True
        parent = parent.parent
    return False


def iter_methods(src: Parsed, cls: Node) -> Iterator[Node]:
    for m in statements(cls.child_by_field_name("body")):
        if m.type == "method":
            yield m


def admin_gate(src: Parsed, method: Node) -> bool:
    """Whether a callback refuses every caller who isn't an admin: its first statement halts
    (a response or a raise; a callback that renders or redirects stops the action) unless
    the caller is an admin."""
    body = statements(method.child_by_field_name("body"))
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
        if (
            text
            and text.rsplit(".", 1)[0] in (*_CALLERS, *_CALLER_IVARS, "Current.user")
            and _PRIVILEGE.match(text.rsplit(".", 1)[-1])
        ):
            return "admin"
        if text in _CALLERS or text in _CALLER_IVARS:
            return "caller"
        if node is not None and node.type in ("call", "identifier", "binary"):
            return f"?{src.text(node)}"
        return None

    refuse = first.type in ("if_modifier", "if")
    cond = first.child_by_field_name("condition")
    return "admin" in _atoms(src, cond, atom) and holds(src, cond, atom, {"admin": False}, refuse)


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


def action_facts(
    code: RubyCode,
    steps: list[tuple[Parsed, Node, bool]],
    path_ids: set[str],
    *,
    guarded: bool,
    methods: Callable[[str], tuple[Parsed, Node] | None],
    action: str,
    model: str | None,
    load_and_authorize: bool,
) -> HandlerFacts:
    """An action's ownership facts from the statements it runs in order (its callbacks', then
    its own)."""
    walk_ = _Action(
        code,
        [_Step(s, n, callback) for s, n, callback in steps],
        path_ids,
        guarded,
        methods,
        action,
        model,
        load_and_authorize,
    )
    return walk_.run()
