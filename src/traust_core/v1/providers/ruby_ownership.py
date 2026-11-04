"""Ownership of the object a Rails action acts on, read from its `before_action` callbacks, its
body and the same-repository methods, models, policies and abilities they use. Protection
counts only from allow-listed shapes (D8, D15-D18)."""

from __future__ import annotations

import dataclasses
import itertools
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatchcase
from glob import escape as glob_escape

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
# where the server keeps what it trusts across requests (D20 amended): the session and the
# cookie jar (only its signed and encrypted cookies count)
_STORE_ROOTS = {"session", "cookies", "cookie_jar", "session_options"}
_MAX_CLOSURE = 4000  # statements and methods read for one route's session writes
_PURE_CONSTANTS = {"Time", "Date", "DateTime", "SecureRandom", "Float", "Integer", "Digest"}
_SENDS = {"send", "public_send", "__send__", "try", "method"}
# what a store's methods do: read a key, read the whole store, or drop keys; any other may
# write it, or hand it on (`session.tap`, `session.send(:[]=, …)`)
_STORE_KEY_READS = {"fetch", "dig", "key?", "has_key?", "include?", "member?"}
_STORE_READS = {
    "to_h",
    "to_hash",
    "keys",
    "values",
    "id",
    "loaded?",
    "empty?",
    "present?",
    "blank?",
    "any?",
    "exists?",
    "inspect",
    "each",
    "each_pair",
    "each_key",
    "slice",
    "except",
    "select",
    "reject",
    "to_json",
    "as_json",
    "to_a",
    "nil?",
    "enabled?",
    "map",
    "count",
    "size",
    "length",
    "with_indifferent_access",
}
_STORE_DROPS = {"delete", "clear", "destroy"}
# what reading a value kept in the store may do without changing it
_VALUE_READS = {
    "to_i",
    "to_s",
    "to_sym",
    "to_a",
    "to_h",
    "to_param",
    "present?",
    "blank?",
    "nil?",
    "presence",
    "first",
    "last",
    "size",
    "length",
    "count",
    "empty?",
    "any?",
    "include?",
    "key?",
    "has_key?",
    "fetch",
    "dig",
    "==",
    "!=",
    "eql?",
    "with_indifferent_access",
    "symbolize_keys",
    "stringify_keys",
    "as_json",
    "to_json",
    "inspect",
    "id",
}
# `Current` attributes that name no caller (`Current.request_id = request.uuid`)
_CURRENT_PLAIN = {
    "request_id",
    "request_uuid",
    "user_agent",
    "ip_address",
    "ip",
    "remote_ip",
    "request",
    "host",
    "url",
    "path",
    "locale",
    "time_zone",
    "timezone",
    "referer",
    "referrer",
    "controller",
    "action",
    "started_at",
    "organization",
    "tenant",
    "workspace",
    "team",
    "site",
    "company",
    "region",
    "country",
    "subdomain",
    "domain",
    "beta",
}
_SIGN_IN_CALLS = re.compile(
    r"^(sign_in(_and_redirect)?|bypass_sign_in|log_?in|login_user|log_in_user|auto_login|"
    r"remember_me|set_user)$"
)
# session and cookie keys a gem's caller reads (Devise's warden keys and remember cookie)
_GEM_KEYS = ("warden*", "remember_*token*", "*remember_token*")
# session keys that hold the interface's state, never a caller a gem reads
_UI_KEYS = (
    "locale",
    "theme",
    "*return_to*",
    "forwarding_url",
    "*_url",
    "ip",
    "remote_ip",
    "user_agent",
    "flash",
    "filter*",
    "*_filter*",
    "sort*",
    "page",
    "per_page",
    "tab",
    "redirect*",
    "prefs",
    "preferences",
    "q",
    "search*",
    "view*",
    "layout",
    "time_zone",
    "timezone",
    "currency",
    "lang",
    "language",
    "referer",
    "referrer",
    "utm_*",
    "cart*",
    "visit*",
    "tracking*",
    "_csrf_token",
    "previous_url",
    "last_*",
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
_REQUEST_VALUE = re.compile(
    r"\brequest\.(headers|env|raw_post|body|get_header|fetch_header|authorization)\b"
)
_WARDEN = re.compile(r"""request\.env\[\s*["']warden["']\s*\]""")  # Devise's session
# calls that verify a request-supplied secret (`JWT.decode(t, key)`, `find_by(token: t)`)
_VERIFYING = re.compile(
    r"(?i)^(verify\w*|authenticate\w*|valid\w*|secure_compare|find_by_token\w*|digest)$"
)
_MAX_CLIMB = 64  # levels a request value is followed up its expression
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
    table: str | None = None  # `self.table_name = "people"`
    children: list[str] = field(default_factory=list)  # the classes its `has_many`s hold
    scopes: dict[str, Node] = field(default_factory=dict)  # `scope :x, -> { … }`, `def self.x`
    polymorphic: set[str] = field(default_factory=set)  # `belongs_to :owner, polymorphic: true`
    qualified: set[str] = field(default_factory=set)  # `Note`, `Archive::Note`


def _signature(model: _Model) -> tuple[object, ...]:
    return (
        sorted(model.associations.items()),
        sorted(model.belongs.items()),
        sorted(model.members),
        model.linked,
        model.policy,
        model.base,
        sorted(model.users),
        model.table,
        sorted(model.polymorphic),
        sorted(model.scopes),
    )


class RubyCode:
    """A checkout's ActiveRecord models (associations from the model, columns from
    `db/schema.rb`), Pundit policies and the CanCanCan `Ability`."""

    def __init__(self, sources: dict[str, Parsed]) -> None:
        self.sources = sources
        self.roots = app_roots(list(sources))
        self.model_roots: dict[str, set[str]] = {}  # a model several apps define: unread
        self.table_roots: dict[str, set[str]] = {}
        self.models: dict[str, _Model] = {}
        self.by_root: dict[tuple[str, str], _Model] = {}  # (model, app) -> its definition
        self.model_texts: dict[tuple[str, str], list[str]] = {}  # its source, to compare apps
        self.ambiguous: set[str] = set()  # models several apps define differently
        self.columns: dict[str, list[str]] = {}  # table -> columns
        self.columns_by_root: dict[tuple[str, str], list[str]] = {}
        # `Admin::NotePolicy` -> its class; never keyed by the bare name several may share
        self.policies: dict[str, list[tuple[Parsed, Node]]] = {}
        self.modules: dict[str, list[tuple[Parsed, Node]]] = {}  # module name -> definitions
        self.ability: tuple[Parsed, Node] | None = None
        self.abilities: dict[str, list[tuple[Parsed, Node]]] = {}  # `Ability`, `Admin::Ability`
        # `Api::Relaxed` -> every definition (a module reopened in another file)
        self.qualified: dict[str, list[tuple[Parsed, Node]]] = {}
        self.method_cache: dict[tuple[str, int, int], dict[str, Node]] = {}
        # what each statement does with the session and the caller's setters, and the app
        # methods it may call; each scope's locals
        self.scans: dict[
            tuple[str, int, int], tuple[list[_Use], list[str], list[tuple[str, Node | None]]]
        ] = {}
        self.scope_locals: dict[tuple[str, int, int], _Locals] = {}
        self.locals_at: dict[tuple[str, int, int], tuple[list[Node], bool] | None] = {}
        self.defined: set[str] = set()  # every method name the checkout defines
        for rel, src in sources.items():
            self._index(rel, src)
            self.defined |= {
                src.text(m.child_by_field_name("name"))
                for m in walk(src.root)
                if m.type in ("method", "singleton_method")
            }
        # CanCanCan's own `Ability` (top level), unless reopened or `class_eval`'d somewhere
        top = self.abilities.get("Ability", [])
        reopened = any(
            n.type == "call"
            and call_name(src, n)
            in (
                "class_eval",
                "class_exec",
                "module_eval",
                "instance_eval",
                "prepend",
                "include",
                "send",
                "public_send",
                "__send__",
            )
            and src.text(n.child_by_field_name("receiver")).removeprefix("::") == "Ability"
            for rel, src in sources.items()
            if not test_file(rel, self.roots)
            for n in walk(src.root)
        )
        if len(top) == 1 and not reopened:
            self.ability = top[0]
        # a model (or table) several apps define alike is one; defined differently, unread
        for (name, _root), model in self.by_root.items():
            self.models.setdefault(name, model)
            if self.model_texts.get((name, _root)) != self.model_texts.get(
                (name, next(r for (m, r) in self.by_root if m == name))
            ):
                self.model_roots[name] |= {"<differs>"}
        for name, roots in self.model_roots.items():
            if "<differs>" not in roots:
                self.model_roots[name] = {next(iter(roots))}
            else:  # several apps define it differently: nothing about it is read
                self.models[name] = _Model(name, linked=True)
                self.ambiguous.add(name)
        for (table, _root), columns in self.columns_by_root.items():
            first = self.columns.setdefault(table, columns)
            if sorted(first) != sorted(columns):
                self.table_roots[table] |= {"<differs>"}
        for table, roots in self.table_roots.items():
            if "<differs>" not in roots:
                self.table_roots[table] = {next(iter(roots))}
        self.fields = self._fields()

    def _index(self, rel: str, src: Parsed) -> None:
        if test_file(rel, self.roots):
            return  # a test double (`spec/support/note_policy.rb`) is no app's
        if rel.endswith("db/schema.rb"):
            self._schema(src)
        for n in walk(src.root):
            if n.type == "module" and n.is_named:
                written = src.text(n.child_by_field_name("name"))
                self.modules.setdefault(written.rsplit("::", 1)[-1], []).append((src, n))
                key = (
                    written[2:]
                    if written.startswith("::")
                    else "::".join([*_lexical(src, n), written])
                )
                self.qualified.setdefault(key, []).append((src, n))
            if n.type != "class" or not n.is_named:
                continue
            name = src.text(n.child_by_field_name("name")).rsplit("::", 1)[-1]
            sup = n.child_by_field_name("superclass")
            base = src.text(sup.named_children[0]) if sup is not None and sup.named_children else ""
            body = statements(n.child_by_field_name("body"))
            if name.endswith("Policy") or base.endswith("Policy") or name == "Scope":
                if name.endswith("Policy"):
                    written = src.text(n.child_by_field_name("name")).removeprefix("::")
                    key = (
                        written
                        if written.startswith("::")
                        else "::".join([*_lexical(src, n), written])
                    )
                    self.policies.setdefault(key.removeprefix("::"), []).append((src, n))
            elif name == "Ability":
                written = src.text(n.child_by_field_name("name"))
                key = (
                    written[2:]
                    if written.startswith("::")
                    else "::".join([*_lexical(src, n), written])
                )
                self.abilities.setdefault(key, []).append((src, n))
            elif "/app/" in f"/{rel}" and (
                base in ("ApplicationRecord", "ActiveRecord::Base") or "/app/models/" in f"/{rel}"
            ):  # never a migration's or a task's stub (`db/migrate`: `class Account < …`)
                if (
                    not base
                    or base.endswith(("Controller", "CurrentAttributes"))
                    or name.endswith("Controller")
                ):
                    continue
                root = root_of(rel, self.roots)
                model = self.by_root.setdefault((name, root), _Model(name))
                # its full name and source: `Billing::Note` is never `Note`, however alike
                qualified = "::".join([*_lexical(src, n), src.text(n.child_by_field_name("name"))])
                self.model_texts.setdefault((name, root), []).append(
                    f"{qualified} {' '.join(src.text(n).split())}"
                )
                self.model_roots.setdefault(name, set()).add(root)
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
                    if s.type == "assignment" and src.text(s.child_by_field_name("left")) in (
                        "self.table_name",
                    ):
                        model.table = symbol(src, s.child_by_field_name("right")) or "?"
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
            root = root_of(src.file.rel, self.roots)
            self.table_roots.setdefault(table, set()).add(root)
            block = n.child_by_field_name("block")
            columns = self.columns_by_root.setdefault((table, root), [])
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
            table = model.table or _table_of(name)
            # owned through a join (`has_many :users, through: :memberships`), or by a user
            # under a name we don't read as an owner (`belongs_to :uploader`): not readable;
            # nor is a model or a table several apps in the checkout define
            if model.linked or model.members or table not in self.columns:
                continue
            if len(self.model_roots.get(name, ())) > 1 or len(self.table_roots.get(table, ())) > 1:
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

    def module_defs(self, name: str) -> list[tuple[Parsed, Node]] | object | None:
        """A module's definitions by the name it's included as: None when the checkout
        doesn't define it, UNREAD when several modules (or apps) share the name."""
        if name in self.qualified:
            defs = self.qualified[name]
        elif "::" in name:
            found = [q for q in self.qualified if q.endswith(f"::{name}")]
            if not found:
                return None  # `Pundit::Authorization`: a gem's, not the app's `Authorization`
            if len(found) > 1:
                return UNREAD
            defs = self.qualified[found[0]]
        else:
            found = [q for q in self.qualified if q.rsplit("::", 1)[-1] == name]
            if not found:
                return None
            if len(found) > 1:
                return UNREAD
            defs = self.qualified[found[0]]
        roots = {root_of(src.file.rel, self.roots) for src, _ in defs}
        return defs if len(roots) == 1 else UNREAD  # `spec/dummy`'s and the app's

    def module(self, name: str) -> tuple[Parsed, Node] | object | None:
        """A module's first definition (see `module_defs`)."""
        found = self.module_defs(name)
        return found[0] if isinstance(found, list) else found  # type: ignore[return-value]

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
            nested = (
                n.type == "module" and src.text(n.child_by_field_name("name")) == "ClassMethods"
            )
            if (n.type == "call" and call_name(src, n) == "class_methods") or nested:
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
        """The class a model's `has_many`/`has_one` association holds; none for a model
        several apps define (theirs may differ)."""
        if len(self.model_roots.get(model or "", ())) > 1:
            return None
        found = self.models.get(model or "")
        return found.associations.get(name) if found is not None else None

    def owner_columns(self, model: str | None) -> set[str]:
        found = self.models.get(model or "")
        cols = set(self.columns.get(_table_of(model or ""), []))
        if found is not None:
            cols |= set(found.belongs) | {f"{b}_id" for b in found.belongs}
        return {c for c in cols if OWNER_CHECK_RX.match(c)}

    def default_policy(self, model: str) -> str:
        """Pundit's own name for a model's policy: its full name and `Policy`
        (`Billing::NotePolicy` for `Billing::Note`)."""
        found = self.models.get(model)
        names = found.qualified if found is not None else set()
        return f"{next(iter(names))}Policy" if len(names) == 1 else f"{model}Policy"

    def policy_name(self, model: str, policy: str | None = None) -> str:
        """The policy Pundit uses: the one named, a `policy_class` the model or a class it
        inherits from defines, else `<Model>Policy`."""
        found, seen = self.models.get(model), set()
        while policy is None and found is not None and found.name not in seen:
            seen.add(found.name)
            policy = found.policy
            found = self.models.get(found.base)
        return (policy or self.default_policy(model)).removeprefix("::")

    def policy(
        self, name: str, scopes: tuple[str, ...] = (), exact: bool = False
    ) -> tuple[Parsed, Node] | None:
        """A policy class by the name it's written as, resolved in Ruby's constant scopes
        (`_scopes`) then at the top; a short name several policies share is unread unless one
        is that exact name; a policy several apps define differently is unread. `exact`:
        Pundit's own `<Model>Policy` lookup, the name alone."""
        name = name.removeprefix("::")
        for q in [*(f"{s}::{name}" for s in scopes if s), name]:
            if q in self.policies:
                return self._one(self.policies[q])
        if exact:
            return None
        found = [q for q in self.policies if q == name or q.endswith(f"::{name}")]
        return self._one(self.policies[found[0]]) if len(found) == 1 else None

    def _one(self, defs: list[tuple[Parsed, Node]]) -> tuple[Parsed, Node] | None:
        """A class defined once, or alike wherever it's defined; else unread."""
        texts = {" ".join(src.text(n).split()) for src, n in defs}
        return defs[0] if len(texts) == 1 else None

    def policy_method(
        self,
        model: str,
        query: str,
        policy: str | None = None,
        lexical: tuple[str, ...] = (),
    ) -> tuple[Parsed, Node] | None:
        """`NotePolicy#destroy?` (through aliases, included modules and policy inheritance);
        None when it can't be read. `lexical`: where a `policy_class:` is written."""
        if model in self.ambiguous and policy is None:
            return None  # which app's model, and so which policy, isn't read
        name = self.policy_name(model, policy)
        # Pundit's own lookup by the model's name; a `policy_class:` resolves where written
        default = policy is None and name == self.default_policy(model)
        found = self.policy(name, () if default else lexical, exact=default)
        seen: set[tuple[str, str]] = set()
        while found is not None and (id(found[1]), query) not in seen:
            seen.add((id(found[1]), query))
            src, cls = found
            # in order, as Ruby defines them: an alias copies what its target is at that point
            # (a `def` above it, else an inherited method by that name)
            defined: dict[str, Node | str] = {}
            includes: list[str] = []
            for m in statements(cls.child_by_field_name("body")):
                if m.type == "call" and call_name(src, m) in ("include", "prepend", "extend"):
                    includes += [src.text(a).removeprefix("::") for a in reversed(args(m))]
                if m.type == "method":
                    defined[src.text(m.child_by_field_name("name"))] = m
                pair: tuple[str | None, str | None] | None = None
                if m.type == "call" and call_name(src, m) == "alias_method" and len(args(m)) == 2:
                    pair = (symbol(src, args(m)[0]), symbol(src, args(m)[1]))
                if m.type == "alias" and len(m.named_children) == 2:
                    pair = (
                        src.text(m.named_children[0]).lstrip(":"),
                        src.text(m.named_children[1]).lstrip(":"),
                    )
                if pair is not None and pair[0] and pair[1]:
                    defined[pair[0]] = defined.get(pair[1], pair[1])
            if includes:
                # its modules aren't read: an included one's `included do`, or a prepended one,
                # may define the method ahead of the class's own
                return None
            last = defined.get(query)
            if isinstance(last, str):
                query = last  # an inherited method's name: read in its parent
            elif last is not None:
                return src, last
            sup = cls.child_by_field_name("superclass")
            parent = (
                src.text(sup.named_children[0]) if sup is not None and sup.named_children else ""
            )
            # a superclass resolves in the scopes around the class, not the class itself
            found = self.policy(parent, tuple(_scopes(src, cls)[1:])) if parent else None
        return None

    def policy_scope(self, model: str, scope: str | None = None) -> tuple[Parsed, Node] | None:
        """`NotePolicy::Scope#resolve`, or the `policy_scope_class:` named."""
        policy, _, inner = (scope or f"{self.policy_name(model)}::Scope").rpartition("::")
        found = self.policy(policy, exact=scope is None and policy == self.default_policy(model))
        if found is None:
            return None
        src, cls = found
        for n in walk(cls):
            if n.type == "class" and src.text(n.child_by_field_name("name")) == inner:
                for m in statements(n.child_by_field_name("body")):
                    if m.type == "method" and src.text(m.child_by_field_name("name")) == "resolve":
                        return src, m
        return None


UNREAD = object()  # a module several definitions share a name with


def app_roots(rels: list[str]) -> list[str]:
    """The apps a checkout holds, longest first: each directory with a `config/routes.rb`
    or `config/application.rb` (an engine, `spec/dummy/`), and the top one ('')."""
    roots = {""}
    for rel in rels:
        for marker in ("config/routes.rb", "config/application.rb"):
            if rel == marker or rel.endswith(f"/{marker}"):
                roots.add(rel[: len(rel) - len(marker)])
    return sorted(roots, key=len, reverse=True)


def root_of(rel: str, roots: list[str]) -> str:
    """The app a file belongs to: the longest app root it lies under."""
    return next((r for r in roots if rel.startswith(r)), "")


def _scopes(src: Parsed, node: Node) -> list[str]:
    """Ruby's constant scopes at a node, innermost first: each class or module around it (or
    it, if it is one), by the name it's written as. `module Admin; class NotesController`
    opens `Admin::NotesController` then `Admin`; a compact `class Admin::NotesController`
    opens only `Admin::NotesController`."""
    written: list[str] = []
    current: Node | None = node
    while current is not None:
        if current.type in ("class", "module") and current.is_named:
            written.append(src.text(current.child_by_field_name("name")))
        current = current.parent
    out: list[str] = []
    outer = ""
    for name in reversed(written):  # outermost first
        outer = name[2:] if name.startswith("::") else (f"{outer}::{name}" if outer else name)
        out.append(outer)
    return out[::-1]


def test_file(rel: str, roots: list[str]) -> bool:
    """A file of a test suite (`spec/support/…`), not of an app; a test app's own files
    (`spec/dummy/app/…`) are its app's."""
    return bool(re.search(r"(^|/)(spec|test)/", rel[len(root_of(rel, roots)) :]))


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


_IRREGULAR = {"person": "people", "man": "men", "child": "children", "woman": "women"}


def _table_of(model: str) -> str:
    """Rails' default table for a model (`Person`: `people`, `Box`: `boxes`)."""
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", model).lower()
    head, _, last = snake.rpartition("_")
    prefix = f"{head}_" if head else ""
    if last in _IRREGULAR:
        return prefix + _IRREGULAR[last]
    if snake.endswith("y") and snake[-2:-1] not in "aeiou":
        return snake[:-1] + "ies"
    if snake.endswith(("s", "x", "z", "ch", "sh")):
        return snake if snake.endswith("s") and not snake.endswith("ss") else snake + "es"
    return snake + "s"


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
        self.reached = _reachable(steps, methods, code=code)
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
        self.request_uses: dict[tuple[str, int, int], str | None] = {}
        self.unread_caller = False
        self.credentials: dict[tuple[str, int, int, int], bool] = {}
        # the session keys written from the request and the caller ivars depend on each
        # other (`session[:uid] = @user.id`): repeat until neither moves
        self.written: set[str] = set()
        self.cleans: dict[tuple[str, int, int], bool] = {}
        self.capped = False
        self.closure = self._closure(self.reached)
        for _ in range(8):
            self.caller_ivars = self._caller_ivars()
            written = self._session_writes()
            if written == self.written:
                break
            self.written = written
            self.credentials.clear()
            self.cleans.clear()
            self.request_uses.clear()
        else:
            self.written = {"*"}
            self.credentials.clear()
            self.cleans.clear()
            self.request_uses.clear()
            self.caller_ivars = self._caller_ivars()
        # a key written that a gem's caller may read: Devise's own (`warden.*`, its remember
        # cookie), or any but the interface's unless the app builds its caller itself (its
        # own `current_user`, or a setter that copies no gem's caller: `Current.session ||=
        # find_session_by_cookie`, not `Current.user = current_user`); we can't tell
        gem = {n for n in _CALLERS if self.methods(n) is None}
        app_caller = self.methods("current_user") is not None or any(
            use.kind == "caller"
            and not use.gem
            and (use.keys is None or "current_user" in use.keys)  # the caller routes read
            and use.value is not None
            and not any(
                (x.type == "identifier" and src.text(x) in gem) or src.text(x) == "warden"
                for x in walk(use.value)
            )
            for src, node, _ in self.closure
            for use in _scan(self.code, src, node)[0]
        )
        if any(
            w == "*"
            or any(fnmatchcase(w, k) for k in _GEM_KEYS)
            or (not app_caller and not any(fnmatchcase(w, k) for k in _UI_KEYS))
            for w in self.written
        ):
            self.unread_caller = True
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

    def chosen(self, src: Parsed, call: Node) -> bool:
        """A record the request picks by a value other than the path id (`Note.destroy(
        params[:x])`), anywhere down the chain (`Locator.locate(params[:x]).destroy`); a
        record's own write (`@note.update(note_params)`) or a credential lookup
        (`AccessToken.find_by(token: request.headers[…])`) isn't one."""
        node: Node | None = call
        for _ in range(_MAX_DEPTH):
            if node is None or node.type != "call":
                return False
            name = call_name(src, node)
            receiver = unwrap(node.child_by_field_name("receiver"))
            requested = _finder(name) and any(self._requested(src, a) for a in args(node))
            own_write = name in _CLASS_WRITES and (
                receiver is None or receiver.type not in ("constant", "scope_resolution")
            )
            if requested and not own_write and not self._credential(src, node, self.caller_ivars):
                return True
            node = receiver
        return False

    def _request_use(self, src: Parsed, node: Node, depth: int = 0) -> str | None:
        """`_request_use`, through the locals an expression reads (`uid = request.headers[…];
        User.find_by(id: uid)`)."""
        key = (src.file.rel, node.start_byte, node.end_byte)
        if key in self.request_uses:
            return self.request_uses[key]
        self.request_uses[key] = None
        found = _request_use(src, node)
        if found != "identity" and depth < 3:
            for n in walk(node):
                if n.type == "identifier" and src.text(n) in self.local_values:
                    for s, v in self.local_values[src.text(n)]:
                        inner = self._request_use(s, v, depth + 1) if v is not None else None
                        if inner == "identity":
                            found = "identity"
                        elif inner == "unread" and found is None:
                            found = "unread"
        self.request_uses[key] = found
        return found

    def _requested(self, src: Parsed, node: Node) -> bool:
        """A value the request picks: its parameters, headers or environment."""
        return self._untrusted(src, node) or bool(_REQUEST_VALUE.search(code_text(src, node)))

    def _credential(self, src: Parsed, node: Node | None, ivars: set[str], depth: int = 0) -> bool:
        """From the session, a cookie, a verified token or the caller (D17, D20); an app
        helper counts by what it returns, never by its name (`decoded_token`); a request
        header naming the user is no credential, whatever else the expression reads."""
        if node is None or self._untrusted(src, node):
            return False
        written = self._reads_written(src, node)
        if written == "forged":
            return False
        if written == "unknown":
            self.unread_caller = True  # it may read a key the route wrote: unknown
        use = self._request_use(src, node)
        if use == "identity":
            return False
        if use == "unread":
            self.unread_caller = True  # the caller comes from code we don't read: unknown
            return True
        if _WARDEN.search(src.text(node)):
            return True
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

    def _closure(self, steps: list[_Step]) -> list[tuple[Parsed, Node, Kind]]:
        """The steps and the bodies of every app method they may call, with arguments or
        not, however spelled (`self.x(…)`, `send(:x, …)`, a bare `x`). Past the cap, the
        route reads as writing a session key we can't name."""
        out: list[tuple[Parsed, Node, Kind]] = []
        seen: set[str] = set()
        queue = [(s.src, s.node, s.kind) for s in steps]
        while queue:
            if len(out) >= _MAX_CLOSURE:
                self.capped = True
                break
            src, node, kind = queue.pop()
            out.append((src, node, kind))
            for name in _scan(self.code, src, node)[1]:
                if name in seen or (found := self.methods(name)) is None:
                    continue
                seen.add(name)
                inner = Kind.CALLBACK if name in _CALLERS else kind
                queue.append((found[0], found[1], inner))  # the whole method, scanned once
        return out

    def _session_writes(self) -> set[str]:
        """The session or signed-cookie keys (`*_return_to` patterns) the route may write
        from anything but a literal or a credential (`session[:user_id] = params[:id]`);
        "*" for a write it can't name, the store handed on, or code past the cap."""
        if self.capped:
            return {"*"}
        out: set[str] = set()
        for src, node, _ in self.closure:
            for use in _scan(self.code, src, node)[0]:
                if use.kind != "write" or (use.keys is not None and out.issuperset(use.keys)):
                    continue  # a key already written from the request
                if not self._clean(src, use.value):
                    if use.keys is None:
                        return {"*"}
                    out |= set(use.keys)
        return out

    def _clean(self, src: Parsed, node: Node | None, depth: int = 0) -> bool:
        """Whether a written value is a literal or a credential the analyzer reads (an unread
        one isn't): `nil`, `current_user.id`, `{ value: current_user.id, httponly: true }`.
        None: a value it can't tell."""
        node = unwrap(node)
        if node is None or depth > 8:
            return False
        key = (src.file.rel, node.start_byte, node.end_byte)
        if key not in self.cleans:
            self.cleans[key] = False  # a cycle through locals reads as unclean
            self.cleans[key] = self._clean_value(src, node, depth)
        return self.cleans[key]

    def _clean_value(self, src: Parsed, node: Node, depth: int) -> bool:
        if _is_literal(node) or _constant_only(src, node):
            return True
        if node.type in ("hash", "right_assignment_list", "array", "argument_list"):
            items = [c for c in node.named_children if c.type != "comment"]
            return all(
                self._clean(
                    src, c.child_by_field_name("value") if c.type == "pair" else c, depth + 1
                )
                for c in items
            )
        # a name is what it holds where it's read: a parameter, a binding we don't follow
        # (`rescue => token`) or a method we can't read holds anything
        opaque = False  # an app method or an instance variable: only a credential is clean
        for n in walk(node):
            if n.type in (
                "instance_variable",
                "class_variable",
                "global_variable",
                "element_reference",
                "self",
            ) or (
                n.type in ("constant", "scope_resolution")
                and src.text(n) not in _PURE_CONSTANTS
                and (n.parent is None or n.parent.type != "scope_resolution")
            ):
                opaque = True  # `@cart`, `Thread.current[:uid]`, `User.first`: state kept elsewhere
            elif n.type == "call" and (
                ((receiver := n.child_by_field_name("receiver")) is None and args(n))
                or (receiver is not None and receiver.type == "self")
            ):
                if self.methods(call_name(src, n)) is None:
                    return False  # a gem's helper (`t(".x")`): it may return anything
                opaque = True
            if n.type != "identifier" or not _helper_name(src, n):
                continue
            held = _local_at(self.code, src, n)
            if held is not None:
                values, param = held
                if param or not all(self._clean(src, v, depth + 1) for v in values):
                    return False
            elif self.methods(src.text(n)) is not None and src.text(n) not in _CALLERS:
                opaque = True
            elif src.text(n) not in _CALLERS:
                return False
        if self._untrusted(src, node):
            return False
        if not opaque:
            return True  # literals, constants, clean locals and the caller (`current_user.id`)
        # a credential the analyzer reads; one from code it can't read isn't clean, and the
        # check leaves no answer behind for the caller's own reading
        saved = (dict(self.credentials), dict(self.request_uses), self.unread_caller)
        self.unread_caller = False
        ok = self._credential(src, node, self.caller_ivars) and not self.unread_caller
        self.credentials, self.request_uses, self.unread_caller = (
            saved[0],
            saved[1],
            saved[2],
        )
        return ok

    def _trusted(self, src: Parsed, node: Node | None, depth: int = 0) -> bool:
        """Whether a caller's setter is given a literal or a credential; one from code we
        can't read counts, and makes the result unknown (as `_credential`)."""
        node = unwrap(node)
        if node is None or depth > 8:
            return False
        if node.type in ("hash", "right_assignment_list", "array", "argument_list"):
            return all(
                self._trusted(
                    src, c.child_by_field_name("value") if c.type == "pair" else c, depth + 1
                )
                for c in node.named_children
                if c.type != "comment"
            )
        for n in walk(node):
            if n.type != "call" or not args(n):
                continue
            receiver = n.child_by_field_name("receiver")
            found = (
                self.methods(call_name(src, n))
                if receiver is None or receiver.type == "self"
                else None
            )
            if found is not None and any(
                self._untrusted(s, b) or self._request_use(s, b) == "identity"
                for s, b, _ in self._closure(
                    [_Step(found[0], b, Kind.CALLBACK) for b in method_body(found[1])]
                )
            ):
                return False  # `find_user(cookies.signed[:id])` that reads `params[:as]`
        return _is_literal(node) or self._credential(src, node, self.caller_ivars)

    def _reads_written(self, src: Parsed, node: Node) -> str | None:
        """Whether a value reads the session where the route wrote what the request chose
        (D20): "forged" for a key it wrote, "unknown" when it may (a key it can't name, the
        whole store, after a write it can't name)."""
        if not self.written:
            return None
        found = None
        for use in _scan(self.code, src, node)[0]:
            if use.kind != "read":
                continue
            if use.keys is None or "*" in self.written or any("*" in k for k in use.keys):
                found = "unknown"
            elif any(fnmatchcase(k, w) for k in use.keys for w in self.written):
                return "forged"
        return found

    def _words(self, src: Parsed, node: Node) -> str:
        """The names an expression calls or reads, not its locals, its strings or the keys it
        filters by (`find_by(id: …, verified: true)`), except a token's (`find_by(token: …)`)."""
        out = []
        for n in walk(node):
            parent = n.parent
            # a token key counts only when it's matched against a value, not a constant
            # (`find_by(token: header)`, never `token_type: "api"`)
            value = (
                parent.child_by_field_name("value")
                if parent is not None and parent.type == "pair"
                else None
            )
            token_key = (
                n.type == "hash_key_symbol"
                and _TOKEN_KEY.search(src.text(n))
                and not _is_literal(value)
                and (value is None or value.type not in ("constant", "scope_resolution"))
            )
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
                if not named and (held := _local_at(self.code, src, n)) is not None and held[1]:
                    continue  # a parameter (`|token|`): whatever it was passed, not its name
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
        for src, node, kind in self.closure:  # helpers taking arguments set ivars too
            params = node.child_by_field_name("parameters") if node.type in _DEFS else None
            for name, right in _scan(self.code, src, node)[2]:
                # set by a helper that takes arguments: from what the call site passed,
                # which we don't read
                assigned.setdefault(name, []).append(
                    (kind, src, None if params is not None and params.named_children else right)
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
            reads = (
                {
                    self._reads_written(s, n)
                    for s, n, _ in self._closure(
                        [_Step(found[0], b, Kind.CALLBACK) for b in method_body(found[1])]
                    )
                }
                if found is not None
                else set()
            )
            if self.capped:
                self.unread_caller = True
            if "forged" in reads:
                out.add(name)  # `def current_user = User.find_by(id: session[:user_id])`
            elif "unknown" in reads:
                self.unread_caller = True
            if found is not None and any(
                self._request_use(s.src, s.node) == "identity"
                or (
                    (self._requested(s.src, s.node) and not self._credential(s.src, s.node, set()))
                    and self._request_use(s.src, s.node) != "unread"
                )
                for s in _reachable(
                    [_Step(found[0], b, Kind.CALLBACK) for b in method_body(found[1])],
                    self.methods,
                )
            ):
                out.add(name)  # `User.find(request.headers["X-User-Id"])`
            if found is None and self.unread(name):
                out.add(name)  # an app `current_user` we can't read may come from params
            if found is not None and self._returns_unset(found):
                out.add(name)  # `def current_user; @user; end` with `@user` from params
            if found is not None and any(
                self._untrusted(s.src, s.node)
                for s in _reachable(
                    [_Step(found[0], b, Kind.CALLBACK) for b in method_body(found[1])],
                    self.methods,
                )
            ):
                out.add(name)
        for src, node, kind in self.closure:
            for use in _scan(self.code, src, node)[0]:
                if use.kind != "caller":
                    continue
                if kind is not Kind.ACTION and self._trusted(src, use.value):
                    continue
                if use.keys is None:
                    self.unread_caller = True  # a setter we can't name may set any caller
                else:
                    out |= set(use.keys)
        return out

    def _returns_unset(self, found: tuple[Parsed, Node]) -> bool:
        """Whether a caller helper reads an ivar it doesn't set itself (`@user`) that the
        action's code sets from anything but a credential, or never sets."""
        steps = _reachable(
            [_Step(found[0], b, Kind.CALLBACK) for b in method_body(found[1])], self.methods
        )
        own = {
            s.src.text(left)
            for s in steps
            for n in walk(s.node)
            if n.type in ("assignment", "operator_assignment")
            and (left := n.child_by_field_name("left")) is not None
        }
        read = {
            s.src.text(n)
            for s in steps
            for n in walk(s.node)
            if n.type == "instance_variable" and not self._narrows_within(s.src, n)
        } - own
        for ivar in read:
            values = [
                (step.kind, step.src, n.child_by_field_name("right"))
                for step in self.reached
                for n in walk(step.node)
                if n.type in ("assignment", "operator_assignment")
                and step.src.text(n.child_by_field_name("left")) == ivar
            ]
            if not values or any(
                kind is Kind.ACTION or not self._credential(src, value, self.caller_ivars)
                for kind, src, value in values
            ):
                return True
        return False

    def _narrows_within(self, src: Parsed, ivar: Node) -> bool:
        """`@tenant.users.find_by(id: session[:user_id])`: the ivar only narrows a lookup
        keyed by a credential; the user still comes from the credential."""
        top: Node = ivar
        while (
            top.parent is not None
            and top.parent.type == "call"
            and (top.parent.child_by_field_name("receiver") == top)
        ):
            top = top.parent
        return (
            top != ivar
            and _finder(call_name(src, top))
            and bool(args(top))
            and all(self._credential(src, a, self.caller_ivars) for a in args(top))
        )

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
            if any(self.chosen(src, c) for c in chain[start:]):
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
    def facts(self, guarded: bool) -> HandlerFacts:
        """The ownership facts; `guarded`: an authenticating callback runs first (D17). A
        caller built by code we can't read (a gem's token decoder) makes the result unknown,
        never protected."""
        self.guarded = guarded
        found = self.run()
        if self.unread_caller and found.handoff is None and self.steps:
            span = self.span(self.steps[0].src, self.steps[0].node)
            found = dataclasses.replace(found, handoff=span)
        return found

    def run(self) -> HandlerFacts:
        if self.cancan[0] and self.model is not None and self.path_ids:
            self.cancan_load()  # by the route's `id`, or the `id_param:` it names
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
        key, field_ = getattr(self, "cancan_key", ("id", "pk"))
        step = self.steps[0] if self.steps else None
        if step is None:
            return
        if key not in self.path_ids:
            self.handoff(step.src, step.node)  # `id_param:` a parameter the route doesn't hold
            return
        lookup = Lookup(self.span(step.src, step.node), record_type=self.model)
        k = self.add(step.src, step.node, lookup, {(key, self.model, field_)}, True)  # type: ignore[arg-type]
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
            elif self.chosen(src, c):
                self.handoff(src, c)  # `GlobalID::Locator.locate(params[:x])`: handed on
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
            params = found[1].child_by_field_name("parameters")
            # `note` in `owner?` is its helper, maybe not the action's local `note`
            clash = (
                any(n.type == "identifier" and src.text(n) in self.locals for n in walk(body[0]))
                if body
                else True
            )
            if (
                len(body) == 1
                and body[0].type not in ("assignment", "operator_assignment")
                and not (params is not None and params.named_children)
                and not clash
            ):
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
                else any(not _is_literal(x) for x in args(n)[1:])  # a header with a value
                if call_name(src, n) == "head"
                else _redirect_leaks(src, n, self.literals)
                for s in stmts
                for n in walk(s)
                if n.type == "call"
                and call_name(src, n) in ("render", "redirect_to", "redirect_back", "head")
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

    def unread(self, name: str) -> bool:
        """Whether the chain may define `name` where it can't be read (an ambiguous module,
        a dynamic definition, a `delegate`)."""
        check = getattr(self.methods, "unread", None)
        return bool(check(name)) if check is not None else False

    def library(self, name: str) -> bool:
        """Whether `authorize`/`authorize!` is the library's: the app doesn't define it, or
        only wraps it (`def authorize(*) = super`)."""
        found = self.methods(name)
        if found is None:
            return not self.unread(name)  # one we can't read may be anything
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
        written_in = tuple(_scopes(src, call))
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
                    _policy_refuses(self.code, m, query or "", policy, lexical=written_in)
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
    steps: list[_Step],
    methods: Callable[[str], tuple[Parsed, Node] | None],
    limit: int = 2000,
    code: RubyCode | None = None,
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
            if code is not None and n.type == "identifier" and _a_local(code, step.src, n):
                continue  # a local there (`helper = "safe"`), not the method
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


@dataclass(frozen=True)
class _Use:
    """A statement's use of the session (`read`, `write`) or of a caller's setter
    (`caller`). `keys`: the store keys (`*_return_to` patterns) or the caller groups; None
    for any. `value`: what it writes; None for one that's never clean."""

    kind: str
    keys: tuple[str, ...] | None
    value: Node | None
    gem: bool = False  # a gem's own setter (`sign_in`, `auto_login`)


@dataclass(frozen=True)
class _Locals:
    params: frozenset[str]
    assigned: tuple[tuple[str, int, int, Node], ...]  # (name, start, end, value), this scope


_SCOPES = ("block", "do_block", "lambda", "method", "singleton_method")
_DEFS = ("method", "singleton_method")
_BOUNDARIES = ("method", "singleton_method", "class", "module", "singleton_class", "program")


def _scan(
    code: RubyCode, src: Parsed, node: Node
) -> tuple[list[_Use], list[str], list[tuple[str, Node | None]]]:
    """What a statement does with the session and the callers' setters, the names of the
    app methods it may call, and the instance variables it assigns."""
    key = (src.file.rel, node.start_byte, node.end_byte)
    if key not in code.scans:
        uses: list[_Use] = []
        names: list[str] = []
        ivars: list[tuple[str, Node | None]] = []
        for n in walk(node):
            if n.type in ("assignment", "operator_assignment"):
                left = n.child_by_field_name("left")
                if left is not None and left.type == "instance_variable":
                    ivars.append((src.text(left), n.child_by_field_name("right")))
            uses += _store_uses(code, src, n) or []
            uses += _caller_uses(src, n) or []
            if n.type == "call":
                receiver = n.child_by_field_name("receiver")
                if receiver is None or receiver.type == "self":
                    names.append(call_name(src, n))
                a = args(n)
                if call_name(src, n) in _SENDS and a and (name := symbol(src, a[0])):
                    names.append(name)
            elif n.type == "identifier" and _helper_name(src, n) and not _a_local(code, src, n):
                names.append(src.text(n))  # a bare name that isn't a local there
        code.scans[key] = (uses, names, ivars)
    return code.scans[key]


def _store_root(code: RubyCode, src: Parsed, n: Node) -> str | None:
    """ "store" for the session, "jar" for the cookie jar, "*" for one reached in a way we
    don't follow (`send(:session)`, `env["rack.session"]`), None for anything else."""
    if n.type == "identifier" and src.text(n) in _STORE_ROOTS:
        parent = n.parent
        if (
            parent is not None
            and parent.type == "call"
            and (parent.child_by_field_name("method") == n)
        ):
            return None  # the call is the mention
        if _local_at(code, src, n) is not None:
            return None  # a local or a parameter named `session`
        return {"session": "store", "session_options": "options"}.get(src.text(n), "jar")
    if n.type == "call" and call_name(src, n) in _STORE_ROOTS:
        receiver = unwrap(n.child_by_field_name("receiver"))
        if receiver is not None and not (
            receiver.type == "self"
            or re.fullmatch(r"@?_?(request|controller)", src.text(receiver).split(".")[-1])
            or (
                receiver.type == "identifier"
                and (held := _local_at(code, src, receiver)) is not None
                and held[1]  # a block's parameter: `before_action { |c| c.session[…] }`
            )
        ):
            return None  # `account.session`, `Current.session`: another object's attribute
        name = call_name(src, n)
        return {"session": "store", "session_options": "options"}.get(name, "jar")
    if n.type == "call" and call_name(src, n) in _SENDS and args(n):
        return "*" if symbol(src, args(n)[0]) in _STORE_ROOTS else None
    if n.type == "string_content" and "rack.session" in src.text(n):
        return "*"
    if n.type == "scope_resolution" and src.text(n).endswith("RACK_SESSION"):
        return "*"  # `request.env[Rack::RACK_SESSION]`
    if n.type == "self" and n.parent is not None and n.parent.type in ("argument_list", "pair"):
        return "*"  # `Impersonator.call(self, …)`: the controller, session and all
    return None


def _store_uses(code: RubyCode, src: Parsed, n: Node) -> list[_Use] | None:
    """What a mention of the session or the cookie jar does, climbing the expression it's
    in: a read of a key, a write of a key and its value, or a write we can't name."""
    root = _store_root(code, src, n)
    if root is None:
        return None
    unnamed = [_Use("write", None, None)]
    if root == "*":
        return unnamed
    cur = n
    if root == "jar":
        parent = cur.parent
        while _receives(parent, cur) and call_name(src, parent) == "permanent":  # type: ignore[arg-type]
            cur, parent = parent, parent.parent  # type: ignore[union-attr]
        if _receives(parent, cur) and call_name(src, parent) in ("signed", "encrypted"):  # type: ignore[arg-type]
            cur = parent  # type: ignore[assignment]
        elif (
            parent is not None
            and parent.type == "element_reference"
            and parent.child_by_field_name("object") == cur
        ) or (
            _receives(parent, cur) and call_name(src, parent) in ("delete", "[]=", "fetch", "key?")
        ):  # type: ignore[arg-type]
            return []  # a plain cookie: the client sets it anyway (D20 amended)
        else:
            return unnamed  # the jar handed on: `c = cookies`
    keyed, keys = False, None
    if root == "options":
        keyed, keys = True, ("*",)  # `request.session_options[:id] = sid`: any key, any read
    for _ in range(_MAX_DEPTH):
        parent = cur.parent
        if parent is None:
            break
        if parent.type == "element_reference" and parent.child_by_field_name("object") == cur:
            if not keyed:
                index = [c for c in parent.named_children if c != cur]
                keys = _key_patterns(code, src, index[0]) if len(index) == 1 else None
                keyed = True
            cur = parent
            continue
        if _receives(parent, cur):
            name, a = call_name(src, parent), args(parent)
            if keyed:
                if name in _VALUE_READS and parent.child_by_field_name("block") is None:
                    cur = parent  # `session[:ids].first`: still the stored value
                    continue
                return [_Use("write", keys, None)]  # `.replace(…)`, `<<`, `.each { … }`
            if name == "permanent":
                cur = parent
                continue
            if name == "options":
                keyed, keys, cur = True, ("*",), parent  # `session.options[:id] = sid`
                continue
            if name in _STORE_KEY_READS:
                keys = _key_patterns(code, src, a[0]) if a else None
                if name not in ("fetch", "dig"):
                    return [_Use("read", keys, None)]
                keyed, cur = True, parent
                continue
            if name in _STORE_READS:
                if parent.child_by_field_name("block") is not None:
                    return unnamed  # `session.each { |k, v| v.replace(…) }`: the values handed on
                keyed, keys, cur = True, None, parent  # `session.values.first.replace(…)`
                continue
            if name in _STORE_DROPS:
                return []
            if name in ("[]=", "store") and len(a) == 2:
                return [_Use("write", _key_patterns(code, src, a[0]), a[1])]
            found = pairs(src, a) if name in ("update", "merge!", "replace") else None
            if found is not None and parent.child_by_field_name("block") is None:
                return [_Use("write", (k,), v) for k, v in found]
            return unnamed  # `session.tap { … }`, `session.send(:[]=, …)`
        if parent.type in (
            "left_assignment_list",
            "destructured_left_assignment",
            "rest_assignment",
        ):
            cur = parent
            continue
        if parent.type in ("assignment", "operator_assignment") and _inside(
            cur, parent.child_by_field_name("left")
        ):
            if not keyed:
                return unnamed
            whole = parent.child_by_field_name("left") == cur
            return [_Use("write", keys, parent.child_by_field_name("right") if whole else None)]
        if (
            parent.type == "binary"
            and parent.child_by_field_name("left") == cur
            and src.text(parent.child_by_field_name("operator")) == "<<"
        ):
            return [_Use("write", keys if keyed else None, None)]  # `session[:ids] << id`
        if keyed or parent.type == "interpolation":
            return [_Use("read", keys if keyed else None, None)]
        return unnamed  # the store handed on: `s = session`, `Cart.new(session)`
    return unnamed


def _receives(parent: Node | None, node: Node) -> bool:
    return (
        parent is not None
        and parent.type == "call"
        and parent.child_by_field_name("receiver") == node
    )


def _key_patterns(
    code: RubyCode, src: Parsed, node: Node | None, depth: int = 0
) -> tuple[str, ...] | None:
    """The key a store is indexed by: `:user_id`, `"user_id"`, `"#{scope}_return_to"` as
    `*_return_to`, or a local holding only those; None when it can't be named."""
    node = unwrap(node)
    if node is None or depth > 8:
        return None  # past a cycle of locals (`a = b; b = a` in a loop): any key
    if node.type == "string" and any(c.type == "escape_sequence" for c in node.named_children):
        return None  # `"view\x5fas"`: `symbol()` would drop the escape
    if (key := symbol(src, node)) is not None:
        return (key,)
    if node.type == "string":
        parts = [
            glob_escape(src.text(c)) if c.type == "string_content" else "*"
            for c in node.named_children
        ]
        return (
            ("".join(parts),)
            if any(c.type == "string_content" for c in node.named_children)
            else None
        )
    if node.type == "identifier" and (held := _local_at(code, src, node)) is not None:
        values, param = held
        found = [_key_patterns(code, src, v, depth + 1) for v in values]
        if param or not found or None in found:
            return None
        return tuple(k for ks in found for k in ks)  # type: ignore[union-attr]
    return None


def _local_at(code: RubyCode, src: Parsed, node: Node) -> tuple[list[Node], bool] | None:
    """What a bare name holds where it's read, if it's a local there: the values its
    earlier assignments in the scopes around it give, and whether it's also a parameter
    (whose value we don't know); None when it's no local there (a method call)."""
    key = (src.file.rel, node.start_byte, node.end_byte)
    if key not in code.locals_at:
        code.locals_at[key] = _find_local(code, src, node)
    return code.locals_at[key]


def _find_local(code: RubyCode, src: Parsed, node: Node) -> tuple[list[Node], bool] | None:
    name = src.text(node)
    values: list[Node] = []
    loops = [
        a
        for a in _ancestors(node)
        if a.type
        in ("while", "until", "for", "block", "do_block", "while_modifier", "until_modifier")
    ]
    scope = node.parent
    while scope is not None:
        if scope.type in _SCOPES or scope.type in _BOUNDARIES:
            found = _scope_locals(code, src, scope)
            values += [
                v
                for n, start, end, v in found.assigned
                if n == name
                and not start <= node.start_byte < end  # `key = key` reads the earlier one
                # earlier, or later in a loop around the read (its next pass)
                and (end <= node.start_byte or any(_inside_span(start, lp) for lp in loops))
            ]
            if name in found.params:
                return values, True
            if scope.type in _BOUNDARIES:
                break
        scope = scope.parent
    return (values, False) if values else None


def _scope_locals(code: RubyCode, src: Parsed, scope: Node) -> _Locals:
    key = (src.file.rel, scope.start_byte, scope.end_byte)
    if key not in code.scope_locals:
        params = next(
            (
                c
                for c in scope.named_children
                if c.type in ("block_parameters", "method_parameters", "lambda_parameters")
            ),
            None,
        )
        names = (
            frozenset(src.text(p) for p in walk(params) if p.type == "identifier")
            if params
            else frozenset()
        )
        assigned: list[tuple[str, int, Node]] = []
        stack = [c for c in scope.named_children if c != params]
        while stack:
            n = stack.pop()
            if n.type in _SCOPES or n.type in _BOUNDARIES:
                continue  # its own scope
            if n.type in ("assignment", "operator_assignment"):
                left = n.child_by_field_name("left")
                targets = (
                    [left]
                    if left is not None and left.type == "identifier"
                    else [t for t in walk(left) if t.type == "identifier"]
                    if left is not None and left.type == "left_assignment_list"
                    else []
                )
                for t in targets:
                    right = n.child_by_field_name("right")
                    assigned.append((src.text(t), n.start_byte, n.end_byte, right))
            stack += n.named_children
        code.scope_locals[key] = _Locals(names, tuple(assigned))
    return code.scope_locals[key]


def _caller_uses(src: Parsed, n: Node) -> list[_Use] | None:
    """A setter of a caller: `@current_user =`, `Current.user =`, `self.current_user =`,
    `instance_variable_set`, a `send` of one, `warden.set_user`, `sign_in`; a `Current`
    attribute we can't name sets any caller (`Current.session =`)."""
    if n.type in ("assignment", "operator_assignment"):
        left = unwrap(n.child_by_field_name("left"))
        if left is None:
            return None
        targets = (
            [t for t in left.named_children] if left.type == "left_assignment_list" else [left]
        )
        whole = len(targets) == 1
        out = []
        for t in targets:
            groups = _caller_target(src, t)
            if groups is not False:
                out.append(
                    _Use("caller", groups, n.child_by_field_name("right") if whole else None)
                )  # type: ignore[arg-type]
        return out
    if n.type != "call":
        return None
    name, a = call_name(src, n), args(n)
    receiver = unwrap(n.child_by_field_name("receiver"))
    if name == "instance_variable_set" and len(a) == 2:
        ivar = symbol(src, a[0])
        if ivar is None:
            return [_Use("caller", None, a[1])]
        group = _caller_group(ivar)
        return [_Use("caller", (group,), a[1])] if group else None
    if name in _SENDS and a:
        setter = symbol(src, a[0])
        on = src.text(receiver).removeprefix("::") if receiver is not None else "self"
        if setter is None and (on == "self" or on.startswith("Current")):
            return [_Use("caller", None, None)]
        if setter is not None and setter.endswith("="):
            groups = _setter_groups(f"{on}.{setter[:-1]}")
            if groups is not False:
                return [_Use("caller", groups, a[1] if len(a) > 1 else None)]  # type: ignore[arg-type]
        return None
    if name in ("set_user", "store") and receiver is not None and "warden" in src.text(receiver):
        return [_Use("caller", ("current_user",), a[0] if a else None)]
    if (
        name == "set"
        and receiver is not None
        and (src.text(receiver).removeprefix("::") in ("Current", "Current.instance"))
    ):
        found = pairs(src, a)
        if found is None:
            return [_Use("caller", None, None)]  # `Current.set(h)`, `Current.set(**h)`
        uses = []
        for key, value in found:
            groups = _setter_groups(f"Current.{key}")
            if groups is not False:
                uses.append(_Use("caller", groups, value))  # type: ignore[arg-type]
        return uses
    if receiver is None and _SIGN_IN_CALLS.match(name):
        return [_Use("caller", ("current_user",), n.child_by_field_name("arguments"), gem=True)]
    return None


def _caller_target(src: Parsed, target: Node) -> tuple[str, ...] | bool | None:
    """The callers an assignment target sets: a tuple of groups, None for any, False for
    none (a local, another object's attribute)."""
    target = unwrap(target) or target
    if target.type == "instance_variable":
        group = _caller_group(src.text(target))
        return (group,) if group else False
    if target.type == "call":
        return _setter_groups(chain_text(src, target))
    if target.type == "element_reference":
        obj = src.text(target.child_by_field_name("object")).removeprefix("::")
        index = [c for c in target.named_children if c != target.child_by_field_name("object")]
        if obj.startswith("Current"):
            key = symbol(src, index[0]) if len(index) == 1 else None
            return _setter_groups(f"Current.{key}") if key else None
    return False


def _setter_groups(chain: str) -> tuple[str, ...] | bool | None:
    chain = chain.removeprefix("::")
    if not chain:
        return False
    if (group := _caller_group(chain)) is not None:
        return (group,)
    head, _, rest = chain.partition(".")
    if head != "Current" or not rest:
        return False
    attr = rest.removeprefix("instance.").removeprefix("attributes.")
    if (group := _caller_group(f"Current.{attr}")) is not None:
        return (group,)
    return False if attr in _CURRENT_PLAIN else None


def _constant_only(src: Parsed, node: Node) -> bool:
    """Built from literals, time and randomness alone (`30.minutes.from_now`,
    `SecureRandom.hex`): no local, parameter, variable, request, bare call, or a store
    another class keeps (`Thread.current[:uid]`, `Rails.cache.read`, `Current.x`)."""
    for n in walk(node):
        if n.type in (
            "instance_variable",
            "class_variable",
            "global_variable",
            "self",
            "element_reference",
        ):
            return False
        if (
            n.type in ("constant", "scope_resolution")
            and src.text(n) not in _PURE_CONSTANTS
            and (n.parent is None or n.parent.type != "scope_resolution")
        ):
            return False  # `Thread.current`, `Rails.cache`, `Current`: state kept elsewhere
        if n.type == "identifier":
            parent = n.parent
            if not (
                parent is not None
                and parent.type == "call"
                and parent.child_by_field_name("method") == n
                and parent.child_by_field_name("receiver") is not None
            ):
                return False
        if n.type == "call" and n.child_by_field_name("receiver") is None:
            return False
    return True


def _a_local(code: RubyCode, src: Parsed, node: Node) -> bool:
    """A bare name that's a local where it stands: assigned there, or read after one."""
    parent = node.parent
    if (
        parent is not None
        and parent.type in ("assignment", "operator_assignment")
        and parent.child_by_field_name("left") == node
    ):
        return True
    return _local_at(code, src, node) is not None


def _ancestors(node: Node) -> Iterator[Node]:
    parent = node.parent
    while parent is not None:
        yield parent
        parent = parent.parent


def _inside_span(at: int, outer: Node) -> bool:
    return outer.start_byte <= at < outer.end_byte


def _inside(node: Node, outer: Node | None) -> bool:
    return outer is not None and outer.start_byte <= node.start_byte < outer.end_byte


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


def _verifies(src: Parsed, call: Node) -> bool:
    """A call that checks a request-supplied secret: `verify…`/`authenticate…`, or a decode
    given a key (`JWT.decode(t, key)`, never `JSON.decode(t)` or `JWT.decode(t, nil, false)`)."""
    name = call_name(src, call)
    if _VERIFYING.match(name):
        return True
    a = args(call)
    return name == "decode" and len(a) >= 2 and a[1].type not in ("nil", "false")


def _request_use(src: Parsed, node: Node, code: RubyCode | None = None) -> str | None:
    """How an expression uses a request header or env value: "identity" when it names the
    caller (`User.find(request.headers["X-User-Id"] || session[:id])`), "unread" when it
    passes through code we don't read (`TokenDecoder.new.call(…)`, an app's
    `decode_token`), None when only a verification reads it (`find_by(token: …)`)."""
    found: str | None = None
    for n in walk(node):
        if n.type not in ("call", "element_reference") or not _REQUEST_VALUE.search(src.text(n)):
            continue
        if not src.text(n).startswith("request."):
            continue
        outer = n.parent if n.parent is not None else n
        if _WARDEN.search(src.text(n)) or _WARDEN.search(src.text(outer)):
            continue  # `request.env["warden"]`: Devise's session
        child, parent, use = n, n.parent, "identity"
        for _ in range(_MAX_CLIMB):
            if parent is None or child == node:
                break
            if parent.type == "pair" and _TOKEN_KEY.search(
                src.text(parent.child_by_field_name("key"))
            ):
                use = ""
                break
            if parent.type == "call" and child != parent.child_by_field_name("receiver"):
                if _verifies(src, parent):
                    use = ""
                    break
                name = call_name(src, parent)
                if not _finder(name) and name not in _PASS_THROUGH:
                    use = "unread"  # a call we don't read decides what it yields
                    break
            child, parent = parent, parent.parent
        if use == "identity":
            return "identity"
        if use == "unread":
            found = "unread"
    return found


# calls a value passes through unchanged for identity purposes
_PASS_THROUGH = {"to_i", "to_s", "presence", "strip", "downcase", "split", "first", "last", "[]"}


def _finder(name: str) -> bool:
    """A read or write of a record by a value (`find`, `find_by_slug!`, `where`,
    `Note.destroy(id)`, `GlobalID::Locator.locate`)."""
    return name in _FINDERS or name.startswith(
        ("find_by", "destroy_by", "delete_by", "find_or_", "create_or_find", "locate")
    )


# writes by id on the class (`Note.update(params[:x], …)`), not a record's own
_CLASS_WRITES = {"destroy", "delete", "update", "update!"}
_FINDERS = {
    "find",
    "find!",
    "where",
    "find_sole_by",
    "exists?",
    "find_signed",
    "find_signed!",
    "destroy",
    "delete",
    "update",
    "update!",
}


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
        # `head :forbidden, "X-Note-Title" => @note.title`: headers carrying a value
        extra = [x for x in a[1:] if not _is_literal(x)]
        return (status in _REFUSING_STATUS or status in _REFUSING_CODES) and not extra
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
            if (
                n.type == "call"
                and not (
                    call_name(src, n) in ("t", "translate")
                    and chain_text(src, n.child_by_field_name("receiver")) in ("", "I18n")
                    and all(_is_literal(a) for a in args(n))
                )
                and not (  # `{ error: "Forbidden" }.to_json`
                    call_name(src, n) in ("to_json", "to_s", "freeze", "to_h")
                    and _is_literal(n.child_by_field_name("receiver"))
                    and not args(n)
                )
            ):
                return True
    return False


def _redirect_leaks(src: Parsed, node: Node, safe: set[str]) -> bool:
    """A redirect carrying a value in its flash (`alert: "#{@note.body}"`, `flash: {…}`)."""
    for x in args(node):
        for p in x.named_children if x.type == "hash" else [x]:
            if p.type in ("hash_splat_argument", "splat_argument", "block_argument"):
                return True  # `**{alert: @note.body}`
            if p.type != "pair":
                if _carries(src, p):
                    return True  # a URL built from the record's fields
                continue
            key = symbol(src, p.child_by_field_name("key"))
            if key == "status":
                continue
            value = p.child_by_field_name("value")
            if key == "fallback_location":
                if value is not None and _carries(src, value):
                    return True
                continue
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


def _carries(src: Parsed, node: Node) -> bool:
    """A redirect target that carries a record's fields (`"/x?t=#{@note.body}"`); a record or
    its path (`@note`, `note_path(@note)`) carries only its id."""
    for n in walk(node):
        if n.type == "call" and n.child_by_field_name("receiver") is not None:
            receiver = unwrap(n.child_by_field_name("receiver"))
            if (
                receiver is not None
                and receiver.type in ("instance_variable", "identifier")
                and (call_name(src, n) not in ("id", "to_param", "slug"))
            ):
                return True
    return False


def uses_record(
    src: Parsed, node: Node, methods: Callable[[str], tuple[Parsed, Node] | None], depth: int = 0
) -> bool:
    """Whether code may send or act on a record: an instance variable, an exception's record
    (`e.record`, `exception.subject`), the exception itself in a response (`e.note`,
    `e.message`), or a helper doing so."""
    params = node.child_by_field_name("parameters")
    raised = (
        {src.text(x).lstrip("*&") for x in params.named_children} if params is not None else set()
    )
    for n in walk(node):
        if (
            raised
            and n.type == "identifier"
            and src.text(n) in raised
            and n.parent is not None
            and (
                n.parent.type != "method_parameters"
                and n.parent.type != "block_parameters"
                and n.parent.type != "lambda_parameters"
            )
        ):
            return True
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
    code: RubyCode,
    model: str,
    query: str,
    policy: str | None = None,
    depth: int = 0,
    lexical: tuple[str, ...] = (),
) -> bool | None:
    """Whether `<Model>Policy#<query>` is false for every user who doesn't own the record
    (an admin aside, D10): `record.user == user`, `record.user_id == user.id`; None when the
    policy can't be read."""
    found = code.policy_method(model, query, policy, lexical)
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
        return _policy_refuses(
            code, model, src.text(expr), policy, depth + 1, lexical
        )  # `= update?`
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
    sup = cls.child_by_field_name("superclass")
    if sup is not None or any(n.type in ("super", "zsuper") for n in walk(cls)):
        return None  # `class Ability < BaseAbility`, `super`: rules a parent adds (ORed in)
    if any(
        n.type == "call"
        and call_name(src, n) in ("send", "public_send", "__send__", "instance_eval")
        for n in walk(cls)
    ):
        return None  # `send(:can, :manage, Note)`: rules we don't read
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
    rules = [
        n
        for n in walk(cls)
        if n.type == "call"
        and (
            n.child_by_field_name("receiver") is None
            or src.text(n.child_by_field_name("receiver")) == "self"  # `self.can :manage, …`
        )
    ]
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
        and not _sends(src, body[1])
        and (_stops(src, body[1]) or all(_inert(src, s) for s in body[2:]))
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
        or any(_sends(src, s) for s in stmts)  # `render json: @note unless current_user.admin?`
        # the callback runs on after a response with no `return`: what follows still acts
        or (not any(_stops(src, s) for s in stmts) and not all(_inert(src, s) for s in body[1:]))
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


def _stops(src: Parsed, node: Node) -> bool:
    """A statement that leaves the method: a `return` or a `raise` in it."""
    return any(n.type == "return" or _raises(src, n) for n in walk(node))


def _sends(src: Parsed, node: Node) -> bool:
    """A response that may carry the record: a `render` of a value or a view, a redirect
    carrying it, a `head` with a valued header (the checks D19 applies to a refusal)."""
    for n in walk(node):
        if n.type != "call" or n.child_by_field_name("receiver") is not None:
            continue
        name = call_name(src, n)
        if name == "render" and _render_leaks(src, n, set()):
            return True
        if name in ("redirect_to", "redirect_back") and _redirect_leaks(src, n, set()):
            return True
        if name == "head" and any(not _is_literal(x) for x in args(n)[1:]):
            return True
    return False


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


def prepare(
    code: RubyCode,
    steps: list[tuple[Parsed, Node, Kind]],
    path_ids: set[str],
    *,
    methods: Callable[[str], tuple[Parsed, Node] | None],
    action: str,
    model: str | None,
    cancan: tuple[bool, bool],
    raises: bool = True,
    cancan_key: tuple[str, str] = ("id", "pk"),
) -> _Action:
    """An action read from the statements it runs in order (its callbacks', then its own):
    `forged` names the callers the request may choose; `facts()` gives its ownership facts.
    `cancan`: whether `load_resource` and `authorize_resource` run for it."""
    walk_ = _Action(
        code,
        [_Step(s, n, kind) for s, n, kind in steps],
        path_ids,
        True,
        methods,
        action,
        model,
        cancan,
        raises,
    )
    walk_.cancan_key = cancan_key
    return walk_


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
    """An action's ownership facts (see `prepare`)."""
    walk_ = prepare(
        code,
        steps,
        path_ids,
        methods=methods,
        action=action,
        model=model,
        cancan=cancan,
        raises=raises,
    )
    return walk_.facts(guarded)
