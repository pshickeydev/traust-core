"""Ownership of the object an Express id route acts on, read from its handler and the
same-repository functions it calls. Protection counts only from allow-listed shapes (D8)."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_ownership import (
    OWNER_CHECK_RX,
    OWNER_FIELD_RX,
    HandlerFacts,
    Lookup,
)
from traust_core.v1.providers.syntax import Node, Parsed, walk

_FUNCTIONS = (
    "arrow_function",
    "function_expression",
    "function",
    "function_declaration",
    "generator_function_declaration",
    "method_definition",
)
_SCOPES = (*_FUNCTIONS, "class_declaration", "class")
_UNWRAP = (
    "await_expression",
    "parenthesized_expression",
    "as_expression",
    "non_null_expression",
    "satisfies_expression",
    "type_assertion",
)
# the store calls a model, delegate or repository answers, and which of them only read
_READS = {
    "findById",
    "findByPk",
    "findUnique",
    "findUniqueOrThrow",
    "findOne",
    "findFirst",
    "findFirstOrThrow",
    "findOneBy",
    "findOneOrFail",
    "findOneByOrFail",
    "findByIdOrFail",
    "get",
}
_WRITES = {
    "findByIdAndUpdate",
    "findByIdAndDelete",
    "findByIdAndRemove",
    "findOneAndUpdate",
    "findOneAndDelete",
    "findOneAndRemove",
    "updateOne",
    "updateMany",
    "deleteOne",
    "deleteMany",
    "update",
    "delete",
    "destroy",
    "remove",
    "upsert",
    "set",
    "save",
}
_STORE_CALLS = _READS | _WRITES | {"find", "findMany", "findAll", "findBy", "count", "exists"}
# fetches that refuse a missing record themselves
_OR_FAIL = {"findUniqueOrThrow", "findFirstOrThrow", "findOneOrFail", "findOneByOrFail"}
_LOOKUP_NAME = re.compile(
    r"^(get|find|fetch|load|read|lookup|select|query|search|retrieve|delete|remove|update|destroy)"
    r"([A-Z_]|$)"
)
_AUTHORIZE_NAME = re.compile(
    r"^(check|verify|authori[sz]e|assert|ensure|require|validate|enforce|can|has|is|owns)([A-Z_]|$)"
)
_VALIDATOR_NAME = re.compile(
    r"^(validate|check|verify|assert|ensure|require)(Id|Ids|Uuid|ObjectId|Param|Params|Input"
    r"|Format|NotEmpty|NotNull)?$|^is(Valid(ObjectId|Id|Uuid)?|UUID|Uuid|MongoId|ObjectId)$"
)
_CONVERSIONS = {
    "Number",
    "String",
    "parseInt",
    "parseFloat",
    "BigInt",
    "ObjectId",
    "Types.ObjectId",
}
_CONVERSION_METHODS = {"toString", "trim", "toLowerCase", "toUpperCase", "valueOf"}
_INERT_ROOTS = re.compile(r"^(console|logger|log|JSON|Math|Object\.keys|debug)$")
_THROWN = re.compile(r"(Error|Exception)$")
_ID_TYPES = re.compile(r"^(\w+\.)*(ObjectId|ObjectID|Number|String|BigInt|Date)$")
_PRIVILEGE_FLAG = re.compile(r"^(is)?(Admin|Superuser|SuperUser|Staff|admin|superuser|staff)$")
_MUTATORS = re.compile(r"^(set\w*|push|splice|assign|update|delete)$")
_MAX_DEPTH = 64
_FUNCTION_VALUES = ("arrow_function", "function_expression", "function")
_Pos = int


def unwrap(node: Node | None) -> Node | None:
    while node is not None and node.type in _UNWRAP:
        node = next(
            (
                c
                for c in node.named_children
                if c.type not in ("type_annotation", "predefined_type")
            ),
            None,
        )
        if node is not None and node.type in ("type_identifier", "generic_type"):
            return None
    return node


def args(call: Node) -> list[Node]:
    a = call.child_by_field_name("arguments")
    return [x for x in a.named_children if x.type != "comment"] if a is not None else []


def own(fn: Node) -> Iterator[Node]:
    """The nodes of `fn`'s own body: nested functions and classes are yielded, not entered."""
    body = fn.child_by_field_name("body")
    stack = [body] if body is not None else []
    while stack:
        node = stack.pop()
        yield node
        if node.type not in _SCOPES:
            stack.extend(node.named_children)


def statements(fn: Node) -> list[Node]:
    """A function body's statements; an arrow's expression body is `return <expr>`."""
    body = fn.child_by_field_name("body")
    if body is None:
        return []
    if body.type != "statement_block":
        return [body]
    return [s for s in body.named_children if s.type not in ("comment", "empty_statement")]


def param_patterns(fn: Node) -> list[Node]:
    single = fn.child_by_field_name("parameter")
    if single is not None:
        return [single]
    params = fn.child_by_field_name("parameters")
    out = []
    for p in params.named_children if params is not None else []:
        if p.type in ("required_parameter", "optional_parameter"):
            pat = p.child_by_field_name("pattern")
            if pat is not None:
                out.append(pat)
        elif p.type == "assignment_pattern":
            out.append(p.child_by_field_name("left"))
        elif p.type != "comment":
            out.append(p)
    return out


def bound_names(src: Parsed, pattern: Node | None) -> list[str]:
    """The names a binding pattern introduces (`{ id, user: me }`, `[a, b]`, `x`)."""
    if pattern is None:
        return []
    if pattern.type in ("identifier", "shorthand_property_identifier_pattern"):
        return [src.text(pattern)]
    out = []
    for c in pattern.named_children:
        if c.type == "pair_pattern":
            out += bound_names(src, c.child_by_field_name("value"))
        elif c.type == "object_assignment_pattern":
            out += bound_names(src, c.child_by_field_name("left"))
        else:
            out += bound_names(src, c)
    return out


def chain_text(src: Parsed, node: Node | None) -> str:
    """`req.user.sub` for a member chain of plain names, else ''."""
    node = unwrap(node)
    if node is None:
        return ""
    if node.type in ("identifier", "this"):
        return src.text(node)
    if node.type == "member_expression":
        base = chain_text(src, node.child_by_field_name("object"))
        prop = node.child_by_field_name("property")
        return f"{base}.{src.text(prop)}" if base and prop is not None else ""
    if node.type == "subscript_expression":
        index = unwrap(node.child_by_field_name("index"))
        base = chain_text(src, node.child_by_field_name("object"))
        if base and index is not None and index.type == "string":
            text = "".join(src.text(c) for c in index.named_children if c.type == "string_fragment")
            return f"{base}.{text}"
    return ""


def callee_name(src: Parsed, call: Node) -> str:
    fn = unwrap(call.child_by_field_name("function"))
    if fn is not None and fn.type == "member_expression":
        return src.text(fn.child_by_field_name("property"))
    return src.text(fn) if fn is not None else ""


def converted(src: Parsed, node: Node | None) -> Node | None:
    """The value `Number(x)`, `parseInt(x, 10)`, `new ObjectId(x)`, `+x` or `x.toString()`
    converts, else None."""
    node = unwrap(node)
    if node is None:
        return None
    if node.type == "unary_expression" and src.text(node.child_by_field_name("operator")) == "+":
        return node.child_by_field_name("argument")
    if node.type not in ("call_expression", "new_expression"):
        return None
    fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
    a = args(node)
    if src.text(fn) in _CONVERSIONS and a and all(x.type == "number" for x in a[1:]):
        return a[0]
    if (
        fn is not None
        and fn.type == "member_expression"
        and not a
        and src.text(fn.child_by_field_name("property")) in _CONVERSION_METHODS
    ):
        return fn.child_by_field_name("object")
    return None


def string_value(src: Parsed, node: Node | None) -> str | None:
    node = unwrap(node)
    if node is not None and node.type == "string":
        return "".join(src.text(c) for c in node.named_children if c.type == "string_fragment")
    return None


# ---- the checkout's code, resolved exactly


@dataclass
class _File:
    src: Parsed
    functions: dict[str, list[Node]] = field(default_factory=dict)
    objects: dict[str, dict[str, Node]] = field(default_factory=dict)  # literal: prop -> fn
    classes: dict[str, Node] = field(default_factory=dict)
    instances: dict[str, str] = field(default_factory=dict)  # name -> constructor text
    models: dict[str, str | None] = field(default_factory=dict)  # name -> record, a store
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)  # local -> (file, export)
    namespaces: dict[str, str] = field(default_factory=dict)  # `import * as m` -> file
    exports: dict[str, str] = field(default_factory=dict)  # exported -> local


@dataclass(frozen=True)
class Target:
    """A checkout function a call runs, and the class it is a method of."""

    rel: str
    fn: Node
    cls: Node | None = None


@dataclass(frozen=True)
class _Model:
    record: str | None  # the record type a model or store holds, when known


class JsCode:
    """Each JS/TS file's functions, object literals, classes, instances, models and stores, its
    imports and exports; and the record types with their fields (for the classification)."""

    def __init__(self, sources: list[Parsed], prisma: list[str]) -> None:
        self.files = {s.file.rel: _File(s) for s in sources}
        self.fields_by_record: dict[str, list[str]] = {}
        self.holds: dict[str, set[str]] = {}
        for f in self.files.values():
            self._index(f)
        for text in prisma:
            self._prisma(text)
        self.fields = self._fields()
        self.scans: dict[tuple, _Scan] = {}

    # -- indexing
    def _resolve_module(self, rel: str, spec: str | None) -> str | None:
        if not spec or not spec.startswith("."):
            return None
        base = posixpath.normpath(posixpath.join(posixpath.dirname(rel), spec))
        stem = (
            posixpath.splitext(base)[0] if posixpath.splitext(base)[1] in (".js", ".ts") else base
        )
        suffixes = (".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
        for candidate in (
            base,
            *(stem + s for s in suffixes),
            *(f"{base}/index{s}" for s in suffixes),
        ):
            if candidate in self.files:
                return candidate
        return None

    def _index(self, f: _File) -> None:
        src, rel = f.src, f.src.file.rel
        for n in walk(src.root):
            t = n.type
            if t == "import_statement":
                where = self._resolve_module(
                    rel, string_value(src, n.child_by_field_name("source"))
                )
                if where is None:
                    continue
                for c in walk(n):
                    if c.type == "import_clause":
                        default = next(
                            (x for x in c.named_children if x.type == "identifier"), None
                        )
                        if default is not None:
                            f.imports[src.text(default)] = (where, "default")
                    elif c.type == "namespace_import":
                        ident = next((x for x in c.named_children if x.type == "identifier"), None)
                        if ident is not None:
                            f.namespaces[src.text(ident)] = where
                    elif c.type == "import_specifier":
                        name, alias = c.child_by_field_name("name"), c.child_by_field_name("alias")
                        f.imports[src.text(alias or name)] = (where, src.text(name))
            elif t == "variable_declarator":
                self._declarator(f, n)
            elif t in ("function_declaration", "generator_function_declaration"):
                name = n.child_by_field_name("name")
                if name is not None:
                    f.functions.setdefault(src.text(name), []).append(n)
                    if n.parent is not None and n.parent.type == "export_statement":
                        default = any(c.type == "default" for c in n.parent.children)
                        f.exports["default" if default else src.text(name)] = src.text(name)
            elif t in ("class_declaration", "class") and (name := n.child_by_field_name("name")):
                f.classes[src.text(name)] = n
                self._class_fields(src, src.text(name), n)
                if n.parent is not None and n.parent.type == "export_statement":
                    default = any(c.type == "default" for c in n.parent.children)
                    f.exports["default" if default else src.text(name)] = src.text(name)
            elif t in ("interface_declaration", "type_alias_declaration"):
                name = n.child_by_field_name("name")
                if name is not None:
                    self._type_fields(src, src.text(name), n)
            elif t == "export_statement":
                self._export(f, n)
            elif t == "assignment_expression":
                self._commonjs_export(f, n)
            elif t == "call_expression":
                self._sequelize_init(src, n)

    def _declarator(self, f: _File, n: Node) -> None:
        src = f.src
        name, value = n.child_by_field_name("name"), unwrap(n.child_by_field_name("value"))
        if name is None or value is None:
            return
        exported = (
            n.parent is not None
            and n.parent.parent is not None
            and (n.parent.parent.type == "export_statement")
        )
        if name.type == "object_pattern" and value.type == "call_expression":
            if callee_name(src, value) == "require":
                where = self._resolve_module(
                    src.file.rel, string_value(src, (args(value) or [None])[0])
                )
                if where is not None:
                    for c in name.named_children:
                        if c.type == "shorthand_property_identifier_pattern":
                            f.imports[src.text(c)] = (where, src.text(c))
                        elif c.type == "pair_pattern":
                            key, val = c.child_by_field_name("key"), c.child_by_field_name("value")
                            if val is not None and val.type == "identifier":
                                f.imports[src.text(val)] = (where, src.text(key))
            return
        if name.type != "identifier":
            return
        local = src.text(name)
        if exported:
            f.exports[local] = local
        if value.type in _FUNCTION_VALUES:
            f.functions.setdefault(local, []).append(value)
        elif value.type == "object":
            f.objects[local] = self._object_functions(src, value)
        elif value.type in ("class", "class_expression"):
            f.classes[local] = value
        elif value.type == "new_expression":
            ctor = src.text(value.child_by_field_name("constructor"))
            f.instances[local] = ctor
            if ctor.rsplit(".", 1)[-1] == "Map":
                typed = value.child_by_field_name("type_arguments")
                kinds = [src.text(c) for c in typed.named_children] if typed is not None else []
                f.models[local] = kinds[-1] if len(kinds) == 2 and kinds[-1] != "any" else None
        elif value.type == "call_expression":
            callee = src.text(value.child_by_field_name("function"))
            a = args(value)
            if callee == "require":
                where = self._resolve_module(src.file.rel, string_value(src, (a or [None])[0]))
                if where is not None:
                    f.imports[local] = (where, "default")
            elif (record := self._model_call(f, value)) is not False:
                f.models[local] = record  # type: ignore[assignment]
            elif (
                len(a) == 1
                and (wrapped := unwrap(a[0])) is not None
                and (wrapped.type in _FUNCTION_VALUES)
            ):
                # `const getOrder = asyncHandler(async (req, res) => …)`: the wrapped function
                f.functions.setdefault(local, []).append(wrapped)

    def _object_functions(self, src: Parsed, obj: Node) -> dict[str, Node]:
        out = {}
        for p in obj.named_children:
            if p.type == "pair":
                value = unwrap(p.child_by_field_name("value"))
                key = src.text(p.child_by_field_name("key"))
                if value is not None and value.type in _FUNCTION_VALUES:
                    out[key] = value
            elif p.type == "method_definition" and (name := p.child_by_field_name("name")):
                out[src.text(name)] = p
        return out

    def _model_call(self, f: _File, call: Node) -> str | bool | None:
        """The record `mongoose.model("Item", schema)`, `sequelize.define("Item", {…})` or
        `getRepository(Item)` is a model of (None when unknown); False when it is no model."""
        src = f.src
        name = callee_name(src, call)
        a = args(call)
        if name == "model" and a and (record := string_value(src, a[0])):
            if len(a) > 1:
                self.fields_by_record.setdefault(record, []).extend(self._schema_fields(f, a[1]))
            return record
        if name == "define" and len(a) >= 2 and (record := string_value(src, a[0])):
            obj = unwrap(a[1])
            if obj is not None and obj.type == "object":
                self.fields_by_record.setdefault(record, []).extend(self._keys(src, obj))
            return record
        if name == "getRepository" and a:
            return src.text(a[0])
        return False

    def _sequelize_init(self, src: Parsed, call: Node) -> None:
        """`Item.init({ … }, { sequelize })`: a Sequelize model class's fields."""
        fn = unwrap(call.child_by_field_name("function"))
        a = [unwrap(x) for x in args(call)]
        if (
            fn is not None
            and fn.type == "member_expression"
            and src.text(fn.child_by_field_name("property")) == "init"
            and len(a) == 2
            and all(x is not None and x.type == "object" for x in a)
            and any(
                (c.type == "shorthand_property_identifier" and src.text(c) == "sequelize")
                or (c.type == "pair" and src.text(c.child_by_field_name("key")) == "sequelize")
                for c in a[1].named_children  # type: ignore[union-attr]
            )
        ):
            name = src.text(fn.child_by_field_name("object"))
            self.fields_by_record.setdefault(name, []).extend(self._keys(src, a[0]))

    def _schema_fields(self, f: _File, node: Node) -> list[str]:
        src = f.src
        node = unwrap(node)
        if node is None:
            return []
        if node.type == "new_expression":
            first = args(node)[:1]
            return self._keys(src, unwrap(first[0])) if first else []
        if node.type == "identifier":
            for d in walk(src.root):
                if d.type == "variable_declarator" and src.text(
                    d.child_by_field_name("name")
                ) == src.text(node):
                    return self._schema_fields(f, d.child_by_field_name("value"))
        return []

    def _keys(self, src: Parsed, obj: Node | None) -> list[str]:
        if obj is None or obj.type != "object":
            return []
        return [
            src.text(p.child_by_field_name("key")).strip("'\"")
            for p in obj.named_children
            if p.type == "pair"
        ] + [src.text(p) for p in obj.named_children if p.type == "shorthand_property_identifier"]

    def _class_fields(self, src: Parsed, name: str, cls: Node) -> None:
        body = cls.child_by_field_name("body")
        fields = [
            src.text(m.child_by_field_name("name") or m.child_by_field_name("property"))
            for m in (body.named_children if body is not None else [])
            if m.type in ("public_field_definition", "field_definition")
        ]
        if fields:
            self.fields_by_record.setdefault(name, []).extend(f for f in fields if f)
            self.holds.setdefault(name, set()).update(
                {
                    src.text(t)
                    for m in body.named_children
                    for t in walk(m)
                    if t.type == "type_identifier"
                }
            )

    def _type_fields(self, src: Parsed, name: str, node: Node) -> None:
        props = [n for n in walk(node) if n.type == "property_signature"]
        if props:
            self.fields_by_record.setdefault(name, []).extend(
                src.text(p.child_by_field_name("name")) for p in props
            )
            self.holds.setdefault(name, set()).update(
                {src.text(t) for p in props for t in walk(p) if t.type == "type_identifier"}
            )

    def _prisma(self, text: str) -> None:
        for name, body in re.findall(r"(?m)^model\s+(\w+)\s*\{([^}]*)\}", text):
            fields = re.findall(r"(?m)^\s*(\w+)\s+(\w+)", body)
            self.fields_by_record.setdefault(name, []).extend(f for f, _ in fields)
            self.holds.setdefault(name, set()).update(kind for _, kind in fields)

    def _export(self, f: _File, n: Node) -> None:
        src = f.src
        if any(c.type == "default" for c in n.children):
            value = unwrap(n.child_by_field_name("value"))
            if value is not None and value.type == "identifier":
                f.exports["default"] = src.text(value)
            elif value is not None and value.type == "new_expression":
                f.instances["<default>"] = src.text(value.child_by_field_name("constructor"))
                f.exports["default"] = "<default>"
            elif value is not None and value.type == "object":
                f.objects["<default>"] = self._object_functions(src, value)
                f.exports["default"] = "<default>"
            elif value is not None and value.type in _FUNCTION_VALUES:
                f.functions.setdefault("<default>", []).append(value)
                f.exports["default"] = "<default>"
            elif value is not None and value.type == "call_expression":
                record = self._model_call(f, value)
                if record is not False:
                    f.models["<default>"] = record  # type: ignore[assignment]
                    f.exports["default"] = "<default>"
        for c in walk(n):
            if c.type == "export_specifier":
                name, alias = c.child_by_field_name("name"), c.child_by_field_name("alias")
                f.exports[src.text(alias or name)] = src.text(name)

    def _commonjs_export(self, f: _File, n: Node) -> None:
        src = f.src
        left, right = n.child_by_field_name("left"), unwrap(n.child_by_field_name("right"))
        target = src.text(left)
        if right is None:
            return
        if target == "module.exports":
            if right.type == "identifier":
                f.exports["default"] = src.text(right)
            elif right.type in _FUNCTION_VALUES:
                f.functions.setdefault("<default>", []).append(right)
                f.exports["default"] = "<default>"
            elif right.type == "object":
                f.objects["<default>"] = self._object_functions(src, right)
                f.exports["default"] = "<default>"
                for p in right.named_children:
                    if p.type == "shorthand_property_identifier":
                        f.exports[src.text(p)] = src.text(p)
                    elif p.type == "pair" and unwrap(p.child_by_field_name("value")) is not None:
                        value = unwrap(p.child_by_field_name("value"))
                        if value.type == "identifier":
                            f.exports[src.text(p.child_by_field_name("key"))] = src.text(value)
            elif right.type == "new_expression":
                f.instances["<default>"] = src.text(right.child_by_field_name("constructor"))
                f.exports["default"] = "<default>"
            elif (
                right.type == "call_expression"
                and (record := self._model_call(f, right)) is not False
            ):
                f.models["<default>"] = record  # type: ignore[assignment]
                f.exports["default"] = "<default>"
        elif target.startswith(("module.exports.", "exports.")):
            key = target.rsplit(".", 1)[-1]
            if right.type in _FUNCTION_VALUES:
                f.functions.setdefault(key, []).append(right)
                f.exports[key] = key
            elif right.type == "identifier":
                f.exports[key] = src.text(right)

    def _fields(self) -> dict[str, tuple[str, ...]]:
        """As for Java and Python: a record that may be owned through another (holding or held
        by another record, pointed at by `<name>Id`) is left out unless it names an owner."""
        records = set(self.fields_by_record)
        held_by_others = {k for n, ts in self.holds.items() for k in ts if k != n and k in records}
        pointed = {
            re.sub(r"_?id$", "", f, flags=re.I).replace("_", "").lower()
            for fs in self.fields_by_record.values()
            for f in fs
            if re.search(r"_id$|(?<=[a-z])Id$", f)
        }
        out = {}
        for name, fs in self.fields_by_record.items():
            linked = (
                not fs
                or bool(self.holds.get(name, set()) & (records - {name}))
                or name in held_by_others
                or name.lower() in pointed
            )
            if any(OWNER_FIELD_RX.match(x) for x in fs) or not linked:
                out[name] = tuple(dict.fromkeys(fs))
        return out

    # -- resolution
    def _local(
        self, rel: str, name: str, seen: frozenset[str] = frozenset()
    ) -> tuple[str, str] | None:
        """The file and local name a name refers to from `rel`, through imports and exports."""
        f = self.files.get(rel)
        if f is None or f"{rel}:{name}" in seen:
            return None
        if (
            name in f.functions
            or name in f.objects
            or name in f.classes
            or name in f.instances
            or name in f.models
        ):
            return rel, name
        if name in f.imports:
            where, exported = f.imports[name]
            target = self.files.get(where)
            if target is None:
                return None
            local = target.exports.get(exported, exported if exported != "default" else "")
            return self._local(where, local, seen | {f"{rel}:{name}"}) if local else None
        return None

    def model(self, rel: str, node: Node | None) -> _Model | None:
        """The model, delegate, repository or store an expression is (`Item`, `prisma.item`,
        `db.Item`, `comments` a `Map`)."""
        node = unwrap(node)
        if node is None:
            return None
        src = self.files[rel].src
        if node.type == "identifier":
            found = self._local(rel, src.text(node))
            if found is None:
                return None
            f = self.files[found[0]]
            if found[1] in f.models:
                return _Model(f.models[found[1]])
            if found[1] in f.classes and found[1] in self.fields_by_record:
                return _Model(found[1])  # `class Item extends Model` (Sequelize)
            return None
        if node.type == "member_expression":
            obj = chain_text(src, node.child_by_field_name("object"))
            prop = src.text(node.child_by_field_name("property"))
            # `prisma.item`, `db.Item`, `models.Item`
            matches = [r for r in self.fields_by_record if r.lower() == prop.lower()]
            if obj.rsplit(".", 1)[-1] in ("prisma", "db", "models", "client", "orm") and matches:
                return _Model(matches[0])
            if obj.rsplit(".", 1)[-1] == "prisma":
                return _Model(None)
            if (
                node.child_by_field_name("object") is not None
                and unwrap(node.child_by_field_name("object")).type == "call_expression"
            ):
                inner = unwrap(node.child_by_field_name("object"))
                if callee_name(src, inner) == "model" and (
                    record := string_value(src, (args(inner) or [None])[0])
                ):
                    return _Model(record)  # `mongoose.model("Item").findById(…)`
        if node.type == "call_expression" and callee_name(src, node) == "model":
            record = string_value(src, (args(node) or [None])[0])
            return _Model(record) if record else None
        return None

    def functions(self, rel: str, node: Node | None, cls: Node | None) -> list[Target] | None:
        """The checkout functions an expression names: [] when none, None when ambiguous."""
        node = unwrap(node)
        if node is None:
            return []
        src = self.files[rel].src
        if node.type == "identifier":
            return self._named(rel, src.text(node))
        if node.type != "member_expression":
            return []
        obj = unwrap(node.child_by_field_name("object"))
        prop = src.text(node.child_by_field_name("property"))
        if obj is None:
            return []
        if obj.type == "this" and cls is not None:
            return self._methods(rel, cls, prop)
        if obj.type == "call_expression" and callee_name(src, obj) == "require":
            # `require("./get-order").default`
            module = self._resolve_module(rel, string_value(src, (args(obj) or [None])[0]))
            exported = self.files[module].exports.get(prop) if module is not None else None
            return self._named(module, exported) if module is not None and exported else []
        if obj.type != "identifier":
            return []
        name = src.text(obj)
        f = self.files[rel]
        found = self._local(rel, name)
        module = f.namespaces.get(name)
        if found is None and name in f.imports and f.imports[name][1] == "default":
            module = f.imports[name][0]  # `const c = require("./c")` with `exports.handler = …`
        exported_object = self.files[found[0]].objects.get(found[1]) if found else None
        if found is None or (
            found[1] == "<default>" and exported_object is not None and prop not in exported_object
        ):
            # `module.exports = { show }`, `show` defined beside it
            module = found[0] if found is not None else module
            exported = self.files[module].exports.get(prop) if module is not None else None
            return self._named(module, exported) if module is not None and exported else []
        where, local = found
        g = self.files[where]
        if local in g.objects:
            fn = g.objects[local].get(prop)
            return [Target(where, fn)] if fn is not None else []
        if local in g.instances:
            cls_found = self._class(where, g.instances[local])
            return self._methods(cls_found[0], cls_found[1], prop) if cls_found else []
        if local in g.classes:
            return self._methods(where, g.classes[local], prop)
        return []

    def _named(self, rel: str, name: str) -> list[Target] | None:
        found = self._local(rel, name)
        if found is None:
            return []
        fns = self.files[found[0]].functions.get(found[1], [])
        if len(fns) > 1:
            return None
        return [Target(found[0], fns[0])] if fns else []

    def _class(self, rel: str, ctor: str) -> tuple[str, Node] | None:
        found = self._local(rel, ctor)
        if found is None:
            return None
        cls = self.files[found[0]].classes.get(found[1])
        return (found[0], cls) if cls is not None else None

    def _methods(self, rel: str, cls: Node, name: str) -> list[Target] | None:
        src = self.files[rel].src
        seen: set[int] = set()
        current: Node | None = cls
        where = rel
        while current is not None and current.start_byte not in seen:
            seen.add(current.start_byte)
            body = current.child_by_field_name("body")
            found = [
                m
                for m in (body.named_children if body is not None else [])
                if m.type == "method_definition" and src.text(m.child_by_field_name("name")) == name
            ]
            if len(found) > 1:
                return None
            if found:
                return [Target(where, found[0], current)]
            heritage = next((c for c in current.named_children if c.type == "class_heritage"), None)
            base = (
                next((c for c in walk(heritage) if c.type == "identifier"), None)
                if heritage
                else None
            )
            nxt = self._class(where, src.text(base)) if base is not None else None
            if nxt is None:
                return []
            where, current = nxt
            src = self.files[where].src
        return []


# ---- one function body


@dataclass
class _Scan:
    facts: HandlerFacts
    verified: set[str] = field(default_factory=set)
    owned_or_null: set[str] = field(default_factory=set)
    covers: tuple[set[str] | None, ...] = ()
    reads: tuple[bool, ...] = ()
    handoff_cover: set[str] | None = None
    pure_read: bool = False


class _Walk:
    """One function: its lookups by id, hand-offs, and the ids each allow-listed statement in its
    body verifies from its end on. `ids`: parameters (or `req.params.<p>` for a handler) that are
    path ids; `callers`: caller roots (`req.user`, or parameters handed the caller)."""

    def __init__(
        self,
        o: ExpressOwnership,
        target: Target,
        ids: set[str],
        path_ids: set[str],
        callers: set[str],
        depth: int,
        handler: tuple[bool, bool],
    ) -> None:
        self.o, self.code, self.rel, self.fn, self.cls = (
            o,
            o.code,
            target.rel,
            target.fn,
            target.cls,
        )
        self.src = self.code.files[self.rel].src
        self.depth = depth
        patterns = param_patterns(self.fn)
        self.params = {n for p in patterns for n in bound_names(self.src, p)}
        # `handler`: whether the first parameter is the request (and the second the response)
        self.req = self.src.text(patterns[0]) if handler[0] and patterns else ""
        self.res = self.src.text(patterns[1]) if handler[1] and len(patterns) > 1 else ""
        self.path_ids = path_ids if self.req else set()
        self.root: dict[str, str] = {i: i for i in ids}
        self.callers = set(callers)
        self.nested = {
            self.src.text(n.child_by_field_name("name")): n
            for n in own(self.fn)
            if n.type in ("function_declaration", "class_declaration")
            and n.child_by_field_name("name")
        }
        self._bind()
        self.lookups: list[Lookup] = []
        self.cover: list[set[str] | None] = []
        self.starts: list[_Pos] = []
        self.reads: list[bool] = []
        self.made: dict[int, list[int]] = {}
        self.consumed: set[int] = set()
        self.raising: set[int] = set()  # lookups whose chain refuses a missing record (`orFail`)
        self.hop_verified: dict[int, set[str]] = {}
        self.hop_owned: dict[int, set[str]] = {}
        self.handoffs: list[tuple[CodeSpan, set[str] | None, _Pos]] = []
        self.hop: CodeSpan | None = None
        self.caller = next(
            (
                self.span(n)
                for n in own(self.fn)
                if n.type == "member_expression" and self.is_caller(n)
            ),
            next(
                (
                    self.span(n)
                    for n in own(self.fn)
                    if n.type == "identifier" and self.src.text(n) in self.callers
                ),
                None,
            ),
        )
        self.verified: dict[str, _Pos] = {}
        self.owned_or_null: dict[str, _Pos] = {}
        self.uncovered: list[tuple[_Pos, _Pos]] = []  # a closing `try`'s `catch` and `finally`

    # -- the id and the caller
    def span(self, node: Node) -> CodeSpan:
        return CodeSpan(path=RepoPath(self.rel), line=self.src.line(node))

    def path_id(self, node: Node | None) -> str | None:
        """`req.params.id` (or `req.params["id"]`) for a path id `id`."""
        text = chain_text(self.src, node)
        if self.req and text.startswith(f"{self.req}.params."):
            name = text.removeprefix(f"{self.req}.params.")
            return name if name in self.path_ids else None
        return None

    def mentions(self, node: Node | None) -> bool:
        """Whether a value carries a path id: an id name, `req.params.<id>`, or `req.params`."""
        if node is None:
            return False
        for n in walk(node):
            if n.type == "identifier" and self.src.text(n) in self.root:
                return True
            if n.type == "shorthand_property_identifier" and self.src.text(n) in self.root:
                return True
            if n.type == "member_expression" and (
                self.path_id(n) is not None
                or (self.req and chain_text(self.src, n) == f"{self.req}.params")
            ):
                return True
        return False

    def exact(self, node: Node | None) -> str | None:
        """The path id a value is exactly: the id, `req.params.id`, or a conversion of it."""
        node = unwrap(node)
        if node is None:
            return None
        if node.type in ("identifier", "shorthand_property_identifier"):
            return self.root.get(self.src.text(node))
        if (pid := self.path_id(node)) is not None:
            return pid
        inner = converted(self.src, node)
        return self.exact(inner) if inner is not None else None

    def exact_ids(self, values: list[Node]) -> set[str] | None:
        roots = [self.exact(v) for v in values if self.mentions(v)]
        return None if not roots or None in roots else {r for r in roots if r}

    def is_caller(self, node: Node | None) -> bool:
        """`req.user`, `req.auth`, `res.locals.user`, or a caller name."""
        node = unwrap(node)
        if node is None:
            return False
        if node.type in ("identifier", "shorthand_property_identifier"):
            return self.src.text(node) in self.callers
        text = chain_text(self.src, node)
        return bool(text) and text in self.caller_paths

    def derived(self, node: Node | None, depth: int = 0) -> bool:
        """`req.user.sub`, `String(me.id)`, `me._id.toString()`: built only from the caller and
        literals (never a fallback, a conditional or another input)."""
        node = unwrap(node)
        if node is None or depth > _MAX_DEPTH:
            return False
        if self.is_caller(node):
            return True
        t = node.type
        if t in ("member_expression", "subscript_expression"):
            if t == "subscript_expression":
                index = unwrap(node.child_by_field_name("index"))
                if index is None or index.type not in ("string", "number"):
                    return False
            return self.derived(node.child_by_field_name("object"), depth + 1)
        if (inner := converted(self.src, node)) is not None:
            return self.derived(inner, depth + 1)
        if t == "template_string":
            subs = [c for c in node.named_children if c.type == "template_substitution"]
            return bool(subs) and all(
                self.derived(next(iter(s.named_children), None), depth + 1) for s in subs
            )
        return False

    def _bind(self) -> None:
        """The id names (`const { id } = req.params`), the caller locals (`const me =
        req.user.id`), and what is rebound or written, which is neither."""
        src = self.src
        self.caller_paths = set()
        if self.o.guarded and self.req:
            self.caller_paths = {f"{self.req}.user", f"{self.req}.auth"}
            if self.res:
                self.caller_paths.add(f"{self.res}.locals.user")
        bindings: dict[str, int] = dict.fromkeys(self.params, 1)
        values: dict[str, list[Node | None]] = {}
        written: set[str] = set()
        for n in own(self.fn):
            if n.type == "variable_declarator":
                pattern, value = n.child_by_field_name("name"), n.child_by_field_name("value")
                if pattern is None:
                    continue
                for name in bound_names(src, pattern):
                    bindings[name] = bindings.get(name, 0) + 1
                    values.setdefault(name, []).append(n)
            elif n.type in ("assignment_expression", "augmented_assignment_expression"):
                left = n.child_by_field_name("left")
                text = chain_text(src, left)
                if left is not None and left.type == "identifier":
                    bindings[text] = bindings.get(text, 0) + 1
                    values.setdefault(text, []).append(None)
                elif text:
                    written.add(text)
            elif n.type == "update_expression":
                written.add(chain_text(src, n.child_by_field_name("argument")))
            elif n.type == "call_expression":
                fn = unwrap(n.child_by_field_name("function"))
                if fn is not None and fn.type == "member_expression":
                    prop = src.text(fn.child_by_field_name("property"))
                    if _MUTATORS.match(prop):
                        written.add(chain_text(src, fn.child_by_field_name("object")))
                if src.text(fn) in ("Object.assign", "Reflect.set") and args(n):
                    written.add(chain_text(src, args(n)[0]))
            elif n.type in ("for_in_statement",):
                for name in bound_names(src, n.child_by_field_name("left")):
                    bindings[name] = bindings.get(name, 0) + 2  # rebound on every pass
        # a caller path written in the handler (`req.user = …`, `req.user.id = …`) isn't the caller
        self.caller_paths = {
            p
            for p in self.caller_paths
            if not any(
                w == p or w.startswith(p + ".") or p.startswith(w + ".") for w in written if w
            )
        }
        self.callers -= {n for n, c in bindings.items() if c > 1}
        self.callers -= {w.split(".", 1)[0] for w in written if w}
        # ids and caller locals, bound once
        for _ in range(3):
            for name, decls in values.items():
                if bindings.get(name, 0) != 1 or len(decls) != 1 or decls[0] is None:
                    continue
                decl = decls[0]
                pattern, value = decl.child_by_field_name("name"), decl.child_by_field_name("value")
                if pattern is None or value is None:
                    continue
                if pattern.type == "object_pattern":
                    base = chain_text(src, value)
                    for c in pattern.named_children:
                        key = (
                            src.text(c.child_by_field_name("key") or c)
                            if c.type != "shorthand_property_identifier_pattern"
                            else src.text(c)
                        )
                        local = bound_names(src, c)[:1]
                        if not local or local[0] != name:
                            continue
                        if self.req and base == f"{self.req}.params" and key in self.path_ids:
                            self.root[name] = key
                        elif base and f"{base}.{key}" in self.caller_paths:
                            self.callers.add(name)
                        elif (
                            self.req
                            and base == self.req
                            and f"{self.req}.{key}" in self.caller_paths
                        ):
                            self.callers.add(name)  # `const { user } = req`
                        elif (
                            base
                            and self.derived(value)
                            and c.type in ("pair_pattern", "shorthand_property_identifier_pattern")
                        ):
                            self.callers.add(name)  # `const { id } = req.user`
                    continue
                if pattern.type != "identifier":
                    continue
                if self.mentions(value) and not self.loads(value):
                    self.root[name] = self.exact(value) or name
                elif name not in written and self.derived(value):
                    self.callers.add(name)
        moved = {n for n, c in bindings.items() if c > 1}
        for n in moved & set(self.root):
            self.root[n] = n
        self.unstable = moved & set(self.root)
        for n in written:
            if n in self.root:
                self.unstable.add(n)
        params = f"{self.req}.params"
        if self.req and any(w == params or w.startswith(params + ".") for w in written):
            self.unstable |= self.path_ids | set(self.root)  # `req.params.id = …`

    def loads(self, value: Node) -> bool:
        """Whether a value is read from something by the id (a call or subscript), not the id."""
        return any(
            (
                n.type in ("call_expression", "new_expression")
                and converted(self.src, n) is None
                and any(self.mentions(a) for a in args(n))
            )
            or (n.type == "subscript_expression" and self.mentions(n.child_by_field_name("index")))
            for n in walk(value)
        )

    # -- recording
    def add(self, node: Node, lookup: Lookup, *, read: bool, cover: set[str] | None) -> int:
        k = len(self.lookups)
        self.lookups.append(lookup)
        self.cover.append(cover)
        self.starts.append(node.start_byte)
        self.reads.append(read)
        self.made.setdefault(self.key(node), []).append(k)
        return k

    def handoff(self, node: Node, cover: set[str] | None) -> None:
        self.handoffs.append((self.span(node), cover, node.start_byte))

    def verify(self, roots: set[str], at: _Pos) -> None:
        for r in roots - self.unstable:
            self.verified[r] = min(at, self.verified.get(r, at))

    @staticmethod
    def key(node: Node) -> int:
        return node.start_byte * 100000 + node.end_byte

    # -- the walk
    def run(self) -> _Scan:
        calls = sorted(
            (
                n
                for n in own(self.fn)
                if n.type in ("call_expression", "new_expression", "subscript_expression")
            ),
            key=lambda n: (n.start_byte, -n.end_byte),
        )
        for n in calls:
            if n.type == "subscript_expression":
                self.subscript(n)
            elif n.type == "new_expression":
                self.creation(n)
            else:
                self.call(n)
        body = statements(self.fn)
        if body and body[-1].type == "try_statement":
            # `try { … } catch (err) { next(err) }` closing the body: its block runs in order, and
            # what `catch` or `finally` runs is never covered by a check inside it
            last = body[-1]
            for name in ("handler", "finalizer"):
                if (part := last.child_by_field_name(name)) is not None:
                    self.uncovered.append((part.start_byte, part.end_byte))
            block = last.child_by_field_name("body")
            body = body[:-1] + [
                s
                for s in (block.named_children if block is not None else [])
                if s.type not in ("comment", "empty_statement")
            ]
        following: list[list[Node]] = [[] for _ in body]
        after: list[Node] = []
        for k in range(len(body) - 1, -1, -1):
            following[k] = after
            if not self.caller_declaration(body[k]):
                after = [body[k], *after[:1]]
        for stmt, nxt in zip(body, following, strict=True):
            self.statement(stmt, nxt)
        returns = [
            s
            for s in body
            if s.type == "return_statement"
            or any(n.type == "return_statement" for n in self._own_of(s))
        ]
        expression_body = (self.fn.child_by_field_name("body") or self.fn).type != "statement_block"
        first = (
            returns[0].start_byte
            if returns
            else (body[0].start_byte if expression_body and body else None)
        )
        return self.result(first, self.pure_read(body))

    def _own_of(self, node: Node) -> Iterator[Node]:
        stack = [node]
        while stack:
            n = stack.pop()
            yield n
            if n.type not in _SCOPES:
                stack.extend(n.named_children)

    def chain(self, call: Node) -> list[Node]:
        """`call` and the calls chained on its result (`.populate(…).orFail().exec()`)."""
        out, node = [call], call
        while True:
            parent = node.parent
            grand = (
                parent.parent if parent is not None and parent.type == "member_expression" else None
            )
            if not (
                grand is not None
                and grand.type == "call_expression"
                and grand.child_by_field_name("function") == parent
            ):
                return out
            out.append(grand)
            node = grand

    def filters(self, value: Node | None) -> list[tuple[str, Node]] | None:
        """The (field, value) equalities a query narrows by (`{ _id: id, owner: me }`, or its
        `where`); None when any is something else (an operator, `$or`, a spread, a computed key)."""
        value = unwrap(value)
        if value is None or value.type != "object":
            return None
        where = next(
            (
                c.child_by_field_name("value")
                for c in value.named_children
                if c.type == "pair" and self.src.text(c.child_by_field_name("key")) == "where"
            ),
            None,
        )
        if where is not None:
            return self.filters(where)  # the rest are options (`include`, Prisma's `data`)
        pairs: list[tuple[str, Node]] = []
        for p in value.named_children:
            if p.type == "shorthand_property_identifier":
                pairs.append((self.src.text(p), p))
            elif p.type == "pair":
                key = p.child_by_field_name("key")
                if key is None or key.type == "computed_property_name":
                    return None
                name = self.src.text(key).strip("'\"")
                v = unwrap(p.child_by_field_name("value"))
                if name.startswith("$") or name in ("OR", "AND", "NOT") or v is None:
                    return None
                if v.type == "object" and (relation := self.relation(v)) is not None:
                    v = relation  # Prisma's `author: { id: me }`
                elif v.type in ("object", "array"):
                    return None  # `{ owner: { $ne: me } }`, `{ id: { in: ids } }`
                pairs.append((name, v))
            elif p.type != "comment":
                return None
        return pairs

    def relation(self, value: Node) -> Node | None:
        """The id a relation filter equals: `{ id: me }`, one plain pair and nothing else."""
        pairs = [c for c in value.named_children if c.type != "comment"]
        if len(pairs) != 1 or pairs[0].type != "pair":
            return None
        key = self.src.text(pairs[0].child_by_field_name("key")).strip("'\"")
        v = unwrap(pairs[0].child_by_field_name("value"))
        return (
            v
            if key in ("id", "_id") and v is not None and v.type not in ("object", "array")
            else None
        )

    def store_call(self, call: Node, model: _Model) -> None:
        name = callee_name(self.src, call)
        a = args(call)
        span = self.span(call)
        links = self.chain(call)
        self.consumed |= {self.key(c) for c in links}
        raising = name in _OR_FAIL or any(callee_name(self.src, c) == "orFail" for c in links[1:])
        if not any(self.mentions(x) for x in a):
            return  # not a load of the path's object (`findById(req.user.id)`)
        objects = [x for x in (unwrap(y) for y in a) if x is not None and x.type == "object"]
        first = unwrap(a[0]) if a else None
        if first is not None and first.type != "object":
            scoped, cover = False, self.exact_ids(a[:1])  # by key: `findById(id)`, `.delete(id)`
        else:
            # the filter: Sequelize's `update(values, { where })` names it second
            query = next((o for o in objects if self.keyed(o, "where")), first)
            pairs = self.filters(query)
            if pairs is None:
                scoped, cover = False, None
            else:
                # shape 1: plain equalities, one on an owner field with a caller-only value
                scoped = any(OWNER_CHECK_RX.match(k) and self.derived(v) for k, v in pairs)
                cover = self.exact_ids([v for _, v in pairs if self.mentions(v)])
            raising = raising or any(self.keyed(o, "rejectOnEmpty") for o in objects)
        read = name in _READS
        k = self.add(
            links[-1], Lookup(span, scoped, record_type=model.record), read=read, cover=cover
        )
        for c in links:
            self.made.setdefault(self.key(c), [])
            if k not in self.made[self.key(c)]:
                self.made[self.key(c)].append(k)
        if raising:
            self.raising.add(k)

    def keyed(self, obj: Node, key: str) -> bool:
        return any(
            c.type == "pair" and self.src.text(c.child_by_field_name("key")).strip("'\"") == key
            for c in obj.named_children
        )

    def subscript(self, node: Node) -> None:
        if self.key(node) in self.consumed or not self.mentions(node.child_by_field_name("index")):
            return
        if self.derived(node.child_by_field_name("object")):
            return
        lookup = Lookup(self.span(node))
        self.add(node, lookup, read=True, cover=self.exact_ids([node.child_by_field_name("index")]))

    def creation(self, node: Node) -> None:
        a = args(node)
        if not any(self.mentions(x) for x in a):
            return
        ctor = self.src.text(node.child_by_field_name("constructor"))
        if _ID_TYPES.match(ctor) or _THROWN.search(ctor):
            return
        self.handoff(node, self.exact_ids([x for x in a if self.mentions(x)]))

    def call(self, call: Node) -> None:
        if self.key(call) in self.consumed:
            return
        src = self.src
        fn = unwrap(call.child_by_field_name("function"))
        a = args(call)
        name = callee_name(src, call)
        receiver = (
            unwrap(fn.child_by_field_name("object"))
            if fn is not None and fn.type == "member_expression"
            else None
        )
        # a store call: a model, delegate, repository or Map
        if (
            receiver is not None
            and (model := self.code.model(self.rel, receiver)) is not None
            and name in _STORE_CALLS
        ):
            self.store_call(call, model)
            return
        refs = (
            {src.text(n) for n in walk(fn) if n.type == "identifier"} & self.nested.keys()
            if fn
            else set()
        )
        handed = {src.text(x) for x in a if x.type == "identifier"} & self.nested.keys()
        if refs or handed:
            if any(self.mentions(self.nested[n]) for n in refs | handed) or (
                refs and any(self.mentions(x) for x in a)
            ):
                self.handoff(call, None)
            if refs:
                return
        used = [x for x in a if self.mentions(x)]
        passes = bool(self.req) and any(
            (x := unwrap(y)) is not None and x.type == "identifier" and src.text(x) == self.req
            for y in a
        )
        if passes and not used and name not in ("next",) and root_of(src, fn) != self.res:
            targets = self.code.functions(self.rel, fn, self.cls)
            if targets is None or (targets and self.depth >= 1):
                self.handoff(call, None)
            elif targets:
                self.hop_into(call, targets)
            return  # a library reading the request (`validationResult(req)`) can't load ours
        if not used:
            if (
                receiver is not None
                and self.mentions(receiver)
                and any(
                    (unwrap(x) is not None and unwrap(x).type in _FUNCTION_VALUES)
                    or (x.type == "identifier" and src.text(x) not in self.root)
                    for x in a
                )
                and not self.loads(receiver)
            ):
                self.handoff(call, None)  # `[req.params.id].forEach(remove)`
            return
        cover = self.exact_ids(used)
        dotted = chain_text(src, fn)
        root = dotted.split(".", 1)[0]
        if (
            dotted in _CONVERSIONS
            or _INERT_ROOTS.match(root)
            or _INERT_ROOTS.match(dotted)
            or _THROWN.search(name)
        ):
            return
        if self.res and root == self.res:
            return  # the response: `res.json(…)`, `res.status(404)`
        if dotted == "next" or (self.req and root == self.req):
            return
        targets = self.code.functions(self.rel, fn, self.cls)
        if targets is None:
            if not _VALIDATOR_NAME.match(name):
                self.handoff(call, cover)
            return
        if targets:
            if self.depth >= 2 or (self.depth == 1 and not _AUTHORIZE_NAME.match(name)):
                if not _VALIDATOR_NAME.match(name):
                    self.handoff(call, cover)
                return
            self.hop_into(call, targets)
            return
        if self.kept(call) and receiver is not None and not self.derived(receiver):
            # shape 4: a kept load we can't follow, handed a caller-only value (owner decision)
            scoped = any(self.derived(x) for x in a)
            self.add(call, Lookup(self.span(call), scoped), read=False, cover=cover)
        elif _LOOKUP_NAME.match(name) and (receiver is None or not self.derived(receiver)):
            self.add(call, Lookup(self.span(call)), read=False, cover=cover)
        elif not _VALIDATOR_NAME.match(name):
            self.handoff(call, cover)

    def kept(self, call: Node) -> bool:
        node = call
        while node.parent is not None and node.parent.type in _UNWRAP:
            node = node.parent
        return node.parent is not None and node.parent.type == "variable_declarator"

    def hop_into(self, call: Node, targets: list[Target]) -> None:
        self.hop = self.hop or self.span(call)
        verified: set[str] | None = None
        owned: set[str] | None = None
        for target in targets:
            scan, exact = self.o.hop(self, target, call)

            def mapped(inner: set[str] | None, exact: dict[str, str] = exact) -> set[str] | None:
                return {exact[p] for p in inner} if inner and inner <= exact.keys() else None

            for x, read, inner in zip(scan.facts.lookups, scan.reads, scan.covers, strict=True):
                lookup = Lookup(x.span, x.scoped, x.checked, x.record_type)
                self.add(call, lookup, read=read and scan.pure_read, cover=mapped(inner))
            self.caller = self.caller or scan.facts.caller
            if scan.facts.handoff:
                self.handoffs.append(
                    (scan.facts.handoff, mapped(scan.handoff_cover), call.start_byte)
                )
            v = {exact[p] for p in scan.verified if p in exact}
            o = {exact[p] for p in scan.owned_or_null if p in exact}
            verified = v if verified is None else verified & v
            owned = o if owned is None else owned & o
        self.hop_verified[self.key(call)] = verified or set()
        self.hop_owned[self.key(call)] = owned or set()

    # -- the allow-listed statements
    def load(self, expr: Node | None) -> int | None:
        """The one read an expression is (a store read, or a hop doing only that), never a
        fallback, a conditional or a write."""
        expr = unwrap(expr)
        if expr is None or expr.type not in ("call_expression", "subscript_expression"):
            return None
        if any(n.type in ("binary_expression", "ternary_expression") for n in walk(expr)):
            return None
        made = {k for n in walk(expr) for k in self.made.get(self.key(n), [])}
        if len(made) != 1:
            return None
        k = next(iter(made))
        return k if self.reads[k] else None

    def declared(self, stmt: Node) -> tuple[str, Node] | None:
        """`const item = <value>` (one plain name), its name and value."""
        if stmt.type not in ("lexical_declaration", "variable_declaration"):
            return None
        decls = [d for d in stmt.named_children if d.type == "variable_declarator"]
        if len(decls) != 1:
            return None
        name, value = decls[0].child_by_field_name("name"), decls[0].child_by_field_name("value")
        if name is None or name.type != "identifier" or value is None:
            return None
        return self.src.text(name), value

    def statement(self, stmt: Node, following: list[Node]) -> None:
        end = stmt.end_byte
        value = None
        if (stmt.type == "expression_statement" and stmt.named_children) or (
            stmt.type == "return_statement" and stmt.named_children
        ):
            value = stmt.named_children[0]
        elif (d := self.declared(stmt)) is not None:
            value = d[1]
        elif stmt.type not in ("lexical_declaration", "variable_declaration") and stmt.type in (
            "call_expression",
            "await_expression",
            "member_expression",
            "identifier",
            "ternary_expression",
            "subscript_expression",
        ):
            value = stmt  # an arrow's expression body
        inner = unwrap(value)
        if inner is not None and inner.type == "call_expression":
            self.verify(self.hop_verified.get(self.key(inner), set()), end)
        k = self.load(value)
        scoped = k is not None and self.lookups[k].scoped
        if scoped and k in self.raising:
            # shape 1, refused when absent: `.orFail()`, `findUniqueOrThrow`, `rejectOnEmpty`
            self.verify(self.cover[k] or set(), end)  # type: ignore[index]
        d = self.declared(stmt)
        if d is None or not following:
            return
        record = d[0]
        nxt = following[0]
        absent = self.refuses_absence(nxt, record)
        if scoped and absent:
            # shape 1: a scoped query's record, then `if (!item) return res.status(404)…`
            self.verify(self.cover[k] or set(), nxt.end_byte)  # type: ignore[index]
        check = following[1] if absent and len(following) > 1 else nxt
        if k is not None and self.refuses_foreign(check, record):
            # shape 2: the load, then a refusal of a record the caller doesn't own
            self.checked(k)
            self.verify(self.cover[k] or set(), check.end_byte)
        elif k is not None and self.returns_if_owned(nxt, record):
            # shape 5: the load, then `return item?.owner === me ? item : undefined`
            self.checked(k)
            self.owned_or_null.update(dict.fromkeys(self.cover[k] or set(), nxt.start_byte))
        elif inner is not None and inner.type == "call_expression" and absent:
            self.verify(self.hop_owned.get(self.key(inner), set()), nxt.end_byte)

    def checked(self, k: int) -> None:
        x = self.lookups[k]
        self.lookups[k] = Lookup(x.span, x.scoped, True, x.record_type)

    def caller_declaration(self, stmt: Node) -> bool:
        d = self.declared(stmt)
        return d is not None and d[0] in self.callers

    # refusals: a 4xx response then return, a throw, or `return next(err)` (owner decision)
    def refusal(self, node: Node | None) -> bool:
        if node is None:
            return False
        if node.type == "statement_block":
            body = [s for s in node.named_children if s.type != "comment"]
            if len(body) == 1:
                return self.refusal(body[0])
            if len(body) == 2 and body[1].type == "return_statement" and not body[1].named_children:
                return self.responds_4xx(body[0]) or self.calls_next(body[0])
            return False
        if node.type == "throw_statement":
            return True
        if node.type == "return_statement" and node.named_children:
            value = unwrap(node.named_children[0])
            return self.responds_4xx(value) or self.calls_next(value)
        return False

    def responds_4xx(self, node: Node | None) -> bool:
        """`res.status(403).json(…)`, `res.sendStatus(404)`: a 4xx response."""
        node = unwrap(node)
        if node is not None and node.type == "expression_statement" and node.named_children:
            node = unwrap(node.named_children[0])
        if node is None or node.type != "call_expression" or not self.res:
            return False
        for n in walk(node):
            if n.type != "call_expression":
                continue
            fn = unwrap(n.child_by_field_name("function"))
            if fn is None or fn.type != "member_expression":
                continue
            if chain_text(self.src, fn.child_by_field_name("object")) != self.res:
                continue
            prop = self.src.text(fn.child_by_field_name("property"))
            status = (args(n) or [None])[0]
            if prop in ("status", "sendStatus") and status is not None:
                code = self.src.text(status)
                return code.isdigit() and 400 <= int(code) < 500
        return False

    def calls_next(self, node: Node | None) -> bool:
        node = unwrap(node)
        if node is not None and node.type == "expression_statement" and node.named_children:
            node = unwrap(node.named_children[0])
        if node is None or node.type != "call_expression":
            return False
        a = args(node)
        return (
            self.src.text(node.child_by_field_name("function")) == "next"
            and len(a) == 1
            and string_value(self.src, a[0]) not in ("route", "router")
        )

    def condition(self, stmt: Node) -> Node | None:
        if stmt.type != "if_statement" or stmt.child_by_field_name("alternative") is not None:
            return None
        if not self.refusal(stmt.child_by_field_name("consequence")):
            return None
        return unwrap(stmt.child_by_field_name("condition"))

    def parts(self, node: Node | None, op: str) -> list[Node]:
        node = unwrap(node)
        if node is None:
            return []
        if (
            node.type == "binary_expression"
            and self.src.text(node.child_by_field_name("operator")) == op
        ):
            return [
                *self.parts(node.child_by_field_name("left"), op),
                *self.parts(node.child_by_field_name("right"), op),
            ]
        return [node]

    def absence(self, node: Node | None, record: str, *, present: bool) -> bool:
        node = unwrap(node)
        if node is None:
            return False
        text = self.src.text
        if (
            not present
            and node.type == "unary_expression"
            and text(node.child_by_field_name("operator")) == "!"
        ):
            arg = unwrap(node.child_by_field_name("argument"))
            return arg is not None and text(arg) == record
        if present and node.type == "identifier":
            return text(node) == record
        if node.type == "binary_expression":
            op = text(node.child_by_field_name("operator"))
            sides = {
                text(unwrap(node.child_by_field_name("left"))),
                text(unwrap(node.child_by_field_name("right"))),
            }
            nothing = {"null", "undefined"}
            wanted = ("!=", "!==") if present else ("==", "===")
            return op in wanted and record in sides and bool(sides & nothing)
        return False

    def refuses_absence(self, stmt: Node, record: str) -> bool:
        test = self.condition(stmt)
        return test is not None and self.absence(test, record, present=False)

    def refuses_foreign(self, stmt: Node, record: str) -> bool:
        """`if (!item || item.owner !== req.user.id) { res.status(403)…; return; }`, also behind
        `!req.user.isAdmin &&` (owner decision 2026-11-02)."""
        test = self.condition(stmt)
        if test is None:
            return False
        ands = self.parts(test, "&&")
        if len(ands) == 2:
            rest = [p for p in ands if not self.unprivileged(p)]
            if len(rest) != 1:
                return False
            test = rest[0]
        elif len(ands) > 2:
            return False
        compared = False
        for part in self.parts(test, "||"):
            if self.absence(part, record, present=False):
                continue
            if not self.compares(part, record, negated=True):
                return False
            compared = True
        return compared

    def unprivileged(self, node: Node | None) -> bool:
        node = unwrap(node)
        if (
            node is None
            or node.type != "unary_expression"
            or self.src.text(node.child_by_field_name("operator")) != "!"
        ):
            return False
        arg = unwrap(node.child_by_field_name("argument"))
        if arg is None or arg.type != "member_expression":
            return False
        prop = self.src.text(arg.child_by_field_name("property"))
        base = unwrap(arg.child_by_field_name("object"))
        return (
            bool(_PRIVILEGE_FLAG.match(prop))
            and base is not None
            and chain_text(self.src, base) in self.caller_paths
        )

    def returns_if_owned(self, stmt: Node, record: str) -> bool:
        """`return item?.owner === me ? item : undefined` (or `null`), optionally `item && …`."""
        if stmt.type != "return_statement" or not stmt.named_children:
            return False
        expr = unwrap(stmt.named_children[0])
        if expr is None or expr.type != "ternary_expression":
            return False
        yes = unwrap(expr.child_by_field_name("consequence"))
        no = unwrap(expr.child_by_field_name("alternative"))
        if (
            yes is None
            or self.src.text(yes) != record
            or no is None
            or no.type not in ("null", "undefined")
        ):
            return False
        compared = False
        for part in self.parts(expr.child_by_field_name("condition"), "&&"):
            if self.absence(part, record, present=True):
                continue
            if not self.compares(part, record, negated=False):
                return False
            compared = True
        return compared

    def compares(self, part: Node | None, record: str, *, negated: bool) -> bool:
        """`item.owner !== me` (`negated`), `item.owner === me`, `item.owner.equals(me)`,
        `String(item.owner) === me`; the owner a member of the record, `me` caller-only."""
        part = unwrap(part)
        if part is None:
            return False
        text = self.src.text
        if part.type == "unary_expression" and text(part.child_by_field_name("operator")) == "!":
            return negated and self.compares(
                part.child_by_field_name("argument"), record, negated=False
            )
        if part.type == "binary_expression":
            op = text(part.child_by_field_name("operator"))
            if op not in (("!==", "!=") if negated else ("===", "==")):
                return False
            sides = (part.child_by_field_name("left"), part.child_by_field_name("right"))
            return any(
                self.owner_of(a, record) and self.derived(b) for a, b in (sides, sides[::-1])
            )
        if not negated and part.type == "call_expression":
            fn = unwrap(part.child_by_field_name("function"))
            a = args(part)
            if (
                fn is not None
                and fn.type == "member_expression"
                and text(fn.child_by_field_name("property")) == "equals"
                and len(a) == 1
            ):
                return self.owner_of(fn.child_by_field_name("object"), record) and self.derived(
                    a[0]
                )
        return False

    def owner_of(self, node: Node | None, record: str) -> bool:
        """`item.owner`, `item?.ownerId`, `item.owner.toString()`, `String(item.owner)`."""
        node = unwrap(node)
        if node is None:
            return False
        if (inner := converted(self.src, node)) is not None:
            return self.owner_of(inner, record)
        if node.type != "member_expression":
            return False
        base = unwrap(node.child_by_field_name("object"))
        prop = self.src.text(node.child_by_field_name("property"))
        if base is not None and base.type == "identifier" and self.src.text(base) == record:
            return bool(OWNER_CHECK_RX.match(prop))
        # `item.owner._id`, `item.author.id`: the owner's own id
        return (
            prop in ("_id", "id")
            and base is not None
            and base.type == "member_expression"
            and self.owner_of(base, record)
        )

    def pure_read(self, body: list[Node]) -> bool:
        """`return <read>`, an arrow returning one, or `const r = <read>; return r`."""
        if not body:
            return False
        last = body[-1]
        value = (
            last.named_children[0]
            if last.type == "return_statement" and last.named_children
            else (
                last
                if last.type
                not in (
                    "return_statement",
                    "expression_statement",
                    "lexical_declaration",
                    "variable_declaration",
                    "if_statement",
                )
                else None
            )
        )
        if value is None:
            return False
        if len(body) == 2 and (d := self.declared(body[0])) is not None:
            if unwrap(value) is None or self.src.text(unwrap(value)) != d[0]:
                return False
            value = d[1]
        elif len(body) != 1:
            return False
        return len(self.lookups) == 1 and self.load(value) == 0

    def result(self, first_return: int | None, pure_read: bool) -> _Scan:
        verified = {r: at for r, at in self.verified.items() if r not in self.unstable}

        def holds(roots: set[str] | None, at: int) -> bool:
            return (
                bool(roots)
                and all(r in verified and verified[r] <= at for r in roots)
                and not any(start <= at < end for start, end in self.uncovered)
            )

        unheld = [(span, roots) for span, roots, at in self.handoffs if not holds(roots, at)]
        handoff, handoff_cover = unheld[0] if unheld else (None, None)
        before = first_return if first_return is not None else 1 << 60
        return _Scan(
            HandlerFacts(
                lookups=tuple(
                    Lookup(
                        x.span,
                        x.scoped,
                        x.checked or (not x.scoped and holds(self.cover[k], self.starts[k])),
                        x.record_type,
                    )
                    for k, x in enumerate(self.lookups)
                ),
                caller=self.caller,
                hop=self.hop,
                handoff=handoff,
            ),
            verified={r for r, at in verified.items() if at <= before}
            & (self.params | self.path_ids),
            owned_or_null={
                r
                for r, at in self.owned_or_null.items()
                if r in (self.params | self.path_ids) - self.unstable and at <= before
            },
            covers=tuple(self.cover),
            reads=tuple(self.reads),
            handoff_cover=handoff_cover,
            pure_read=pure_read,
        )


def root_of(src: Parsed, node: Node | None) -> str:
    return chain_text(src, node).split(".", 1)[0]


def _plain_request(src: Parsed, fn: Node) -> bool:
    patterns = param_patterns(fn)
    return bool(patterns) and all(p.type == "identifier" for p in patterns[:2])


def _flat(nodes: list[Node]) -> Iterator[Node]:
    for node in nodes:
        node = unwrap(node) or node
        if node.type == "array":
            yield from _flat(node.named_children)
        else:
            yield node


class ExpressOwnership:
    """An Express handler's ownership facts. `guarded`: an authenticating middleware runs before
    it, so `req.user` (and `req.auth`, `res.locals.user`) is the caller (owner decision)."""

    def __init__(self, code: JsCode) -> None:
        self.code = code
        self.guarded = False

    def handler(
        self,
        rel: str,
        fn_node: Node,
        path_ids: set[str],
        *,
        guarded: bool,
        middleware: list[Node] = (),  # type: ignore[assignment]
        preloaded: set[str] = frozenset(),  # type: ignore[assignment]
    ) -> HandlerFacts:
        target = self._target(rel, fn_node)
        if target is None:
            span = CodeSpan(path=RepoPath(rel), line=self.code.files[rel].src.line(fn_node))
            return HandlerFacts(handoff=span if path_ids else None, takes_id=bool(path_ids))
        if path_ids & preloaded or not _plain_request(self.code.files[target.rel].src, target.fn):
            # `router.param("id", load)` hands the id to code that runs first, and a destructured
            # request (`({ params }, res) => …`) isn't read: neither is followed
            span = CodeSpan(path=RepoPath(rel), line=self.code.files[rel].src.line(fn_node))
            return HandlerFacts(handoff=span, takes_id=bool(path_ids))
        self.guarded = guarded
        scan = self.scan(target, set(), path_ids, 0)
        # checkout middleware in the route's chain that reads the path (`loadPost, update`): its
        # own lookups count, but nothing it checks covers the handler's
        loaders = [
            self.scan(m, set(), path_ids, 0)
            for node in _flat(middleware)
            if (m := self._target(rel, node)) is not None
            and ".params" in self.code.files[m.rel].src.text(m.fn)
            and _plain_request(self.code.files[m.rel].src, m.fn)
        ]
        facts = [*(s.facts for s in loaders), scan.facts]
        return HandlerFacts(
            lookups=tuple(x for f in facts for x in f.lookups),
            caller=next((f.caller for f in facts if f.caller), None),
            hop=scan.facts.hop,
            handoff=next((f.handoff for f in facts if f.handoff), None),
            takes_id=bool(path_ids),
        )

    def _target(self, rel: str, node: Node) -> Target | None:
        node = unwrap(node)
        if node is None:
            return None
        if node.type in _FUNCTION_VALUES:
            return Target(rel, node)
        if node.type == "call_expression":
            a = args(node)
            inner = unwrap(a[0]) if len(a) == 1 else None
            if inner is not None and (wrapped := self._target(rel, inner)) is not None:
                return wrapped  # `asyncHandler(async (req, res) => …)`
            # a factory: `retrieveBasket()` returning the handler it builds
            found = self.code.functions(rel, node.child_by_field_name("function"), None)
            if not found or len(found) != 1:
                return None
            made = [
                fn
                for s in statements(found[0].fn)
                if (
                    fn := unwrap(
                        s.named_children[0]
                        if s.type == "return_statement" and s.named_children
                        else s
                    )
                )
                is not None
                and fn.type in _FUNCTION_VALUES
            ]
            returns = [n for n in own(found[0].fn) if n.type == "return_statement"]
            expression_body = (
                found[0].fn.child_by_field_name("body") or found[0].fn
            ).type != "statement_block"
            return (
                Target(found[0].rel, made[0])
                if len(made) == 1 and (expression_body or len(returns) == 1)
                else None
            )
        found = self.code.functions(rel, node, None)
        if found and len(found) == 1:
            return found[0]
        return None

    def scan(
        self,
        target: Target,
        ids: set[str],
        path_ids: set[str],
        depth: int,
        handed: set[str] = frozenset(),  # type: ignore[assignment]
        handler: tuple[bool, bool] = (True, True),
    ) -> _Scan:
        guarded = self.guarded and handler[0]
        key = (target.rel, target.fn.start_byte, frozenset(ids), frozenset(path_ids))
        key += (frozenset(handed), depth, handler, guarded)
        if key not in self.code.scans:
            walk_ = _Walk(self, target, ids, path_ids, set(handed), depth, handler)
            self.code.scans[key] = walk_.run()
        return self.code.scans[key]

    def hop(self, walk_: _Walk, target: Target, call: Node) -> tuple[_Scan, dict[str, str]]:
        src = self.code.files[target.rel].src
        patterns = param_patterns(target.fn)
        a = args(call)
        if any(x.type == "spread_element" for x in a) or len(a) > len(patterns):
            return _Scan(HandlerFacts(handoff=walk_.span(call))), {}

        def passed(k: int, name: str) -> bool:
            value = unwrap(a[k]) if k < len(a) else None
            return bool(name) and value is not None and walk_.src.text(value) == name

        # `ctrl.get(req, res)`: the request handed on whole, its path ids with it
        handler = (passed(0, walk_.req), passed(0, walk_.req) and passed(1, walk_.res))
        if any(passed(k, walk_.req) for k in range(1, len(a))) or (
            handler[0] and (patterns[0].type != "identifier")
        ):
            return _Scan(HandlerFacts(handoff=walk_.span(call))), {}
        mapping = {}
        for k, (p, v) in enumerate(zip(patterns, a, strict=False)):
            if k < sum(handler):
                continue
            if p.type != "identifier":
                if walk_.mentions(v):
                    return _Scan(HandlerFacts(handoff=walk_.span(call))), {}  # destructured
                continue
            mapping[src.text(p)] = v
        inner_ids = {p for p, v in mapping.items() if walk_.mentions(v)}
        handed = {p for p, v in mapping.items() if p not in inner_ids and walk_.derived(v)}
        path_ids = walk_.path_ids if handler[0] else set()
        if path_ids & mapping.keys():
            return _Scan(HandlerFacts(handoff=walk_.span(call))), {}  # a parameter named as an id
        scan = self.scan(target, inner_ids, path_ids, walk_.depth + 1, handed, handler)
        exact = {p: r for p, v in mapping.items() if (r := walk_.exact(v))}
        return scan, {**{i: i for i in path_ids}, **exact}
