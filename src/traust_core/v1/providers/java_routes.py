"""Spring MVC/WebFlux and JAX-RS (Quarkus, RESTEasy, Jersey) routes in Java and the guards on
each, parsed with tree-sitter. Guards are method-security annotations,
Spring Security's request-matcher rules (first match wins), Quarkus HTTP permissions, and the
Spring Boot default that authenticates every request when the security starter has no config."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_guards import _guards_in, _mark, _Row, _row, _unique
from traust_core.v1.providers.route_ownership import (
    OWNER_CHECK_RX,
    OWNER_FIELD_RX,
    HandlerFacts,
    Lookup,
    owner_field,
)
from traust_core.v1.providers.syntax import Node, Parsed, walk
from traust_core.v1.providers.syntax import java_parser as parser
from traust_core.v1.providers.tree import TreeFile

SPRING_IMPORT = re.compile(r"\borg\.springframework\.web\.bind\.annotation\b")
JAXRS_IMPORT = re.compile(r"\b(?:javax|jakarta)\.ws\.rs\b")
SPRING_MAPPINGS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
    "RequestMapping": None,
}
JAXRS_VERBS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
_CONTROLLERS = ("RestController", "Controller")
_GUARD_ANNOTATIONS = (
    "PreAuthorize",
    "PostAuthorize",
    "Secured",
    "RolesAllowed",
    "Authenticated",
    "DenyAll",
    "PermissionsAllowed",
)
# Spring enforces these only once method security is enabled; JAX-RS containers enforce them.
_METHOD_SECURITY_ANNOTATIONS = ("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed")
_METHOD_SECURITY = re.compile(r"@Enable(Global|Reactive)?MethodSecurity\b(?:\s*\(([^)]*)\))?")
# the annotation family Spring enables each method-security annotation with
_FAMILY = {
    "PreAuthorize": "prepost",
    "PostAuthorize": "prepost",
    "Secured": "secured",
    "RolesAllowed": "jsr250",
    "PermitAll": "jsr250",
    "DenyAll": "jsr250",
}
_FILTER_CHAIN = re.compile(
    r"\b(?:SecurityFilterChain|SecurityWebFilterChain|WebSecurityConfigurerAdapter)\b"
)
_SECURITY_STARTER = re.compile(r"spring-boot-starter-security")
_MANIFESTS = ("pom.xml", "build.gradle", "build.gradle.kts")
SPRING_DEFAULT_GUARD = "spring-security:default"
METHOD_SECURITY_OFF = "method-security-not-enabled"
CONDITIONAL_CONFIG = "spring-security:conditional-config"
_MATCHERS = {"requestMatchers", "antMatchers", "mvcMatchers", "regexMatchers", "pathMatchers"}
_ANY = {"anyRequest", "anyExchange"}
_OPEN = {"permitAll", "anonymous"}
_DECISIONS = _OPEN | {
    "denyAll",
    "authenticated",
    "fullyAuthenticated",
    "rememberMe",
    "hasRole",
    "hasAnyRole",
    "hasAuthority",
    "hasAnyAuthority",
    "access",
    "hasIpAddress",
}
_QUARKUS_PERMISSION = re.compile(
    r"^quarkus\.http\.auth\.permission\.([^.]+)\.(paths|policy|methods)$"
)
_QUARKUS_REST_PATH = ("quarkus.rest.path", "quarkus.resteasy.path")
_JAXRS = "quarkus.security.jaxrs"
_TYPE_DECLS = ("class_declaration", "interface_declaration")
_PATH_ANNOTATIONS = ("PathVariable", "PathParam")
_CALLER_TYPES = re.compile(
    r"^(Principal|Authentication|\w*AuthenticationToken|Jwt|OAuth2User|OidcUser|UserDetails|"
    r"SecurityContext|SecurityIdentity|JsonWebToken)$"
)
# a parameter Spring fills from the authentication without an annotation
_PARAM_CALLER_TYPES = re.compile(r"^(Principal|Authentication|\w*AuthenticationToken)$")
_CALLER_ANNOTATIONS = ("AuthenticationPrincipal", "CurrentSecurityContext")
_CALLER_CALLS = re.compile(
    r"\b(SecurityContextHolder|getUserPrincipal|getRemoteUser|getCallerPrincipal)\b"
)
_REPOSITORIES = re.compile(r"^\w*(Crud|Jpa|Sorting|Mongo|R2dbc)?Repository(Base)?$|^Panache\w*$")
_ENTITY_MANAGER_LOOKUPS = ("find", "getReference")
_LOOKUP_NAME = re.compile(
    r"^(find|get|load|fetch|read|delete|remove|exists|lookup|select)(?=[A-Z_]|$)"
)
# a store call that only reads (`findById`, `getReferenceById`, a map's `get`)
_READ_NAME = re.compile(r"^(find|get|load|fetch|read|lookup|select|query|search)(?=[A-Z_]|$)")
# a Spring Data derived query (`findByIdAndOwnerId`) and its predicates
_DERIVED_QUERY = re.compile(
    r"(?:find|get|read|query|search|stream|exists|count|delete|remove)\w*?By(\w+?)(?:OrderBy\w+)?"
)
_OR_QUERY = re.compile(r"Or[A-Z]")
_QUERY_OPERATOR = re.compile(
    r"(Not|Like|Containing|Contains|In|Between|LessThan|LessThanEqual|GreaterThan|GreaterThanEqual"
    r"|Before|After|Null|True|False|StartingWith|StartsWith|EndingWith|EndsWith|IgnoreCase|Regex"
    r"|Matches|Exists|Near|Within|Empty)$"
)
# the value types an id is converted into (`new DeviceId(…)`), and what's thrown with one
_ID_TYPE = re.compile(r"^(\w*(Id|ID|Key|Uuid|UUID)|Long|Integer|Short|String|BigInteger|ObjectId)$")
_THROWN = re.compile(r"\w*(Exception|Error)$")
# calls that act on a loaded result, not on the id
_RESULT_CALLS = frozenset(
    {"orElseThrow", "orElse", "orElseGet", "get", "map", "flatMap", "filter", "ifPresent"}
    | {"ifPresentOrElse", "isPresent", "isEmpty", "stream", "toList", "collect", "findFirst"}
)
# store calls that take an id with no lookup-shaped name: JPQL parameters, JdbcTemplate
_QUERY_CALLS = ("setParameter", "queryForObject", "queryForList", "queryForMap", "query", "update")
# an authorization-shaped helper earns a second hop (never credit by its name)
_AUTHORIZE_NAME = re.compile(
    r"^(check|verify|authori[sz]e|assert|ensure|require|validate|enforce|can|has|is|owns)(?=[A-Z_]|$)"
)
# a check of the id's form (`validateId`, `checkNotNull`) is presumed not to act on the object
_VALIDATOR_NAME = re.compile(
    r"^(validate|check|verify|assert|ensure|require)(Not(Null|Empty|Blank)|Non(Null|Empty|Blank)"
    r"|Valid|Id|Ids|Uuid|UUID|Param|Parameter|Parameters|Params|Arg|Argument|Arguments|Format"
    r"|Length|Size|Range|Positive|Input)?$"
)
# receivers of an id that don't act on the object
_INERT_RECEIVERS = re.compile(
    r"^(log|logger|LOG|LOGGER|System\.(out|err)|Objects|Assert|Preconditions|Validate|String"
    r"|StringUtils|Math|Integer|Long|UUID|Optional|List|Set|Map|Arrays|Collections)$"
)
# a value derived from a path id (`new DeviceId(toUUID(id))`, `UUID.fromString(id)`) is that id
_CONVERSION = re.compile(
    r"^(to[A-Z]\w*|from[A-Z]\w*|parse\w*|valueOf|of|decode|trim|strip|format)$"
)
# shape 3: exactly one bean call (`@access.canRead(#id, authentication)`)
_SPEL_SINGLE_BEAN = re.compile(r'@PreAuthorize\(\s*"\s*@\w+\.\w+\(([^()]*)\)\s*"\s*\)')
_MAPPING_VERBS = {
    "GetMapping": False,
    "PostMapping": True,
    "PutMapping": True,
    "DeleteMapping": True,
    "PatchMapping": True,
    "GET": False,
    "POST": True,
    "PUT": True,
    "DELETE": True,
    "PATCH": True,
}


def _name(src: Parsed, ann: Node) -> str:
    return src.text(ann.child_by_field_name("name")).rsplit(".", 1)[-1]


def _annotations(src: Parsed, decl: Node) -> dict[str, Node]:
    mods = next((c for c in decl.named_children if c.type == "modifiers"), None)
    if mods is None:
        return {}
    return {
        _name(src, a): a
        for a in mods.named_children
        if a.type in ("annotation", "marker_annotation")
    }


def _items(node: Node) -> list[Node]:
    if node.type == "element_value_array_initializer":
        return [c for c in node.named_children if c.type != "comment"]
    return [node]


def _attr(src: Parsed, ann: Node, *keys: str) -> list[Node]:
    """An annotation attribute's values; a bare value is `value`."""
    args = ann.child_by_field_name("arguments")
    found: list[Node] = []
    for c in args.named_children if args is not None else []:
        if c.type == "element_value_pair":
            if src.text(c.child_by_field_name("key")) in keys:
                found += _items(c.child_by_field_name("value"))
        elif c.type != "comment" and "value" in keys:
            found += _items(c)
    return found


@dataclass
class _Type:
    src: Parsed
    node: Node
    name: str
    interface: bool
    abstract: bool
    supers: list[str]
    annotations: dict[str, Node]
    methods: dict[str, Node]


def _types(src: Parsed) -> list[_Type]:
    found = []
    for n in walk(src.root):
        if n.type not in _TYPE_DECLS:
            continue
        supers = [
            src.text(t).split("<", 1)[0].rsplit(".", 1)[-1].strip()
            for c in n.named_children
            if c.type in ("superclass", "super_interfaces", "extends_interfaces")
            for t in (
                c.named_children[0].named_children
                if c.named_children and c.named_children[0].type == "type_list"
                else c.named_children
            )
        ]
        body = n.child_by_field_name("body")
        methods = {
            src.text(m.child_by_field_name("name")): m
            for m in (body.named_children if body is not None else [])
            if m.type == "method_declaration"
        }
        mods = next((c for c in n.named_children if c.type == "modifiers"), None)
        found.append(
            _Type(
                src,
                n,
                src.text(n.child_by_field_name("name")),
                n.type == "interface_declaration",
                mods is not None and "abstract" in src.text(mods).split(),
                supers,
                _annotations(src, n),
                methods,
            )
        )
    return found


class _Constants:
    """String constants (`static final String BASE = "/v1"`), by simple and `Class.NAME`."""

    def __init__(self, sources: list[Parsed]) -> None:
        self.values: dict[str, str] = {}
        pending: list[tuple[Parsed, str, Node]] = []
        for src in sources:
            for n in walk(src.root):
                if n.type != "field_declaration":
                    continue
                if src.text(n.child_by_field_name("type")) != "String":
                    continue
                cls = next((p for p in _ancestors(n) if p.type in _TYPE_DECLS), None)
                owner = src.text(cls.child_by_field_name("name")) if cls is not None else ""
                for d in n.named_children:
                    if d.type == "variable_declarator" and d.child_by_field_name("value"):
                        name = src.text(d.child_by_field_name("name"))
                        pending += [(src, name, d.child_by_field_name("value"))]
                        pending += [(src, f"{owner}.{name}", d.child_by_field_name("value"))]
        for _ in range(3):  # constants built from constants
            for src, key, value in pending:
                if key not in self.values and (v := self.resolve(src, value)) is not None:
                    self.values[key] = v

    def resolve(self, src: Parsed, node: Node | None) -> str | None:
        if node is None:
            return None
        if node.type == "string_literal":
            return "".join(src.text(c) for c in node.named_children if c.type == "string_fragment")
        if node.type == "parenthesized_expression" and node.named_children:
            return self.resolve(src, node.named_children[0])
        operator = src.text(node.child_by_field_name("operator"))
        if node.type == "binary_expression" and operator == "+":
            left = self.resolve(src, node.child_by_field_name("left"))
            right = self.resolve(src, node.child_by_field_name("right"))
            return left + right if left is not None and right is not None else None
        if node.type == "identifier":
            return self.values.get(src.text(node))
        if node.type == "field_access":
            owner = src.text(node.child_by_field_name("object")).rsplit(".", 1)[-1]
            return self.values.get(f"{owner}.{src.text(node.child_by_field_name('field'))}")
        return None


def _ancestors(node: Node) -> list[Node]:
    found = []
    while node.parent is not None:
        node = node.parent
        found.append(node)
    return found


def _join(*parts: str) -> str:
    segments = [p.strip("/") for p in parts if p.strip("/")]
    return "/" + "/".join(segments)


def _sample(path: str) -> str:
    """A concrete path a route pattern serves, for matching it against security rules."""
    return re.sub(r"\{[^}]*\}", "x", path)


def _ant(pattern: str) -> re.Pattern[str]:
    out = ""
    for token in re.split(r"(\*\*|\*|\?|\{[^}]*\})", pattern):
        if token == "**":
            out += ".*"
        elif token == "*":
            out += "[^/]*"
        elif token == "?":
            out += "[^/]"
        elif token.startswith("{"):
            out += ".*" if token.startswith("{*") else "[^/]+"
        else:
            out += re.escape(token)
    return re.compile(out.replace("/.*", "(/.*)?") + "/?")


@dataclass
class _Rule:
    patterns: list[re.Pattern[str]] | None  # None: any request
    methods: set[str] | None
    guard: str
    opens: bool

    def matches(self, method: str, path: str) -> bool:
        # a verb-restricted rule only opens, never guards, a route that takes every verb
        if (
            self.methods is not None
            and method not in self.methods
            and not (method == "ALL" and self.opens)
        ):
            return False
        return self.patterns is None or any(p.fullmatch(path) for p in self.patterns)


@dataclass
class _Chain:
    scope: list[re.Pattern[str]] | None
    conditional: bool = False  # its bean exists only under a property or profile
    rules: list[_Rule] = field(default_factory=list)

    def covers(self, path: str) -> bool:
        return self.scope is None or any(p.fullmatch(path) for p in self.scope)


def _matcher_args(
    src: Parsed, consts: _Constants, call: Node
) -> tuple[list[re.Pattern[str]], set[str] | None]:
    args = call.child_by_field_name("arguments")
    patterns: list[re.Pattern[str]] = []
    methods: set[str] = set()
    for a in args.named_children if args is not None else []:
        owner = src.text(a.child_by_field_name("object")) if a.type == "field_access" else ""
        if owner.endswith("HttpMethod"):
            methods.add(src.text(a.child_by_field_name("field")))
            continue
        value = consts.resolve(src, a)
        if value is None:  # new AntPathRequestMatcher("/x"), mvc.pattern("/x")
            strings = (s for s in walk(a) if s.type == "string_literal")
            value = next((consts.resolve(src, s) for s in strings), None)
        if value is not None:
            patterns.append(_ant(value))
    return patterns, methods or None


def _chains(sources: list[Parsed], consts: _Constants) -> list[_Chain]:
    """Spring Security filter chains, the scoped (`securityMatcher`) ones first, each with its
    authorization rules in declaration order."""
    chains: list[_Chain] = []
    for src in sources:
        if not _FILTER_CHAIN.search(src.file.text):
            continue
        for method in (n for n in walk(src.root) if n.type == "method_declaration"):
            calls = sorted(
                (n for n in walk(method) if n.type == "method_invocation"),
                key=lambda n: n.child_by_field_name("name").start_byte,
            )
            cls = next((a for a in _ancestors(method) if a.type == "class_declaration"), None)
            anns = [*_annotations(src, method), *(_annotations(src, cls) if cls else {})]
            chain = _Chain(None, any(a.startswith("Conditional") or a == "Profile" for a in anns))
            for call in calls:
                name = src.text(call.child_by_field_name("name"))
                if name in ("securityMatcher", "securityMatchers", "requestMatcher"):
                    scope, _ = _matcher_args(src, consts, call)
                    chain.scope = (chain.scope or []) + scope
                if name not in _DECISIONS:
                    continue
                target = call.child_by_field_name("object")
                target_name = (
                    src.text(target.child_by_field_name("name"))
                    if (target is not None and target.type == "method_invocation")
                    else ""
                )
                if target_name in _ANY:
                    patterns, methods = None, None
                elif target_name in _MATCHERS:
                    patterns, methods = _matcher_args(src, consts, target)
                    if not patterns and methods is None:
                        continue
                    patterns = patterns or None
                else:
                    continue
                full = src.text(call.child_by_field_name("arguments")).strip("()")
                args = full[:60] + ("…" if len(full) > 60 else "")
                chain.rules.append(
                    _Rule(
                        patterns,
                        methods,
                        f"spring-security:{name}" + (f"({args})" if args else ""),
                        name in _OPEN,
                    )
                )
            if chain.rules:
                chains.append(chain)
    return sorted(chains, key=lambda c: c.scope is None)


@dataclass
class _Quarkus:
    permissions: list[tuple[str, set[str] | None, str]] = field(default_factory=list)
    deny_unannotated: bool = False
    default_roles: str | None = None
    prefix: str = ""

    @classmethod
    def of(cls, files: list[TreeFile]) -> _Quarkus:
        props: dict[str, str] = {}
        for f in files:
            if f.name != "application.properties" or "test" in f.parts[:-1]:
                continue
            for raw in f.text.splitlines():
                line = raw.strip()
                if not line or line[0] in "#!" or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip().removeprefix("%prod.")
                if not key.startswith("%"):  # other profiles don't run in production
                    props[key] = value.strip()
        sets: dict[str, dict[str, str]] = {}
        for key, value in props.items():
            if m := _QUARKUS_PERMISSION.match(key):
                sets.setdefault(m.group(1), {})[m.group(2)] = value
        found = cls(
            deny_unannotated=props.get(f"{_JAXRS}.deny-unannotated-endpoints") == "true",
            default_roles=props.get(f"{_JAXRS}.default-roles-allowed"),
            prefix=next((props[k] for k in _QUARKUS_REST_PATH if k in props), ""),
        )
        for perm in sets.values():
            if "paths" not in perm or "policy" not in perm:
                continue
            methods = (
                {m.strip().upper() for m in perm["methods"].split(",")}
                if ("methods" in perm)
                else None
            )
            for p in perm["paths"].split(","):
                found.permissions.append((p.strip(), methods, perm["policy"]))
        return found

    def guard(self, method: str, path: str) -> tuple[list[str], list[str]]:
        """(scope guards, unguards) from the most specific HTTP permission covering the path."""
        best: tuple[int, str] | None = None
        for pattern, methods, policy in self.permissions:
            opens_all = method == "ALL" and policy == "permit"
            if methods is not None and method not in methods and not opens_all:
                continue
            exact = not pattern.endswith("*")
            stem = pattern.rstrip("*").rstrip("/")
            if path == pattern if exact else (path == stem or path.startswith(stem + "/")):
                rank = len(stem) * 2 + exact
                if best is None or rank > best[0]:
                    best = (rank, policy)
        if best is None:
            return [], []
        policy = best[1]
        if policy == "permit":
            return [], ["quarkus:permit"]
        return [f"quarkus:{policy}"], []


@dataclass
class _Java:
    sources: list[Parsed]
    manifests: list[TreeFile]
    files: list[TreeFile]
    types: dict[str, list[_Type]] = field(default_factory=dict)
    # controllers whose routes come from an interface not in the checkout (generated at build)
    generated: dict[RouteFamily, list[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.hierarchies: dict[tuple[str, str], list[_Type]] = {}
        for src in self.sources:
            for t in _types(src):
                self.types.setdefault(t.name, []).append(t)
        self.consts = _Constants(self.sources)
        self.chains = _chains(self.sources, self.consts)
        texts = [s.file.text for s in self.sources]
        self.enforced = _enforced(texts)
        starter = any(_SECURITY_STARTER.search(m.text) for m in self.manifests)
        self.spring_default = starter and not any(_FILTER_CHAIN.search(t) for t in texts)
        self.quarkus = _Quarkus.of(self.files)
        self.app_path = self._application_path()
        self.fields = _record_fields(self.sources)
        self.repositories = _repository_entities(self.sources)
        # shared across every handler: entities, implementations, fields, names, hop scans
        self.entities = set(self.repositories.values()) | {
            x.name
            for ts in self.types.values()
            for x in ts
            if {"Entity", "Document", "Table", "MappedSuperclass"} & set(x.annotations)
        }
        self.implementations: dict[str, list[_Type]] = {}
        for ts in self.types.values():
            for x in ts:
                if not x.interface and not x.abstract:
                    for s in {*x.supers, *(h.name for h in self._hierarchy(x)[1:])}:
                        self.implementations.setdefault(s, []).append(x)
        # Spring Data fragment implementations (`CardRepositoryImpl`): their queries are custom
        self.custom_methods = {
            (x.src.text(m.child_by_field_name("name")), len(_params(x.src, m)))
            for ts in self.types.values()
            for x in ts
            if not x.interface and x.name.endswith("Impl")
            for m in x.node.child_by_field_name("body").named_children
            if m.type == "method_declaration"
        }
        self.field_decls: dict[tuple[str, str], list[tuple[_Type, Node]]] = {}
        self.resolved: dict[tuple[str, str], list[_Type]] = {}
        self.scans: dict[tuple[str, int, frozenset[str], frozenset[str], int], _Scan] = {}
        self.helpers: dict[tuple[str, str], frozenset[str]] = {}

    def _application_path(self) -> str:
        paths = {
            v
            for ts in self.types.values()
            for t in ts
            if "ApplicationPath" in t.annotations
            for n in _attr(t.src, t.annotations["ApplicationPath"], "value")
            if (v := self.consts.resolve(t.src, n)) is not None
        }
        return paths.pop() if len(paths) == 1 else ""

    def _hierarchy(self, t: _Type) -> list[_Type]:
        """`t`, then its superclasses and interfaces found in the checkout, nearest first."""
        key = (t.src.file.rel, t.name)
        if key not in self.hierarchies:
            found: list[_Type] = []
            seen: set[str] = set()
            pending = [t]
            while pending:
                x = pending.pop()
                if x.name in seen:
                    continue
                seen.add(x.name)
                found.append(x)
                pending += reversed([p for n in x.supers for p in self.types.get(n, [])[:1]])
            self.hierarchies[key] = found
        return self.hierarchies[key]

    def rows(self) -> list[_Row]:
        rows: list[_Row] = []
        for ts in self.types.values():
            for t in ts:
                if not t.interface and not t.abstract:
                    rows += self._resource(t)
        return rows

    def _resource(self, t: _Type) -> list[_Row]:
        chain = self._hierarchy(t)
        if any(c in h.annotations for h in chain for c in _CONTROLLERS) and any(
            SPRING_IMPORT.search(h.src.file.text) for h in chain
        ):
            family = RouteFamily.SPRING
            prefixes = next(
                (
                    self._paths(h, h.annotations["RequestMapping"], "value", "path")
                    for h in chain
                    if "RequestMapping" in h.annotations
                ),
                [("", False)],
            )
        elif any("Path" in h.annotations for h in chain) and any(
            JAXRS_IMPORT.search(h.src.file.text) for h in chain
        ):
            family = RouteFamily.JAX_RS
            prefixes = next(
                (
                    self._paths(h, h.annotations["Path"], "value")
                    for h in chain
                    if "Path" in h.annotations
                ),
                [("", False)],
            )
            prefixes = [(_join(self.quarkus.prefix, self.app_path, p), d) for p, d in prefixes]
        else:
            return []
        if any(name not in self.types for name in t.supers) and any(
            "Override" in _annotations(t.src, m) and self._mapping(family, t, m) is None
            for m in t.methods.values()
        ):
            self.generated.setdefault(family, []).append(t.src.file.rel)
        rows: list[_Row] = []
        done: set[str] = set()
        for owner in chain:
            for name, method in owner.methods.items():
                if name in done:
                    continue
                found = self._mapping(family, owner, method)
                if found is None:
                    continue
                done.add(name)
                verbs, patterns = found
                override = t.methods.get(name) if owner is not t else None
                rows += self._rows(family, t, owner, method, override, verbs, prefixes, patterns)
        return rows

    def _paths(self, t: _Type, ann: Node, *keys: str) -> list[tuple[str, bool]]:
        values = _attr(t.src, ann, *keys)
        if not values:
            return [("", False)]
        out = []
        for v in values:
            resolved = self.consts.resolve(t.src, v)
            out.append((resolved, False) if resolved is not None else (t.src.text(v)[:160], True))
        return out

    def _mapping(
        self, family: RouteFamily, owner: _Type, method: Node
    ) -> tuple[list[str], list[tuple[str, bool]]] | None:
        anns = _annotations(owner.src, method)
        if family is RouteFamily.SPRING:
            name = next((n for n in SPRING_MAPPINGS if n in anns), None)
            if name is None:
                return None
            verb = SPRING_MAPPINGS[name]
            verbs = (
                [verb]
                if verb
                else [
                    owner.src.text(v).rsplit(".", 1)[-1]
                    for v in _attr(owner.src, anns[name], "method")
                ]
                or ["ALL"]
            )
            return verbs, self._paths(owner, anns[name], "value", "path")
        verbs = [v for v in JAXRS_VERBS if v in anns]
        if not verbs:
            return None  # a sub-resource locator, or not a resource method
        paths = self._paths(owner, anns["Path"], "value") if "Path" in anns else [("", False)]
        return verbs, paths

    def _guards(
        self, family: RouteFamily, decls: list[tuple[_Type, Node]]
    ) -> tuple[list[str], list[str]]:
        guards: list[str] = []
        unguards: list[str] = []
        for owner, decl in decls:
            for name, ann in _annotations(owner.src, decl).items():
                if name == "PermitAll":
                    unguards.append("@PermitAll")
                elif name in _GUARD_ANNOTATIONS:
                    full = owner.src.text(ann.child_by_field_name("arguments")).strip("()")
                    args = full[:60] + ("…" if len(full) > 60 else "")
                    label = f"@{name}" + (f"({args})" if args else "")
                    if "permitAll" in args:
                        unguards.append(label)
                        continue
                    guards.append(label)
                    if (
                        family is RouteFamily.SPRING
                        and name in _METHOD_SECURITY_ANNOTATIONS
                        and _FAMILY[name] not in self.enforced
                    ):
                        unguards.append(METHOD_SECURITY_OFF)
        return _unique(guards), sorted(set(unguards))

    def _rows(
        self,
        family: RouteFamily,
        t: _Type,
        owner: _Type,
        method: Node,
        override: Node | None,
        verbs: list[str],
        prefixes: list[tuple[str, bool]],
        patterns: list[tuple[str, bool]],
    ) -> list[_Row]:
        src = owner.src
        name = src.text(method.child_by_field_name("name"))
        decls = [(owner, method)] + ([(t, override)] if override is not None else [])
        guards, unguards = self._guards(family, decls)
        types = [(t, t.node)] + ([(owner, owner.node)] if owner is not t else [])
        scope_guards, scope_unguards = self._guards(family, types)
        annotated = bool(guards or scope_guards or unguards or scope_unguards)
        body = (t.src, override) if override is not None else (src, method)
        guards = _unique([*guards, *_body_guard_calls(*body)])
        facts = _Ownership(self, t).handler(*body, decls, types)
        rows = []
        for prefix, prefix_dynamic in prefixes:
            for pattern, dynamic in patterns:
                full = _join(prefix, pattern)
                for verb in verbs:
                    g, u = self._config_guards(family, verb, full, annotated)
                    row = _row(
                        family,
                        verb,
                        full,
                        f"{t.name}.{name}",
                        src.file.rel,
                        src.line(method),
                        guards,
                        _unique([*scope_guards, *g]),
                        sorted({*unguards, *scope_unguards, *u}),
                    )
                    _mark(row, None, dynamic or prefix_dynamic, src.file.rel)
                    row.view_class = t.name
                    effective = _effective_guards(
                        family,
                        self.enforced,
                        (guards, unguards),
                        (scope_guards, scope_unguards),
                        (g, u),
                    )
                    row.own(facts, self.fields, guards=effective)
                    rows.append(row)
        return rows

    def _config_guards(
        self, family: RouteFamily, verb: str, path: str, annotated: bool
    ) -> tuple[list[str], list[str]]:
        """Scope guards and unguards the security configuration gives a route."""
        if family is RouteFamily.JAX_RS:
            scope, opened = self.quarkus.guard(verb, path)
            if not annotated and self.quarkus.default_roles:
                scope.append("quarkus:default-roles-allowed")
            if not annotated and self.quarkus.deny_unannotated:
                scope.append("quarkus:deny-unannotated-endpoints")
            return scope, opened
        sample = _sample(path)
        covering = [c for c in self.chains if c.covers(sample)]
        if not covering:
            return ([SPRING_DEFAULT_GUARD], []) if self.spring_default else ([], [])
        # which conditional chain runs is decided at deploy time: report what each would do
        candidates = covering if covering[0].conditional else covering[:1]
        scope: list[str] = []
        opened = [CONDITIONAL_CONFIG] if covering[0].conditional else []
        for chain in candidates:
            rule = next((r for r in chain.rules if r.matches(verb, sample)), None)
            if rule is not None:
                (opened if rule.opens else scope).append(rule.guard)
        return _unique(scope), opened


def _effective_guards(
    family: RouteFamily,
    enforced: frozenset[str],
    method: tuple[list[str], list[str]],
    scope: tuple[list[str], list[str]],
    config: tuple[list[str], list[str]],
) -> list[str]:
    """The guards that authenticate a route, from (guards, unguards) of the method, its class and
    the security config: the method's own annotations override the class's, an enforced one
    overrides an open config, and annotations Spring doesn't enforce count for nothing."""

    def counts(label: str) -> bool:
        name = label[1:].split("(", 1)[0]
        return label.startswith("@") and (
            family is not RouteFamily.SPRING or name not in _FAMILY or _FAMILY[name] in enforced
        )

    own = [g for g in method[0] if counts(g)]
    calls = [g for g in method[0] if not g.startswith("@")]
    annotations = own or [g for g in scope[0] if counts(g)]
    opened = [u for u in method[1] if counts(u)] or (
        [] if own else [u for u in scope[1] if counts(u)]
    )
    if opened:
        return []  # `@PermitAll`
    if config[1]:
        # the config opens the route, or which config runs is a deploy-time choice
        return [*annotations, *calls]
    return [*annotations, *calls, *config[0]]


def _enforced(texts: list[str]) -> frozenset[str]:
    """The annotation families method security enforces: `@EnableMethodSecurity` turns on
    pre/post by default, `@EnableGlobalMethodSecurity` only what it names."""
    found = set()
    for text in texts:
        for m in _METHOD_SECURITY.finditer(text):
            for flag, family, default in (
                ("prePostEnabled", "prepost", m.group(1) != "Global"),
                ("securedEnabled", "secured", False),
                ("jsr250Enabled", "jsr250", False),
            ):
                value = re.search(rf"\b{flag}\s*=\s*(true|false)\b", m.group(2) or "")
                if (value.group(1) == "true") if value else default:
                    found.add(family)
    return frozenset(found)


def _record_fields(sources: list[Parsed]) -> dict[str, tuple[str, ...]]:
    """Each class's and record's field names, inherited ones included, by simple type name. A type
    that may be owned through another is left out unless it names an owner itself, so never taken
    for ownerless: its superclass is outside the checkout, it holds or is held by another checkout
    type (`Patient patient`), or it has subclasses."""
    fields: dict[str, list[str]] = {}
    held: dict[str, set[str]] = {}
    parents: dict[str, str] = {}
    for src in sources:
        for n in walk(src.root):
            if n.type not in ("class_declaration", "record_declaration"):
                continue
            name = src.text(n.child_by_field_name("name"))
            superclass = n.child_by_field_name("superclass")
            if superclass is not None and superclass.named_children:
                parents[name] = (
                    src.text(superclass.named_children[0]).split("<", 1)[0].rsplit(".", 1)[-1]
                )
            names = fields.setdefault(name, [])
            types = held.setdefault(name, set())
            params = n.child_by_field_name("parameters") if n.type == "record_declaration" else None
            body = n.child_by_field_name("body")
            for f in [
                *(
                    p
                    for p in (params.named_children if params else [])
                    if p.type == "formal_parameter"
                ),
                *(
                    f
                    for f in (body.named_children if body else [])
                    if f.type == "field_declaration"
                ),
            ]:
                types |= {
                    src.text(k)
                    for k in walk(f.child_by_field_name("type"))
                    if k.type == "type_identifier"
                }
                names += (
                    [src.text(f.child_by_field_name("name"))]
                    if f.type == "formal_parameter"
                    else [
                        src.text(d.child_by_field_name("name"))
                        for d in f.named_children
                        if d.type == "variable_declarator"
                    ]
                )

    def resolved(
        name: str, seen: frozenset[str] = frozenset()
    ) -> tuple[list[str], set[str]] | None:
        parent = parents.get(name)
        if parent is None:
            return fields[name], held[name]
        if parent not in fields or parent in seen:
            return None
        inherited = resolved(parent, seen | {name})
        if inherited is None:
            return None
        return [*fields[name], *inherited[0]], held[name] | inherited[1]

    held_by_others = {k for name, types in held.items() for k in types if k != name}
    out = {}
    for name, own in fields.items():
        full = resolved(name)
        owned = any(OWNER_FIELD_RX.match(f) for f in full[0]) if full is not None else False
        if full is not None and (
            owned
            or not (full[1] & fields.keys() or name in held_by_others or name in parents.values())
        ):
            out[name] = tuple(full[0])
        elif any(OWNER_FIELD_RX.match(f) for f in own):
            out[name] = tuple(own)
    return out


def _repository_entities(sources: list[Parsed]) -> dict[str, str]:
    """The entity each checkout repository interface stores (`JpaRepository<Item, Long>`)."""
    found = {}
    for src in sources:
        for n in walk(src.root):
            if n.type not in _TYPE_DECLS:
                continue
            for g in walk(n):
                if g.type == "class_body" or g.type == "interface_body":
                    break
                if g.type != "generic_type" or not g.named_children:
                    continue
                base = src.text(g.named_children[0]).rsplit(".", 1)[-1]
                args = [c for c in g.named_children[1:] if c.type == "type_arguments"]
                if _REPOSITORIES.match(base) and args and args[0].named_children:
                    found[src.text(n.child_by_field_name("name"))] = src.text(
                        args[0].named_children[0]
                    ).split("<", 1)[0]
                    break
    return found


class _Ownership:
    """A handler's ownership facts. Lookups and hand-offs are read anywhere in the body; protection
    counts only from the allow-listed shapes 1-5 (owner decisions 2026-10-31, 2026-11-02)."""

    def __init__(self, java: _Java, t: _Type) -> None:
        self.java, self.type = java, t

    def handler(
        self,
        src: Parsed,
        method: Node,
        decls: list[tuple[_Type, Node]],
        types: list[tuple[_Type, Node]],
    ) -> HandlerFacts:
        """`decls`: the mapped declaration, then the implementation; `types`: their classes."""
        params = _params(src, method)
        # Spring inherits parameter annotations from the mapped (interface) declaration
        mapped = _params(decls[0][0].src, decls[0][1])
        if len(mapped) == len(params):
            params = [(n, k, {**m[2], **a}) for (n, k, a), m in zip(params, mapped, strict=True)]
        ids = {n for n, _, anns in params if any(a in anns for a in _PATH_ANNOTATIONS)}
        ids |= self._path_fields(self.type)
        callers = {n for n, kind, anns in params if self._caller(kind, anns, param=True)}
        callers |= self._caller_fields(self.type) - {n for n, _, _ in params}
        # shape 3; the method's own @PreAuthorize overrides the class's
        security = (
            []
            if "prepost" not in self.java.enforced
            else [
                (o, a)
                for o, d in decls
                for n, a in _annotations(o.src, d).items()
                if n == "PreAuthorize"
            ]
            or [
                (o, a)
                for o, d in types
                for n, a in _annotations(o.src, d).items()
                if n == "PreAuthorize"
            ]
        )
        covered = {i for o, a in security for i in _bean_check_ids(o.src.text(a), ids)}
        span = self._span(security[0][0].src, security[0][1]) if security else None
        scan = self._scan(src, self.type, method, ids, callers, 0, covered)
        return HandlerFacts(
            lookups=scan.facts.lookups,
            caller=scan.facts.caller,
            check=span if ids and ids <= covered - scan.unstable else None,
            hop=scan.facts.hop,
            handoff=scan.facts.handoff,
            takes_id=bool(ids),
        )

    def _span(self, src: Parsed, node: Node) -> CodeSpan:
        return CodeSpan(path=RepoPath(src.file.rel), line=src.line(node))

    def _caller(self, kind: str, annotations: dict[str, Node], *, param: bool) -> bool:
        """Spring resolves only a `Principal` parameter from the authentication unannotated; any
        other parameter, or a checkout type sharing a framework name, is request data."""
        if any(a in annotations for a in _CALLER_ANNOTATIONS):
            return True
        if kind in self.java.types:
            return False
        if param and "Context" not in annotations:
            return bool(_PARAM_CALLER_TYPES.match(kind))
        return bool(_CALLER_TYPES.match(kind))

    def _fields(self, t: _Type) -> list[tuple[_Type, Node]]:
        """The field declarations of `t` and its superclasses in the checkout."""
        key = (t.src.file.rel, t.name)
        if key not in self.java.field_decls:
            self.java.field_decls[key] = [
                (h, f)
                for h in self.java._hierarchy(t)
                for f in h.node.child_by_field_name("body").named_children
                if f.type == "field_declaration"
            ]
        return self.java.field_decls[key]

    def _field_names(self, h: _Type, f: Node) -> set[str]:
        return {
            h.src.text(d.child_by_field_name("name"))
            for d in f.named_children
            if d.type == "variable_declarator"
        }

    def _caller_fields(self, t: _Type) -> set[str]:
        return {
            n
            for h, f in self._fields(t)
            if self._caller(_type_name(h.src, f), _annotations(h.src, f), param=False)
            for n in self._field_names(h, f)
        }

    def _path_fields(self, t: _Type) -> set[str]:
        """JAX-RS resource fields injected from the path (`@PathParam("id") String id;`)."""
        return {
            n
            for h, f in self._fields(t)
            if any(a in _annotations(h.src, f) for a in _PATH_ANNOTATIONS)
            for n in self._field_names(h, f)
        }

    def _field_type(self, t: _Type, name: str) -> str | None:
        for h, f in self._fields(t):
            if name in self._field_names(h, f):
                return _type_name(h.src, f)
        return None

    def _caller_helpers(self, t: _Type) -> frozenset[str]:
        """No-argument methods of `t`'s own hierarchy whose every return is the caller alone."""
        key = (t.src.file.rel, t.name)
        if key in self.java.helpers:
            return self.java.helpers[key]
        fields = self._caller_fields(t)
        nearest: dict[str, tuple[_Type, Node]] = {}
        for h in self.java._hierarchy(t):
            for m in h.node.child_by_field_name("body").named_children:
                if (
                    m.type == "method_declaration"
                    and m.child_by_field_name("body") is not None
                    and not _params(h.src, m)
                ):
                    nearest.setdefault(h.src.text(m.child_by_field_name("name")), (h, m))
        found: frozenset[str] = frozenset()
        while more := {
            n
            for n, (h, m) in nearest.items()
            if n not in found
            and _Values(h.src, fields, found).returns_caller(m.child_by_field_name("body"))
        }:
            found |= more
        self.java.helpers[key] = found
        return found

    def _resolve(self, src: Parsed, kind: str) -> list[_Type]:
        """The checkout types a simple name refers to from `src`: by import, then package."""
        key = (src.file.rel, kind)
        if key not in self.java.resolved:
            candidates = self.java.types.get(kind, [])
            found = candidates
            if len(candidates) > 1:
                imported = re.findall(
                    rf"^\s*import\s+([\w.]+)\.{re.escape(kind)}\s*;", src.file.text, re.M
                )
                for wanted in [*imported, _package(src)]:
                    if matching := [c for c in candidates if _package(c.src) == wanted]:
                        found = matching
                        break
            self.java.resolved[key] = found
        return self.java.resolved[key]

    def _receiver_type(
        self, src: Parsed, t: _Type, receiver: Node | None, local_types: dict[str, str]
    ) -> list[_Type]:
        if receiver is None or src.text(receiver) in ("this", "super"):
            return [t]
        text = src.text(receiver).removeprefix("this.")
        if receiver.type == "object_creation_expression":
            kind = src.text(receiver.child_by_field_name("type")).split("<", 1)[0]
        elif receiver.type == "identifier" and text[:1].isupper() and text in self.java.types:
            kind = text  # a static call on a checkout class
        else:
            kind = local_types.get(text) or self._field_type(t, text) or ""
        return self._resolve(src, kind.rsplit(".", 1)[-1]) if kind else []

    def _callees(
        self, src: Parsed, t: _Type, call: Node, local_types: dict[str, str]
    ) -> list[tuple[_Type, Node]]:
        """The checkout methods a call reaches, with exactly its arity; through an interface or
        abstract class, every implementation."""
        name = src.text(call.child_by_field_name("name"))
        arity = len(_arguments(call))
        found = []
        for k in self._receiver_type(src, t, call.child_by_field_name("object"), local_types):
            targets = (
                self.java.implementations.get(k.name, []) if k.interface or k.abstract else []
            ) or [k]
            for target in targets:
                for h in self.java._hierarchy(target):
                    if not h.interface and (m := _method(h, name, arity)) is not None:
                        found.append((h, m))
                        break
        return found

    def _owner_query(self, repository: str, name: str, values: list[Node], v: _Values) -> bool:
        """Shape 1: a derived query of plain equalities, one of them on the owner and handed a
        caller-only value; never a declared query, a default body or a custom implementation."""
        predicates = _derived_predicates(name)
        if predicates is None or len(predicates) != len(values):
            return False
        for r in self._resolve_all(repository):
            for h in self.java._hierarchy(r):
                m = _method(h, name, len(values))
                if m is not None and (
                    m.child_by_field_name("body") is not None
                    or {"Query", "NativeQuery"} & set(_annotations(h.src, m))
                ):
                    return False
        if (name, len(values)) in self.java.custom_methods:
            return False
        return any(
            OWNER_CHECK_RX.match(p) and v.derived(values[k]) for k, p in enumerate(predicates)
        )

    def _resolve_all(self, kind: str) -> list[_Type]:
        return self.java.types.get(kind.rsplit(".", 1)[-1], [])

    def _scan(
        self,
        src: Parsed,
        t: _Type,
        method: Node,
        ids: set[str],
        callers: set[str],
        depth: int,
        covered: set[str] | None = None,
    ) -> _Scan:
        body = method.child_by_field_name("body")
        if body is None or not ids:
            # a method we can't read (abstract), or an id reaching the handler some way we don't
            # follow (a command object, a @BeanParam): never settle it
            return _Scan(HandlerFacts(handoff=self._span(src, method)))
        return _Walk(self, src, t, method, body, ids, callers, depth, covered or set()).run()

    def _hop(
        self, walk: _Walk, target: _Type, callee: Node, call: Node
    ) -> tuple[_Scan, set[str], set[str]]:
        """The callee's facts, with its parameters mapped by position from the call's arguments;
        and the outer ids it verified, and returns only when owned."""
        params = [n for n, _, _ in _params(target.src, callee)][: len(_arguments(call))]
        values = _arguments(call)[: len(params)]
        inner_ids = {p for p, v in zip(params, values, strict=True) if walk.names(v) & walk.ids}
        inner_callers = {
            p
            for p, v in zip(params, values, strict=True)
            if p not in inner_ids and walk.v.derived(v)
        } | (self._caller_fields(target) - set(params))
        key = (
            target.src.file.rel,
            callee.start_byte,
            frozenset(inner_ids),
            frozenset(inner_callers),
            walk.depth + 1,
        )
        if key not in self.java.scans:
            self.java.scans[key] = self._scan(
                target.src, target, callee, inner_ids, inner_callers, walk.depth + 1
            )
        scan = self.java.scans[key]
        exact = {p: r for p, v in zip(params, values, strict=True) if (r := walk.exact(v))}
        return (
            scan,
            {exact[p] for p in scan.verified if p in exact},
            {exact[p] for p in scan.owned_or_null if p in exact},
        )


@dataclass
class _Scan:
    facts: HandlerFacts
    verified: set[str] = field(default_factory=set)  # parameters verified before any return
    owned_or_null: set[str] = field(default_factory=set)  # parameters whose load returns if owned
    unstable: set[str] = field(default_factory=set)  # ids reassigned in the body
    reads: tuple[bool, ...] = ()  # per lookup: a read, not a write


class _Values:
    """Which values in one method body come from the caller alone."""

    def __init__(self, src: Parsed, callers: set[str], helpers: frozenset[str]) -> None:
        self.src, self.callers, self.helpers = src, set(callers), helpers

    def bind(self, body: Node) -> set[str]:
        """Adds the body's caller-only locals, dropping any caller it reassigns or shadows; returns
        the names it assigns."""
        src = self.src
        assigned = {
            src.text(a.child_by_field_name("left") or a.named_children[0]).removeprefix("this.")
            for a in walk(body)
            if a.type in ("assignment_expression", "update_expression") and a.named_children
        }
        declared: dict[str, list[Node | None]] = {}
        for d in walk(body):
            if d.type == "variable_declarator":
                name = src.text(d.child_by_field_name("name"))
                declared.setdefault(name, []).append(d.child_by_field_name("value"))
        shadowed = {
            src.text(n)
            for d in walk(body)
            if d.type in ("lambda_expression", "enhanced_for_statement", "catch_formal_parameter")
            for n in (
                [d.child_by_field_name("name")]
                if d.type != "lambda_expression"
                else walk(d.child_by_field_name("parameters"))
            )
            if n is not None and n.type == "identifier"
        }
        base = self.callers - assigned - set(declared) - shadowed
        found: set[str] = set()
        while True:
            self.callers = base | found
            more = {
                n
                for n, values in declared.items()
                if n not in found
                and n not in assigned | shadowed
                and all(v is not None and self.derived(v) for v in values)
            }
            if not more:
                return assigned
            found |= more

    def returns_caller(self, body: Node) -> bool:
        self.bind(body)
        returns = [r for r in walk(body) if r.type == "return_statement"]
        return bool(returns) and all(
            r.named_children and self.derived(r.named_children[0]) for r in returns
        )

    def is_caller(self, n: Node) -> bool:
        """A direct read of the caller: a caller variable, `SecurityContextHolder`, a caller
        helper of the class, `request.getUserPrincipal()`."""
        if n.type == "identifier":
            return self.src.text(n) in self.callers
        if n.type != "method_invocation":
            return False
        receiver = n.child_by_field_name("object")
        name = self.src.text(n.child_by_field_name("name"))
        if receiver is None or self.src.text(receiver) in ("this", "super"):
            return name in self.helpers and not _arguments(n)
        return self.src.text(receiver) == "SecurityContextHolder" or bool(_CALLER_CALLS.match(name))

    def derived(self, node: Node | None) -> bool:
        """`me.getName()`, `getCurrentUser().getTenantId()`, `"t:" + me.getName()`: a value
        built only from the caller and literals (never a ternary, a fallback or another input)."""
        node = _unparen(node)
        if node is None:
            return False
        if self.is_caller(node):
            return True
        kind = node.type
        if kind == "cast_expression":
            return self.derived(node.child_by_field_name("value"))
        if kind == "field_access":
            obj = node.child_by_field_name("object")
            if self.src.text(obj) in ("this", "super"):
                return self.src.text(node.child_by_field_name("field")) in self.callers
            return self.derived(obj)
        if kind == "binary_expression" and _operator(self.src, node) == "+":
            sides = [node.child_by_field_name("left"), node.child_by_field_name("right")]
            return any(self.derived(s) for s in sides) and all(
                self.derived(s) or _literal(s) for s in sides
            )
        if kind in ("method_invocation", "object_creation_expression"):
            args = _arguments(node)
            obj = node.child_by_field_name("object") if kind == "method_invocation" else None
            if kind == "object_creation_expression" or (
                obj is not None and obj.type == "identifier" and self.src.text(obj)[:1].isupper()
            ):
                # a static conversion or a value type of the caller's values
                return bool(args) and all(self.derived(a) for a in args)
            if obj is not None and self.derived(obj):
                return all(self.derived(a) or _literal(a) for a in args)
            # a resolver handed only the caller (`tenants.of(auth)`): trusted (owner decision)
            return (
                obj is not None
                and obj.type == "identifier"
                and self.src.text(obj)[:1].islower()
                and bool(args)
                and all(self.derived(a) for a in args)
            )
        return False


class _Walk:
    """One method body: its lookups by id (with record types), hand-offs, and the ids each
    allow-listed statement directly in the body verifies from its end on."""

    def __init__(
        self,
        o: _Ownership,
        src: Parsed,
        t: _Type,
        method: Node,
        body: Node,
        ids: set[str],
        callers: set[str],
        depth: int,
        covered: set[str],
    ) -> None:
        self.o, self.src, self.t, self.method, self.body = o, src, t, method, body
        self.depth = depth
        self.v = _Values(src, callers, o._caller_helpers(t))
        assigned = self.v.bind(body)
        self.params = {n for n, _, _ in _params(src, method)}
        self.local_types: dict[str, str] = {}
        for d in walk(body):
            if d.type == "local_variable_declaration":
                kind = src.text(d.child_by_field_name("type")).split("<", 1)[0]
                for v in d.named_children:
                    if v.type == "variable_declarator":
                        self.local_types[src.text(v.child_by_field_name("name"))] = kind
        # each id name, and the path id it holds exactly (`Long key = Long.valueOf(raw)`); a value
        # merely built from an id (`f ? id : 0L`, `"k" + id`) holds an id of its own
        self.root = {i: i for i in ids}
        self.ids = set(ids)
        for d in walk(body):
            if d.type != "variable_declarator" or (value := d.child_by_field_name("value")) is None:
                continue
            if self.names(value) & set(self.root) and not self.loads(value):
                name = src.text(d.child_by_field_name("name"))
                self.root[name] = self.exact(value) or name
                self.ids.add(name)
        moved = assigned & self.ids
        self.unstable = moved | {self.root[n] for n in moved}
        self.lookups: list[Lookup] = []
        self.cover: list[set[str] | None] = []  # the path ids each lookup is by, when exact
        self.starts: list[int] = []
        self.direct: set[int] = set()  # lookups a store call makes itself (not through a hop)
        self.reads: list[bool] = []
        self.made: dict[tuple[int, int], list[int]] = {}  # call span -> lookups it made
        self.hop_verified: dict[tuple[int, int], set[str]] = {}
        self.hop_owned_or_null: dict[tuple[int, int], set[str]] = {}
        self.handoffs: list[tuple[CodeSpan, set[str] | None, int]] = []
        self.hop: CodeSpan | None = None
        self.caller = next((o._span(src, n) for n in walk(body) if self.v.is_caller(n)), None)
        self.verified: dict[str, int] = dict.fromkeys(covered & self.ids, body.start_byte)
        self.owned_or_null: set[str] = set()

    # ---- small helpers
    def names(self, node: Node | None) -> set[str]:
        return _identifiers(self.src, node)

    def exact(self, node: Node | None) -> str | None:
        """The path id a value is exactly: the id, a cast or conversion of it (`toUUID(id)`,
        `new DeviceId(…)`), else None."""
        node = _unparen(node)
        if node is None:
            return None
        if node.type == "identifier":
            return self.root.get(self.src.text(node))
        if node.type == "cast_expression":
            return self.exact(node.child_by_field_name("value"))
        args = (
            _arguments(node)
            if node.type in ("method_invocation", "object_creation_expression")
            else []
        )
        if node.type == "method_invocation" and _CONVERSION.match(
            self.src.text(node.child_by_field_name("name"))
        ):
            obj = node.child_by_field_name("object")
            if obj is not None and not args and (found := self.exact(obj)):
                return found
            if len(args) == 1 and (obj is None or _static(self.src, obj)):
                return self.exact(args[0])
        if node.type == "object_creation_expression" and len(args) == 1:
            kind = _simple_type(self.src, node)
            return self.exact(args[0]) if _ID_TYPE.match(kind) else None
        return None

    def exact_ids(self, call: Node) -> set[str] | None:
        """The path ids a call is handed, when every id-carrying argument is exactly one."""
        roots = [self.exact(v) for v in _arguments(call) if self.names(v) & self.ids]
        return None if None in roots else set(roots)  # type: ignore[arg-type]

    def loads(self, value: Node) -> bool:
        """Whether a value is (or wraps) a call that may load something with the id."""
        return any(
            n.type == "method_invocation"
            and self.names(n.child_by_field_name("arguments")) & self.ids
            and not _CONVERSION.match(self.src.text(n.child_by_field_name("name")))
            and not _INERT_RECEIVERS.match(self.src.text(n.child_by_field_name("object")))
            and self.src.text(n.child_by_field_name("object")) not in self.ids
            for n in walk(value)
        )

    def verify(self, roots: set[str], at: int) -> None:
        for r in roots - self.unstable:
            self.verified[r] = min(at, self.verified.get(r, at))

    def add(
        self, call: Node, lookup: Lookup, *, direct: bool = False, read: bool | None = None
    ) -> None:
        k = len(self.lookups)
        self.lookups.append(lookup)
        name = self.src.text(call.child_by_field_name("name"))
        self.reads.append(bool(_READ_NAME.match(name)) if read is None else read)
        self.cover.append(self.exact_ids(call))
        self.starts.append(call.start_byte)
        self.made.setdefault((call.start_byte, call.end_byte), []).append(k)
        if direct:
            self.direct.add(k)

    def handoff(self, node: Node) -> None:
        self.handoffs.append((self.o._span(self.src, node), self.exact_ids(node), node.start_byte))

    def load(self, call: Node | None, *, read: bool) -> int | None:
        """The one lookup a call makes, with nothing else loaded in its arguments. `read`: a read
        (`find…`, `get…`; through a hop, one doing only that read), else the store call itself."""
        if call is None or call.type != "method_invocation":
            return None
        made = self.made.get((call.start_byte, call.end_byte), [])
        inner = [k for n in walk(call) for k in self.made.get((n.start_byte, n.end_byte), [])]
        if len(made) != 1 or inner != made:
            return None
        k = made[0]
        return k if (self.reads[k] if read else k in self.direct) else None

    # ---- the walk
    def run(self) -> _Scan:
        for n in walk(self.body):
            if n.type == "method_invocation":
                self.call(n)
            elif n.type == "object_creation_expression":
                self.creation(n)
        statements = [
            s for s in self.body.named_children if s.type not in ("line_comment", "block_comment")
        ]
        # caller-only declarations, which can't act on a record, may sit before its check
        following: list[Node | None] = [None] * len(statements)
        after = None
        for k in range(len(statements) - 1, -1, -1):
            following[k] = after
            if not self.caller_declaration(statements[k]):
                after = statements[k]
        for stmt, nxt in zip(statements, following, strict=True):
            self.statement(stmt, nxt)
        first_return = next(
            (
                s.start_byte
                for s in statements
                if any(n.type == "return_statement" for n in walk(s))
            ),
            None,
        )
        return self.result(first_return)

    def creation(self, node: Node) -> None:
        """`new PurgeCommand(id)` hands the id on; an id value type or an exception doesn't."""
        if self.names(node.child_by_field_name("arguments")) & self.ids and not (
            _ID_TYPE.match(kind := _simple_type(self.src, node)) or _THROWN.match(kind)
        ):
            self.handoff(node)

    def call(self, call: Node) -> None:
        src = self.src
        receiver = call.child_by_field_name("object")
        rtext = src.text(receiver).removeprefix("this.") if receiver is not None else ""
        name = src.text(call.child_by_field_name("name"))
        values = _arguments(call)
        if receiver is not None and self.loads(receiver) and name in _RESULT_CALLS:
            return  # acts on a loaded result (`….orElseThrow(() -> new NotFound(id))`)
        if not self.names(call.child_by_field_name("arguments")) & self.ids:
            # `Optional.of(id).ifPresent(cards::deleteById)`: the id flows into a function
            if (
                receiver is not None
                and self.names(receiver) & self.ids
                and any(v.type in ("lambda_expression", "method_reference") for v in values)
            ):
                self.handoff(call)
            return
        span = self.o._span(src, call)
        repository = self.local_types.get(rtext) or self.o._field_type(self.t, rtext) or ""
        if entity := self.o.java.repositories.get(repository):
            scoped = self.o._owner_query(repository, name, values, self.v)
            self.add(call, Lookup(span, scoped, record_type=entity), direct=True)
        elif name in _ENTITY_MANAGER_LOOKUPS and values and values[0].type == "class_literal":
            record = src.text(values[0]).removesuffix(".class")
            self.add(call, Lookup(span, record_type=record), direct=True)
        elif rtext in self.o.java.entities:
            self.add(call, Lookup(span, record_type=rtext), direct=True)
        elif name in _QUERY_CALLS:
            self.add(call, Lookup(span), direct=True)
        elif targets := self.o._callees(src, self.t, call, self.local_types):
            # one hop, and a second only into an authorization-shaped helper (`checkXxxId`)
            if self.depth >= 2 or (self.depth == 1 and not _AUTHORIZE_NAME.match(name)):
                if not _VALIDATOR_NAME.match(name):
                    self.handoff(call)
                return
            self.hop = self.hop or span
            verified: set[str] | None = None
            owned: set[str] | None = None
            for target, callee in targets:
                scan, v, o = self.o._hop(self, target, callee, call)
                returns = target.src.text(callee.child_by_field_name("type")).split("<", 1)[0]
                # an owner-bearing return type says what an untyped lookup loaded; it never
                # makes one ownerless
                record = returns if owner_field(returns, self.o.java.fields) else None
                for x, read in zip(scan.facts.lookups, scan.reads, strict=True):
                    lookup = Lookup(x.span, x.scoped, x.checked, x.record_type or record)
                    self.add(call, lookup, read=read)
                self.caller = self.caller or scan.facts.caller
                if scan.facts.handoff:
                    self.handoffs.append(
                        (scan.facts.handoff, self.exact_ids(call), call.start_byte)
                    )
                verified = v if verified is None else verified & v
                owned = o if owned is None else owned & o
            key = (call.start_byte, call.end_byte)
            self.hop_verified[key], self.hop_owned_or_null[key] = verified or set(), owned or set()
        elif call.parent is not None and call.parent.type == "variable_declarator":
            # shape 4: a kept load we can't follow, handed a caller-only value (owner decision)
            scoped = any(self.v.derived(v) for v in values)
            self.add(call, Lookup(span, scoped=scoped), direct=True)
        elif rtext[:1].islower() and _LOOKUP_NAME.match(name) and not _INERT_RECEIVERS.match(rtext):
            self.add(call, Lookup(span), direct=True)
        elif not (
            _INERT_RECEIVERS.match(rtext)
            or (_CONVERSION.match(name) and (receiver is None or _static(src, receiver)))
            or _VALIDATOR_NAME.match(name)
            or rtext in self.ids
        ):
            self.handoff(call)

    def statement(self, stmt: Node, following: Node | None) -> None:
        """The ids a statement directly in the body verifies, by the allow-list."""
        end = stmt.end_byte
        expr = _statement_value(stmt)
        if expr is not None:
            # shape 1, refused when absent: `repo.findByIdAndOwnerId(id, me).orElseThrow(…)`
            k = self.load(_or_else_throw_root(self.src, expr), read=False)
            if k is not None and self.lookups[k].scoped:
                self.verify(self.cover[k] or set(), end)
            if expr.type == "method_invocation":
                self.verify(self.hop_verified.get((expr.start_byte, expr.end_byte), set()), end)
            if stmt.type == "local_variable_declaration" and following is not None:
                record = self.src.text(stmt.named_children[-1].child_by_field_name("name"))
                k = self.load(_unwrap_optional(self.src, expr), read=True)
                if k is not None and self.refuses_foreign(following, record):
                    # shape 2: the load, then a refusal of a record the caller doesn't own
                    self.checked(k)
                    self.verify(self.cover[k] or set(), following.end_byte)
                elif k is not None and self.returns_if_owned(following, record):
                    # shape 5: the load, then `return r != null && r.owner.equals(me) ? r : null`
                    self.checked(k)
                    self.owned_or_null |= self.cover[k] or set()
                elif expr.type == "method_invocation" and _refuses_null(
                    self.src, following, record
                ):
                    # a hop returning its record only when owned, refused when null
                    owned = self.hop_owned_or_null.get((expr.start_byte, expr.end_byte), set())
                    self.verify(owned, following.end_byte)
        elif (
            stmt.type == "if_statement"
            and stmt.child_by_field_name("alternative") is None
            and _bare_throw(stmt.child_by_field_name("consequence"))
        ):
            # shape 1, refused when absent: `if (!repo.existsByIdAndOwnerId(id, me)) throw …`
            test = _unparen(stmt.child_by_field_name("condition"))
            if test is not None and test.type == "unary_expression" and _is_not(test):
                k = self.load(_unparen(test.named_children[-1]), read=False)
                if k is not None and self.lookups[k].scoped:
                    self.verify(self.cover[k] or set(), end)

    def checked(self, k: int) -> None:
        x = self.lookups[k]
        self.lookups[k] = Lookup(x.span, x.scoped, True, x.record_type)

    def caller_declaration(self, stmt: Node) -> bool:
        """`String me = auth.getName();`: declares only caller-only locals."""
        declarators = [d for d in stmt.named_children if d.type == "variable_declarator"]
        return (
            stmt.type == "local_variable_declaration"
            and bool(declarators)
            and all(
                self.src.text(d.child_by_field_name("name")) in self.v.callers for d in declarators
            )
        )

    def refuses_foreign(self, stmt: Node, record: str) -> bool:
        """`if (!record.<owner>.equals(<caller-only>)) throw …;`, optionally after
        `record == null ||`, and nothing else in the branch."""
        if stmt.type != "if_statement" or stmt.child_by_field_name("alternative") is not None:
            return False
        if not _bare_throw(stmt.child_by_field_name("consequence")):
            return False
        parts = _parts(self.src, stmt.child_by_field_name("condition"), "||")
        compared = False
        for part in parts:
            if _null_test(self.src, part, record, "=="):
                continue
            if not self.compares(part, record, negated=True):
                return False
            compared = True
        return compared

    def returns_if_owned(self, stmt: Node, record: str) -> bool:
        """`return record != null && record.<owner>.equals(<caller-only>) ? record : null;`"""
        if stmt.type != "return_statement" or not stmt.named_children:
            return False
        expr = _unparen(stmt.named_children[0])
        if expr is None or expr.type != "ternary_expression":
            return False
        alternative = _unparen(expr.child_by_field_name("alternative"))
        if self.src.text(expr.child_by_field_name("consequence")).strip() != record or (
            alternative is None or alternative.type != "null_literal"
        ):
            return False
        compared = False
        for part in _parts(self.src, expr.child_by_field_name("condition"), "&&"):
            if _null_test(self.src, part, record, "!="):
                continue
            if not self.compares(part, record, negated=False):
                return False
            compared = True
        return compared

    def compares(self, part: Node, record: str, *, negated: bool) -> bool:
        """`record.f` compared with a caller-only value: `!record.f.equals(c)`, `!c.equals(…)`,
        `!Objects.equals(…)`, `record.f != c` when `negated`, else the same without the `!`."""
        part = _unparen(part)
        if part is None:
            return False
        sides: tuple[Node, Node] | None = None
        if part.type == "binary_expression" and _operator(self.src, part) == (
            "!=" if negated else "=="
        ):
            sides = (part.child_by_field_name("left"), part.child_by_field_name("right"))
        elif negated and part.type == "unary_expression" and _is_not(part):
            inner = _unparen(part.named_children[-1])
            sides = _equals_sides(self.src, inner) if inner is not None else None
        elif not negated:
            sides = _equals_sides(self.src, part)
        if sides is None:
            return False
        return any(self.owner_of(a, record) and self.v.derived(b) for a, b in (sides, sides[::-1]))

    def owner_of(self, node: Node, record: str) -> bool:
        """`record.ownerId` or `record.getOwnerId()`: an owner member of the record (the narrow
        set; the broad one only says a record might have an owner)."""
        text = self.src.text(node).replace(" ", "")
        found = re.fullmatch(rf"{re.escape(record)}\.(?:get)?(\w+)(?:\(\))?", text)
        return bool(found) and bool(
            OWNER_CHECK_RX.match(found.group(1)[:1].lower() + found.group(1)[1:])
        )

    def result(self, first_return: int | None) -> _Scan:
        verified = {r: at for r, at in self.verified.items() if r not in self.unstable}

        def holds(roots: set[str] | None, at: int) -> bool:
            return bool(roots) and all(r in verified and verified[r] <= at for r in roots)

        handoff = next((span for span, roots, at in self.handoffs if not holds(roots, at)), None)
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
            # what this body did for its caller, before anything in it could return
            verified={r for r, at in verified.items() if first_return is None or at <= first_return}
            & self.params,
            owned_or_null=(self.owned_or_null - self.unstable) & self.params,
            unstable=self.unstable,
            reads=tuple(self.reads),
        )


def _type_name(src: Parsed, decl: Node) -> str:
    return src.text(decl.child_by_field_name("type")).split("<", 1)[0]


def _simple_type(src: Parsed, node: Node) -> str:
    return src.text(node.child_by_field_name("type")).split("<", 1)[0].rsplit(".", 1)[-1]


def _static(src: Parsed, node: Node) -> bool:
    """A class receiver (`UUID`, `Long`, `java.util.UUID`) or one that doesn't act on objects."""
    text = src.text(node)
    return text.rsplit(".", 1)[-1][:1].isupper() or bool(_INERT_RECEIVERS.match(text))


def _literal(node: Node | None) -> bool:
    return node is not None and node.type in (
        "string_literal",
        "character_literal",
        "decimal_integer_literal",
    )


def _derived_predicates(name: str) -> list[str] | None:
    """The properties a Spring Data derived query compares for plain equality, in argument order;
    None when it isn't one, or any predicate is something else (`Not`, `Like`, `In`, `Or`, …)."""
    found = _DERIVED_QUERY.fullmatch(name)
    if found is None:
        return None
    predicates = []
    for part in re.split(r"And(?=[A-Z])", found.group(1)):
        if _OR_QUERY.search(part):
            return None
        part = re.sub(r"(?:Is|Equals|IsEqualTo)$", "", part)
        if not part or _QUERY_OPERATOR.search(part):
            return None
        predicates.append(part[:1].lower() + part[1:])
    return predicates


def _statement_value(stmt: Node) -> Node | None:
    """An expression statement's expression, or a single declaration's value."""
    if stmt.type == "expression_statement" and stmt.named_children:
        return stmt.named_children[0]
    if stmt.type == "local_variable_declaration":
        values = [d for d in stmt.named_children if d.type == "variable_declarator"]
        return values[0].child_by_field_name("value") if len(values) == 1 else None
    return None


def _unwrap_optional(src: Parsed, expr: Node | None) -> Node | None:
    """The load under `.orElseThrow(…)`, `.get()` or `.orElse(null)`."""
    expr = _unparen(expr)
    while expr is not None and expr.type == "method_invocation":
        name, args = src.text(expr.child_by_field_name("name")), _arguments(expr)
        if not (
            name == "orElseThrow"
            or (name == "get" and not args)
            or (name == "orElse" and len(args) == 1 and args[0].type == "null_literal")
        ):
            break
        inner = expr.child_by_field_name("object")
        if inner is None or inner.type != "method_invocation":
            break
        expr = inner
    return expr


def _arguments(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return [a for a in (args.named_children if args is not None else []) if a.type != "comment"]


def _package(src: Parsed) -> str:
    found = re.search(r"^\s*package\s+([\w.]+)\s*;", src.file.text, re.M)
    return found.group(1) if found else ""


def _method(t: _Type, name: str, arity: int) -> Node | None:
    """`t`'s own method `name` taking exactly `arity` arguments."""
    body = t.node.child_by_field_name("body")
    return next(
        (
            m
            for m in (body.named_children if body is not None else [])
            if m.type == "method_declaration"
            and t.src.text(m.child_by_field_name("name")) == name
            and len(_params(t.src, m)) == arity
        ),
        None,
    )


def _bean_check_ids(expression: str, ids: set[str]) -> set[str]:
    """Shape 3: the ids a `@PreAuthorize` covers when it is exactly one bean call handed the path
    id and `authentication` (`@access.canRead(#id, authentication)`); none otherwise."""
    found = _SPEL_SINGLE_BEAN.fullmatch(expression.strip())
    if found is None:
        return set()
    args = [a.strip() for a in found.group(1).split(",")]
    if "authentication" not in args and "principal" not in args:
        return set()
    return {a[1:] for a in args if a.startswith("#")} & ids


def _identifiers(src: Parsed, node: Node | None) -> set[str]:
    return (
        {src.text(n) for n in walk(node) if n.type == "identifier"} if node is not None else set()
    )


def _operator(src: Parsed, node: Node) -> str:
    op = node.child_by_field_name("operator")
    return src.text(op) if op is not None else ""


def _unparen(node: Node | None) -> Node | None:
    while node is not None and node.type == "parenthesized_expression" and node.named_children:
        node = node.named_children[0]
    return node


def _is_not(node: Node) -> bool:
    return bool(node.children) and node.children[0].type == "!"


def _parts(src: Parsed, node: Node | None, op: str) -> list[Node]:
    """The operands of `a <op> b <op> c` (one when there's no `op`)."""
    found, pending = [], [_unparen(node)]
    while pending:
        n = pending.pop()
        if n is None:
            continue
        if n.type == "binary_expression" and _operator(src, n) == op:
            pending += [
                _unparen(n.child_by_field_name("right")),
                _unparen(n.child_by_field_name("left")),
            ]
        else:
            found.append(n)
    return found


def _null_test(src: Parsed, node: Node, record: str, op: str) -> bool:
    """`record == null` (or `!=`, by `op`)."""
    node = _unparen(node)
    return (
        node is not None
        and node.type == "binary_expression"
        and _operator(src, node) == op
        and {
            src.text(node.child_by_field_name("left")),
            src.text(node.child_by_field_name("right")),
        }
        == {record, "null"}
    )


def _refuses_null(src: Parsed, stmt: Node, record: str) -> bool:
    """`if (record == null) throw …;` and nothing else."""
    return (
        stmt.type == "if_statement"
        and stmt.child_by_field_name("alternative") is None
        and _bare_throw(stmt.child_by_field_name("consequence"))
        and _null_test(src, stmt.child_by_field_name("condition"), record, "==")
    )


def _equals_sides(src: Parsed, node: Node) -> tuple[Node, Node] | None:
    """`a.equals(b)` or `Objects.equals(a, b)`."""
    if node.type != "method_invocation" or src.text(node.child_by_field_name("name")) != "equals":
        return None
    values = _arguments(node)
    receiver = node.child_by_field_name("object")
    if receiver is not None and src.text(receiver) == "Objects":
        return (values[0], values[1]) if len(values) == 2 else None
    return (receiver, values[0]) if receiver is not None and len(values) == 1 else None


def _bare_throw(node: Node | None) -> bool:
    """A branch that is only a throw: `throw …;` or `{ throw …; }`."""
    if node is None:
        return False
    if node.type == "throw_statement":
        return True
    return (
        node.type == "block"
        and len(node.named_children) == 1
        and (node.named_children[0].type == "throw_statement")
    )


def _or_else_throw_root(src: Parsed, expr: Node) -> Node | None:
    """For `<call>.orElseThrow(…)`, the call the absent result refuses (top-down, no parents)."""
    expr = _unparen(expr)
    if (
        expr is not None
        and expr.type == "method_invocation"
        and src.text(expr.child_by_field_name("name")) == "orElseThrow"
    ):
        root = expr.child_by_field_name("object")
        return root if root is not None and root.type == "method_invocation" else None
    return None


def _params(src: Parsed, method: Node) -> list[tuple[str, str, dict[str, Node]]]:
    """Each parameter's name, type and annotations."""
    params = method.child_by_field_name("parameters")
    return [
        (
            src.text(p.child_by_field_name("name")),
            src.text(p.child_by_field_name("type")).split("<", 1)[0].rsplit(".", 1)[-1],
            _annotations(src, p),
        )
        for p in (params.named_children if params else [])
        if p.type == "formal_parameter"
    ]


def _body_guard_calls(src: Parsed, method: Node) -> list[str]:
    """Guard-shaped calls a handler makes as bare statements of its own body."""
    body = method.child_by_field_name("body")
    names = [
        src.text(stmt.named_children[0].child_by_field_name("name"))
        for stmt in (body.named_children if body is not None else [])
        if stmt.type == "expression_statement"
        and stmt.named_children
        and stmt.named_children[0].type == "method_invocation"
    ]
    return [f"call:{n}" for n in _guards_in(" ".join(names))]


@dataclass
class JavaRoutes:
    rows: list[_Row]
    evidence: dict[RouteFamily, str]  # a file per family that imports its annotations
    parsed: bool  # whether the Java parser was available
    generated: dict[RouteFamily, list[str]]


def java_rows(files: list[TreeFile]) -> JavaRoutes:
    """The Spring and JAX-RS rows of a checkout, with what route_guards needs to name gaps."""
    java = [f for f in files if f.path.suffix == ".java"]
    evidence: dict[RouteFamily, str] = {}
    for f in java:
        for family, rx in ((RouteFamily.SPRING, SPRING_IMPORT), (RouteFamily.JAX_RS, JAXRS_IMPORT)):
            if family not in evidence and rx.search(f.text):
                evidence[family] = f.rel
    if not evidence:
        return JavaRoutes([], {}, True, {})
    available = parser()
    if available is None:
        return JavaRoutes([], evidence, False, {})
    sources = []
    for f in java:
        data = f.text.encode("utf-8")
        sources.append(Parsed(f, available.parse(data).root_node, data))
    manifests = [f for f in files if f.name in _MANIFESTS]
    java_index = _Java(sources, manifests, files)
    return JavaRoutes(java_index.rows(), evidence, True, java_index.generated)
