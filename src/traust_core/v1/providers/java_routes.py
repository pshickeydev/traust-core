"""Spring MVC/WebFlux and JAX-RS (Quarkus, RESTEasy, Jersey) routes in Java and the guards on
each, parsed with tree-sitter. Guards are method-security annotations,
Spring Security's request-matcher rules (first match wins), Quarkus HTTP permissions, and the
Spring Boot default that authenticates every request when the security starter has no config."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_guards import _guards_in, _mark, _Row, _row, _unique
from traust_core.v1.providers.route_ownership import OWNER_FIELD_RX, HandlerFacts, Lookup
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
_METHOD_SECURITY = re.compile(r"@Enable(?:Global|Reactive)?MethodSecurity\b")
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
_CALLER_ANNOTATIONS = ("AuthenticationPrincipal", "CurrentSecurityContext")
_CALLER_CALLS = re.compile(
    r"\b(SecurityContextHolder|getUserPrincipal|getRemoteUser|getCallerPrincipal)\b"
)
_REPOSITORIES = re.compile(r"^\w*(Crud|Jpa|Sorting|Mongo|R2dbc)?Repository(Base)?$|^Panache\w*$")
_ENTITY_MANAGER_LOOKUPS = ("find", "getReference")
_LOOKUP_NAME = re.compile(r"^(find|get|load|fetch|read|delete|remove|exists|lookup|select)")
# store calls that take an id with no lookup-shaped name: JPQL parameters, JdbcTemplate
_QUERY_CALLS = ("setParameter", "queryForObject", "queryForList", "queryForMap", "query", "update")
# a bare statement that refuses by itself; a boolean authorization only counts in a condition
_ENFORCING_NAME = re.compile(
    r"(?i)^(check|verify|authori[sz]e|assert|ensure|require|validate|demand|enforce)"
)
_CONDITION_NAME = re.compile(r"(?i)^(can|has|is|allow|owns|permit|may)")
_AUTHORIZE_NAME = re.compile(
    r"(?i)^(check|verify|authori[sz]e|assert|ensure|require|validate|demand|enforce"
    r"|can|has|is|allow|owns|permit|may)"
)
_ENFORCED_RESULT = ("orElseThrow", "get", "getOrThrow")
# a derived query with an Or clause doesn't narrow to the caller (`findByIdOrOwnerId`)
_OR_QUERY = re.compile(r"By\w*Or[A-Z]")
# receivers of an id that don't act on the object
_INERT_RECEIVERS = re.compile(
    r"^(log|logger|LOG|LOGGER|System\.(out|err)|Objects|Assert|Preconditions|Validate|String"
    r"|StringUtils|Math|Integer|Long|UUID|Optional|List|Set|Map|Arrays|Collections)$"
)
# a value derived from a path id (`new DeviceId(toUUID(id))`, `UUID.fromString(id)`) is that id
_CONVERSION = re.compile(r"(?i)^(to\w*|from\w*|parse\w*|valueOf|of|decode|as\w*|uuid\w*)$")
_SPEL_OBJECT = re.compile(r"\b(returnObject|filterObject)\b")
_SPEL_VARIABLE = re.compile(r"#(\w+)")
_SPEL_CALLER = re.compile(r"\b(principal|authentication)\b")
_SPEL_BEAN_CALL = re.compile(r"@\w+\.\w+\(([^)]*)\)")
_SPEL_COMPARISON = re.compile(
    r"#(\w+)\s*(?:==|\.equals\()\s*(?:principal|authentication)\b"
    r"|(?:principal|authentication)[\w.]*\s*(?:==|\.equals\()\s*#(\w+)"
)
_FILTERING = ("filter",)
_CRITERIA = ("where", "and", "eq", "equal")
_EQUALITY = ("equals", "equalsIgnoreCase", "contentEquals")
_DENY_RETURN = re.compile(
    r"^(null|Optional\.empty\(\)"
    r"|(ResponseEntity|Response)\.(status\(\s*((Http)?Status\.|Response\.Status\.)?"
    r"(FORBIDDEN|NOT_FOUND|UNAUTHORIZED|40[134])\b|notFound\(|forbidden\(|badRequest\()"
    r"|new ResponseEntity<\w*>\(\s*(HttpStatus\.)?(FORBIDDEN|NOT_FOUND|UNAUTHORIZED)\b)"
)
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
                args = src.text(call.child_by_field_name("arguments")).strip("()")[:60]
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
        for src in self.sources:
            for t in _types(src):
                self.types.setdefault(t.name, []).append(t)
        self.consts = _Constants(self.sources)
        self.chains = _chains(self.sources, self.consts)
        texts = [s.file.text for s in self.sources]
        self.method_security = any(_METHOD_SECURITY.search(t) for t in texts)
        starter = any(_SECURITY_STARTER.search(m.text) for m in self.manifests)
        self.spring_default = starter and not any(_FILTER_CHAIN.search(t) for t in texts)
        self.quarkus = _Quarkus.of(self.files)
        self.app_path = self._application_path()
        self.fields = _record_fields(self.sources)
        self.repositories = _repository_entities(self.sources)
        self.caller_methods = _caller_methods(self.sources)
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
                    for s in x.supers:
                        self.implementations.setdefault(s, []).append(x)
        self.field_decls: dict[tuple[str, str], list[tuple[_Type, Node]]] = {}
        self.resolved: dict[tuple[str, str], list[_Type]] = {}
        self.scans: dict[tuple[str, int, frozenset[str], frozenset[str], int], _Scan] = {}

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

    def _hierarchy(self, t: _Type, seen: frozenset[str] = frozenset()) -> list[_Type]:
        """`t`, then its superclasses and interfaces found in the checkout, nearest first."""
        found = [t]
        for name in t.supers:
            if name in seen or name == t.name:
                continue
            for parent in self.types.get(name, [])[:1]:
                found += self._hierarchy(parent, seen | {t.name})
        return found

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
                        and not self.method_security
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
                    # a deploy-time choice of config: only the route's own guards count, and
                    # method security that isn't enabled guards nothing
                    effective = (
                        ([] if METHOD_SECURITY_OFF in row.unguards else row.guards)
                        if CONDITIONAL_CONFIG in row.unguards
                        else None
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


def _record_fields(sources: list[Parsed]) -> dict[str, tuple[str, ...]]:
    """Each class's and record's field names, inherited ones included, by simple type name. A type
    whose superclass is outside the checkout is left out unless its own fields name an owner, so
    it is never taken for ownerless."""
    fields: dict[str, list[str]] = {}
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
            if n.type == "record_declaration":
                params = n.child_by_field_name("parameters")
                names += [
                    src.text(p.child_by_field_name("name"))
                    for p in (params.named_children if params else [])
                    if p.type == "formal_parameter"
                ]
            body = n.child_by_field_name("body")
            for f in body.named_children if body else []:
                if f.type == "field_declaration":
                    names += [
                        src.text(d.child_by_field_name("name"))
                        for d in f.named_children
                        if d.type == "variable_declarator"
                    ]

    def resolved(name: str, seen: frozenset[str] = frozenset()) -> list[str] | None:
        parent = parents.get(name)
        if parent is None:
            return fields[name]
        if parent not in fields or parent in seen:
            return None
        inherited = resolved(parent, seen | {name})
        return None if inherited is None else [*fields[name], *inherited]

    out = {}
    for name, own in fields.items():
        full = resolved(name)
        if full is not None:
            out[name] = tuple(full)
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
    """A handler's ownership facts. Protection is credited only where it provably runs first: a
    statement directly in the method body that refuses when the object isn't the caller's."""

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
        callers = {n for n, kind, anns in params if _caller(kind, anns)} | self._caller_fields(
            self.type
        )
        mutating = any(
            _MAPPING_VERBS.get(name, False)
            or (name == "RequestMapping" and "GET" not in owner.src.text(ann))
            for owner, decl in decls
            for name, ann in _annotations(owner.src, decl).items()
        )
        covered: set[str] = set()
        returned: CodeSpan | None = None
        covering: CodeSpan | None = None
        for owner, decl in [*decls, *types]:
            for name, ann in _annotations(owner.src, decl).items():
                if name not in ("PreAuthorize", "PostAuthorize"):
                    continue
                expression = owner.src.text(ann)
                if found := _object_security_ids(expression, ids):
                    covered |= found
                    covering = covering or self._span(owner.src, ann)
                if (
                    name == "PostAuthorize"
                    and not mutating
                    and _SPEL_OBJECT.search(expression)
                    and _SPEL_CALLER.search(expression)
                ):
                    returned = self._span(owner.src, ann)
        check = returned or (covering if ids and ids <= covered else None)
        scan = self._body(src, self.type, method, ids, callers, 0, covered)
        return HandlerFacts(
            lookups=scan.facts.lookups,
            caller=scan.facts.caller,
            check=check,
            hop=scan.facts.hop,
            handoff=scan.facts.handoff,
        )

    def _span(self, src: Parsed, node: Node) -> CodeSpan:
        return CodeSpan(path=RepoPath(src.file.rel), line=src.line(node))

    def _fields(self, t: _Type) -> list[tuple[_Type, Node]]:
        """The field declarations of `t` and its superclasses in the checkout."""
        key = (t.src.file.rel, t.name)
        if key not in self.java.field_decls:
            self.java.field_decls[key] = [
                (h, f)
                for h in self.java._hierarchy(t)
                for f in (h.node.child_by_field_name("body").named_children)
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
            if _caller(
                h.src.text(f.child_by_field_name("type")).split("<", 1)[0], _annotations(h.src, f)
            )
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
                return h.src.text(f.child_by_field_name("type")).split("<", 1)[0]
        return None

    def _body(
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
        if body is None:
            return _Scan(HandlerFacts(), set())
        if not ids:
            # the path id reaches the handler some way we don't follow (a command object, a
            # @BeanParam): never settle it
            return _Scan(HandlerFacts(handoff=self._span(src, method)), set())
        params = {n for n, _, _ in _params(src, method)}
        ids, callers = set(ids), set(callers)
        local_types: dict[str, str] = {}
        for d in walk(body):
            if d.type == "local_variable_declaration":
                kind = src.text(d.child_by_field_name("type")).split("<", 1)[0]
                for v in d.named_children:
                    if v.type == "variable_declarator":
                        local_types[src.text(v.child_by_field_name("name"))] = kind
        for d in walk(body):
            value = d.child_by_field_name("value") if d.type == "variable_declarator" else None
            if value is None:
                continue
            name = src.text(d.child_by_field_name("name"))
            if _identifiers(src, value) & ids and _converts(src, value, ids):
                ids.add(name)
            elif self._pure_caller(src, value, callers, params | set(local_types)):
                callers.add(name)
        reassigned = {
            src.text(a.child_by_field_name("left"))
            for a in walk(body)
            if a.type == "assignment_expression"
        } & ids

        def is_caller(n: Node) -> bool:
            if n.type == "identifier":
                return src.text(n) in callers
            if n.type != "method_invocation":
                return False
            receiver = src.text(n.child_by_field_name("object"))
            return (
                bool(_CALLER_CALLS.search(src.text(n.child_by_field_name("name"))))
                or (
                    receiver in ("", "this", "super")
                    and src.text(n.child_by_field_name("name")) in self.java.caller_methods
                )
                or (receiver == "SecurityContextHolder")
            )

        def calls_caller(node: Node | None) -> bool:
            return node is not None and any(is_caller(n) for n in walk(node))

        scan = _Walk(self, src, t, body, ids, callers, depth, local_types, is_caller, calls_caller)
        scan.in_scope = params | set(local_types)
        scan.verify(covered or set(), body.start_byte)
        for stmt in body.named_children:
            scan.statement(stmt)
        for i in reassigned:
            scan.verified.pop(i, None)
        return scan.result()

    def _pure_caller(self, src: Parsed, value: Node, callers: set[str], names: set[str]) -> bool:
        """A value read only from the caller (`me.getName()`), not mixed with request data."""
        refs = {
            src.text(n)
            for n in walk(value)
            if n.type == "identifier"
            and not (
                n.parent is not None
                and n.parent.type == "method_invocation"
                and n.parent.child_by_field_name("name") is not None
                and (
                    n.parent.child_by_field_name("name").start_byte,
                    n.parent.child_by_field_name("name").end_byte,
                )
                == (n.start_byte, n.end_byte)
            )
        }
        reads_caller = (
            bool(refs & callers)
            or bool(_CALLER_CALLS.search(src.text(value)))
            or any(
                n.type == "method_invocation"
                and src.text(n.child_by_field_name("object")) in ("", "this", "super")
                and src.text(n.child_by_field_name("name")) in self.java.caller_methods
                for n in walk(value)
            )
        )
        return reads_caller and not (refs & (names - callers))

    def _resolve(self, src: Parsed, kind: str) -> list[_Type]:
        """The checkout types a simple name refers to from `src`: by import, then package."""
        key = (src.file.rel, kind)
        if key in self.java.resolved:
            return self.java.resolved[key]
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
        return found
        imported = re.findall(rf"^\s*import\s+([\w.]+)\.{re.escape(kind)}\s*;", src.file.text, re.M)
        own = _package(src)
        for wanted in [*imported, own]:
            found = [c for c in candidates if _package(c.src) == wanted]
            if found:
                return found
        return candidates

    def _callees(
        self, src: Parsed, t: _Type, call: Node, local_types: dict[str, str]
    ) -> list[tuple[_Type, Node]]:
        """The checkout methods a call can reach: on this class, a field, a local, `new X()`;
        through an interface or abstract class, every implementation."""
        receiver = call.child_by_field_name("object")
        name = src.text(call.child_by_field_name("name"))
        args = call.child_by_field_name("arguments")
        arity = len([a for a in (args.named_children if args else []) if a.type != "comment"])
        text = src.text(receiver).removeprefix("this.") if receiver is not None else ""
        if receiver is None or text in ("this", "super"):
            kinds = [t]
        else:
            if receiver.type == "object_creation_expression":
                kind = src.text(receiver.child_by_field_name("type")).split("<", 1)[0]
            else:
                kind = local_types.get(text) or self._field_type(t, text) or ""
            kinds = self._resolve(src, kind.rsplit(".", 1)[-1])
        found: list[tuple[_Type, Node]] = []
        for k in kinds:
            targets = (
                self.java.implementations.get(k.name, []) if k.interface or k.abstract else []
            ) or [k]
            for target in targets:
                for h in self.java._hierarchy(target):
                    if h.interface:
                        continue
                    method = _method(h, name, arity)
                    if method is not None:
                        found.append((h, method))
                        break
        return found

    def _hop(
        self,
        src: Parsed,
        t: _Type,
        callee: Node,
        args: Node,
        ids: set[str],
        callers: set[str],
        depth: int,
        is_caller: Callable[[Node], bool],
    ) -> _Scan:
        params = [n for n, _, _ in _params(t.src, callee)]
        values = [a for a in args.named_children if a.type != "comment"]
        inner_ids = {p for p, v in zip(params, values, strict=False) if _identifiers(src, v) & ids}
        inner_callers = {
            p
            for p, v in zip(params, values, strict=False)
            if any(is_caller(n) for n in walk(v)) and not _identifiers(src, v) & ids
        } | self._caller_fields(t)
        key = (
            t.src.file.rel,
            callee.start_byte,
            frozenset(inner_ids),
            frozenset(inner_callers),
            depth,
        )
        if key not in self.java.scans:
            self.java.scans[key] = self._body(t.src, t, callee, inner_ids, inner_callers, depth)
        scan = self.java.scans[key]
        returns = t.src.text(callee.child_by_field_name("type")).split("<", 1)[0]
        record = returns if returns in self.java.fields else None
        facts = scan.facts
        # the callee verified what it was handed only if it checks before it can return
        verified = {
            values_index for values_index, p in enumerate(params) if p in scan.verified_params
        }
        mapped = {
            i for k, v in enumerate(values) if k in verified for i in _identifiers(src, v) & ids
        }
        return _Scan(
            HandlerFacts(
                lookups=tuple(
                    Lookup(x.span, x.scoped, x.checked, x.record_type or record)
                    for x in facts.lookups
                ),
                caller=facts.caller,
                handoff=facts.handoff,
            ),
            mapped,
        )


@dataclass
class _Scan:
    facts: HandlerFacts
    verified_params: set[str]


class _Walk:
    """One body, statement by statement: lookups by id, and the ids each statement directly in
    the body verifies from its end on."""

    def __init__(
        self,
        owner: _Ownership,
        src: Parsed,
        t: _Type,
        body: Node,
        ids: set[str],
        callers: set[str],
        depth: int,
        local_types: dict[str, str],
        is_caller: Callable[[Node], bool],
        calls_caller: Callable[[Node | None], bool],
    ) -> None:
        self.o, self.src, self.t, self.body = owner, src, t, body
        self.ids, self.callers, self.depth, self.local_types = ids, callers, depth, local_types
        self.is_caller, self.calls_caller = is_caller, calls_caller
        self.in_scope: set[str] = set()  # parameters and locals: request data unless a caller
        self.lookups: list[Lookup] = []
        self.lookup_ids: list[set[str]] = []
        self.starts: list[int] = []
        self.verified: dict[str, int] = {}
        self.handoffs: list[tuple[CodeSpan, set[str], int]] = []
        self.hop: CodeSpan | None = None
        self.caller = next((owner._span(src, n) for n in walk(body) if is_caller(n)), None)
        self.loaded: dict[str, list[int]] = {}  # record variable -> lookups that produced it
        self.used: set[str] = set()  # record variables already used before any check
        self.first_return: int | None = None
        self.produced: dict[tuple[int, int], tuple[list[int], set[str], bool]] = {}

    def verify(self, ids: set[str], at: int) -> None:
        for i in ids:
            self.verified[i] = min(at, self.verified.get(i, at))

    def names(self, node: Node | None) -> set[str]:
        return _identifiers(self.src, node) if node is not None else set()

    # ---- one statement directly in the body
    def statement(self, stmt: Node) -> None:
        for call in (n for n in walk(stmt) if n.type == "method_invocation"):
            self.call(call)
        if self.first_return is None and any(n.type == "return_statement" for n in walk(stmt)):
            self.first_return = stmt.start_byte
        end = stmt.end_byte
        declared: set[str] = set()
        if stmt.type == "if_statement":
            self.condition_checks(stmt, stmt.child_by_field_name("condition"), end)
        elif stmt.type == "expression_statement" and stmt.named_children:
            expr = stmt.named_children[0]
            self.enforced_call(expr, end, bare=True)
        elif stmt.type == "local_variable_declaration":
            for v in stmt.named_children:
                value = v.child_by_field_name("value") if v.type == "variable_declarator" else None
                if value is None:
                    continue
                made = self.made_by(value)
                if made:
                    declared.add(self.src.text(v.child_by_field_name("name")))
                    self.loaded[self.src.text(v.child_by_field_name("name"))] = made
                self.enforced_call(value, end, bare=False)
        elif stmt.type == "return_statement" and stmt.named_children:
            value = stmt.named_children[0]
            if value.type == "ternary_expression":
                self.condition_checks(value, value.child_by_field_name("condition"), end)
        # a record used here before any check can no longer be credited by a later one
        self.used |= (self.names(stmt) - declared) & set(self.loaded)

    def made_by(self, node: Node) -> list[int]:
        return [
            i
            for n in walk(node)
            for i in self.produced.get((n.start_byte, n.end_byte), ([], set(), False))[0]
        ]

    def enforced_call(self, expr: Node, end: int, bare: bool) -> None:
        """A statement-level call that refuses for a foreign object: an enforcing authorization
        (`checkPermission(me, id)`), a scoped lookup whose absence throws (`…orElseThrow()`), or a
        hop that verifies what it is handed."""
        chain = [expr]
        while (
            chain[-1].type == "method_invocation"
            and chain[-1].child_by_field_name("object") is not None
            and chain[-1].child_by_field_name("object").type == "method_invocation"
        ):
            chain.append(chain[-1].child_by_field_name("object"))
        outer = chain[0]
        for call in chain:
            if call.type != "method_invocation":
                continue
            made, used, verifies = self.produced.get(
                (call.start_byte, call.end_byte), ([], set(), False)
            )
            name = self.src.text(call.child_by_field_name("name"))
            args = call.child_by_field_name("arguments")
            if verifies:
                self.verify(used, end)
            elif (
                bare
                and call is outer
                and _ENFORCING_NAME.match(name)
                and self.names(args) & self.ids
                and self.calls_caller(args)
            ):
                self.checked_call(call, end)
            elif (
                made
                and any(self.lookups[i].scoped for i in made)
                and _enforced(self.src, outer, call)
            ):
                self.verify(used, end)

    def checked_call(self, call: Node, end: int) -> None:
        args = call.child_by_field_name("arguments")
        used = self.names(args) & self.ids
        for var in (self.names(args) & set(self.loaded)) - self.used:
            for i in self.loaded[var]:
                x = self.lookups[i]
                self.lookups[i] = Lookup(x.span, x.scoped, True, x.record_type)
        self.lookups.append(Lookup(self.o._span(self.src, call), checked=True))
        self.lookup_ids.append(used)
        self.starts.append(call.start_byte)
        self.verify(used, end)

    def condition_checks(self, cond: Node, test: Node | None, end: int) -> None:
        if test is None:
            return
        # the loaded record compared with the caller, refused when they differ, as its first use
        for var, made in self.loaded.items():
            if var in self.used:
                continue
            if self.guards(
                cond, test, lambda a, b, v=var: v in self.names(a) and self.calls_caller(b)
            ):
                for i in made:
                    self.lookups[i] = Lookup(
                        self.lookups[i].span,
                        self.lookups[i].scoped,
                        True,
                        self.lookups[i].record_type,
                    )
                self.verify(set().union(*(self.lookup_ids[i] for i in made)), end)
        # an authorization or scoped lookup in the condition: `if (!access.canRead(me, id)) throw`
        for call in (n for n in walk(test) if n.type == "method_invocation"):
            args = call.child_by_field_name("arguments")
            name = self.src.text(call.child_by_field_name("name"))
            used = self.names(args) & self.ids
            if not used or not self.calls_caller(args):
                continue
            made, _, _ = self.produced.get((call.start_byte, call.end_byte), ([], set(), False))
            scoped = bool(made) and all(self.lookups[i].scoped for i in made)
            if (_AUTHORIZE_NAME.match(name) or scoped) and _denies_on_failure(
                self.src, cond, call, test
            ):
                if not made:
                    self.checked_call(call, end)
                else:
                    self.verify(used, end)

    def guards(self, cond: Node, test: Node, sides_ok: Callable[[Node, Node], bool]) -> bool:
        for cmp in walk(test):
            sides = _equality_sides(self.src, cmp)
            if sides is None:
                continue
            left, right = sides
            if sides_ok(left, right) or sides_ok(right, left):
                return _denies_on_failure(self.src, cond, cmp, test)
        return False

    # ---- one call anywhere in the body
    def call(self, call: Node) -> None:
        src = self.src
        args = call.child_by_field_name("arguments")
        used = self.names(args) & self.ids
        if args is None or not used:
            return
        receiver = call.child_by_field_name("object")
        rtext = src.text(receiver).removeprefix("this.") if receiver is not None else ""
        name = src.text(call.child_by_field_name("name"))
        start = len(self.lookups)
        scoped = self.scoped(call, args, name)
        verifies = False
        if (
            name in _ENTITY_MANAGER_LOOKUPS
            and args.named_children[:1]
            and args.named_children[0].type == "class_literal"
        ):
            kind = src.text(args.named_children[0]).removesuffix(".class")
            self.add(call, used, Lookup(self.o._span(src, call), scoped, record_type=kind))
        elif (
            kind := self.o.java.repositories.get(
                self.local_types.get(rtext) or self.o._field_type(self.t, rtext) or ""
            )
        ) or rtext in self.o.java.entities:
            self.add(call, used, Lookup(self.o._span(src, call), scoped, record_type=kind or rtext))
        elif name in _QUERY_CALLS:
            self.add(call, used, Lookup(self.o._span(src, call), scoped))
        elif targets := self.o._callees(src, self.t, call, self.local_types):
            # one hop, and a second only into an authorization-shaped helper (`checkXxxId`)
            if self.depth >= 2 or (self.depth == 1 and not _AUTHORIZE_NAME.match(name)):
                # past the depth limit; a check- or validation-shaped helper (`validateId`) is
                # presumed not to act on the object, so it isn't an unseen hand-off (no credit)
                if not _ENFORCING_NAME.match(name):
                    self.handoffs.append((self.o._span(src, call), used, call.start_byte))
                return
            self.hop = self.hop or self.o._span(src, call)
            handed_caller = self.calls_caller(args)
            all_verify = True
            for target_type, target in targets:
                inner = self.o._hop(
                    src,
                    target_type,
                    target,
                    args,
                    self.ids,
                    self.callers,
                    self.depth + 1,
                    self.is_caller,
                )
                all_verify = all_verify and bool(inner.verified_params & used)
                for x in inner.facts.lookups:
                    # handed the caller, and it uses it: to the route, the lookup is scoped
                    protected = handed_caller and (x.scoped or x.checked)
                    self.add(
                        call,
                        used,
                        Lookup(x.span, scoped=True, record_type=x.record_type) if protected else x,
                    )
                self.caller = self.caller or inner.facts.caller
                if inner.facts.handoff:
                    self.handoffs.append((inner.facts.handoff, used, call.start_byte))
            verifies = all_verify
        elif scoped and _LOOKUP_NAME.match(name):
            self.add(call, used, Lookup(self.o._span(src, call), scoped=True))
        elif _AUTHORIZE_NAME.match(name) and self.calls_caller(args):
            pass  # credited only where it refuses (a bare enforcing statement or a condition)
        elif rtext[:1].islower() and _LOOKUP_NAME.match(name):
            self.add(call, used, Lookup(self.o._span(src, call)))
        elif (
            not _INERT_RECEIVERS.match(rtext)
            and not _CONVERSION.match(name)
            and not _ENFORCING_NAME.match(name)  # a validator (`validateId(id, …)`) doesn't act
        ):
            if call.parent is not None and call.parent.type == "variable_declarator":
                # a kept load through code we can't see (`finder.apply(user.getTenantId(), id)`):
                # handed a value taken only from the caller, it is trusted to narrow to it
                # (owner decision 2026-10-30)
                trusted = self.caller_value(args)
                self.add(call, used, Lookup(self.o._span(src, call), scoped=trusted))
            else:
                self.handoffs.append((self.o._span(src, call), used, call.start_byte))
        self.produced[(call.start_byte, call.end_byte)] = (
            list(range(start, len(self.lookups))),
            used,
            verifies,
        )

    def add(self, call: Node, used: set[str], lookup: Lookup) -> None:
        self.lookups.append(lookup)
        self.lookup_ids.append(used)
        self.starts.append(call.start_byte)

    def caller_value(self, args: Node | None) -> bool:
        """An argument taken only from the caller (`user.getTenantId()`, `me.getName()`), not
        mixed with request data."""
        return args is not None and any(
            self.o._pure_caller(self.src, a, self.callers, self.in_scope)
            for a in args.named_children
            if a.type != "comment"
        )

    def scoped(self, call: Node, args: Node, name: str) -> bool:
        """The query itself narrows to the caller: a caller argument to a lookup that isn't an
        Or-query, or a chained filter comparing the record with the caller."""
        if self.caller_value(args) and _LOOKUP_NAME.match(name) and not _OR_QUERY.search(name):
            return True
        if name in _ENTITY_MANAGER_LOOKUPS + _QUERY_CALLS:
            return False
        node = call
        while node.parent is not None and node.parent.type == "method_invocation":
            node = node.parent
            link = self.src.text(node.child_by_field_name("name"))
            link_args = node.child_by_field_name("arguments")
            if link in _CRITERIA and self.calls_caller(link_args):
                return True
            if link in _FILTERING and link_args is not None:
                for lam in (n for n in link_args.named_children if n.type == "lambda_expression"):
                    record = self.names(lam.child_by_field_name("parameters"))
                    for cmp in walk(lam.child_by_field_name("body")):
                        sides = _equality_sides(self.src, cmp)
                        if sides and any(
                            self.names(a) & record and self.calls_caller(b)
                            for a, b in (sides, sides[::-1])
                        ):
                            return True
        return False

    def result(self) -> _Scan:
        covered = [
            all(
                i in self.verified and self.verified[i] <= self.starts[k]
                for i in self.lookup_ids[k]
            )
            and bool(self.lookup_ids[k])
            for k in range(len(self.lookups))
        ]
        handoff = next(
            (
                span
                for span, used, at in self.handoffs
                if any(u not in self.verified or at < self.verified[u] for u in used)
            ),
            None,
        )
        # what this body verified for its caller: checked before anything could return
        verified_params = {
            i
            for i, at in self.verified.items()
            if self.first_return is None or at <= self.first_return
        }
        return _Scan(
            HandlerFacts(
                lookups=tuple(
                    Lookup(
                        x.span, x.scoped, x.checked or (covered[k] and not x.scoped), x.record_type
                    )
                    for k, x in enumerate(self.lookups)
                ),
                caller=self.caller,
                hop=self.hop,
                handoff=handoff,
            ),
            verified_params,
        )


def _package(src: Parsed) -> str:
    found = re.search(r"^\s*package\s+([\w.]+)\s*;", src.file.text, re.M)
    return found.group(1) if found else ""


def _method(t: _Type, name: str, arity: int) -> Node | None:
    """`t`'s own method `name` taking `arity` arguments (any overload of it when none does)."""
    body = t.node.child_by_field_name("body")
    named = [
        m
        for m in (body.named_children if body is not None else [])
        if m.type == "method_declaration" and t.src.text(m.child_by_field_name("name")) == name
    ]
    exact = [m for m in named if len(_params(t.src, m)) == arity]
    return (exact or named or [None])[0]


def _enforced(src: Parsed, outer: Node, call: Node) -> bool:
    """A lookup whose empty result throws: `.orElseThrow()` / `.get()` chained on it."""
    node = call
    while (node.start_byte, node.end_byte) != (outer.start_byte, outer.end_byte):
        node = node.parent
        if node is None:
            return False
        if (
            node.type == "method_invocation"
            and src.text(node.child_by_field_name("name")) in _ENFORCED_RESULT
        ):
            return True
    return False


def _object_security_ids(expression: str, ids: set[str]) -> set[str]:
    """The path ids method security ties to the caller: handed to a bean check together with
    the caller, or compared with `principal`/`authentication`."""
    found: set[str] = set()
    for args in _SPEL_BEAN_CALL.findall(expression):
        if _SPEL_CALLER.search(args):
            found |= set(_SPEL_VARIABLE.findall(args)) & ids
    for a, b in _SPEL_COMPARISON.findall(expression):
        found |= {a or b} & ids
    return found


def _identifiers(src: Parsed, node: Node | None) -> set[str]:
    return (
        {src.text(n) for n in walk(node) if n.type == "identifier"} if node is not None else set()
    )


def _operator(src: Parsed, node: Node) -> str:
    op = node.child_by_field_name("operator")
    return src.text(op) if op is not None else ""


def _equality_sides(src: Parsed, node: Node) -> tuple[Node, Node] | None:
    """The two sides of an equality test: `a.equals(b)`, `Objects.equals(a, b)`, `a == b`."""
    if node.type == "binary_expression" and _operator(src, node) in ("==", "!="):
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if src.text(left) in ("true", "false") or src.text(right) in ("true", "false"):
            return None
        return left, right
    if node.type != "method_invocation":
        return None
    name = src.text(node.child_by_field_name("name"))
    args = node.child_by_field_name("arguments")
    values = [a for a in (args.named_children if args else []) if a.type != "comment"]
    receiver = node.child_by_field_name("object")
    if name == "equals" and src.text(receiver) == "Objects" and len(values) == 2:
        return values[0], values[1]
    if name in _EQUALITY and receiver is not None and len(values) == 1:
        return receiver, values[0]
    return None


def _negated(src: Parsed, node: Node, root: Node) -> bool:
    """Whether `node` holding means the condition `root` is false-ish: `!`, `!=`, `== false`."""
    flips = int(node.type == "binary_expression" and _operator(src, node) == "!=")
    n = node
    while (n.start_byte, n.end_byte) != (root.start_byte, root.end_byte) and n.parent is not None:
        parent = n.parent
        if parent.type == "unary_expression" and parent.children and parent.children[0].type == "!":
            flips += 1
        if parent.type == "binary_expression":
            other = (
                parent.child_by_field_name("right")
                if parent.child_by_field_name("left") is not None
                and (
                    parent.child_by_field_name("left").start_byte,
                    parent.child_by_field_name("left").end_byte,
                )
                == (n.start_byte, n.end_byte)
                else parent.child_by_field_name("left")
            )
            op, value = _operator(src, parent), src.text(other)
            if (op, value) in (("==", "false"), ("!=", "true")):
                flips += 1
        n = parent
    return flips % 2 == 1


def _denies_on_failure(src: Parsed, cond: Node, node: Node, test: Node) -> bool:
    """`cond` refuses when `node` (a comparison or an authorization result) fails."""
    negated = _negated(src, node, test)
    if cond.type == "ternary_expression":
        branch = cond.child_by_field_name("consequence" if negated else "alternative")
        return branch is not None and _deny_expression(src, branch)
    if negated:
        return _deny_branch(src, cond.child_by_field_name("consequence"))
    alternative = cond.child_by_field_name("alternative")
    if alternative is not None:
        return _deny_branch(src, alternative)
    # `if (owns) { return record; }  throw …;`: the denial comes straight after an exiting branch
    consequence = cond.child_by_field_name("consequence")
    after = cond.next_named_sibling
    return _exits(consequence) and after is not None and _deny_branch(src, after)


def _exits(node: Node | None) -> bool:
    if node is None:
        return False
    if node.type in ("return_statement", "throw_statement"):
        return True
    return (
        node.type == "block"
        and bool(node.named_children)
        and node.named_children[-1].type
        in (
            "return_statement",
            "throw_statement",
        )
    )


def _deny_branch(src: Parsed, node: Node | None) -> bool:
    """A branch that refuses as it starts: a throw, or a return of nothing, null, empty or a
    401/403/404 response, directly in it."""
    if node is None:
        return False
    statements = node.named_children if node.type == "block" else [node]
    return any(
        s.type == "throw_statement"
        or (
            s.type == "return_statement"
            and (not s.named_children or _deny_expression(src, s.named_children[0]))
        )
        for s in statements
    )


def _deny_expression(src: Parsed, node: Node) -> bool:
    return node.type == "null_literal" or bool(_DENY_RETURN.match(src.text(node).strip()))


def _converts(src: Parsed, value: Node, ids: set[str]) -> bool:
    """Whether an assigned value is the id itself, converted (`UUID.fromString(id)`,
    `id.trim()`, `vars.get("id")`), rather than something loaded with it."""
    while value.type in ("cast_expression", "parenthesized_expression"):
        value = value.named_children[-1]
    if value.type in ("identifier", "object_creation_expression"):
        return True
    if value.type != "method_invocation":
        return False
    receiver = value.child_by_field_name("object")
    if receiver is not None and src.text(receiver) in ids:
        return True
    return bool(_CONVERSION.match(src.text(value.child_by_field_name("name"))))


def _caller_methods(sources: list[Parsed]) -> frozenset[str]:
    """No-argument helpers that read the caller (`getCurrentUser()`), directly or via another."""
    bodies: dict[str, list[str]] = {}
    for src in sources:
        for m in walk(src.root):
            if m.type != "method_declaration" or m.child_by_field_name("body") is None:
                continue
            params = m.child_by_field_name("parameters")
            if params is not None and params.named_children:
                continue
            bodies.setdefault(src.text(m.child_by_field_name("name")), []).append(
                src.text(m.child_by_field_name("body"))
            )
    found = {n for n, texts in bodies.items() if any(_CALLER_CALLS.search(b) for b in texts)}
    while True:
        more = (
            {
                n
                for n, texts in bodies.items()
                if n not in found
                and any(re.search(rf"\b({'|'.join(found)})\s*\(", b) for b in texts)
            }
            if found
            else set()
        )
        if not more:
            return frozenset(found)
        found |= more


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


def _caller(kind: str, annotations: dict[str, Node]) -> bool:
    return bool(_CALLER_TYPES.match(kind)) or any(a in annotations for a in _CALLER_ANNOTATIONS)


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
