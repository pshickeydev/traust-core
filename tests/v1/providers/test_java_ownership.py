"""Ownership of the object a Spring or JAX-RS id route acts on, read from its handler."""
# ruff: noqa: E501  (embedded Java fixture lines; wrapped in the follow-up PR)

from __future__ import annotations

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

POM = "<project><dependency>spring-boot-starter-security</dependency></project>\n"
METHOD_SECURITY = (
    "import org.springframework.security.config.annotation.method.configuration.*;\n"
    "@EnableMethodSecurity class MethodSecurity {}\n"
)
ENTITIES = (
    "import jakarta.persistence.*;\n"
    "@Entity class Invoice { @Id Long id; String ownerId; long cents; }\n"
    "@Entity class Currency { @Id String code; String symbol; }\n"
    "interface InvoiceRepository extends JpaRepository<Invoice, Long> {\n"
    "  Optional<Invoice> findByIdAndOwnerId(Long id, String ownerId);\n}\n"
)
SERVICE = (
    "class InvoiceService {\n"
    "  private InvoiceRepository invoices;\n"
    "  private AuditTrail trail;\n"
    "  long total(Long invoiceId) { return invoices.findById(invoiceId).get().cents; }\n"
    "  void audit(Long invoiceId) { trail.record(invoiceId); }\n"
    "  Invoice checkInvoiceId(Long invoiceId) { return checkOwned(invoiceId); }\n"
    "  Invoice checkOwned(Long ref) {\n"
    "    Invoice inv = invoices.findById(ref).orElseThrow();\n"
    "    String me = SecurityContextHolder.getContext().getAuthentication().getName();\n"
    "    if (!inv.ownerId.equals(me)) {\n"
    "      throw new IllegalStateException();\n    }\n"
    "    trail.record(ref);\n"
    "    return inv;\n  }\n"
    "  Invoice loadInvoice(Long invoiceId) { return fetchDeep(invoiceId); }\n"
    "  Invoice fetchDeep(Long ref) { return invoices.findById(ref).orElseThrow(); }\n}\n"
    "class AuditTrail { void record(Long id) {} }\n"
)
CONTROLLER = (
    "import org.springframework.web.bind.annotation.*;\n"
    "import org.springframework.security.core.Authentication;\n"
    "import java.security.Principal;\n"
    '@RestController @RequestMapping("/api")\n'
    "class Billing {\n"
    "  private EntityManager em;\n"
    "  private InvoiceRepository invoices;\n"
    "  private InvoiceService service;\n"
    '  @GetMapping("/invoices/{id}") Invoice get(@PathVariable Long id) {\n'
    "    return em.find(Invoice.class, id);\n  }\n"
    '  @GetMapping("/mine/{id}") Invoice mine(@PathVariable Long id, Principal me) {\n'
    "    return invoices.findByIdAndOwnerId(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/filtered/{id}") Invoice filtered(@PathVariable Long id, Principal me) {\n'
    "    return invoices.findById(id).filter(i -> i.ownerId.equals(me.getName())).orElseThrow();\n"
    "  }\n"
    '  @DeleteMapping("/invoices/{id}") void remove(@PathVariable Long id, Authentication auth) {\n'
    "    Invoice inv = invoices.findById(id).orElseThrow();\n"
    "    if (!inv.ownerId.equals(auth.getName())) { throw new IllegalStateException(); }\n"
    "    invoices.deleteById(id);\n  }\n"
    '  @PreAuthorize("@access.canEdit(#id, authentication)")\n'
    '  @PutMapping("/invoices/{id}") void edit(@PathVariable Long id) {\n'
    "    invoices.findById(id);\n  }\n"
    '  @GetMapping("/currencies/{code}") Currency currency(@PathVariable String code) {\n'
    "    return em.find(Currency.class, code);\n  }\n"
    '  @GetMapping("/invoices/{id}/total") long total(@PathVariable("id") Long invoiceId) {\n'
    "    return service.total(invoiceId);\n  }\n"
    '  @GetMapping("/invoices/{id}/audit") void audit(@PathVariable Long id) {\n'
    "    service.audit(id);\n  }\n"
    '  @GetMapping("/checked/{id}") Invoice checkedTwice(@PathVariable Long id) {\n'
    "    return service.checkInvoiceId(id);\n  }\n"
    '  @GetMapping("/deep/{id}") Invoice deep(@PathVariable Long id) {\n'
    "    return service.loadInvoice(id);\n  }\n"
    '  @GetMapping("/raw/{id}") Invoice raw(@PathVariable Long id, Principal me) {\n'
    "    System.out.println(me.getName());\n"
    "    return em.find(Invoice.class, id);\n  }\n"
    "  @PreAuthorize(\"hasRole('ADMIN')\")\n"
    '  @DeleteMapping("/admin/invoices/{id}") void purge(@PathVariable Long id) {\n'
    "    invoices.deleteById(id);\n  }\n"
    "  @PreAuthorize(\"hasAnyRole('ADMIN', 'CLERK')\")\n"
    '  @GetMapping("/clerk/invoices/{id}") Invoice clerk(@PathVariable Long id) {\n'
    "    return em.find(Invoice.class, id);\n  }\n"
    '  @GetMapping("/invoices") Object list() { return null; }\n'
    '  @GetMapping("/owned/{id}") Invoice owned(@PathVariable Long id) {\n'
    "    return invoices.findByIdAndOwnerId(id, currentOwner()).orElseThrow();\n  }\n"
    '  @GetMapping("/keyed/{raw}") Invoice keyed(@PathVariable String raw) {\n'
    "    Long key = Long.valueOf(raw);\n"
    "    return em.find(Invoice.class, key);\n  }\n"
    '  @GetMapping("/logged/{id}") Invoice logged(@PathVariable Long id, Principal me) {\n'
    "    log.info(id, me.getName());\n"
    "    return this.invoices.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/permitted/{id}") Invoice permitted(@PathVariable Long id) {\n'
    "    access.checkPermission(currentOwner(), id);\n"
    "    return invoices.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/self/{id}") long self(@PathVariable Long id) { return this.sum(id); }\n'
    "  long sum(Long ref) { return invoices.findById(ref).get().cents; }\n"
    "  String currentOwner() { return principal().getName(); }\n"
    "  Authentication principal() {\n"
    "    return SecurityContextHolder.getContext().getAuthentication();\n  }\n"
    "}\n"
)
RESOURCE = (
    "import jakarta.ws.rs.*;\n"
    "import jakarta.annotation.security.RolesAllowed;\n"
    '@Path("/docs") @RolesAllowed("reader")\n'
    "class Docs {\n"
    "  @Inject SecurityIdentity identity;\n"
    "  private DocStore store;\n"
    '  @GET @Path("/{id}") Doc get(@PathParam("id") String id) {\n'
    "    return store.owned(id, identity.getPrincipal().getName());\n  }\n"
    '  @DELETE @Path("/{id}") void delete(@PathParam("id") String id) {}\n'
    '  @GET @Path("/{id}/peek") Doc peek(@PathParam("id") String id) {\n'
    "    return store.find(id);\n  }\n"
    '  @GET @Path("/{id}/careless") Doc careless(@PathParam("id") String id) {\n'
    "    return store.careless(id, identity.getPrincipal().getName());\n  }\n"
    "}\n"
    "class Doc { String id; String owner; }\n"
    "class DocStore {\n"
    "  private Map<String, Doc> byId;\n"
    "  Doc find(String id) { return byId.get(id); }\n"
    "  Doc owned(String id, String owner) {\n"
    "    Doc d = byId.get(id);\n"
    "    return d != null && d.owner.equals(owner) ? d : null;\n  }\n"
    "  Doc careless(String id, String owner) { return byId.get(id); }\n}\n"
)


@pytest.fixture(scope="module")
def result(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("billing")
    for rel, text in {
        "pom.xml": POM,
        "src/main/java/billing/MethodSecurity.java": METHOD_SECURITY,
        "src/main/java/billing/Model.java": ENTITIES,
        "src/main/java/billing/InvoiceService.java": SERVICE,
        "src/main/java/billing/Billing.java": CONTROLLER,
        "src/main/java/docs/Docs.java": RESOURCE,
    }.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return route_guards(tree_files(root)).model_dump(mode="json")


def _row(result: dict, method: str, pattern: str) -> dict:
    [row] = [r for r in result["routes"] if r["method"] == method and r["pattern"] == pattern]
    return row


@pytest.mark.parametrize(
    ("method", "pattern", "ownership", "judged"),
    [
        ("GET", "/api/invoices/{id}", "caller-blind", True),
        ("GET", "/api/mine/{id}", "scoped", False),
        ("GET", "/api/filtered/{id}", "scoped", False),
        ("DELETE", "/api/invoices/{id}", "checked", False),
        ("PUT", "/api/invoices/{id}", "checked", False),
        ("GET", "/api/currencies/{code}", "none", False),
        ("GET", "/api/invoices/{id}/total", "caller-blind", True),
        ("GET", "/api/invoices/{id}/audit", "unknown", False),
        ("GET", "/api/checked/{id}", "checked", False),
        ("GET", "/api/deep/{id}", "unknown", False),
        ("GET", "/api/raw/{id}", "unchecked", True),
        ("DELETE", "/api/admin/invoices/{id}", "n/a", False),
        ("GET", "/api/clerk/invoices/{id}", "caller-blind", True),
        ("GET", "/api/invoices", "n/a", False),
        ("GET", "/docs/{id}", "scoped", False),
        ("DELETE", "/docs/{id}", "caller-blind", True),
        ("GET", "/api/owned/{id}", "scoped", False),
        ("GET", "/api/keyed/{raw}", "caller-blind", True),
        ("GET", "/api/logged/{id}", "unchecked", True),
        ("GET", "/api/permitted/{id}", "checked", False),
        ("GET", "/api/self/{id}", "caller-blind", True),
        ("GET", "/docs/{id}/peek", "caller-blind", True),
        ("GET", "/docs/{id}/careless", "unchecked", True),
    ],
)
def test_ownership_of_each_route(
    result: dict, method: str, pattern: str, ownership: str, judged: bool
) -> None:
    row = _row(result, method, pattern)
    assert row["ownership"] == ownership
    assert row["judgement_required"] is judged


def test_an_owner_bearing_entity_names_its_owner_field(result: dict) -> None:
    evidence = _row(result, "GET", "/api/invoices/{id}")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Invoice", "ownerId")
    assert evidence["lookup"]["line"] == 10 and evidence["caller"] is None


def test_a_hop_lookup_carries_its_repository_entity_and_the_call_site(result: dict) -> None:
    evidence = _row(result, "GET", "/api/invoices/{id}/total")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Invoice", "ownerId")
    assert evidence["hop"]["path"] == "src/main/java/billing/Billing.java"
    assert evidence["lookup"]["path"] == "src/main/java/billing/InvoiceService.java"


def test_a_store_lookup_takes_the_record_type_its_method_returns(result: dict) -> None:
    evidence = _row(result, "GET", "/docs/{id}/peek")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Doc", "owner")


def test_method_security_naming_the_id_is_the_check(result: dict) -> None:
    evidence = _row(result, "PUT", "/api/invoices/{id}")["ownership_evidence"]
    assert evidence["check"]["path"] == "src/main/java/billing/Billing.java"


def test_owner_bearing_judged_rows_sort_ahead_of_unresolved_ones(result: dict) -> None:
    judged = [r for r in result["routes"] if r["ownership"] in ("caller-blind", "unchecked")]
    owners = [bool(r["ownership_evidence"]["owner_field"]) for r in judged]
    assert owners == sorted(owners, reverse=True)


# Code that looks protected but isn't: each must stay judged beside a correct twin.
LEDGER = (
    "import org.springframework.web.bind.annotation.*;\n"
    "import java.security.Principal;\n"
    "interface LedgerApi {\n"
    '  @GetMapping("/ledger/{id}") Entry byInterface(@PathVariable("id") Long id);\n}\n'
    "class Entry { Long id; String ownerId; long cents; }\n"
    "class OwnedRecord { String ownerId; }\n"
    "class Document extends OwnedRecord { Long id; String body; }\n"
    "class Memo extends ExternalBase { Long id; String body; }\n"
    "interface EntryRepository extends JpaRepository<Entry, Long> {\n"
    "  Optional<Entry> findByIdAndOwnerId(Long id, String ownerId);\n}\n"
    '@RestController @RequestMapping("/v")\n'
    "class Ledger implements LedgerApi {\n"
    "  private EntryRepository entries;\n"
    "  private EntityManager em;\n"
    "  private Access access;\n"
    "  public Entry byInterface(Long id) { return entries.findById(id).orElseThrow(); }\n"
    '  @GetMapping("/logs/{id}") Entry logs(@PathVariable Long id, Principal me) {\n'
    "    Entry e = entries.findById(id).orElseThrow();\n"
    '    if (e.ownerId.equals(me.getName())) { System.out.println("owner"); }\n'
    "    return e;\n  }\n"
    '  @GetMapping("/unrelated/{id}") Entry unrelated(@PathVariable Long id, Principal me) {\n'
    "    Entry e = entries.findById(id).orElseThrow();\n"
    "    if (e.cents > 0 && me != null) { throw new IllegalStateException(); }\n"
    "    return e;\n  }\n"
    '  @GetMapping("/positive/{id}") Entry positive(@PathVariable Long id, Principal me) {\n'
    "    Entry e = entries.findById(id).orElseThrow();\n"
    "    if (e.ownerId.equals(me.getName())) { return e; }\n"
    "    throw new IllegalStateException();\n  }\n"
    '  @GetMapping("/advisory/{id}") Entry advisory(@PathVariable Long id, Principal me) {\n'
    '    if (access.canRead(me.getName(), id)) { System.out.println("ok"); }\n'
    "    return entries.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/enforced/{id}") Entry enforced(@PathVariable Long id, Principal me) {\n'
    "    if (!access.canRead(me.getName(), id)) { throw new IllegalStateException(); }\n"
    "    return entries.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/mapped/{id}") Object mapped(@PathVariable Long id, Principal me) {\n'
    "    return entries.findById(id).map(e -> new Object[] {e, me.getName()}).orElseThrow();\n"
    "  }\n"
    '  @DeleteMapping("/late/{id}") void late(@PathVariable Long id, Principal me) {\n'
    "    entries.deleteById(id);\n"
    "    access.checkPermission(me.getName(), id);\n  }\n"
    '  @GetMapping("/branch/{id}") Entry branch(@PathVariable Long id, Principal me, boolean f) {\n'
    "    if (f) { entries.findByIdAndOwnerId(id, me.getName()); }\n"
    "    return entries.findById(id).orElseThrow();\n  }\n"
    "  @PreAuthorize(\"#format == 'pdf'\")\n"
    '  @GetMapping("/format/{id}")\n'
    "  Entry format(@PathVariable Long id, @RequestParam String format) {\n"
    "    return entries.findById(id).orElseThrow();\n  }\n"
    "  @PreAuthorize(\"#id.equals('demo')\")\n"
    '  @GetMapping("/demo/{id}") Entry demo(@PathVariable String id) {\n'
    "    return entries.findById(Long.valueOf(id)).orElseThrow();\n  }\n"
    '  @PostAuthorize("returnObject.ownerId == authentication.name")\n'
    '  @GetMapping("/returned/{id}") Entry returned(@PathVariable Long id) {\n'
    "    return entries.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/documents/{id}") Document document(@PathVariable Long id) {\n'
    "    return em.find(Document.class, id);\n  }\n"
    '  @GetMapping("/memos/{id}") Memo memo(@PathVariable Long id) {\n'
    "    return em.find(Memo.class, id);\n  }\n"
    "}\n"
    '@RestController @RequestMapping("/guarded")\n'
    '@PreAuthorize("@access.canRead(#id, authentication)")\n'
    "class Guarded {\n"
    "  private EntryRepository entries;\n"
    '  @GetMapping("/{id}") Entry get(@PathVariable Long id) {\n'
    "    return entries.findById(id).orElseThrow();\n  }\n"
    "}\n"
)


@pytest.fixture(scope="module")
def ledger(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("ledger")
    for rel, text in {
        "pom.xml": POM,
        "src/main/java/ledger/MethodSecurity.java": METHOD_SECURITY,
        "src/main/java/ledger/Ledger.java": LEDGER,
    }.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return route_guards(tree_files(root)).model_dump(mode="json")


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/v/logs/{id}", "unchecked"),  # the condition doesn't deny
        ("GET", "/v/unrelated/{id}", "unchecked"),  # compares nothing with the caller
        ("GET", "/v/positive/{id}", "checked"),  # equal → returns, otherwise throws
        ("GET", "/v/advisory/{id}", "unchecked"),  # an authorization result left unused
        ("GET", "/v/enforced/{id}", "checked"),
        ("GET", "/v/mapped/{id}", "unchecked"),  # the caller added to output, not a filter
        ("DELETE", "/v/late/{id}", "unchecked"),  # the delete runs before the check
        ("GET", "/v/branch/{id}", "unchecked"),  # the scoped lookup sits in an optional branch
        ("GET", "/v/format/{id}", "caller-blind"),  # method security on another parameter
        ("GET", "/v/demo/{id}", "caller-blind"),  # names the id, compares it with a constant
        ("GET", "/v/returned/{id}", "checked"),  # the returned object against the caller
        ("GET", "/v/ledger/{id}", "caller-blind"),  # @PathVariable on the interface
        ("GET", "/v/documents/{id}", "caller-blind"),  # owner field inherited
        ("GET", "/v/memos/{id}", "caller-blind"),  # superclass outside the checkout: not ownerless
        ("GET", "/guarded/{id}", "checked"),  # class-level object security
    ],
)
def test_protection_has_to_be_enforced_to_count(
    ledger: dict, method: str, pattern: str, ownership: str
) -> None:
    row = _row(ledger, method, pattern)
    assert row["ownership"] == ownership
    assert row["judgement_required"] is (ownership in ("caller-blind", "unchecked"))


def test_an_inherited_owner_field_is_named(ledger: dict) -> None:
    evidence = _row(ledger, "GET", "/v/documents/{id}")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Document", "ownerId")


# Shapes an independent review found credited without protection; each must stay judged.
PROBE = (
    "package probe;\n"
    "import org.springframework.web.bind.annotation.*;\n"
    "import java.security.Principal;\n"
    "class Card { Long id; String ownerEmail; long cents; }\n"
    "class Task { Long id; Long projectId; }\n"
    "interface CardRepository extends JpaRepository<Card, Long> {\n"
    "  Optional<Card> findByIdAndOwnerEmail(Long id, String ownerEmail);\n"
    "  Optional<Card> findByIdOrOwnerEmail(Long id, String ownerEmail);\n"
    "  boolean existsByIdAndOwnerEmail(Long id, String ownerEmail);\n}\n"
    "interface CardFinder { Card find(Long id, String owner); }\n"
    "class LooseFinder implements CardFinder {\n"
    "  private CardRepository cards;\n"
    "  public Card find(Long id, String owner) { return cards.findById(id).orElseThrow(); }\n}\n"
    "class Base { protected CardFinder finder; }\n"
    '@RestController @RequestMapping("/p")\n'
    "class Probe extends Base {\n"
    "  private CardRepository cards;\n"
    "  private Access access;\n"
    "  private EntityManager em;\n"
    "  private JdbcTemplate jdbc;\n"
    '  @GetMapping("/try/{id}") Card tried(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    try { if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException(); }\n"
    "    catch (RuntimeException ex) { }\n"
    "    return c;\n  }\n"
    '  @GetMapping("/lambda/{id}") Card lambda(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    Runnable r = () -> { if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException(); };\n"
    "    return c;\n  }\n"
    '  @GetMapping("/nested/{id}") Card nested(@PathVariable Long id, Principal me, boolean s) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (s) { if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException(); }\n"
    "    return c;\n  }\n"
    '  @GetMapping("/early/{id}") Card early(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (c.cents == 0) return c;\n"
    "    if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @PutMapping("/mutated/{id}") void mutated(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    c.cents = 0;\n"
    "    cards.save(c);\n"
    "    if (!c.ownerEmail.equals(me.getName())) throw new IllegalStateException();\n  }\n"
    '  @GetMapping("/unrelated-deny/{id}") Card unrelatedDeny(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    '    if (c.ownerEmail.equals(me.getName())) { System.out.println("owner"); }\n'
    "    if (c.cents < 0) { throw new IllegalStateException(); }\n"
    "    return c;\n  }\n"
    '  @GetMapping("/worded/{id}") Card worded(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    '    if (!c.ownerEmail.equals(me.getName())) System.out.println("forbidden access");\n'
    "    return c;\n  }\n"
    '  @DeleteMapping("/can/{id}") void can(@PathVariable Long id, Principal me) {\n'
    "    access.canDelete(me.getName(), id);\n"
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/swallowed/{id}") void swallowed(@PathVariable Long id, Principal me) {\n'
    "    try { access.checkOwner(me.getName(), id); } catch (Exception ex) { }\n"
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/ignored/{id}") void ignored(@PathVariable Long id, Principal me) {\n'
    "    Optional<Card> mine = cards.findByIdAndOwnerEmail(id, me.getName());\n"
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/unchecked-exists/{id}") void uncheckedExists(@PathVariable Long id, Principal me) {\n'
    '    if (!cards.existsByIdAndOwnerEmail(id, me.getName())) { System.out.println("x"); }\n'
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/enforced-exists/{id}") void enforcedExists(@PathVariable Long id, Principal me) {\n'
    "    if (!cards.existsByIdAndOwnerEmail(id, me.getName())) { throw new IllegalStateException(); }\n"
    "    cards.deleteById(id);\n  }\n"
    '  @DeleteMapping("/thrown/{id}") void thrown(@PathVariable Long id, Principal me) {\n'
    "    cards.findByIdAndOwnerEmail(id, me.getName()).orElseThrow();\n"
    "    cards.deleteById(id);\n  }\n"
    '  @PreAuthorize("@access.canReadProject(#pid, authentication)")\n'
    '  @GetMapping("/projects/{pid}/cards/{cid}") Card two(@PathVariable Long pid, @PathVariable Long cid) {\n'
    "    return cards.findById(cid).orElseThrow();\n  }\n"
    '  @PreAuthorize("@rateLimiter.allow(#id)")\n'
    '  @GetMapping("/limited/{id}") Card limited(@PathVariable Long id) {\n'
    "    return cards.findById(id).orElseThrow();\n  }\n"
    '  @PostAuthorize("returnObject.ownerEmail == authentication.name")\n'
    '  @DeleteMapping("/after/{id}") Card after(@PathVariable Long id) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    cards.deleteById(id);\n"
    "    return c;\n  }\n"
    '  @GetMapping("/as/{id}") Card as(@PathVariable Long id, @RequestParam String as, Principal me) {\n'
    "    String owner = as != null ? as : me.getName();\n"
    "    return cards.findByIdAndOwnerEmail(id, owner).orElseThrow();\n  }\n"
    '  @GetMapping("/nonnull/{id}") Card nonnull(@PathVariable Long id, Principal me) {\n'
    "    return cards.findById(id).filter(c -> me != null).orElseThrow();\n  }\n"
    '  @GetMapping("/or/{id}") Card or(@PathVariable Long id, Principal me) {\n'
    "    return cards.findByIdOrOwnerEmail(id, me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/iface/{id}") Card iface(@PathVariable Long id, Principal me) {\n'
    "    return finder.find(id, me.getName());\n  }\n"
    '  @GetMapping("/created/{id}") Card created(@PathVariable Long id, Principal me) {\n'
    "    return new LooseFinder().find(id, me.getName());\n  }\n"
    '  @GetMapping("/jpql/{id}") Object jpql(@PathVariable Long id) {\n'
    '    return em.createQuery("from Card c where c.id = :id").setParameter("id", id).getSingleResult();\n'
    "  }\n"
    '  @GetMapping("/jdbc/{id}") Object jdbc(@PathVariable Long id) {\n'
    '    return jdbc.queryForObject("select * from card where id = ?", Object.class, id);\n  }\n'
    '  @GetMapping("/trim/{id}") Card trim(@PathVariable String id) {\n'
    "    String key = id.trim();\n"
    "    return cards.findById(Long.valueOf(key)).orElseThrow();\n  }\n"
    '  @GetMapping("/map/{id}") Card map(@PathVariable Map<String, String> vars) {\n'
    '    return cards.findById(Long.valueOf(vars.get("id"))).orElseThrow();\n  }\n'
    '  @GetMapping("/form/{id}") Card form(CardForm form) {\n'
    "    return cards.findById(form.id).orElseThrow();\n  }\n"
    '  @GetMapping("/tasks/{id}") Task task(@PathVariable Long id) {\n'
    "    return em.find(Task.class, id);\n  }\n"
    '  @GetMapping("/emails/{id}") Card email(@PathVariable Long id) {\n'
    "    return em.find(Card.class, id);\n  }\n"
    "  @RolesAllowed({Roles.ADMIN, Roles.USER})\n"
    '  @GetMapping("/roles/{id}") Card roles(@PathVariable Long id) {\n'
    "    return cards.findById(id).orElseThrow();\n  }\n"
    '  @GetMapping("/doubled/{id}") Card doubled(@PathVariable Long id, Principal me) {\n'
    "    Card c = cards.findById(id).orElseThrow();\n"
    "    if (!c.ownerEmail.equals(me.getName()) == false) throw new IllegalStateException();\n"
    "    return c;\n  }\n"
    '  @GetMapping("/inline-as/{id}") Card inlineAs(@PathVariable Long id, @RequestParam String as, Principal me) {\n'
    "    return cards.findByIdAndOwnerEmail(id, as != null ? as : me.getName()).orElseThrow();\n  }\n"
    '  @GetMapping("/finder/{id}") Card viaFinder(@PathVariable Long id, Principal me) {\n'
    "    return load(id, me, cards::findByIdAndOwnerEmail);\n  }\n"
    "  Card load(Long id, Principal me, java.util.function.BiFunction<Long, String, Card> finder) {\n"
    "    Card c = finder.apply(id, me.getName());\n"
    "    return c;\n  }\n"
    '  @GetMapping("/finder-request/{id}") Card viaFinderRequest(@PathVariable Long id, @RequestParam String who) {\n'
    "    return loadFor(id, who, cards::findByIdAndOwnerEmail);\n  }\n"
    "  Card loadFor(Long id, String who, java.util.function.BiFunction<Long, String, Card> finder) {\n"
    "    Card c = finder.apply(id, who);\n"
    "    return c;\n  }\n"
    '  @DeleteMapping("/reassigned/{id}") void reassigned(@PathVariable Long id, Principal me, Long other) {\n'
    "    cards.findByIdAndOwnerEmail(id, me.getName()).orElseThrow();\n"
    "    id = other;\n"
    "    cards.deleteById(id);\n  }\n"
    "}\n"
)


@pytest.fixture(scope="module")
def probe(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("probe")
    for rel, text in {
        "pom.xml": POM,
        "src/main/java/probe/MethodSecurity.java": METHOD_SECURITY,
        "src/main/java/probe/Probe.java": PROBE,
    }.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return route_guards(tree_files(root)).model_dump(mode="json")


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/p/try/{id}", "unchecked"),  # the check is in a try that swallows it
        ("GET", "/p/lambda/{id}", "unchecked"),  # the check never runs
        ("GET", "/p/nested/{id}", "unchecked"),  # only under another condition
        ("GET", "/p/early/{id}", "unchecked"),  # returned before the check
        ("PUT", "/p/mutated/{id}", "unchecked"),  # saved before the check
        ("GET", "/p/unrelated-deny/{id}", "unchecked"),  # the denial belongs to another test
        ("GET", "/p/worded/{id}", "unchecked"),  # "forbidden" in a log line isn't a denial
        ("DELETE", "/p/can/{id}", "unchecked"),  # a boolean authorization thrown away
        ("DELETE", "/p/swallowed/{id}", "unchecked"),  # the check's exception is caught
        ("DELETE", "/p/ignored/{id}", "unchecked"),  # a scoped lookup whose result is ignored
        ("DELETE", "/p/unchecked-exists/{id}", "unchecked"),  # nothing refused when absent
        ("DELETE", "/p/enforced-exists/{id}", "checked"),  # refused when absent: the id is verified
        ("DELETE", "/p/thrown/{id}", "checked"),  # orElseThrow: verified
        ("GET", "/p/projects/{pid}/cards/{cid}", "caller-blind"),  # security names the other id
        ("GET", "/p/limited/{id}", "caller-blind"),  # a bean call without the caller
        ("DELETE", "/p/after/{id}", "caller-blind"),  # PostAuthorize runs after the delete
        ("GET", "/p/as/{id}", "unchecked"),  # a request value can stand in for the caller
        ("GET", "/p/nonnull/{id}", "unchecked"),  # the filter compares nothing with the record
        ("GET", "/p/or/{id}", "unchecked"),  # an Or-query doesn't narrow to the caller
        ("GET", "/p/iface/{id}", "unchecked"),  # through an inherited interface field
        ("GET", "/p/created/{id}", "unchecked"),  # through `new Impl()`
        ("GET", "/p/jpql/{id}", "caller-blind"),  # a JPQL parameter is a lookup
        ("GET", "/p/jdbc/{id}", "caller-blind"),  # JdbcTemplate by id
        ("GET", "/p/trim/{id}", "caller-blind"),  # a trimmed id is the id
        ("GET", "/p/map/{id}", "caller-blind"),  # @PathVariable Map
        ("GET", "/p/form/{id}", "unknown"),  # a command object: the id isn't followed
        ("GET", "/p/tasks/{id}", "caller-blind"),  # projectId: indirect tenancy
        ("GET", "/p/emails/{id}", "caller-blind"),  # ownerEmail is an owner field
        ("GET", "/p/roles/{id}", "caller-blind"),  # Roles.USER admits ordinary users
        ("GET", "/p/doubled/{id}", "unchecked"),  # `!owner == false` denies the owner
        ("DELETE", "/p/reassigned/{id}", "unchecked"),  # the id changed after the check
        ("GET", "/p/inline-as/{id}", "unchecked"),  # a mixed value inline isn't the caller
        (
            "GET",
            "/p/finder/{id}",
            "scoped",
        ),  # a load handed a caller value: trusted (owner decision)
        ("GET", "/p/finder-request/{id}", "caller-blind"),  # handed request data, not the caller
    ],
)
def test_protection_that_doesnt_hold_stays_judged(
    probe: dict, method: str, pattern: str, ownership: str
) -> None:
    row = _row(probe, method, pattern)
    assert row["ownership"] == ownership
    assert row["judgement_required"] is (ownership in ("caller-blind", "unchecked"))
