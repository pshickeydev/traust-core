# Services and interfaces

Rules: `AGENTS.md` → Design rules. Shape to copy: any domain service, e.g. `services/portfolio.py`.

A domain service:

1. One class per domain in `services/<subject>.py` (a package only when the domain holds several responsibilities, e.g. `services/findings/`). Before adding a method, check no other service already owns the capability.
2. Constructor takes its own section's unit-of-work protocol (`InventoryUnitOfWork`, …; `TraustUnitOfWork` only for use cases that write several sections, listed in `SPANS_SECTIONS` in `tests/v1/test_architecture.py`), the other domains' **services** it needs (never their repositories), providers and `Clock`.
3. Methods take typed IDs, commands or contracts artifacts and return domain models or `Page[...]` — never `dict`, never `JobResult`.
4. Skill doors: `prepare(...) -> <X>Input` (extends `SkillInput`) and `record(doc: <X>Artifact, provenance: Provenance)`; `@overload` when the domain records more than one document. Run the document's `Lint` rules inside `record`.
5. Reads use the shared verbs: `get`, `find_*`, `list(filter, page)`, `summary(filter, group_by)`, `timeline(filter, bucket)`.
6. Behaviour about one entity's own state goes on the model; rules needing config or several domains go in a policy class next to the service.
7. Tests run the service over `SqlTraustUnitOfWork` with rows seeded through the `seed` fixture; assert behaviour, never the DDL.

Interfaces implemented outside core (`Materializer`, `Router`):

1. Request/response models in `models/<subject>.py`; the `Protocol` in the service module that consumes it.
2. Implemented in the owning repo; export from `services/__init__.py`; README row.

## Composition root

`Context.services()` builds every service from **one** shared `SqlTraustUnitOfWork`, one line per service, collaborators passed explicitly. No wiring anywhere else, no second unit of work, no extra databases.

## Config

1. Add a frozen `_Model` section in `context/config.py`; unknown keys stay rejected.
2. Secrets are referenced by env var name (`*_env`), read through `_read_env`.
3. `Context` reads the section; nothing else reads config or env.
4. Test: valid file, typo rejected, secret read from env.

## Job (engine and LLM entry)

1. The work is a domain service method returning a domain result.
2. `Materializer` (`services.operations`): `asset` name + `materialize(AssetRequest) -> JobResult`. Parse partition/params into value objects; bad input → `JobResult.failed`; call the one service; turn its result (or degraded/refused outcome) into `JobResult`. No logic beyond that.
3. CLI for LLMs: argv → `AssetRequest` → the same materializer → print `JobResult` JSON → exit code.
4. traust-engine registers materializers at startup: `ctx.assets.register(name, factory)`.
5. Worked example: `tests/v1/example/continuous_ops/` (its service is a module function — predates the one-service-per-domain rule; copy the adapter, not that).
