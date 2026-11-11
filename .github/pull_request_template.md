## What

<!-- One domain, one slice. Which service methods / queries does this implement? -->

## Checklist

- [ ] Targets `development`
- [ ] Only this domain's service and its section's repositories changed; other domains reached through their services
- [ ] No new tables, columns or row models (model gaps are raised, not worked around)
- [ ] New SQL is a named query on the owning table's repository
- [ ] No reads of files or databases outside the contract tables and `ObjectStore`; no in-memory stand-ins in `src/`
- [ ] Duplicated responsibility touched by this change moved to its owner, copy deleted
- [ ] Tests: behaviour on SQLite (+ Postgres for new queries) via `uow` / `seed`
- [ ] Legacy code deleted only with a parity diff attached
- [ ] Comments only for non-obvious whys; docstrings one or two lines, none on private helpers
- [ ] No reinvented functions (searched `src/`); shared logic is one helper
- [ ] Tests cover edge cases; integration tests use sanitized copies of real data
- [ ] Diff is as small as it can be
- [ ] `make lint-fix && make test` green
