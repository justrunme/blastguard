# Contributing

## Development setup

```bash
go mod download
make tidy
```

## Branch naming

- `feat/<short-name>`
- `fix/<short-name>`
- `chore/<short-name>`
- `docs/<short-name>`
- `ci/<short-name>`

## Commits

Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `test:`, `ci:`.

## Tests

```bash
make test
make ci      # offline checks + demo decision must BLOCK
make demo
make rehearse
make prove
```

## Pull requests

Open against `main`. CI must be green. Squash merge preferred.

Checklist:

- [ ] `make ci` passes
- [ ] Branch naming follows convention
- [ ] Conventional commits
- [ ] Decision-engine changes include Go tests
- [ ] Fixtures under `testdata/` / `fixtures/` updated when needed
