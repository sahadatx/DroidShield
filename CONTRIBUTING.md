# Contributing to DroidShield

Thanks for helping improve DroidShield. Contributions should preserve the
project's authorization, isolation, privacy, and evidence-review boundaries.

## Before you begin

- Read [`AGENTS.md`](AGENTS.md) and the relevant workflow documents in `docs/`.
- For a substantial change, open an issue first to agree on scope and behavior.
- Do not include client data, real APK/IPA files, credentials, API traffic,
  private keys, production database exports, or unreviewed generated reports.
- Use synthetic fixtures and disposable local resources. Test only applications,
  devices, APIs, and infrastructure for which you have explicit authorization.

## Development setup

DroidShield requires Python 3.11 or later. Node.js 22 or later is needed only
for frontend tests. Follow the local setup in [`README.md`](README.md), then run
the relevant checks from the repository root:

```sh
pytest
ruff check backend tests
ruff format --check backend tests
alembic check
node --test tests/frontend.mjs
```

PostgreSQL integration tests require `DROIDSHIELD_TEST_DATABASE_URL` to point to
a dedicated disposable test database. Never point tests at production data.
Tests that need MobSF or an Android emulator are opt-in; document actual
external-service/device results separately from simulated tests.

## Implementation expectations

- Preserve the backend-first workflow: relational schema and versioned Alembic
  migration, strict validation, transactional authorization/lifecycle services,
  meaningful tests, API integration, then page-by-page frontend integration.
- Keep workspace, project, authorization, and linked-resource checks at every
  boundary. Recheck authorization during worker execution and before publishing
  results.
- Treat APK/AAB/IPA files, scanner output, API responses, evidence, and user
  input as untrusted. Keep secrets, raw traffic, raw DEX literals, and storage
  paths out of logs, audit events, and ordinary API responses.
- Keep execution bounded and isolated. Do not add unsandboxed fallbacks, custom
  Frida scripts, physical-device auto-selection, general-purpose proxying, or
  out-of-scope API methods.
- Escape browser-rendered content, use authenticated same-origin requests, and
  keep API credentials in tab memory only.
- Update the applicable `docs/` coverage and limitations when behavior changes.
  A configured integration is not evidence that the external service is ready.

## Pull request checklist

- [ ] The change has a focused description, rationale, and user-visible impact.
- [ ] Relevant tests and format/lint checks pass; results and skipped external
      checks are stated accurately.
- [ ] Schema changes include an Alembic migration and migration coverage.
- [ ] Authorization, ownership, scope, privacy, and failure paths are covered.
- [ ] Documentation reflects the actual implementation and its limitations.
- [ ] No secrets, customer data, generated artifacts, or unrelated changes are
      included.

Use a concise commit subject such as `feat(api): add scoped endpoint review`,
`fix(worker): recheck authorization before publication`, or
`docs(repo): clarify contribution and security policies`.
