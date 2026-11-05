# Release readiness checklist

Use this checklist for each reviewed release. Record results in the release
notes or deployment record; a prior verification snapshot does not prove the
current deployment is healthy.

## Source and build

- [ ] Review the complete diff, dependencies, migration changes, and release
  notes. Confirm no credentials, client artifacts, local databases, or generated
  secrets are included.
- [ ] Run `pytest`, `ruff check backend tests`,
  `ruff format --check backend tests`, `alembic check`, and
  `node --test tests/frontend.mjs` on the release candidate.
- [ ] Confirm CI passed on the exact commit and build/install the wheel in a
  clean environment. Verify the packaged frontend, migrations, and report fonts.
- [ ] Review migration upgrade behavior against a restored staging copy. Keep
  recovery forward-compatible; do not assume a downgrade is safe.

## Runtime and integrations

- [ ] Confirm the production service account is unprivileged, protected storage
  is outside web roots, and production uses PostgreSQL with explicit network
  policy and HTTPS.
- [ ] Verify `/health/live` and `/health/ready`; separately verify supervisor
  state and recent logs for each enabled worker. These API endpoints do not
  report worker or integration health.
- [ ] For MobSF or Android runtime changes, run the opt-in integration smoke
  workflow against the isolated service or designated disposable emulator.
  Review the job output and confirm cleanup completed. No customer app or
  production target is permitted in these smoke tests.
- [ ] Check protected storage permissions, database/object backup consistency,
  and the latest isolated `droidshield verify-backup` restore drill.
- [ ] Confirm authorization/scope checks, independent review, immutable report
  snapshots, and evidence-backed retest closure remain enabled.

## Deployment and post-deploy

- [ ] Take a consistent database and private object-store backup, then verify a
  restored copy before a high-risk schema or storage change.
- [ ] Apply database migrations once with the migration identity; restart only
  the enabled API/worker services with the reviewed release.
- [ ] Check API liveness/readiness, service-supervisor status, error logs, and
  expected job heartbeats after deployment.
- [ ] Record the release commit, migration revision, test results, integration
  tests that were skipped, and any operator-approved limitations.

Skip any external integration test whose isolated service, credentials,
dedicated runner, or disposable lab has not been provisioned. A skipped check
must be recorded as unverified, never inferred from a configuration flag.
