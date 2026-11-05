# Deployment and recovery runbook

DroidShield is an operator-managed application. Keep the API, database, private
object storage, and each enabled worker under separate service supervision.
Static, Dynamic, and API workers are independent processes and must use the same
database and protected storage configuration as the API. Do not enable a worker
until its required sandbox, exact integration endpoint, or disposable lab is
ready.

## Service health

Check the API process and database/schema readiness separately:

```sh
curl --fail https://droidshield.example/health/live
curl --fail https://droidshield.example/health/ready
```

`/health/live` confirms that the API process responds. `/health/ready` confirms
that the database can be queried and its Alembic revision matches the running
application. Neither endpoint reports worker process liveness, MobSF
availability, sandbox usability, or emulator readiness.

Monitor each enabled worker through the host's process supervisor. For a
systemd deployment, use the unit names assigned by the operator, for example:

```sh
systemctl is-active droidshield-static-worker
systemctl is-active droidshield-dynamic-worker
systemctl is-active droidshield-api-worker
journalctl -u droidshield-static-worker --since "15 minutes ago" --no-pager
```

Only install/monitor the Dynamic unit on a host assigned to a dedicated
disposable emulator. A running process does not prove that the device is
available or safe. Check recent job heartbeats and sanitized job status through
the authenticated application as well. A stale lease fails safely; interrupted
work is not silently retried or published.

## Initial deployment and upgrade

1. Install the reviewed release in a clean virtual environment as an
   unprivileged service account. Run the API and workers without root.
2. Configure PostgreSQL, explicit host/origin allowlists, HTTPS termination,
   and an absolute private storage root outside web roots and the sandbox's
   exposed `/usr` runtime. Protect the environment file and integration secrets
   from other users and source control.
3. Give application accounts only the database privileges they need. Use a
   separate migration identity for schema changes. Ensure the API and every
   enabled worker have access only to their required configuration, database,
   storage, and tools.
4. Before an upgrade, take a consistent database and object-store backup. Restore
   it into an isolated location and run `droidshield verify-backup` against the
   restored database and storage copy. Do not run restore verification against
   production paths.
5. Apply migrations once using the migration identity: `droidshield migrate`.
   Run `alembic check` in the staged release environment, then restart the API
   and only the workers enabled for that deployment.
6. Verify both API health endpoints, supervisor status for each worker, recent
   logs, storage permissions, and database connectivity. Use synthetic fixtures
   in staging for scanner/device checks; do not seed demo records or queue a
   test against a client assessment in production.

Keep worker polling and restart policies under the host supervisor. On
termination, workers receive SIGTERM and request cancellation. Allow shutdown
time for the bounded task to stop. If a process is killed or crashes, the lease
fencing logic fails the interrupted job rather than publishing stale output.

## Recovery

- **API fails readiness after an upgrade:** stop application processes, inspect
  the sanitized service logs, and verify the database revision. If the new
  application is incompatible, restore a known-compatible application build
  only when the current schema is compatible with it. Prefer a forward migration
  fix; do not downgrade a deployed database without a reviewed recovery plan.
- **Database or object backup must be restored:** restore the database and
  object store as one recovery set into a new location, run
  `droidshield verify-backup`, inspect reported counts, then switch service
  configuration during a controlled maintenance window. Keep the original
  failed copy for investigation until recovery is verified.
- **Referenced object is missing or has the wrong digest:** keep the affected
  services stopped from producing client deliverables, preserve the evidence,
  and restore the matching backup. Do not rewrite references or substitute a
  different object to make verification pass.
- **Worker exits or a lease expires:** inspect that worker's service logs and
  the sanitized failed job status. Confirm the host, sandbox, integration, or
  device state before an authorized operator queues a new attempt. An expired
  attempt is not automatically retried.
- **Dynamic lab crashes or cleanup is uncertain:** keep the device quarantined,
  preserve its state for investigation, and provision a fresh disposable lab
  before resuming. Never select a physical device or reuse a quarantined one.
- **MobSF or another external integration is unavailable:** leave its
  administrator-managed configuration unchanged until the service is restored
  and validated. Do not switch to an unpinned endpoint or bypass normalization.

The integration smoke workflow is opt-in and uses dedicated self-hosted runners
with locally generated or explicitly designated test fixtures. It is not a
production health probe and does not authorize tests against client systems.
See the [release checklist](release-checklist.md) for release gates.

To enable its weekly Monday 04:17 UTC schedule, restrict each self-hosted runner
group to this repository and the trusted `main` branch, then configure only the
needed repository variables and secrets:

- MobSF: set repository variable `DROIDSHIELD_MOBSF_SMOKE_ENABLED=true`; add
  secrets `DROIDSHIELD_MOBSF_TEST_URL` and `DROIDSHIELD_MOBSF_TEST_KEY` for the
  isolated test service.
- Android: set repository variable `DROIDSHIELD_EMULATOR_SMOKE_ENABLED=true`;
  add `DROIDSHIELD_TEST_RUNTIME_APK` as the runner-local path to the generated
  harmless fixture from `scripts/build-runtime-smoke.py`, and
  `DROIDSHIELD_TEST_RUNTIME_DEVICE` as JSON describing its exact already-booted
  disposable AVD. The workflow never discovers or starts devices and does not
  run the Frida or proxy scenarios.

Manual `workflow_dispatch` inputs can run either check on demand. The scheduled
workflow runs only the integration whose variable is explicitly set to
`true`; an enabled job fails if its required secrets or runner files are absent.
GitHub-hosted schedules are best-effort, so use the service supervisor and
dedicated monitoring for production availability.
