# DroidShield implementation guidance

Read `docs/blueprint.md` and `docs/api-contract.md` before extending a workflow.
Read `docs/upload-worker.md` for protected storage, parser and worker boundaries.
Read `docs/frontend.md`, `docs/dex-analysis.md` and `docs/dynamic-lab.md` before
extending browser, bytecode or Android runtime workflows. Read `docs/frida.md`,
`docs/proxy.md` and `docs/api-security.md` before instrumentation or network changes.
The adopted order is backend schema, validation, services and meaningful tests,
then page-by-page frontend integration. Do not seed production demo counters.

- Python package: `backend/droidshield`; tests: `tests`.
- `models.py`: relational constraints; use versioned Alembic migrations for changes.
- `schemas.py`: strict request contracts and safe response allowlists.
- `services.py`: transactional authorization, scope, ownership and lifecycle rules.
- `api.py`: HTTP boundary; identities, roles and workspace come from authentication.
- `main.py`: application factory, health, error envelopes and request correlation.
- `uploads.py` / `storage.py`: bounded authenticated intake and opaque artifact storage.
- `apk_engine.py` / `dex_engine.py` / `sandbox.py`: bounded manifest/DEX parsing
  in a restricted Linux namespace; never expose raw DEX literals or secrets.
- `worker.py`: job claim, lease fencing, authorization monitoring and result publication.
- `dynamic.py` / `lab.py`: disposable emulator sessions, exact device identity,
  offline egress checks, exclusive leases, cancellation and crash quarantine.
- `frida_runtime.py` / `frida_helper.py`: fixed native hooks only; authenticated
  pinned guest server, private token handoff, bounded counters and owned forwards.
- `proxy.py` / `proxy_contract.py`: exact HTTPS GET/HEAD lab proxy, dedicated
  debug-app CA trust, verified upstream TLS and temporary UID loopback rules.
- `api_security.py` / `api_transport.py` / `api_secrets.py`: immutable exact endpoint
  targets, leased API jobs, public-by-default IP-pinned TLS, private project-bound
  credential references and sanitized comparisons. Never persist raw traffic.
- `web/`: buildless browser ES modules/CSS served at `/`; API credentials stay
  only in tab memory. Use same-origin authenticated requests, escaped content,
  abortable reads and real API records. Do not add inline executable handlers,
  external scripts, token persistence or unsupported workflow action buttons.
- `docs/client-form-plan.md`: first form's layout, fields and behavior.

Run `pytest`, `ruff check backend tests`, `ruff format --check backend tests` and
`alembic check` after relevant backend changes. PostgreSQL API/migration tests
use `DROIDSHIELD_TEST_DATABASE_URL` and isolated generated schemas. SQLite is
development-only and deliberately serializes transactions before reads.
Run `node --test tests/frontend.mjs` after relevant browser changes; Node 22+
is needed for tests only. Browser execution needs no build or hosted service.

Keep secrets and raw request bodies out of audit events, logs and ordinary GET
responses. Preserve project/workspace boundaries at every linked-resource lookup.
Treat APK/AAB/IPA archives as untrusted input; trusted ingestion calculates hashes from bytes.
Preserve worker scope/authorization checks before claims, during processing and
before publication. Queue records alone never execute scans. Never introduce an
unsandboxed fallback; the API and worker must run as an unprivileged account.
External MobSF processing needs a fixed administrator-configured service and
strict normalization; configuration flags are not proof of readiness. Dynamic
testing is limited to configured disposable emulators with verified deny-all
guest egress. Only the controlled proxy scenario may add its exact owned-app UID
loopback exception; cleanup must restore and verify DROP-only IPv4/IPv6 rules. Never auto-discover/select a physical device or reuse a quarantined
lab after a crash. Frida accepts no custom script or TLS/pinning bypass. API and
proxy requests must remain exact-scope GET/HEAD, with current authorization, test
windows, rate/body/time budgets and redirect/SSRF controls. Manual engagement
records do not execute arbitrary tools or requests. Read docs/service-delivery.md
and docs/analyst-workflow.md and docs/reporting.md when extending cross-platform
analyst coverage, evidence, findings review, reports or retesting. Scanner success never confirms a finding. Preserve independent
review, immutable report snapshots, scoped evidence and evidence-backed retest
closure. Automated engine orchestration for Full and iOS runtime stays outside
the execution surface; IPA/AAB metadata intake never implies full binary coverage.
