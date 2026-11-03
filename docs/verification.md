# Verification records

Each version section is a dated snapshot of the specific checks and environment
recorded there. Its test counts and integration results do not automatically
apply to later commits or deployments. The current checked-in Alembic head is
`0011_workspace_settings`; the Version 0.5 note that the default local
workspace had reached `0006_reports` describes that workspace at the time of
that historical run. It does not identify the current source head or any
deployment database revision. Use `droidshield migrate` to advance a development
workspace, and verify deployment databases independently.

## Version 0.5 — Android/iOS analyst delivery

Verified on 2026-10-28 using fictional fixtures, an unprivileged Linux account,
real Bubblewrap intake, private SQLite workspaces and PostgreSQL 18 isolated
schemas. No client app or external production target was assessed.

- Full PostgreSQL run: **629 passed, 6 external-runtime/service tests skipped**.
  This covers prior engines and the new analyst/reports/migration checks. The
  six optional emulator/MobSF tests were not rerun for this delivery increment;
  their earlier real-lab results remain recorded below.
- A subsequent archive-classification fix passed **54 SQLite upload/intake/limit
  checks** and its **two new PostgreSQL regressions**. A valid APK/AAB polyglot
  cannot silently acquire a different immutable format through digest dedup;
  both upload orders preserve the first artifact and reject the second binding.
- **22 frontend tests passed.** Browser QA used separate temporary analyst and
  administrator accounts: uploaded an IPA, began a manual engagement, saved
  protected evidence, recorded coverage with 17 Not Run procedures, created and
  scored a fictional informational finding, independently reviewed the finding
  and assessment, generated/reviewed/released a report and downloaded its PDF.
- Browser retest QA uploaded a distinct fixed fixture, recorded new-build
  evidence, compared original/new evidence and verified that the finding stayed
  Retest Required until a separate reviewer approved the Pass result. It then
  became Fixed. No real iOS runtime/security outcome is claimed by these tests.
- A second report version included the reviewed retest and Fixed state while
  the first report snapshot retained its original Open state. PDF and JSON
  export digests matched downloaded bytes. PDF rendering ran through the bounded
  helper with CPU, memory, file, output, concurrency and elapsed-time budgets.
- New regression cases cover contributor-history reviewer bypass, null artifact
  identity, current authorization for new observations, retest capture windows,
  pinned original API release references, source/retest proof separation,
  immutable snapshots/exports, protected download integrity, CVSS4/3.1 exact
  scoring, killed/reaped render processes and a contended audit write that must
  leave the ASGI event loop responsive.
- SQLite and PostgreSQL migration history/round trips and Alembic consistency
  checks passed; populated legacy project/assessment/device lease records are
  preserved. The default local workspace used for this dated QA record was at
  `0006_reports`; it was not seeded with users, clients or demo counters. This
  local-workspace note is distinct from the isolated migration checks above.
- Ruff lint/format checks and the 0.5 wheel build passed. A separately installed
  wheel smoke exercised packaged frontend/migrations/fonts and the bounded PDF
  helper. A five-page fictional sample PDF was rendered and visually inspected.

The temporary browser/preview, isolated PostgreSQL cluster and QA credentials,
workspaces, uploaded fixtures and virtual environment were removed after checks.
The sample PDF, screenshots and packaged wheel are retained as review artifacts.
See [service coverage](service-delivery.md), [analyst workflow](analyst-workflow.md)
and [reports](reporting.md) for exact capabilities and external-lab requirements.

## Version 0.4 — Frida, proxy and API testing

Verified on 2026-10-28 with unprivileged Linux workers, PostgreSQL 18, Frida
17.9.10 and an explicitly provisioned Android 11 disposable AVD. Test data was
locally generated; no customer APK or external application was assessed.

- Full PostgreSQL suite: **554 passed, 6 skipped**. Three emulator runtime cases,
  one Android proxy case and two opt-in MobSF cases were intentionally skipped
  by the ordinary suite. The new runtime and proxy cases passed separately on
  the real device. MobSF's prior real-service verification is retained below.
- Final focused proxy suite: **30 passed, 1 external-runtime opt-in skipped**,
  including three additional budget/TLS/deadline regressions after the full
  suite was collected. Real local CONNECT/TLS requests verified exact endpoint
  forwarding, no raw evidence retention, method/path/framing rejection, redirect
  refusal, CA/key checks, upstream certificate failure, request budgets and
  independent socket shutdown while a permission callback waits.
- Real Android proxy: authenticated protected upload → verified package plus
  HTTPS scope → dynamic session → worker → app request through the dedicated
  loopback proxy → verified upstream TLS → sanitized persisted observation →
  owned APK, proxy setting and reverse cleanup. This complete test passed on
  `DroidShield_Network` / `emulator-5562` using a local HTTPS fixture. The fixture
  trusted its temporary CA only in its own SSLContext; no system trust change,
  pinning bypass or third-party traffic was used.
- Three real runtime cases passed sequentially on that fresh AVD: package
  inspection, launcher observation and authenticated fixed-script Frida. The
  final Frida run included binary hash/version/ownership, protected process
  metadata, ordinary app UID, fixed hook/counter, lease and cleanup checks.
- **16 frontend tests passed.** Browser testing additionally created an API
  target and execution, used project-scoped credential references, queued and
  cancelled a baseline, then executed six real GET/HEAD probes against a private
  local TLS fixture. The UI displayed anonymous 401 vs account 200 responses,
  zero-byte HEAD comparisons as inconclusive, verified TLS and header flags.
  Bodies and credential values were withheld. SQLite UTC timestamp rendering
  was verified after its correction.
- Cleanup fault regressions cover observer exceptions, uncertain lease
  ownership, independent proxy cleanup stages and serialized status/ownership
  callbacks. A failed earlier QA attempt was quarantined; its dedicated old
  AVD was stopped and preserved rather than silently reused. Final real tests
  used the newly provisioned Network AVD.
- Ruff lint/format checks, Alembic consistency on SQLite and isolated PostgreSQL,
  migration round trips/history guards and the 0.4 wheel build passed. The wheel
  includes the trusted Frida helper/script, proxy and API modules and migration
  `0004_api_security`. A downgrade refuses to erase new API/instrumentation
  history; unused feature tables may round-trip without damaging legacy leases.

Both owned emulators are stopped. The Network device was verified to have exact
IPv4/IPv6 DROP policies, no proxy setting, no test APK and no owned ADB mappings
before shutdown. Its Frida server and QA credentials were removed. The old
quarantined `DroidShield_Lab` remains off. Browser/TLS preview services and QA
workspace credentials/data were removed. Dedicated AVD disks and the verified
official Frida binary remain for explicit administrator provisioning.

See [Frida](frida.md), [proxy](proxy.md), [API testing](api-security.md) and
[frontend](frontend.md) for reproducible commands and the exact bounded coverage.
These checks do not establish broad exploit coverage or confirm vulnerabilities.

## Version 0.3

Verified on 2026-10-28 with an unprivileged Linux account, Bubblewrap, PostgreSQL
18, MobSF 4.5.3 and a dedicated Android 11 x86_64 emulator. Only locally generated
test APKs and temporary workspaces were used; no client applications were tested.

- Full backend suite against isolated PostgreSQL schemas and the real private
  MobSF service: **442 passed, 2 skipped**. The two skipped tests require the
  explicitly configured disposable emulator.
- Those two runtime tests passed separately on `DroidShield_Lab`: protected
  upload, verified scope, queued session, real ADB package inspection and launcher
  observation, sanitized results, Needs Review transition and package cleanup.
- Real MobSF upload, scan and report retrieval passed through the worker and
  scoped analysis API. A test DEX APK produced four code candidates, one manifest
  candidate and one certificate candidate, with zero tool errors. Counts are
  scanner observations, not confirmed vulnerabilities. Official JADX 1.5.0 was
  provisioned before service startup; upstream tool integrity checks remained on.
- **11 frontend tests passed** for escaping, form serialization, scoped API
  paths, memory-only credentials, session changes, idempotency, interrupted writes
  and incomplete-analysis warnings.
- Browser smoke: connect, create client/project, create and verify authorization,
  create a DEX assessment, upload a real compiled DEX fixture, queue, run the
  isolated worker, observe Needs Review, inspect nine unreviewed candidates and
  redacted evidence, refresh/disconnect and inspect the unconfigured lab state.
- Ruff lint/format checks, Alembic metadata consistency and a wheel build passed.
  The wheel includes the frontend, engine modules and all three migrations.

The MobSF container, internal test network, loopback relay, emulator, browser
preview and PostgreSQL test cluster were stopped after QA. Temporary workspaces,
credentials and uploaded test artifacts were removed. The SDK image and dedicated
AVD remain available for an explicitly configured future lab run. No production
workspace or demo records were created.

To reproduce, follow [frontend](frontend.md), [DEX](dex-analysis.md),
[MobSF](mobsf.md) and [dynamic lab](dynamic-lab.md). Ordinary test runs skip
external-service tests unless their explicit test environment is configured.
