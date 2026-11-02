# DroidShield

Mobile Security Assessment — an authorized Android and iOS assessment workspace with protected artifacts, isolated Android analysis and reviewed client deliverables.

DroidShield 0.5 adds analyst-led mobile pentest delivery: protected APK/AAB/IPA intake, version-pinned test coverage, sanitized evidence, manual findings, independent review, CVSS 4.0/3.1 scoring, reviewed PDF/JSON reports and evidence-backed retests. The browser uses real persisted records; no production clients or dashboard counters are seeded. Existing isolated manifest/DEX/MobSF, controlled Android Frida/proxy and exact HTTPS API workers remain available.

See the [service coverage matrix and delivery workflow](docs/service-delivery.md) for what runs automatically and what the analyst performs in an external lab. iOS device testing, Burp/Objection workflows, full binary/source/dependency reviews and business-logic testing can be recorded with provenance and evidence; the workspace does not claim to execute them automatically.

## Start locally

Use Python 3.11 or later, Linux, an unprivileged API/worker account, Bubblewrap (`bwrap`), working unprivileged user namespaces and a trusted system Python under `/usr`. APK processing refuses real or effective host UID 0 and fails closed when isolation is unavailable. From the project directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
droidshield migrate
droidshield bootstrap --workspace DroidShield --email analyst@example.com --name 'Workspace Admin'
# Use the User ID printed by bootstrap; the password is entered in hidden prompts:
droidshield set-password --user-id <UUID>
uvicorn droidshield.main:create_app --factory --host 127.0.0.1 --port 8787
```

Open the [DroidShield workspace](http://127.0.0.1:8787/) and sign in with the email and password you set. The browser session uses a server-managed HttpOnly cookie, survives page reloads, and expires after 12 hours by default. Passwords are stored as salted scrypt hashes; no default password is generated. To set or reset an existing user's password, run `droidshield set-password --user-id <UUID>` in a terminal. This also revokes that user's active sessions. `droidshield issue-token --user-id <UUID>` remains available only for programmatic API clients; the browser does not ask for or send bearer tokens.

Start workers separately, with the same database, protected storage and execution configuration:

```sh
# Static manifest, DEX, or configured MobSF analysis:
droidshield worker
# Configured disposable lab sessions, including Frida/proxy observation:
droidshield dynamic-worker
# Exact approved HTTPS API endpoints (GET/HEAD baseline/comparisons):
droidshield api-worker
```

Each worker accepts `--once` to process at most one eligible job. Queue records alone never launch a scan. Static, Dynamic and API workers claim only their own assessment type. Dynamic execution requires an explicitly configured disposable emulator; API execution requires an exact endpoint configuration and active authorization. Full Android/iOS engagements use the manual workflow; automatic Full orchestration remains planned.

## Included

- A responsive, accessible browser workspace: Overview, Clients, Projects, Assessments, APK Analysis, Dynamic Testing, API Security, Findings, Methodology, Retesting, Reports, administrator Audit Logs and read-only Settings/capabilities. Forms, searches, filters, pagination, revision conflicts, uploads and downloads use real authenticated APIs.
- Strict schemas, relational constraints, and versioned Alembic migrations through `0009_evidence_attachment_scope`; salted scrypt password hashes, persistent HttpOnly browser sessions, CSRF checks and optional hashed API credentials; role, workspace and linked-project checks; optimistic revisions, idempotency and sanitized audit history.
- Client/project create, edit and archive; exact scope authorizations with validity windows, administrator verification/revocation and independent worker rechecks.
- Bounded multipart APK/AAB/IPA intake, sandboxed binary/protobuf manifest and Info.plist inspection, server-calculated SHA-256, private opaque storage, immutable project-scoped deduplication and integrity-verified downloads.
- Isolated manifest analysis and actual bounded DEX instruction inspection. DEX candidates include recognized crypto/WebView API references and secret-like literal categories; raw literals and credentials are never published. See [DEX coverage and limits](docs/dex-analysis.md).
- An administrator-configured MobSF engine option that normalizes allowed results rather than returning arbitrary scanner content. External scanner deployment is its own trusted processing boundary; configuration does not prove that a service is reachable or securely isolated.
- Controlled ADB sessions on dedicated disposable Android emulators: package inspection/launch, fixed Frida native-call counters and exact-target HTTPS proxy observations. Exclusive device leases, authorization monitoring, bounded execution, owned-resource cleanup and crash quarantine remain mandatory. Frida keeps deny-all guest egress; proxy sessions add only an exact app-UID loopback path to the guarded proxy. See [lab requirements](docs/dynamic-lab.md), [Frida](docs/frida.md) and [proxy controls](docs/proxy.md).
- An API Security page and separate leased API worker: immutable exact GET/HEAD endpoint configurations, project-bound protected account references, explicit test windows/rates, verified/pinned HTTPS transport, outbound network controls and sanitized response comparisons. HTTP success is an observation; candidate findings remain Unreviewed/Open. See [API testing](docs/api-security.md).
- Database-derived overview counts, source assessment/artifact/hash/engine provenance, job leases/heartbeats/fencing, cancellation/revocation monitoring and immutable normalized results.
- Sanitized text evidence and bounded PNG screenshot attachments in separate protected storage, with immutable metadata and integrity-checked authenticated downloads. PDF/JSON snapshots include screenshot metadata and hashes; image pixels remain separate protected downloads and are not embedded in reports.

The automated engines provide bounded checks. Automated exploit/fuzzing/injection coverage, arbitrary Frida scripts, TLS/certificate-pinning bypass, broad runtime instrumentation, dependency/CVE completeness, signature validation, production identity-provider integration, editable settings and full team administration remain outside their execution surface. Manual coverage records document external analyst work and never imply tool execution. Client reports support audit evidence; they do not certify SOC 2, ISO 27001, HIPAA, PCI DSS or store approval. A clean candidate list is not proof that an application is secure. The binary-manifest parser supports version codes 0–2,147,483,647 with absent/zero `versionCodeMajor`; other major values fail closed.

For manual delivery, use separate analyst and reviewer accounts. Start an authorized manual engagement, record test coverage and sanitized evidence, review findings, submit the assessment for independent review, then generate, approve and export a frozen report. Retests preserve new-build or API-release evidence and require independent approval before a Pass marks a finding Fixed.

## Workflow and documentation

Create a client and application project, record the approved targets/exclusions/testing window, and have an administrator verify the authorization evidence reference. Create a Static or Dynamic assessment, upload the matching APK, and link the verified authorization. Queue Static analysis with the selected engine, or create a Dynamic session on a configured lab device. Inspect the persisted evidence and coverage limitations after the worker completes. For API testing, create an API assessment with exact HTTPS endpoint targets, configure its API target/account references and test window, then queue it from API Security; no APK is required. Frida/proxy scenarios require the additional administrator setup below.

- [Analyst workflow](docs/analyst-workflow.md): manual engagement, evidence, findings review and exact build/release retests.
- [Gig capability review](docs/gig-capability-review.md): which supplied service promises the product can support, where analyst-lab work remains, and which marketing claims the software cannot establish.
- [Reports and scoring](docs/reporting.md): frozen client deliverables, approval, bounded PDF generation and protected exports.
- [Service delivery and capability matrix](docs/service-delivery.md): Android/iOS service coverage, operational steps, external-lab requirements and accurate client-facing claims.
- [Complete product blueprint](docs/blueprint.md): intended pages, forms, data model and delivery phases, with current delivery boundaries.
- [Browser interface](docs/frontend.md): memory-only connection, page behavior, form/accessibility rules and UI limitations.
- [Backend API contract](docs/api-contract.md): concrete endpoints, payloads and guarded transitions.
- [APK upload and static worker](docs/upload-worker.md): protected intake, storage, leases and recovery.
- [DEX analysis](docs/dex-analysis.md): supported bytecode formats, candidate rules and bounded evidence.
- [MobSF adapter](docs/mobsf.md): fixed service configuration, safe normalization and external processing boundaries.
- [Controlled dynamic lab](docs/dynamic-lab.md): disposable device requirements, sessions, firewall checks and quarantine.
- [Frida observation](docs/frida.md): pinned authenticated server, immutable native-call script, bounded counters and exact forward cleanup.
- [HTTPS lab proxy](docs/proxy.md): dedicated debug CA, restricted CONNECT/GET/HEAD forwarding and guest loopback controls.
- [API security testing](docs/api-security.md): exact scope, account references, pinned TLS transport, rate/window budgets and safe evidence.
- [Client form specification](docs/client-form-plan.md): identity/contact fields and ownership rules.

The local [API reference](http://127.0.0.1:8787/docs), [liveness](http://127.0.0.1:8787/health/live) and [readiness](http://127.0.0.1:8787/health/ready) are served by the same application. Readiness checks database/schema compatibility, not worker liveness, sandbox usability, external scanner availability or Android lab boot state. Authenticated `GET /api/v1/capabilities` exposes safe configuration flags, upload/session limits and opaque lab labels; it never returns scanner credentials, device serials or host paths.

Frida is an optional administrator-provisioned lab dependency. Install the pinned
host extra with `python -m pip install -e '.[instrumentation]'`, provision the
matching authenticated Frida 17.9.10 server on the dedicated AVD, and configure its
verified SHA-256, protected token and interpreter. The worker never downloads or
starts a server and accepts no custom scripts. The built-in hooks count native
`open`/`openat`, `connect` and `getaddrinfo` calls without recording their arguments.

For proxy sessions, create a new private CA directory:

```sh
droidshield init-proxy-ca --directory /absolute/private/droidshield-lab-ca
```

Configure its cert/key paths and provision the certificate into the authorized
app's debug trust configuration. The command never installs device/app trust.
Certificate pinning remains intact. The proxy is a bounded HTTP/1 implementation
using the standard library and cryptography, with exact HTTPS target checks and
independent upstream TLS verification; it is not a general tunnel. See the
runbooks before configuring the optional fields in `.env.example`.

API credentials live in an owner-only project/workspace-bound JSON reference
store configured by the administrator. The browser selects reference names; it
never receives token/cookie/API-key values. Outbound HTTPS is public-address-only
by default, with narrow administrator CIDRs and CA trust for private test labs.

Trusted local administration also supports:

```sh
droidshield create-user --workspace-id <UUID> --email tester@example.com --name Tester --role SECURITY_ANALYST
droidshield set-password --user-id <UUID>
droidshield issue-token --user-id <UUID>  # only for programmatic API clients
droidshield revoke-tokens --user-id <UUID>
droidshield cleanup-storage --older-than-hours 24
```

Cleanup removes stale temporary/unreferenced objects after a minimum one-hour grace period. It does not implement retention deletion for referenced artifacts. No tables are created at application startup; migrate before serving.

## Deployment boundaries

SQLite is for development and uses `BEGIN IMMEDIATE` to serialize transactions before reads. Production settings require PostgreSQL with the psycopg driver and an absolute protected storage root. Use HTTPS, explicit allowed hosts/origins and restricted service/database accounts. Apply migrations with an administrative account; application accounts must not own tables or have DDL privileges. Keep `.env`, API credentials and customer artifacts out of source control.

Storage belongs outside web roots and the `/usr` runtime exposed to the parser sandbox. Back up protected objects and the database together. Audit, artifact and normalized-result mutation guards preserve history against normal application writes; trusted database owners can alter schema and triggers. Internal notes, raw APK/DEX strings, tokens, arbitrary scanner output and device logs are not ordinary audit or GET data.

APKs are untrusted. Local manifest/DEX processing runs in a network-disabled Linux namespace with read-only runtime/input and bounded resources. Workers revalidate access, scope, authorization and immutable artifact identity before execution, while running and before publication. The Android adapter additionally verifies a dedicated emulator identity and deny-all guest egress before installing application code. A proxy session permits only its owned app UID to reach a guest loopback/ADB-reversed guarded proxy, then restores and verifies DROP-only rules. API/proxy outbound requests use exact authorization checks, DNS/IP pinning, verified upstream TLS, no redirect following and bounded response bodies. An external MobSF service must be separately isolated and operated under the authorized assessment policy. All boundaries share underlying host/emulator trust; none certifies safety against kernel or emulator exploits.

## Verification

The [verification record](docs/verification.md) contains dated test snapshots for versions 0.3–0.5; each result describes that recorded setup and is not a claim that every later commit or deployment was re-tested. The checked-in migration head is `0009_evidence_attachment_scope`. The version 0.5 record's note about the default local workspace being at `0006_reports` is historical and refers only to that workspace at the time; migrate a development database with `droidshield migrate`, and do not infer a deployment database's revision from the note. Frida, proxy and API runbooks document their test coverage and actual integration results separately from simulated fault tests.

```sh
pytest
ruff check backend tests
ruff format --check backend tests
alembic check
node --test tests/frontend.mjs
```

Node.js 22 or newer is needed only for browser logic/security tests, not for running the interface. Backend checks use real binary manifests, real Bubblewrap/DEX processing, strict adapter output tests and fault-injected lab behavior. Real MobSF or emulator validation must be recorded separately from simulated adapter tests.

Set `DROIDSHIELD_TEST_DATABASE_URL` to a dedicated PostgreSQL test database for isolated generated-schema API/migration/worker checks; the test role needs schema creation permission. Never use a production database for tests. Passing tests, installed SDK tooling or a configured capability flag alone do not establish external scanner or device readiness.
