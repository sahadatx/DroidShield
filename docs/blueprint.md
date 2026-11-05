> Implemented delivery update (0.5): Android/iOS analyst engagements, APK/AAB/IPA intake, methodology coverage, private evidence, independent findings/assessment review, PDF/JSON reports and reviewed retests now connect to real APIs. See [service delivery](service-delivery.md) and [API contract](api-contract.md). Sections below retain the adopted product blueprint; unsupported automatic execution remains explicitly distinguished in the service matrix.

# DroidShield UI and assessment workflow blueprint

Status: **adopted initial product blueprint**. This document translates the approved specification into an implementation baseline. It describes the complete intended product; it does not imply that every page, scanner or export workflow is implemented. See [API contract](api-contract.md) for the current backend boundary, [Client form plan](client-form-plan.md) for the first form implementation and [APK upload/worker runbook](upload-worker.md) for delivered intake and execution setup.

## 1. Product boundary and implementation order

DroidShield supports an authorized mobile penetration test from client and project setup through APK intake, assessment execution, finding verification, report release and retesting. The backend owns validation, access control and workflow transitions. Frontend validation improves feedback but never grants permission to test or access data.

Implementation order is schema → request validation → services and permissions → API and meaningful tests → frontend pages. The initial stack is FastAPI, SQLAlchemy and Pydantic, with Python code in `backend/droidshield` and resource APIs under `/api/v1`.

Delivered in 0.4: authenticated Clients/Projects/Authorizations and assessment workflows; protected multipart APK intake, server-derived hashes and private artifact reads; separate isolated manifest/DEX workers and a configurable MobSF adapter; immutable results and unreviewed findings; controlled Dynamic sessions on dedicated disposable emulators, including fixed Frida native-call observation and exact HTTPS proxy observation; a separate leased GET/HEAD API baseline/account-comparison worker; and a real API-connected browser workspace. Alembic revision `0004_api_security` adds immutable API targets/results and extends the controlled lab scenario constraint, preserving prior runtime/device lease records. The 0.5 delivery extension adds cross-platform analyst review, reports and retesting; automatic Full execution, arbitrary scripts and exploit/fuzzing/injection execution remain outside the automated surface.

The current browser shell includes Overview, Clients, Projects, Assessments, APK Analysis, Dynamic Testing, API Security, Findings, Methodology, Reports, Retesting, administrator Audit Logs and Settings/capabilities. Settings supports safe browser editing of a bounded set of workspace/report presentation preferences; sensitive integration values remain server-managed and redacted. Search/filter/pagination, lifecycle forms, protected upload/download and evidence inspection use the delivered APIs. Unsupported workflows do not get pretend working buttons. See [browser behavior](frontend.md), [DEX coverage](dex-analysis.md), [MobSF adapter](mobsf.md), [controlled Android lab](dynamic-lab.md), [Frida observation](frida.md), [HTTPS proxy](proxy.md) and [API testing](api-security.md) for exact current boundaries. The remaining sections retain the complete intended product design, including future fields and pages.

Use persisted data for production counters and tables. Illustrative screenshots, sample names and sample counts are design references only. An empty workspace displays zero counts and useful empty states; it must not display fictional activity.

## 2. Application shell and common interactions

Every page uses the same shell:

- Left navigation: Overview, Clients, Projects, Assessments, APK Analysis, Dynamic Testing, API Security, Findings, Retesting, Reports, Methodology, Team & Access, Audit Logs and Settings.
- Top bar: breadcrumb, global search restricted to accessible records, notifications and profile menu.
- Page header: title, concise purpose and primary action appropriate to the current role.
- Content: grouped cards, filter controls, tables, forms and contextual details.
- Context actions: Open, Edit, Export, Archive and other resource actions, each backed by server authorization.
- Feedback: loading, empty, success, field error, request failure, missing resource and access-denied states. Retryable failures preserve user input.

Tables use server-side pagination, stable sorting and explicit filters. Show the total or a reliable next-page indication, distinguish loading from no results, and provide Clear filters. Default sorting should surface recent work. Use UUIDs as resource identities and separate human-readable identifiers such as `ASM-000124` for display where useful.

Forms mark required fields with `*`, group related inputs, associate errors with fields and move focus to the first invalid field. Long forms use sections or steps with a final review. Disable repeated submission while pending; server-side protection remains necessary. A successful create opens the new record and announces success. Failed submissions preserve non-secret values. Save persists, Cancel navigates back without saving, and Reset restores the last persisted values or initial create defaults. Warn before discarding dirty edits. Destructive actions require a confirmation that names the resource and explains the consequence.

All stored timestamps are timezone-aware UTC. Render dates in the workspace timezone and show the timezone for test windows. Validation applies normalized values and declared length/size bounds; the API remains the final authority. Use optimistic concurrency for conflicting edits and idempotency for operations that can create duplicate records or jobs as those workflows are added.

## 3. Page specifications

### 01 — Overview

Purpose: show the workspace's actual assessment posture and next actions.

Layout: KPI row; risk trend and severity distribution; recent assessments, latest findings and pending retests; activity and pending-action panels.

| Component | Data and behavior |
| --- | --- |
| KPIs | Total projects, total assessments, open findings, overdue retests; database-derived and permission-filtered |
| Risk summary | Critical, High, Medium, Low, Informational; state which findings qualify for the count |
| Recent assessments | App, client, type, status, last updated; Open action |
| Activity | Recent persisted resource events within the actor's accessible project scope; event type, actor ID and timestamp |
| Pending actions | Database-derived assessment, report and retest review queues |

Filters: date range, project and assessment status. Actions: New Project, New Assessment, View Findings and Generate Report, subject to role and prerequisites. `GET /api/v1/overview` provides persisted project/assessment counts, queued/running count, confirmed non-fixed finding counts by severity, assessment/report/retest review queue totals, up to 10 sanitized recent events, a bounded rolling risk trend and a count of findings past an explicitly recorded client-agreed retest date. The trend groups current confirmed non-fixed findings by creation date and is not a historical status snapshot. Missing deadlines are never inferred. See the [API contract](api-contract.md) for filter scope and UTC window rules.

### 02 — Clients

Purpose: manage engagement identity and authorized contact information.

Table: client name, contact email, active project count, assessment count, last activity and Active/Archived status. Actions: Create, Open, Edit, Archive and, if supported by policy, Restore. Details tabs: Overview, Projects, Assessments, Reports and Activity.

Form fields: Company/Individual type; required company or individual name according to type; optional organization name where relevant, website, contact person, email, phone and internal notes; status and archive reason when archived. System fields: UUID, creator, creation and update timestamps. Name is required; a supplied email or website must be valid. Archive reason is required on archival. Do not collect passwords, payment cards or unnecessary personal data. See the [Client form plan](client-form-plan.md) for field behavior, API mapping and acceptance tests.

Backend requirement: scoped CRUD and archive service; computed related counts; prevent cross-workspace client references. Archive is a retained status change, not record deletion. Internal notes and archive reason are private to the Client creator and ADMIN. A non-owner who can read a Client through an accessible Project receives those fields as null and cannot edit the Client; the UI treats them as restricted, not blank stored data.

### 03 — Projects

Purpose: represent an Android application and its approved testing scope.

Table: project name, client, application name and package ID, platform/framework, latest version, assessment count, status and last assessment date. Details tabs: Overview, App Versions, Scope & Authorization, Assessments, Findings, Reports and Activity.

| Field | Rule |
| --- | --- |
| Project name | Required text |
| Client | Required accessible client; archived-client handling is explicit in the service |
| Application name | Required text |
| Android package ID | Required; valid dot-separated package syntax |
| Framework | Native, Flutter, React Native, Other or Unknown |
| Version name | Optional text |
| Version code | Optional non-negative integer |
| Repository URL | Optional valid URL; access-controlled |
| Description and scope notes | Optional textareas |
| Status | Active, On hold or Archived; archive reason when applicable |

App versions are separate records. Authorization evidence, approved targets, exclusions and validity are linked records. Creating a project never authorizes active testing. Actions: Create/Edit, add app version, manage authorization, create assessment and Archive.

Backend requirement: client ownership checks, version history, explicit authorization verification/revocation and scope validation. An app artifact binds its recorded version to a server-calculated immutable hash.

### 04 — Assessments

Purpose: configure, queue and observe each assessment.

Table: display ID, project, type, app version, status, verified finding count, creation time and Open/Cancel/Archive actions. Configuration fields: required project, assessment name and type (Static, Dynamic, API or Full); artifact/version; linked authorization; approved scope and exclusions. Display authorization state as service-derived information, never as a user-controlled permission switch.

Store UUID, creator, reviewer, project and artifact references, immutable artifact hash, approved scope/exclusions snapshot, authorization reference, start/end timestamps, tool versions, configuration snapshot, failure reason and cancellation metadata. Execution snapshots remain stable when later settings change.

Canonical workflow:

```text
Draft → Awaiting Authorization → Queued → Running → Needs Review → Completed
                                      ↘ Failed
Any eligible nonterminal state → Cancelled
```

The service defines permitted transitions; a general edit cannot set status arbitrarily. Queueing requires a current verified authorization covering requested targets, time window and test type, as well as required artifacts and configuration. Workers recheck authorization immediately before active execution; expiry or revocation prevents execution. Review approval and completion are separate from scanner success. The API creates/edits draft or awaiting records, submits, queues and cancels, including cancellation while Running. Queueing persists a job; the separate worker claims eligible Static jobs, revalidates scope/authorization throughout execution and publishes a normalized result plus Unreviewed findings. Success marks the job Completed and the assessment Needs Review. A separate Dynamic worker runs bounded package, launch, fixed Frida and restricted proxy sessions. API execution uses its own exact-endpoint configuration and worker, with no APK requirement. Full Android/iOS engagements and human review completion use the implemented [analyst workflow](analyst-workflow.md); automatic Full orchestration and automatic job retry remain outside execution.

Backend requirement: transition service, atomic queueing, deduplication, worker lifecycle and durable cancellation. These are delivered for bounded Static, controlled Dynamic and exact-target GET/HEAD API testing with leases, heartbeats, fenced publication and safe failure/cancellation reads. Dynamic devices additionally have exclusive leases and crash quarantine. An expired running lease fails safely when a subsequent worker observes it; interrupted scans are not automatically retried. Failed and cancelled jobs expose sanitized reasons and timestamps. Planned assessment archival affects retention/visibility, not historical evidence.

### 05 — APK Analysis

Purpose: ingest an untrusted APK and review static-analysis evidence.

Layout: upload panel; metadata and integrity details; analysis progress; severity summary; Summary, Manifest, Code Indicators, Dependencies, Findings and Raw Evidence tabs.

Upload fields: required project, assessment and APK; optional version label, build type (Debug/Release/Unknown) and notes. The assessment must belong to the selected project. Enforce configured upload size and APK file/type validation on the server, inspect archive structure safely and reject malformed or unsupported input. Never rely on extension or browser MIME alone.

Server metadata: SHA-256, byte size, detected package, version name/code, signing certificate, Android SDK metadata when available, analysis engine version and upload timestamp. Show declared/detected metadata mismatches for review; do not silently replace provenance.

Tabs cover risk and scan status; permissions/exported components/configuration; potential secrets and insecure patterns; detected libraries and known-risk indicators; normalized findings; sanitized excerpts and source metadata. Code indicators are unverified candidates.

Backend requirement: protected artifact storage, streaming ingestion, server-side digest, quarantined parsing, normalized results and evidence references. APKs must never execute in the API process. Use an isolated worker with CPU, memory, time, file-system and network limits. Return sanitized errors; do not expose engine credentials or host paths.

Delivered: strict assessment-scoped multipart upload, a default 100 MiB file limit plus at most 64 KiB multipart overhead, a 120-second transfer deadline and two concurrent uploads per API process by default (408 on timeout, 429 when capacity is busy), sandboxed ZIP/binary-manifest inspection before association, private opaque storage, immutable per-Project hash deduplication, version/artifact metadata reads and integrity-verified downloads. Intake can occur before authorization; it never grants execution permission. Current identity, role and Project access are checked again after inspection; current authorization/scope and access are revalidated during worker execution. The upload binds the artifact and increments the assessment revision atomically; exact idempotent retries do not duplicate it.

The `droidshield-manifest-2` engine reads package/version/SDK metadata, permissions, application flags and components, with explicit manifest risk indicators. APK/AAB `version_code` is Android's composed long value `(versionCodeMajor << 32) | versionCode`; each component is bounded to 0–2,147,483,647, and unresolved/out-of-range values are rejected. Older builds with an absent or zero major component retain their original version code. The default engine remains manifest-only. The selectable `droidshield-dex-2` engine adds bounded decoded-instruction and secret-like-category candidates with numeric locations and no raw literals; it does not establish data flow or exploitability. A separately administered MobSF service can provide allowlisted normalized candidates through the configured adapter. A standalone, version-pinned dependency-review adapter can normalize an externally generated CycloneDX 1.6 vulnerability report into a constrained component inventory and unreviewed CVE candidates; it does not scan or resolve dependencies and is not part of worker execution. Signature verification and richer evidence remain product requirements. See [DEX limits](dex-analysis.md), [MobSF boundaries](mobsf.md) and [dependency report normalization](dependency-review.md). Linux Bubblewrap provides no network, a cleared environment, read-only runtime/input and bounded resources; missing isolation or a root (real/effective UID 0) service process fails closed. Deploy API/worker as an unprivileged user with protected data outside the exposed runtime. It shares the host kernel and does not cover kernel exploits or certify deployment security. See the [runbook](upload-worker.md) for operation and limits.

### 06 — Dynamic Testing

Purpose: inspect runtime behavior in a controlled lab.

Session fields: assessment, APK artifact, lab device/emulator, Android version, secret-safe test-account reference, scenarios, network profile, timeout, linked authorization and notes. Required dependencies and timeout bounds must be enforced server-side. Device and APK must match the approved assessment scope and environment.

Scenarios: local storage, runtime permissions, sensitive logs, network observation, TLS verification, session handling, backup/exported components and root/emulator detection review.

Results: timeline, device details, sanitized logs and traffic evidence, case results and manual observations. Actions: create/start/cancel session, inspect evidence and create/link a finding. Lab configuration for ADB, Frida and proxy tools is separate from assessment inputs. Each active test validates target scope, device and authorization before execution.

Delivered subset: configured disposable emulators, one bounded session per Dynamic assessment job, package inspection/launch, fixed Frida native hooks and restricted HTTPS proxy observation. Frida counts `open`/`openat`, `connect` and `getaddrinfo` calls without arguments or raw strings; it accepts no custom scripts or TLS/pinning bypass. Proxy observation forwards only exact approved GET/HEAD targets through a dedicated CA the authorized app already trusts, with verified upstream TLS and no redirects. Deny-all IPv4/IPv6 guest egress is verified before installation; only the proxy scenario adds an exact owned-app UID loopback exception and restores DROP-only rules afterward. The workers preserve exclusive leases, exact device/APK identity, authorization monitoring, cleanup ownership and crash quarantine. The browser integrates supported scenario forms/results and safe configuration capabilities. Broad runtime instrumentation, app login automation, physical-device management and general network testing remain planned. See [lab requirements](dynamic-lab.md), [Frida](frida.md) and [proxy](proxy.md); Full assessments are not treated as Dynamic execution.

### 07 — API Security

Purpose: manage mobile backend API testing targets and evidence.

Target fields: project/assessment, base URL, optional OpenAPI import, authentication method, secret-safe account references, approved endpoint allowlist, excluded endpoint denylist, rate limit, test window and required authorization evidence for active testing. Authentication methods: None, Bearer, OAuth 2.0, API key, Cookie/session and Other.

Validate URL, endpoint patterns, positive bounded rate limit and start-before-end window. Endpoints must be in approved scope; exclusions take precedence. OpenAPI import describes endpoints and never establishes permission. Active testing requires verified authorization. Protected secret storage or OS-protected references hold tokens; ordinary forms, GET responses and logs do not expose plaintext secrets.

Findings view: endpoint/method, authentication state, authorization outcome, sanitized request/response, data exposure, input validation, TLS, reproducibility, severity and remediation.

Delivered subset: immutable API targets with 1–20 exact approved GET/HEAD endpoint/method definitions and explicit authentication expectations, project/workspace-bound primary/secondary credential references, exclusions, rate/window/request/body/time limits and a separate API worker. Direct HTTPS verifies trust/hostname and pins resolved IPs; nonpublic destinations require narrow administrator CIDRs, with metadata/link-local addresses still denied. Redirects are never followed. Only HTTP status, byte count, coarse response comparisons and fixed observations are persisted; no raw response, header, cookie, token or digest evidence is stored. Anonymous success on a configured protected endpoint creates an Unreviewed/Open candidate requiring analyst verification, not a confirmed authorization issue. The API Security browser page uses these real APIs. OpenAPI import/execution, interactive OAuth refresh, state-changing probes, input attacks, data-exposure proof and general API coverage remain planned. See [API runbook](api-security.md).

### 08 — Findings

Purpose: manage vulnerabilities independently of scanner severity and remediation claims.

Table: finding ID/title, project/assessment, severity, verification status, OWASP mapping, reviewer and remediation status. Filters include those fields and app version. Actions: Create/Edit, assign reviewer, attach evidence, verify, request retest and include eligible findings in a report.

| Field | Rule |
| --- | --- |
| Title, description, affected component, category | Required according to finding schema; Markdown rendered safely |
| Severity | Critical, High, Medium, Low or Info |
| CVSS vector and score | Structured versioned vector; validate consistency and calculate score server-side |
| MASVS mapping | Versioned framework reference; CWE optional |
| Reproduction steps, impact, remediation | Structured writing fields; required before confirmation/report release under workflow policy |
| Evidence | Sanitized text, screenshot or artifact with provenance and controlled access |
| Verification | Unreviewed, Confirmed, False Positive or Needs More Evidence |
| Remediation | Open, In Progress, Fixed, Accepted Risk or Retest Required |

Keep source assessment, app version, artifact hash, engine/manual origin and evidence provenance. Severity and verification are separate fields: an automated High result starts Unreviewed. Capture reviewer, reason and time for decisions; accepted risk needs an accountable decision. Evidence and verification requirements are enforced by the service.

Backend requirement: normalized findings, review transitions, assignment, evidence access, deduplication with traceable source links and activity history. The worker now persists normalized scanner candidates with assessment/artifact/hash/job/result/engine provenance, Unreviewed verification and Open remediation; scoped assessment/global finding summaries and sanitized details are readable through the API and Findings UI. Analyst create/edit/verify, validated CVSS/framework mappings, protected sanitized text evidence and guarded remediation transitions are implemented; richer assignment and image evidence management remain extensions. A scanner result cannot complete analyst review.

### 09 — Retesting

Purpose: determine whether a remediation works in the new build.

Form: required finding, original assessment, new app version/APK hash, method (Static/Dynamic/API/Manual), environment and result (Pass/Fail/Inconclusive/Not Reproducible); authenticated operator is server-set. Automatically link previous evidence; require new evidence where applicable and capture a reason when a result cannot be evidenced. Notes are optional.

Comparison layout: original and new evidence side by side, original/current status, versions and hashes, test date, operator and notes. A developer's claim cannot set Fixed. A service applies the reviewer-approved evidence-based outcome; Not Reproducible and Inconclusive do not automatically imply Fixed. Preserve the original finding and append retest history.

Delivered: retest records, same-project new-build linkage, current authorization checks, evidence comparison and independently reviewed remediation transitions. API-only findings can use an original release reference pinned on evidence before completion and a distinct new release; this does not fabricate an application hash. See the [analyst workflow](analyst-workflow.md) for exact gates.

### 10 — Reports

Purpose: produce reviewed, client-specific deliverables.

Form: required title, client/project, assessment and template (Executive/Technical/Combined); severity multiselect; evidence, remediation, methodology and limitations inclusion toggles; workspace branding; reviewer approval required for final release. Validate that every selected record belongs to the same authorized client/project and that findings are eligible for release.

Structure: cover/metadata, executive summary, scope/authorization, methodology/limitations, risk summary, confirmed findings, evidence/reproduction, remediation, retests and appendix/tool versions. Show omitted material and limitations clearly. Review draft, approve release and export PDF/JSON are distinct operations.

Store version, source snapshot, author, reviewer decision, export time, format, checksum and protected output reference. A released version remains reproducible when findings later change. Reports cannot contain another client's data. Exports use protected downloads and safe Markdown rendering.

Delivered: immutable client-specific snapshots, independent release approval, bounded PDF/JSON rendering, protected downloads and checksums. Asynchronous export scheduling and broader retention-policy administration remain extensions.

### 11 — Methodology

Purpose: maintain test knowledge, framework mappings and evidence of coverage.

Layout: framework selector, control categories, test library, assessment coverage matrix, execution history and finding links.

Fields: system-generated case ID; required title; framework (MASVS/MASTG/CWE), framework version/reference ID, category, objective, procedure, expected result, preconditions, applicability (Android/API/Both), risk notes and execution status (Not Run/Pass/Fail/N/A/Blocked). Store case definitions separately from per-assessment execution results. N/A and Blocked require a reason. Version mappings so framework updates cannot silently change old reports.

Delivered: version 1.1.0 of the local test library, with framework source revisions, direct MASVS control references, persisted execution snapshots and scoped evidence/finding relationships. Missing execution remains Not Run. Custom library editing and managed framework-update workflows remain extensions.

### 12 — Team & Access

Purpose: manage users and resource access.

Current table: name, email, role, account status and creation time. Administrators can filter by role and status, create a disabled account, update role/status, or revoke the sessions of another member. Password setup remains a trusted local CLI operation; no invitation, last-login, project-grant editor or temporary-password flow is exposed in the browser.

Initial roles:

| Role | Product permissions |
| --- | --- |
| ADMIN | Workspace and user administration plus authorized operational access |
| SECURITY_ANALYST | Work with accessible clients/projects, assessments, evidence and findings; no user/workspace administration |
| VIEWER | Read-only access to explicitly authorized workspace/project data |

Reviewer and Client Viewer roles can be added later. Every endpoint checks role and object access on the server; hidden menus are only a presentation choice. Disabled accounts and revoked sessions cannot continue authenticated operations. Final report release and authorization verification must use explicit policy, with separation of duties available where required.

Backend and browser delivery: ADMIN-only workspace user listing, disabled-account creation, role/status updates and session revocation use workspace-scoped services and audit events. Team & Access is an administrator-only page with server-backed filters and pagination plus right-side create/edit/revoke drawers. Accounts require trusted local password setup before activation, and the last active administrator cannot be disabled or demoted. Last-login tracking and self-service invitation/setup remain unavailable. The browser signs in with email/password, salted scrypt hashes, HttpOnly expiring sessions and CSRF-checked writes; explicit bearer credentials remain available only for programmatic API clients. The ADMIN Project grant is implemented. Non-admin Project access is limited to created or explicitly granted Projects; linked Client visibility does not grant Client-editing rights.

### 13 — Audit Logs

Purpose: provide append-only-style history of consequential actions.

Table: UTC timestamp, actor ID, action, resource type/ID, Success/Failure, correlation/request ID and sanitized source metadata. Filters: date range, actor, action, resource, result and project. Users cannot edit or delete audit records through ordinary application APIs. Admin export, where supported, is permission-controlled and audited.

Capture authorization changes, lifecycle transitions, evidence changes, report export/release, account changes and configuration updates. Do not log passwords, access tokens, API secrets or complete sensitive request/response bodies. Versioned migrations install SQLite/PostgreSQL triggers that reject UPDATE and DELETE of audit events, APK artifact metadata and normalized analysis results; PostgreSQL also rejects audit/result TRUNCATE. Retention and tamper-evidence still need an explicit operational policy.

Backend requirement: transactional or reliably delivered audit events, sanitized metadata and scoped read/export. The foundation records successful resource mutations and exposes ADMIN-only workspace audit reads with action/resource/result filters. The browser exposes the delivered administrator-only audit table and filters. The API provides bounded ADMIN-only CSV/JSON export using the same workspace and filter scope, sanitized metadata and spreadsheet-safe CSV cells; successful exports append an audit event. A browser export control, project filter and broader audit retention policy remain planned.

### 14 — Settings

Use tabs with independent validation and Save/Cancel states:

| Tab | Configuration |
| --- | --- |
| General | Workspace name, timezone and date format |
| Security | Session timeout, password policy and account controls |
| Analysis Engines | MobSF endpoint, health/status, timeout and resource limits |
| Storage & Retention | Artifact/report retention and cleanup policy |
| Reporting | Default templates, branding and severity display |
| Integrations | Optional API connections and secret references |
| Notifications | Assessment failures, completed reports and retest reminders |

Settings changes require server-side role checks, bounded values and audit events. Mask secret references and never return sensitive configuration values through normal GET responses. Secret rotation uses a dedicated write operation. Engine health checks must not expose secrets or internal diagnostic details to unauthorized users. Configuration snapshots protect existing assessments from later settings edits.

Backend delivery: `GET/PATCH /api/v1/settings` provides an ADMIN-only, typed and revision-checked workspace settings contract for workspace name, display timezone, date format, report template and report branding. It audits changed field names, not values. Sensitive runtime configuration remains server-owned; reads expose configured/not-configured status only, with no secret-reference write or rotation endpoint. The browser Settings page edits these allowlisted fields through the shared drawer and shows integration configuration presence only, not runtime readiness. Environment settings validate protected storage, sandbox resource limits and worker lease/heartbeat/poll bounds. `droidshield cleanup-storage --older-than-hours 24` removes old temporary/unreferenced objects with a minimum one-hour grace period; referenced-artifact retention remains a future policy.

## 4. Data model and ownership

Every workspace-owned record carries workspace ownership directly or through a checked parent relationship. UUID possession is never permission. Queries and mutations apply ownership and project-access checks before returning related data or accepting references.

| Entity | Relationships and durable data |
| --- | --- |
| Users, roles, memberships, grants | Identity, role, enabled state, workspace/project access; passwords only as secure hashes in a future authentication service |
| Clients | Workspace, type, display/organization/contact fields, state, creator and timestamps |
| Projects | Client, application/package/framework, description, scope notes and state |
| App versions | Project, declared version, build metadata; may exist before APK upload |
| App artifacts | Project/version, server digest, metadata, size and protected storage reference |
| Authorizations | Project, authorized activity, targets, exclusions, validity, evidence reference, verifier and revocation history |
| Assessments | Project/version/artifact, authorization, type, state, configuration/scope snapshots and review/execution metadata |
| Analysis jobs | Assessment/optional artifact, engine/worker identity, state, attempt count, lease/heartbeat, execution limits, timestamps and sanitized failure/cancellation reasons |
| API targets/executions | Immutable exact endpoint scope, project-bound secret reference names, rate/test windows, leased job origin and write-once sanitized result |
| Analysis results | Immutable normalized metadata/indicators/limitations with exact assessment, job, artifact hash and engine provenance |
| Findings | Assessment/artifact/version, severity, verification/remediation state, mapping, reviewer and source provenance |
| Evidence | Protected artifact or sanitized excerpt, source record, integrity metadata and creator |
| Retests | Finding, original assessment, new artifact/version, environment, method, evidence and review result |
| Reports | Assessment/client/project snapshot, version, release review, export metadata/checksum and storage reference |
| Methodology cases and executions | Versioned framework case, assessment-specific result and linked evidence/findings |
| Audit events | Actor, action, resource, result, UTC timestamp, request ID and sanitized metadata |

File bytes belong in protected storage; the database stores metadata and opaque references. Downloads require resource permission. Evidence must remain attributable to its assessment and app build. Foreign-key relationships and transactions enforce consistency; audit history and released snapshots are retained through archival.

## 5. Cross-cutting backend requirements

- Validate all writes server-side, reject unsupported fields and avoid mass assignment of status, identity or reviewer fields.
- Validate workspace/project ownership for every referenced ID, list, count and download. Return only data allowed for the actor; never leak another client's related data through search, errors or exports.
- Treat authorization as a time-limited record with evidence, verified scope and exclusions. Recheck at queue and execution boundaries; revocation and expiry block future active work.
- Separate authorization validation, assessment state, job state, finding verification and remediation state. Give transitions explicit service methods.
- Keep secrets in a protected store and persist only references. Redact evidence, logs and errors by default; restrict access even to redacted artifacts.
- Isolate untrusted APK, OpenAPI and report processing; apply resource budgets, safe archive handling and outbound controls.
- Use database migrations and transactional writes. Protect concurrent queueing, verification and export operations; add idempotency where duplicate writes/jobs are possible.
- Bound pagination, text, upload sizes, timeouts and rates. Reject unsafe paths and user-controlled storage locations.
- Propagate request IDs and produce structured, sanitized errors. Readiness checks test dependencies; liveness only reports process availability.
- Use authentication and server-side RBAC for all non-health operations. A local demo identity must be explicit and disabled for production.

## 6. Delivery phases and completion criteria

| Phase | Deliverable | Completion evidence |
| --- | --- | --- |
| 01 | Backend foundation, configuration and health | Runnable app, typed configuration, persistence, access-control foundation, health and validation tests |
| 02 | Clients, Projects, App Versions, Authorizations | Scoped resource services/APIs, ownership checks, archival and verification/revocation tests |
| 03 | Assessments, APK uploads and jobs | State service, secure intake, durable jobs, idempotency and cancellation tests |
| 04 | APK analysis results and engine adapters | Isolated engine adapter, normalized evidence/results and failure tests |
| 05 | Findings, verification and evidence | Review/remediation invariants, provenance, evidence access and tests |
| 06 | Reports and exports | Tenant-safe snapshots, approval, PDF/JSON generation and export integrity tests |
| 07 | Global shell, sidebar and navigation | Accessible routing, role-aware navigation and common feedback states |
| 08 | Overview, Projects, Assessments, APK Analysis, Findings UI | Real API integration, forms, filters and empty/error/loading states; Client UI accompanies resource intake |
| 09 | Dynamic Testing and API Security UI | Lab/target configuration integrated with scope-aware backend services |
| 10 | Retesting and report delivery | Evidence comparison, reviewed status transitions and client delivery workflow |
| 11 | Team & Access, Audit Logs, Settings and security QA | Production identity, permissions matrix, audit/settings integration and cross-client isolation tests |
| 12 | Deployment, documentation and portfolio polish | Migrations, backups/restore, worker/storage configuration, operational runbook and clearly separated demo material |

Phases express delivery sequence, not permission to postpone security enforcement: server-side object authorization, input validation and protected storage begin with the first relevant backend feature. A phase is complete only when its documented behavior is implemented and verified. Placeholder UI, queue records without a worker, and unimplemented endpoint descriptions do not count as delivered execution workflows.

The delivered backend includes real binary-manifest intake and Bubblewrap Static execution checks, including protected bytes, normalized results, Unreviewed finding provenance, authorization/access changes, cancellation, expired leases and migration history guards. Database/API/migration checks support default SQLite and isolated PostgreSQL schemas; SQLite queue/revoke concurrency tests cover both lock orders. DEX execution, adapter normalization, disposable-lab controls and browser logic/security have focused tests. The 0.4 addition covers fixed Frida subprocess/forward ownership, restricted TLS proxy forwarding and cleanup, actual local HTTPS API execution, reference secrecy, DNS/address policy, live cancellation and API result/target history guards. Real-device/scanner proof is recorded separately from simulated faults; [verification history](verification.md) preserves earlier release evidence. Real external MobSF and emulator operation must be recorded separately from simulated adapter tests. These checks cover the delivered boundary. The 0.5 analyst delivery, findings review, coverage, reports and retesting checks are recorded in verification.md; automated static/runtime checks do not imply complete security coverage.
