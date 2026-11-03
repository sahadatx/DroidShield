# DroidShield backend API contract

This document describes the **0.5 implemented backend and connected browser workspace**. It includes protected APK/AAB/IPA intake; bounded Android manifest/DEX/MobSF, Frida/proxy and API workers; analyst Android/iOS engagements; test coverage; protected sanitized evidence; findings review; independently reviewed report versions and retests. See [service delivery](service-delivery.md) for automation boundaries. Automatic Full orchestration, arbitrary tools, broad exploit/fuzzing execution and iOS runtime automation remain external workflows.

Resource prefix: `/api/v1`. Health endpoints are outside that prefix. The generated OpenAPI schema is the source of truth for exact request/response schemas; this document explains workflow and security semantics.

## 1. Common contract

### Identity and access

The browser signs in with `POST /api/v1/auth/login` using an email and password. Passwords are stored as salted scrypt hashes. Successful sign-in sets a 12-hour (configurable) `HttpOnly`, `SameSite=Strict` session cookie and returns a short-lived CSRF value; the opaque session identifier is never returned to JavaScript. `GET /api/v1/auth/session` validates that cookie and refreshes the CSRF value after reload. Cookie-authenticated writes require a matching `X-CSRF-Token` header and CSRF cookie; `POST /api/v1/auth/logout` revokes that session and clears both cookies. Production cookies are Secure. Unknown email and incorrect password use the same response. Sign-in attempts are limited to 10 per 60-second rolling window per source address, shared through the database across API workers. Source-address keys are stored as hashes and stale attempt records are removed as login requests arrive; if the shared limiter is unavailable, sign-in fails closed with `503`.

Programmatic API clients may still send `Authorization: Bearer <opaque API token>`. Issue these explicitly through the trusted CLI; only token hashes are persisted, and they are not used by the browser. Expired or revoked credentials and disabled users fail authentication. Raw API tokens are returned only at issuance and must be handled as secrets. Set or reset a user's browser password with `droidshield set-password --user-id <UUID>`; the hidden terminal prompts never accept a password as a command-line argument and the operation revokes the user's existing sessions and API tokens.

Workspace user administration is API-backed but not yet exposed as a browser screen. ADMINs can list, create, update roles/status and revoke sessions only within their authenticated workspace. New accounts start disabled; configure their password through the trusted CLI before activating them. Disabling an account revokes its tokens, and workspace-level locking prevents concurrent changes from removing the last active administrator. User responses never include password hashes or tokens. The current user record does not track last login.

Every actor belongs to a workspace and has `ADMIN`, `SECURITY_ANALYST` or `VIEWER` role. ADMIN can access the workspace. An analyst or viewer can access projects they created or were explicitly granted. Client access for non-admins is limited to self-created Clients or Clients linked to an accessible Project. A linked record's UUID never bypasses ownership checks.

VIEWER cannot mutate resources. User/project access grants and authorization verification/revocation are ADMIN-only. An analyst can create Clients and edit their own Clients; editing a Client linked through a Project grant still requires its creator or ADMIN. Client reads through Project access redact private `notes` and `archive_reason` to null unless the actor is the Client creator or ADMIN. Creating a Project requires an active Client owned by the analyst or ADMIN access. An authenticated actor cannot access a record in another workspace; inaccessible resource IDs return the same not-found response as missing IDs.

### Requests and concurrency

- JSON field names use `snake_case`; enum wire values are lowercase except role names. The APK endpoint uses strict multipart fields described below.
- UUIDs identify records. Identity, workspace, creator and timestamps are server-generated and cannot be supplied as writable fields.
- Unknown body fields are rejected. Strings are trimmed; optional inputs should send JSON `null` or be omitted rather than sending a blank email/URL.
- Date/time inputs include an explicit offset. Responses use UTC timestamps.
- Every POST mutation, including create, archive, grant, verify/revoke and assessment lifecycle actions, requires `Idempotency-Key` (1–128 characters matching `[A-Za-z0-9_.:-]+`). The server binds the key to actor, operation and request payload. An identical replay resolves to the same resource using its current authorized representation, so its state/revision may have advanced; reusing a key with a different operation or payload returns `409`. The client must reuse the same key only when retrying the same logical operation. Concurrent requests that hit a uniqueness conflict can be safely retried with the same key.
- Mutable domain records that expose `revision` require the last observed positive integer on PATCH and lifecycle requests. A stale revision returns `409`; refresh and reconcile before retrying. Workspace user changes are the exception: they have no revision field and serialize on the workspace row while enforcing the active-administrator invariant.
- PATCH is partial: omitted values remain unchanged; explicit `null` clears only nullable fields. Required fields cannot be cleared.
- Do not automatically retry a request that has an unknown outcome unless its documented idempotency behavior makes retry safe.

### Pagination and errors

Lists return `{"items": [], "total": 0, "limit": 25, "offset": 0}`. `limit` defaults to 25 and is 1–100; `offset` defaults to 0 and is 0–10,000. Users support exact `role` and `status` filters. Clients support `q` across the name, organization and contact fields plus `client_type` and `status`. Projects support `q` across project, application and package ID plus `client_id`, `platform`, `framework` and `status`. Assessments support `q` on the assessment name plus `project_id`, type and status. Project versions support filename/version search plus build type and APK/AAB/IPA format. Findings support title/component search plus project, assessment, severity, verification and remediation state. Dynamic sessions, API targets/executions, reports, retests and audit events accept the exact status/category/date/identity filters documented below. Queries sort newest first with UUID as a stable tie-breaker. Query/filter validation is server-side. No dashboard totals should be inferred by counting only the first page.

Errors have this envelope:

```json
{
  "error": {
    "code": "validation_error",
    "message": "Request validation failed",
    "details": []
  },
  "request_id": "correlation-id"
}
```

The `code` and details vary by error. Field paths can be mapped to inline validation. Error messages and details are sanitized; they must not echo submitted secrets or disclose inaccessible records.

| HTTP status | Meaning |
| --- | --- |
| `200` | Successful read, edit or lifecycle operation |
| `201` | New resource created |
| `401` | Missing, invalid, expired or revoked authentication, or disabled actor |
| `403` | Authenticated actor lacks the role for the operation |
| `404` | Record is missing or outside the actor's authorized visibility |
| `408` | APK transfer deadline exceeded |
| `409` | Stale revision, idempotency mismatch or invalid workflow state |
| `413` | APK file or HTTP body size budget exceeded |
| `415` | Unsupported upload request/file media type |
| `422` | Invalid body/query, malformed or unsupported APK, package mismatch or resource validation failure |
| `429` | Concurrent upload capacity is busy or the sign-in source has exceeded its shared rate limit |
| `503` | Database/readiness dependency, shared sign-in limiter, protected storage or required APK isolation is unavailable |

## 2. Implemented endpoints

| Method and path | Purpose | Notes |
| --- | --- | --- |
| `POST /api/v1/auth/login` | Email/password browser sign-in | Sets HttpOnly session and CSRF cookies; response includes safe user identity and CSRF value, never the session identifier |
| `GET /api/v1/auth/session` | Restore browser session | Requires the session cookie; rotates the CSRF value for the current page |
| `POST /api/v1/auth/logout` | End current browser session | Cookie-authenticated CSRF check, revokes this session and clears cookies |
| `GET /health/live` | Process liveness | Public; no dependency or scanner execution |
| `GET /health/ready` | Dependency readiness | Public; sanitized result, `503` on unavailable dependency |
| `GET /api/v1/me` | Current actor | ID, workspace ID, email, full name, role and account status |
| `GET /api/v1/users` | List workspace users | ADMIN-only, paginated; optional exact role/status filters; no last-login timestamp is currently tracked |
| `POST /api/v1/users` | Create workspace user | ADMIN-only, idempotency key required; account starts disabled and has no password until trusted local setup |
| `PATCH /api/v1/users/{user_id}` | Update account role or status | ADMIN-only and workspace-scoped; activation requires a locally configured password; cannot remove the last active administrator; disabling revokes sessions |
| `POST /api/v1/users/{user_id}/revoke-sessions` | Revoke all account sessions | ADMIN-only, workspace-scoped and idempotent; request body must be `{}` |
| `GET /api/v1/capabilities` | Safe configured capabilities | Engine booleans, upload maximum, opaque lab labels and session timeout maximum; no secrets, service URLs, device serials or host paths |
| `GET /api/v1/directory-metrics` | Page-sized Client/Project table summaries | Repeated `client_ids` and `project_ids` (up to 25 each); only accessible relationships are counted; returns active project/assessment totals, last activity, latest uploaded version and last assessment time |
| `GET /api/v1/findings` | List accessible findings | Paginated; title/component search and exact project, assessment, severity, verification and remediation filters |
| `GET /api/v1/findings/{id}` | Finding detail | Safe narratives, mappings, status and evidence provenance; requires current project/workspace access |
| `GET /api/v1/assessments/{id}/dynamic-sessions` | Session history | Scoped pagination with exact status and scenario filters |
| `POST /api/v1/assessments/{id}/dynamic-sessions` | Create bounded offline session | Writer, current assessment revision, verified scope, configured lab and idempotency key |
| `GET /api/v1/dynamic-sessions/{id}` | Session/result detail | Sanitized typed observations, lifecycle and opaque device ID |
| `POST /api/v1/dynamic-sessions/{id}/cancel` | Cancel session | Writer, required reason and idempotency key; no assessment revision field |
| `GET /api/v1/clients` | List accessible Clients | Paginated; `q`, `status` |
| `POST /api/v1/clients` | Create Client | Analyst/admin, idempotency key |
| `GET /api/v1/clients/{id}` | Client detail | Scoped visibility |
| `PATCH /api/v1/clients/{id}` | Partial Client edit | Analyst/admin, revision |
| `POST /api/v1/clients/{id}/archive` | Archive Client | Creator analyst/admin, revision and reason |
| `GET /api/v1/projects` | List accessible Projects | Paginated; `q`, `status` |
| `POST /api/v1/projects` | Create Project | Analyst/admin, accessible Client, idempotency key |
| `GET /api/v1/projects/{id}` | Project detail | Scoped visibility |
| `PATCH /api/v1/projects/{id}` | Partial Project edit | Analyst/admin, revision |
| `POST /api/v1/projects/{id}/archive` | Archive Project | Analyst/admin, revision and reason |
| `POST /api/v1/projects/{id}/members` | Grant Project access | ADMIN-only; target user must belong to workspace |
| `GET /api/v1/projects/{id}/versions` | Read ingested app versions/artifacts | Safe paginated summaries; filename/version search and exact build/format filters; intake uses the assessment APK endpoint |
| `POST /api/v1/assessments/{id}/apk` | Upload and bind an APK | Analyst/admin; strict multipart fields, revision and idempotency key |
| `GET /api/v1/artifacts/{id}` | Read artifact metadata | Scoped safe manifest metadata; no storage path |
| `GET /api/v1/artifacts/{id}/download` | Download original APK | Current resource access and verified stored-byte integrity; attachment |
| `GET /api/v1/projects/{id}/authorizations` | List Project authorization records | Scoped visibility |
| `POST /api/v1/projects/{id}/authorizations` | Create pending authorization | Analyst/admin, idempotency key |
| `POST /api/v1/authorizations/{id}/verify` | Verify authorization | ADMIN attestation and revision |
| `POST /api/v1/authorizations/{id}/revoke` | Revoke authorization | ADMIN, revision and reason |
| `GET /api/v1/assessments` | List accessible Assessments | Paginated; name search and exact project, type, and status filters |
| `POST /api/v1/assessments` | Create Assessment record | Analyst/admin, idempotency key |
| `GET /api/v1/assessments/{id}` | Assessment detail | Scoped visibility |
| `PATCH /api/v1/assessments/{id}` | Edit draft/awaiting record | Analyst/admin, revision and permitted fields |
| `POST /api/v1/assessments/{id}/submit` | Submit for authorization | Analyst/admin, revision; no job created |
| `POST /api/v1/assessments/{id}/queue` | Validate and queue record | Analyst/admin, revision; separate type-specific worker/session execution |
| `POST /api/v1/assessments/{id}/cancel` | Cancel eligible Assessment/job | Analyst/admin, revision and reason; includes Running |
| `GET /api/v1/assessments/{id}/job` | Read job lifecycle | Safe status, timestamps and sanitized failure/cancellation fields |
| `GET /api/v1/assessments/{id}/analysis` | Read normalized static result | Scoped immutable metadata, indicators, engine version and limitations |
| `GET /api/v1/assessments/{id}/findings` | Read finding summaries | Scoped paginated results; scanner candidates start Unreviewed/Open |
| `GET /api/v1/overview` | Derived workspace/project counts and status summaries | Scoped counts for accessible client/project records |
| `GET /api/v1/audit-events` | Workspace audit history and matching result counts | ADMIN-only; actor/resource/date/action/result filters; no edit/delete API |
| `GET /api/v1/projects/{id}/api-secret-refs` | Safe account reference choices | Project-visible; returns only bound reference names and kinds |
| `GET /api/v1/assessments/{id}/api-targets` | API target configuration | Scoped standard Page; optional exact authentication-method filter; one immutable target per API assessment |
| `POST /api/v1/assessments/{id}/api-targets` | Configure exact API endpoints | Writer, idempotency, draft API assessment and project-bound references |
| `GET /api/v1/api-targets/{id}` | API target detail | Safe configuration and reference names; never credential values |
| `POST /api/v1/api-targets/{id}/execute` | Queue a bounded API execution | Writer, current assessment revision, verified scope/window and idempotency |
| `GET /api/v1/assessments/{id}/api-executions` | API execution history | Scoped standard Page with optional exact lifecycle-status filter |
| `GET /api/v1/api-executions/{id}` | API lifecycle/result detail | Typed sanitized observations and fixed limitations |
| `POST /api/v1/api-executions/{id}/cancel` | Cancel API work | Writer, reason and idempotency; no assessment revision field |
| `POST /api/v1/assessments/{id}/artifact` | Upload and bind a mobile artifact | APK/AAB/IPA intake; protected storage and server-derived identity; automated static analysis is APK-only |
| `GET /api/v1/assessments/{id}/coverage` | Read assessment coverage | Scoped procedures and explicit Not Run gaps |
| `PUT /api/v1/assessments/{id}/coverage/{case_id}` | Record a test result | Revision-checked status, evidence/finding links and analyst provenance |
| `GET /api/v1/assessments/{id}/evidence` | List assessment evidence | Scoped, paginated sanitized records |
| `POST /api/v1/assessments/{id}/evidence` | Create text evidence | Analyst-submitted sanitized evidence with assessment/build provenance |
| `POST /api/v1/assessments/{id}/evidence-attachments` | Upload screenshot evidence | Bounded PNG attachment in protected storage, linked to analyst evidence |
| `GET /api/v1/evidence/{id}` | Read evidence metadata | Scoped provenance and integrity metadata; no storage path |
| `GET /api/v1/evidence/{id}/content` | Download protected evidence | Authorized attachment download with integrity verification |
| `POST /api/v1/assessments/{id}/findings` | Create a finding | Analyst-created finding with scoped evidence and verification lifecycle |
| `PATCH /api/v1/findings/{id}` | Update a finding | Revision-checked analyst edits; verification state uses separate review |
| `POST /api/v1/findings/{id}/review` | Review a finding | Independent ADMIN verification decision |
| `POST /api/v1/assessments/{id}/manual-start` | Begin a manual engagement | Current authorization, exact scope and assessment revision required |
| `POST /api/v1/assessments/{id}/manual-finish` | Submit engagement for review | Records analyst summary; does not execute external tools |
| `POST /api/v1/assessments/{id}/review` | Review a completed assessment | Independent ADMIN review |
| `GET /api/v1/methodology` | Read the methodology library | Versioned local procedures and pinned standards references |
| `POST /api/v1/cvss/score` | Calculate a CVSS score | Authenticated base-vector calculation; does not create a finding |
| `GET /api/v1/retests` | List retests | Scoped, paginated history and supported filters |
| `GET /api/v1/retests/{id}` | Read retest detail | Scoped result, evidence provenance and review state |
| `POST /api/v1/findings/{id}/retests` | Create a retest | Distinct authorized build/API release and new evidence required |
| `POST /api/v1/retests/{id}/review` | Review a retest | Independent ADMIN decision; approved Pass may mark the finding Fixed |
| `POST /api/v1/assessments/{id}/reports` | Create a report snapshot | Freeze a completed, independently reviewed assessment |
| `GET /api/v1/reports` | List reports | Scoped, paginated report versions and supported filters |
| `GET /api/v1/reports/{id}` | Read report snapshot | Immutable scope, coverage, findings and release metadata |
| `POST /api/v1/reports/{id}/release` | Approve a report | Independent ADMIN approval of the exact snapshot |
| `GET /api/v1/reports/{id}/exports` | List report exports | Protected export metadata and digests |
| `POST /api/v1/reports/{id}/exports` | Export a report | Generate approved PDF or JSON into protected storage |
| `GET /api/v1/report-exports/{id}/download` | Download a report export | Authorized attachment download with integrity verification |

There is no hard-delete endpoint. Archive preserves resource identity and historical relationships. Static engines, controlled Dynamic execution, exact-target API execution and connected frontend pages are delivered. Full manual engagement records and email/password browser sessions are implemented; automatic Full execution and full team administration remain outside the execution surface. Database readiness expects Alembic revision `0010_shared_login_rate_limits`; it does not probe sandbox availability, scanner/lab health or a running worker. The application serves its frontend at `/` and only the two named script/style files under `/assets`; it does not expose a directory or protected storage mount.

## 3. Client request and response fields

`POST /clients` body:

| Field | Type/default | Validation |
| --- | --- | --- |
| `client_type` | `company` (default) / `individual` | Conditional UI label for `name` |
| `name` | Required string | Trimmed, 1–200 characters |
| `organization_name` | Nullable string | Up to 255 characters |
| `website` | Nullable URL string | Up to 2,048; absolute HTTP/HTTPS, no embedded credentials |
| `contact_person` | Nullable string | Up to 255 characters |
| `contact_email` | Nullable email | Valid format when supplied |
| `phone` | Nullable string | Up to 64 characters |
| `notes` | Nullable string | Up to 20,000 characters |
| `status` | `active` (default) / `archived` | Archived requires `archive_reason` |
| `archive_reason` | Nullable string | When used, trimmed nonblank, at most 2,000 characters |

`PATCH /clients/{id}` accepts these fields optionally plus required `revision`. `name`, `client_type` and `status` cannot be null. Archive validation applies to the merged resource, not only the submitted patch. Archival is blocked while non-archived Projects exist. Reactivating with `status: active` clears the old archive reason. The dedicated archive body is `{"revision": 1, "reason": "Engagement closed"}`; it also requires an idempotency header.

Client responses add `id`, `workspace_id`, `created_by`, `created_at`, `updated_at` and `revision`. In both list and detail responses, `notes` and `archive_reason` are null for a non-owner whose Client visibility comes through Project access. That is response redaction, not a change to persisted values. Related counts, activity feeds and nested project/assessment/report data are not included in this foundation response. The UI must not invent those values.

Illustrative request, with fictional data:

```http
POST /api/v1/clients
Authorization: Bearer <opaque-token>
Idempotency-Key: client-create-example-1
Content-Type: application/json

{
  "client_type": "company",
  "name": "Example Company",
  "contact_email": "security@example.com",
  "status": "active"
}
```

The frontend labels `name` as Company name or Individual name according to `client_type`. It never submits `client_id`, password fields or payment details.

## 4. Project fields and grants

`POST /projects` requires `client_id`, `name`, `application_name` and `package_id`. It accepts:

- `framework`: `native`, `flutter`, `react_native`, `other`, or `unknown` (default).
- Nullable `repository_url`, `description` and `scope_notes`.
- `status`: `active` (default), `on_hold` or `archived`; archived status requires `archive_reason`.

Names are 1–200 characters. For `platform: android` (default), Package ID is at most 255 characters and matches `^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`. Repository URL follows the same HTTP/HTTPS and no-credentials rules as Client website. Description/scope notes are at most 20,000 characters. Archive reasons are 1–2,000 characters.

`PATCH /projects/{id}` accepts editable Project fields plus `revision`; it does not change `client_id`. Package identity cannot change once an artifact or Assessment exists. Pausing/archiving is blocked while queued/running Assessments exist; reactivation requires an active parent Client. The archive body matches the Client archive body. Responses add common mutable metadata and `client_id`.

`POST /projects/{id}/members` accepts `{"user_id": "<workspace-user-uuid>"}`. This ADMIN access grant is separate from the workspace user lifecycle described above; it does not invite or create a user. The browser's Team & Access page manages workspace accounts, while password setup remains a trusted local CLI operation.

Version name and code are not writable Project fields. `GET /projects/{id}/versions` reads artifact metadata after trusted ingestion: ID/ownership/creator/time, `project_id`, `version_name`, `version_code`, SHA-256, original filename, size and build type. No public endpoint accepts a caller's hash or storage reference as proof of an uploaded APK. The implemented protected ingestion pipeline calculates hashes from received bytes, validates archive/manifest content in the sandbox and links the immutable artifact to its assessment.

## 5. Authorization contract

Create a pending record under the Project:

| Field | Requirement |
| --- | --- |
| `approved_targets` | Required list of 1–100 normalized exact targets |
| `exclusions` | Optional list, at most 100 exact targets; default empty |
| `evidence_ref` | Required bounded opaque reference, at most 2,048 characters; no inline secret/evidence body or local path |
| `valid_from`, `valid_until` | Offset-aware timestamps; end strictly after start |
| `notes` | Optional, at most 20,000 characters |

Targets are `package:com.example.app` or exact HTTPS URLs. Wildcards, fragment identifiers, URL credentials, encoded/relative URL path segments, ambiguous `//` or `;` URL paths and duplicate normalized entries are rejected by the initial contract. Scope is deliberately exact: an allowed host or URL does not imply its subdomains or arbitrary child paths are authorized. Exclusions take precedence: a package exclusion denies that package, and a URL exclusion denies its path and descendant paths on the same authority.

Creating a record does not verify the underlying evidence. Verification is an ADMIN attestation that the referenced signed authorization evidence was reviewed: `POST /authorizations/{id}/verify` with `{"revision": 1}`. Only pending, unexpired records can be verified. Revocation uses `{"revision": 2, "reason": "Authorization withdrawn"}` and cancels linked queued/running Assessment/job records in the same transaction. The active worker observes cancellation/current authorization and discards unpublished output. Both require idempotency headers. Status values are `pending`, `verified` and `revoked`; expiry is additionally checked against the validity window. Responses include scope, evidence reference, notes, common mutable metadata, `verified_by`, `verified_at`, `revoked_at` and `revocation_reason`.

The current evidence reference is a pointer for review, not an uploaded or cryptographically validated evidence document. A future protected evidence API must verify storage ownership and support document integrity. No target is actively contacted by authorization creation or verification.

## 6. Assessment record and transitions

`POST /assessments` body:

| Field | Requirement |
| --- | --- |
| `project_id` | Required accessible Project UUID |
| `name` | Required, 1–200 characters |
| `assessment_type` | `static`, `dynamic`, `api` or `full`; separate execution workers cover Static, Dynamic and bounded API; Full remains planned |
| `engine` | `manifest` (default), `dex` or `mobsf`; captured in the static configuration snapshot |
| `artifact_id` | Optional ingested artifact UUID belonging to the Project |
| `authorization_id` | Optional authorization UUID belonging to the Project |
| `requested_targets` | Required 1–100 unique normalized exact targets |

The backend initializes the state to `draft`; the caller cannot submit status, reviewer, workspace, timestamps or an arbitrary configuration snapshot. Related records must belong to the same Project/workspace and be visible to the actor. While draft/awaiting authorization, PATCH permits name, engine, artifact/authorization reference and requested-target changes with a revision; it does not change Project or type. Submit body `{"revision": 1}` changes Draft to Awaiting Authorization without creating a job.

Queue body: `{"revision": 1}`. Queueing accepts Draft/Awaiting Authorization and checks active Project/Client, required ingested artifact for non-API types, linked verified authorization, current validity and exact requested scope minus exclusions. The artifact's detected package must match the Project and be included in requested targets. Static requires exactly its artifact's package target; API accepts HTTPS targets only. The service captures authorization scope/revision/window and artifact hash in a snapshot and creates one queued Analysis Job. A pending authorization, revoked/expired window or out-of-scope target prevents queueing. Queueing itself launches no process. A separately started Static worker claims eligible jobs using their manifest/DEX/MobSF engine snapshot. Dynamic execution requires creating its bounded session and separately running the Dynamic worker. API execution requires its immutable endpoint configuration/execution and separate `api-worker`; no APK is required. Full entries have no execution worker.

Cancel body: `{"revision": 2, "reason": "Operator cancelled"}`. Draft, Awaiting Authorization, Queued and Running can cancel. The transaction records cancellation time/reason, cancels a linked queued/running job, clears its lease and increments the assessment revision. An active worker terminates through its cancellation callback and cannot publish cancelled results. All lifecycle POSTs require an idempotency header.

Wire statuses are `draft`, `awaiting_authorization`, `queued`, `running`, `needs_review`, `completed`, `failed` and `cancelled`. The API exposes create, guarded draft/awaiting edits, submit, queue and cancel. The appropriate Static, Dynamic or API worker owns Queued → Running → Needs Review (or Failed/Cancelled), and stores the job Completed separately from assessment review. Review completion, retry and assessment archive do not have public endpoints yet.

Responses include common mutable metadata plus project/artifact/authorization references, name, type, engine, status, requested targets, reviewer, start/completion/cancellation times and sanitized failure/cancellation reasons. Job/result/finding reads reflect persisted execution only; an unprocessed assessment has no analysis result.

## 7. Protected APK intake and Static execution

`POST /assessments/{id}/apk` accepts one `.apk` file with a simple filename, a positive decimal `revision`, optional `app_version` (maximum 255 characters), `build_type` (`debug`/`release`/`unknown`, default `unknown`) and `upload_notes` (maximum 20,000 characters). Use `multipart/form-data`; the file MIME must be APK, octet-stream or ZIP. Unknown/duplicate fields, directory paths, caller hashes and arbitrary metadata are rejected. Project/workspace come from the scoped assessment. Only a writer with current Project access can upload, only Draft/Awaiting Authorization accepts a new association, and Client/Project must be active.

The default file limit is 100 MiB with at most 64 KiB additional multipart overhead. Transfers have a default 120-second deadline (408 on expiry), and each API process allows two concurrent upload/inspection requests by default (429 when busy). These are configurable limits; multiple API processes multiply capacity. Body receiving is bounded even without Content-Length, and copying enforces the file limit again. The server computes SHA-256 from uploaded bytes. A separate sandbox inspects bounded ZIP structure and a supported binary Android manifest before any artifact is trusted. Malformed/unsafe archives, excessive entry/expanded/manifest sizes or compression ratio, unavailable isolation and a detected package different from the Project prevent association. APK code is never launched.

A `201` response is the safe artifact summary; the assessment's artifact link and revision change atomically. Identical bytes within one Project reuse its immutable artifact, preserving that artifact's original provenance. `app_version` is a declared label, distinct from detected version metadata. An identical upload replay uses the same original revision, bytes, filename and form metadata; it succeeds after the first request advanced the revision. Changed payload with the same key conflicts. Authentication/role/Project access are rechecked after inspection and on replay. A lost response with an ambiguous commit should be retried with the same key; cleanup retains objects that might belong to a committed record.

`GET /artifacts/{id}` adds allowlisted manifest metadata to the artifact summary. The initial engine supports `version_code` from 0 to 2,147,483,647 and accepts absent/zero `versionCodeMajor`; nonzero or unresolved major values are rejected rather than truncating a 64-bit Android version code. Permissions, components and application flags are bounded identifiers/typed values. Signing certificate metadata is unavailable. `GET /artifacts/{id}/download` verifies the stored bytes' size and SHA-256, then returns a private attachment snapshot with `X-Content-SHA256`. Inaccessible artifacts return 404; modified/missing bytes fail integrity verification. Neither response exposes a storage path.

Run `droidshield worker --once` for one eligible Static job or `droidshield worker` for continuous polling, using the API's database/storage configuration. The worker claims a bounded lease, records engine configuration/version, verifies bytes and runs the selected engine: manifest/DEX inside Bubblewrap, or the bounded adapter against the fixed administrator-configured MobSF service. The external service must provide its own isolated APK processing boundary. It rechecks current account/Project access, authorization revision/window, exact scope/exclusions and artifact identity before claim, during processing and before publication. Failure, cancellation, lost lease or changed authorization prevents stale result publication. An expired running lease is marked Failed by a subsequent worker; interrupted scans are not retried automatically. SIGTERM/Ctrl-C requests graceful cancellation and shutdown.

Successful execution atomically writes an immutable normalized result and candidate Findings, marks the job Completed and moves the assessment to Needs Review. Findings carry assessment/artifact/hash/job/result/engine provenance and start `verification_status: unreviewed`, `remediation_status: open`. Scanner severity never confirms a vulnerability. The engine emits candidates for explicitly enabled debugging, cleartext traffic, backup and unprotected exported components. The default manifest engine does not inspect application code. The selectable DEX engine adds bounded decoded instruction references and secret-like literal categories without raw strings; no candidate alone establishes exploitability. Dependency/CVE coverage, signature verification and API testing remain outside these local engines.

`GET /assessments/{id}/job` exposes only safe lifecycle fields, including attempt count, timestamps and sanitized reasons. `GET /assessments/{id}/analysis` exposes immutable metadata, indicators, engine/schema version, artifact SHA-256, explicit limitations and `requires_review: true`; before a result exists it returns 404. `GET /assessments/{id}/findings` returns paginated safe summaries. All reads enforce current workspace/Project access; no endpoint returns arbitrary engine stdout/stderr, host paths, environment or raw request evidence.

The sandbox has no network, a cleared environment, read-only runtime/engine/APK and bounded CPU, memory, elapsed time, output and temporary storage. Only the trusted runtime, engine and selected APK are exposed; keep application data and the protected storage root outside that runtime. API and worker must run as an unprivileged user; real/effective UID 0 is rejected. Isolation fails closed when unsupported. It shares the host kernel and does not protect against a kernel exploit or certify host/deployment security. See the [runbook](upload-worker.md) for limits and deployment boundaries. Trusted `droidshield cleanup-storage --older-than-hours 24` removes stale temporary/unreferenced objects only, with a minimum one-hour age; it is not a retention policy for referenced artifacts.

## 7a. Engine selection and safe findings

`engine` is selected at assessment creation or draft configuration, never supplied as arbitrary commands or an endpoint URL. Existing records default to `manifest`. Workers pin engine version and bounded configuration; unavailable engines fail safely. `GET /capabilities` reports `engines.manifest.configured`, `engines.dex.configured`, `engines.mobsf.configured`, `max_apk_bytes`, and `dynamic` with `configured`, safe device ID/label/Android version entries and `max_timeout_seconds`. `dynamic.frida.configured` and `dynamic.proxy.configured` report optional administrator setup. `api` reports `configured`, `methods` GET/HEAD, supported `auth_methods`, `max_requests` and `max_timeout_seconds`. These are configuration facts, not health probes; no global secret reference inventory is returned.

Analysis responses use schema version 1 for manifest, 2 for DEX and 3 for MobSF.
`dex_summary` is nullable and contains bounded DEX/class/method/string/code-unit
counts. `mobsf_summary` is nullable and contains the tested service version,
candidate counts by source category, tool-error count and `analysis_complete`.
The frontend visibly marks incomplete MobSF coverage; it never interprets an
empty candidate list as successful security verification. Summary fields are
separate from immutable manifest metadata. Each engine's indicators pass its
strict output contract before persistence and safe reads.

The DEX engine reads supported standard bytecode inside the same network-disabled sandbox, validates decoded instruction references and publishes fixed candidate narratives with numeric locations and no raw strings. See [the DEX contract](dex-analysis.md). MobSF uses only a fixed administrator-configured loopback HTTP or HTTPS service and a protected API key. The adapter bounds remote data and retains normalized allowlisted evidence; arbitrary scanner reports/paths/literals never become ordinary GET data. Its host extraction/processing must run inside the separately administered isolated scanner deployment. See [MobSF operation](mobsf.md).

`GET /findings` returns summaries using normal workspace/project visibility and pagination. Search `q` matches title or affected component; filters accept exact project/assessment UUIDs, severity (`critical`, `high`, `medium`, `low`, `info`), verification state (`unreviewed`, `confirmed`, `false_positive`, `needs_more_evidence`) and remediation state (`open`, `in_progress`, `fixed`, `accepted_risk`, `retest_required`). `GET /findings/{id}` adds description, reproduction, impact/remediation, optional CVSS/mappings/reviewer, revision and sanitized `evidence_provenance`. Provenance links the source result, job, immutable artifact SHA-256, engine and allowlisted evidence. Finding edits and independent verification use separate revision-checked write contracts.

## 7b. Controlled Dynamic sessions

`POST /assessments/{id}/dynamic-sessions` requires a writer role, idempotency header and `{revision, device_id, scenario, proxy_targets, timeout_seconds, notes}`. The current assessment must be Dynamic. `scenario` is `package_inspection`, `launch_observe`, `frida_observe` or `proxy_observe`; timeout is 10–120 seconds and may not exceed the configured maximum; notes are optional and at most 20,000 characters. `device_id` is an opaque entry from the administrator's disposable-lab inventory. Client-supplied ADB commands, serials, host paths or arbitrary shell/script content are not accepted. `proxy_targets` defaults to empty and is valid only for `proxy_observe`, where 1–10 exact approved HTTPS URLs are required. Its assessment requested scope must be the package target followed by those exact ordered URLs; each is checked against current authorization and exclusions.

Draft/Awaiting Authorization records are queued transactionally with the supplied revision; an already queued record uses its current revision. Active account/project/client, exact package scope minus exclusions, verified current authorization, protected artifact identity and device configuration are revalidated before creation, claim, during processing and before publication. One runtime session is allowed per assessment job. A configured device identity never grants target authorization.

The separate `droidshield dynamic-worker` checks an exact dedicated emulator/AVD identity, establishes verified deny-all guest IPv4/IPv6 egress, rejects pre-existing packages, installs the exact protected APK, inspects its package and optionally launches it for bounded observation. Exclusive fenced device leases prevent overlapping sessions; cleanup is allowed only for the exact lease owner. Failures, lost leases and crashes quarantine the device instead of automatically reusing it. Frida observes only fixed native-call counters via a pinned authenticated administrator-provisioned server; guest IP egress stays denied. Proxy observation permits only the owned app UID to reach an ADB-reversed loopback guarded proxy, forwards exact GET/HEAD targets with verified upstream TLS, then removes its own mapping/configuration and verifies DROP-only rules. The app must already trust the dedicated lab CA; no certificate-pinning bypass or automatic trust installation occurs. See [lab](dynamic-lab.md), [Frida](frida.md) and [proxy](proxy.md) runbooks before operation.

Session reads expose lifecycle timestamps, scenario, timeout, opaque device ID and typed `result_json` observations, without raw logs, notes, serials or host paths. The list endpoint accepts exact `status` and `scenario` filters in addition to pagination. Cancel accepts only `{reason}` with its own idempotency header. Cancellation/revocation discards unpublished output. Successful execution completes the job and moves the assessment to Needs Review; it does not confirm vulnerabilities or complete analyst review. Optional typed `result_json.frida` contains only bounded native-call counters/version/coverage, and `result_json.traffic` contains only endpoint ordinals, method/status/TLS version/byte counts. Raw arguments, URLs, request/response bodies, credentials and device logs are never returned. Account login automation, arbitrary scripts, TLS/pinning bypass, broad runtime testing and physical-device testing remain unavailable.

## 7c. Exact HTTPS API baseline and account comparisons

API assessments require no APK. Their requested targets must contain the exact
HTTPS URLs to be probed; a base host never implies permission for other paths.
Create one immutable target using `POST /assessments/{id}/api-targets` while the
API assessment is Draft/Awaiting Authorization:

| Field | Contract |
| --- | --- |
| `name` | Required trimmed string, 1–200 characters |
| `endpoints` | 1–20 objects; `url` exact normalized HTTPS, `method` GET/HEAD (default GET), `expect_authentication` strict Boolean (default false); endpoint/method pairs unique |
| `excluded_endpoints` | Default empty; at most 100 exact unique HTTPS exclusions; parent paths exclude descendants |
| `auth_method` | `none` (default), `bearer`, `api_key` or `cookie` |
| `primary_secret_ref` | Nullable bounded reference; required unless authentication is `none` |
| `secondary_secret_ref` | Nullable distinct reference for the optional second account |
| `requests_per_minute` | Integer 1–120, default 30 |
| `test_window_start`, `test_window_end` | Required offset-aware dates/times; end strictly after start |

Protected endpoint expectations require authentication/reference configuration;
`none` forbids account references and protected expectations. Each configured
reference must match the same workspace, project and authentication kind in the
administrator-owned private store. `GET /projects/{id}/api-secret-refs` returns
only `{"items":[{"ref":"account-reference","kind":"bearer"}]}` for that visible
project. Neither write bodies nor ordinary reads accept or expose credential
values. Target responses contain the form fields plus ID, project/assessment IDs
and UTC creation timestamp. No target edit/delete endpoint exists; use a new
assessment when scope/configuration changes.

`POST /api-targets/{id}/execute` accepts only `{"revision":1}` and an idempotency
header. Draft/Awaiting Authorization is transactionally queued, or an already
queued assessment may use its current revision. It creates the one API execution
for its job after active verified authorization, exact endpoint scope/exclusions,
current operator/project access, test window, credential references and request
budgets pass. An impossible rate plan is rejected. The separate
`droidshield api-worker` claims/leases these records; other workers ignore them.

The API worker sends anonymous GET/HEAD and optional primary/secondary account
probes to the same exact endpoint. It rechecks authorization, account/grants,
project/client state, test window, immutable configuration and lease before each
request, during rate waits/network processing and before publication. Public
addresses are allowed by default; private/loopback requires a narrow administrator
CIDR. Metadata/link-local, multicast and unspecified addresses remain denied.
Every DNS answer is checked, the TCP connection is pinned to a checked IP, and
HTTPS verifies hostname/certificate with TLS 1.2+. Environment proxies and
redirect following are disabled. Defaults: 120 seconds per execution, 10 seconds
per request, 60 requests, 64 KiB response bodies; administrator settings set the
bounded ceiling. Response comparison is inconclusive when truncated or HEAD-only.

Read executions through `/assessments/{id}/api-executions` (standard Page) or
`/api-executions/{id}`. Output includes ID, linked target/assessment IDs, status,
UTC lifecycle timestamps, fixed failure/cancellation codes and typed
`result_json`. The result has engine version, requests sent, endpoint ordinals and
methods, anonymous/primary/secondary status and byte counts, truncation,
HSTS/Content-Type presence, verified TLS, coarse bounded-response comparison,
review requirement and fixed coverage limitations. No response body, credential,
raw header, URL query or body digest is persisted or returned.

`POST /api-executions/{id}/cancel` requires a reason and idempotency header,
without an assessment revision. Normal assessment cancellation/authorization
revocation also stops the execution, closes active transport and discards
unpublished observations. Already in-flight network traffic may reach its target
before concurrent revocation commits; no further probe or result publication is
permitted after the worker observes the control change. Lost/expired leases
cannot publish, and crashed work is never automatically replayed.

Success marks the job Completed and assessment Needs Review. A configured
protected endpoint returning 2xx both anonymously and to the primary account
creates a cautious Medium Unreviewed/Open candidate. HTTP success or equal
account responses alone do not prove sensitive data exposure or broken
object-level authorization. Account-response equality is an observation only.
Immutable target and published-result database guards preserve provenance.
OpenAPI import/execution, interactive OAuth refresh, injection/fuzzing,
state-changing probes and broad API coverage remain planned. See
[API security runbook](api-security.md) for protected-store setup and tests.

## 8. Overview and audit reads

`GET /overview` returns database-derived totals and status breakdowns for visible clients, projects, assessments, APK/AAB/IPA artifacts, findings, reports, retests, dynamic sessions, API targets and API executions. It also retains `total_projects`, `total_assessments`, `in_progress`, `open_findings`, `severity` and `pending_reviews` for compatibility. It accepts optional `project_id`, `assessment_type`, `assessment_status`, `date_from` and `date_to` filters. Project IDs outside the actor’s visible-project set return 404; invalid enum values and reversed date ranges return 422. Dates are inclusive UTC calendar days. Assessment filters scope related findings, reports, retests, dynamic sessions, API targets and executions; date filters apply to each record’s creation date and to its linked project/assessment scope. `in_progress` counts queued/running Assessments. `open_findings`, `critical_findings`, `high_findings` and `severity` include confirmed findings whose remediation state is not Fixed; severity keys are `critical`, `high`, `medium`, `low`, `info`. `pending_reviews` counts Needs Review Assessments. Client counts use the same visibility rules as the Clients list; all other counts are scoped to the actor’s accessible Projects. Scanner findings remain Unreviewed and therefore do not inflate confirmed open-finding counts. Empty-workspace values are zero.

`GET /assessments` also accepts inclusive UTC `date_from` and `date_to` filters. It combines them with project, type, status and name search filters so the Overview’s recent-assessment table follows the selected dashboard scope.

`GET /audit-events` is ADMIN-only and accepts pagination plus exact `action` (up to 128 characters), `resource_type` (up to 64), `result` (`success`/`failure`), `actor_id`, `resource_id`, and inclusive UTC `date_from`/`date_to` filters. A reversed date range returns 422. The response includes matching success/failure summary counts. Each item exposes `id`, UTC `timestamp`, `actor_id`, action, resource type/ID, result, request ID and sanitized `source`. It provides no update/delete operation. Current successful resource mutations generate audit events without request bodies, notes, evidence, headers or credentials. SQLite/PostgreSQL migrations reject UPDATE/DELETE on audit events, artifact metadata and normalized analysis results; PostgreSQL also rejects audit/result TRUNCATE. The browser provides actor, resource ID/type, action, result and date filters. Audit export remains planned.

## 9. Planned operations — not implemented by this contract

The following are implementation requirements, not callable API promises. Final paths and payloads must be defined when their services are delivered.

| Area / phase | Planned API capabilities and validation gates |
| --- | --- |
| APK ingestion and jobs / 03 | Extend delivered intake/jobs with richer artifact lifecycle and retention policy administration as needed |
| Analysis engines / 04 | Extend delivered manifest/DEX/MobSF candidate coverage with deeper data flow, dependency/CVE/signing validation and additional reviewed adapters |
| Findings and evidence / 05 | Extend delivered create/edit/review, validated CVSS/mappings, sanitized text and protected PNG evidence with richer assignment workflows |
| Reports / 06, 10 | Extend delivered reviewed client-specific snapshots, PDF/JSON exports and protected downloads with asynchronous scheduling and retention-policy administration |
| Overview and global shell / 07–08 | Extend the delivered browser workspace and real counts with risk trends, retest metrics, latest activity and notifications from real records |
| Dynamic Testing / 09 | Extend delivered package/launch/fixed-Frida/restricted-proxy sessions with reviewed broader runtime coverage and account-login automation |
| API Security / 09 | Extend delivered exact GET/HEAD targets, reference-based account comparisons and outbound/rate/window controls with safely imported specifications, interactive OAuth and explicitly authorized broader test cases |
| Retests / 10 | Extend delivered build/API-release provenance, evidence comparison, reviewed outcomes and guarded Fixed transition with reminders and scheduling |
| Methodology | Extend the delivered version-pinned library, coverage matrix and evidence/finding links with managed custom test-library updates |
| Team, audit and settings / 11 | User setup/disable/roles and session revocation; extend existing ADMIN Project grants and audit reads; typed role-checked settings, secret-reference writes and redacted reads |

Frontend pages must not send guessed requests to these planned operations. Reviewed report generation and analyst review are implemented as specified below. Broad network/API attacks and automatic Full execution remain outside the execution surface. Application installation/launch is confined to the separately configured disposable-emulator workflow; it is never performed by APK intake, the API process or static engines.

## 10. Required verification coverage

Backend tests verify schema bounds, invalid email/package/URL/scope/time windows, extra-field rejection, role and cross-workspace/project isolation, active/expired/revoked token behavior, reference ownership, archival reasons, stale revisions, idempotency replay/mismatch and authorization-aware queue/cancel transitions. Include success paths and transaction rollback/no-side-effect assertions on failures.

Verification has covered the default SQLite backend and PostgreSQL 18 API behavior with actual Alembic upgrades. Migration checks include the audit/artifact mutation guards and PostgreSQL audit TRUNCATE guard. SQLite queue/revoke concurrency has been tested in both lock orders. Client privacy tests cover null redaction of notes/archive reason for Project grantees.

Current upload/worker checks include real binary manifests and Bubblewrap execution, malformed archives and size/expansion limits, server-derived hashes, private storage/download integrity, idempotency and deduplication, revoked access during intake, ambiguous commit recovery, authorization rechecks, cancellation and expired leases, fenced publication and Unreviewed finding provenance. Delivery integration tests also verify protected evidence, independent review, evidence-backed retesting and client-safe report snapshots/exports. Tests of a button or placeholder endpoint cannot replace those workflow checks.


The 0.4 verification increment adds actual owned loopback HTTPS transport and
full API worker execution, TLS trust and pinned-IP/DNS policy, redirects and body
budgets, project-bound reference secrecy, live cancellation, immutable API history
and SQLite upgrades preserving existing device leases. Frida/proxy runbooks and
the versioned [verification history](verification.md) distinguish simulated faults,
real host TLS checks and actual disposable-emulator runs. Earlier release proof
is historical evidence for its recorded version, not a claim of current broad
security-test coverage.


## 0.5 cross-platform and delivery extensions

Project create/update includes `platform: android | ios` (default Android). Android
identities keep the existing package syntax; iOS bundle IDs allow ASCII letters,
digits and hyphens in nonempty dot-separated segments. Platform and identity
cannot change after assessment/artifact history exists. iOS scope uses exact
`bundle:<bundle-id>` targets; Android keeps `package:<package-id>`. API endpoint
configurations reject both application-target schemes.

`POST /assessments/{id}/artifact` uses the existing protected multipart fields and
limits but accepts APK, AAB or IPA. `/apk` remains APK-only. Artifact responses
include safe `platform` and `artifact_format`; detail metadata is an allowlisted
platform-specific union. AAB parses only the base protobuf manifest; IPA parses
Info.plist and checks main-executable presence/magic. No signature, entitlement,
full binary, source, library or runtime security result is inferred from intake.
Automated queueing/worker claims accept Android APKs only; use manual engagements
for IPA/AAB analyst work.

The analyst delivery router adds:

| Method and path | Purpose |
| --- | --- |
| `POST /assessments/{id}/manual-start` | Begin authorized analyst records, with revision, platform, environment, tool versions and limitations |
| `POST /assessments/{id}/manual-finish` | Submit recorded coverage and summary for review |
| `POST /assessments/{id}/review` | Independent ADMIN assessment completion or return |
| `GET /methodology` | Locally authored procedures and pinned standards references |
| `GET /assessments/{id}/coverage` | Actual coverage and explicit Not Run gaps |
| `PUT /assessments/{id}/coverage/{case_id}` | Revision-checked test status with evidence/finding links and provenance |
| `GET, POST /assessments/{id}/evidence` | Scoped private sanitized text evidence metadata/intake |
| `POST /assessments/{id}/evidence-attachments` | Bounded, authorized PNG screenshot upload linked to immutable analyst evidence |
| `GET /evidence/{id}` | Safe metadata, no protected content/path |
| `GET /evidence/{id}/content` | Authorized integrity-checked text or `nosniff` PNG attachment download |
| `POST /assessments/{id}/findings` | Analyst-authored Unreviewed/Open finding |
| `PATCH /findings/{id}` | Revision-checked narratives, validated scoring/mappings and permitted remediation status |
| `POST /findings/{id}/review` | Independent ADMIN verification decision |
| `GET /retests`, `GET /retests/{id}` | Scoped history/detail; exact project, original assessment, method, result and review-state filters |
| `POST /findings/{id}/retests` | New-build or API-release evidence and result |
| `POST /retests/{id}/review` | Independent ADMIN decision; approved Pass may mark Fixed |
| `POST /cvss/score` | Authenticated pure calculation of a complete base-only CVSS 4.0 or 3.1 vector; no idempotency key needed |
| `GET /reports`, `GET /reports/{id}` | Scoped immutable version metadata/snapshot; title, project, assessment, status and template filters |
| `POST /assessments/{id}/reports` | Freeze a reviewed assessment's client-scoped deliverable |
| `POST /reports/{id}/release` | Independent ADMIN approval |
| `GET, POST /reports/{id}/exports` | Export history and protected PDF/JSON generation |
| `GET /report-exports/{id}/download` | Authorized download with SHA-256 integrity header |

All mutation authorization, linked-resource checks, revision/idempotency semantics
remain server-side. See generated OpenAPI for strict field names and required
values. Evidence credentials are redacted by bounded patterns; descriptive fields
reject recognized credentials. Redaction cannot prove removal of every sensitive
value: the analyst must submit sanitized test data. Reports retain frozen scope,
coverage, confirmed findings, limitations and versions; unresolved/filtered
candidates are not silently promoted to client findings.
