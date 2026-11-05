> 0.5 update: the same isolation/storage boundary now supports protected APK/AAB/IPA intake through `/assessments/{id}/artifact`. Only APKs enter automated Android engines. IPA/AAB identity/configuration inspection feeds analyst-led engagements; see [service delivery](service-delivery.md). Analyst review, protected evidence, reports and retesting are implemented. Older APK-specific execution details below remain applicable to the original `/apk` endpoint.

# Protected APK intake and isolated static analysis

This document describes protected APK storage, intake and the original manifest engine. The current application also delivers the [frontend](frontend.md), isolated [DEX engine](dex-analysis.md), [MobSF adapter](mobsf.md), controlled [dynamic lab](dynamic-lab.md), fixed [Frida observer](frida.md), restricted [HTTPS proxy](proxy.md) and [API baseline worker](api-security.md). Those engines retain the authorization and immutable artifact boundaries described here. Full dependency analysis remains outside the automated engines; analyst verification, reports and retesting use the implemented [analyst workflow](analyst-workflow.md).

An automated indicator starts **Unreviewed**. Successful processing moves an assessment to **Needs Review**, not Completed or Confirmed. Findings review, report delivery and retesting use separate authenticated analyst/reviewer operations; scanner success never grants those approvals.

## Host and storage setup

Use Linux with an unprivileged API/worker service account, Bubblewrap (`bwrap`), unprivileged user namespaces and a trusted system Python under `/usr`. APK processing refuses real or effective UID 0. Install the host's Bubblewrap package, then configure the API and worker with the same database and protected storage root. An absent or unusable sandbox fails closed: it does not fall back to parsing an APK inside the API process or running an unrestricted subprocess.

```sh
python -m pip install -e '.[dev]'
droidshield migrate
export DROIDSHIELD_STORAGE_ROOT=/absolute/protected/path/droidshield-artifacts
export DROIDSHIELD_SANDBOX_EXECUTABLE=/usr/bin/bwrap
export DROIDSHIELD_SANDBOX_PYTHON=/usr/bin/python3
uvicorn droidshield.main:create_app --factory --host 127.0.0.1 --port 8000
```

Keep storage outside web-server document roots, source control and the `/usr` runtime exposed to the sandbox. Restrict its owner and permissions to the service account, and mount it only where the API and worker need it. Local development can use one account; production should use restricted service identities, PostgreSQL and a deployment boundary separating API and worker processes. There is no public static-files mount, caller-selected path, or unauthenticated artifact URL.

Files are staged with private permissions, hashed from their actual bytes and inspected in the sandbox before the database creates a trusted artifact association. Persistent paths use server-generated opaque identifiers. Responses return safe artifact metadata and never storage paths. A digest retains its first immutable format classification: uploading identical bytes under another supported archive format conflicts instead of silently reusing a different format/version record. Artifact records are immutable and a project's identical byte digest is deduplicated; the original artifact's metadata remains its provenance.

The default APK size limit is 100 MiB. The HTTP body budget includes at most 64 KiB of multipart overhead in addition to that file limit. Intake enforces the body budget while receiving data, including requests without `Content-Length`, and enforces the file budget again while copying. Transfers have a default 120-second deadline. Each API process admits at most two concurrent uploads, including inspection; busy capacity returns 429 instead of queueing another upload. Configure proxy body/time limits consistently with these application bounds and account for each API process when sizing total capacity. Archive entry count, expanded size, compression ratio and binary manifest limits also apply; a small compressed file is not automatically safe.

## Upload request

Create an accessible Client, Project and draft Assessment first. The Project's Android package ID must match the detected APK package. Upload does not require an active testing authorization; it is intake only. Queueing and worker execution each independently require the verified, current authorization and approved scope.

`POST /api/v1/assessments/{assessment_id}/apk` accepts `multipart/form-data`:

| Field | Contract |
| --- | --- |
| `file` | Required single `.apk` file; simple filename without directory paths; APK, octet-stream or ZIP MIME |
| `revision` | Required positive decimal assessment revision; stale writes conflict |
| `app_version` | Optional declared build label; does not replace detected version metadata |
| `build_type` | `debug`, `release` or `unknown` (default) |
| `upload_notes` | Optional, maximum 20,000 characters |

Require an active browser session with its matching CSRF value, or an explicit Bearer API credential, plus a unique `Idempotency-Key` and a writer role with access to the linked Project. Authentication, role and Project access are checked again after the bounded isolated inspection, before publishing or replaying an artifact association. A revoked or expired session cannot complete an upload. Client and Project must be active. Uploads can bind artifacts only to Draft or Awaiting Authorization assessments. An assessment's Project is inferred server-side; there is no separately trusted Project form field. Extra or duplicate fields and client-supplied hashes/metadata are rejected.

Example, with locally assigned values in `DROIDSHIELD_TOKEN`, `ASSESSMENT_ID`, `ASSESSMENT_REVISION` and `UPLOAD_KEY`:

```sh
curl --fail-with-body http://127.0.0.1:8000/api/v1/assessments/"$ASSESSMENT_ID"/apk \
  --header "Authorization: Bearer $DROIDSHIELD_TOKEN" \
  --header "Idempotency-Key: $UPLOAD_KEY" \
  --form "revision=$ASSESSMENT_REVISION" \
  --form 'build_type=release' \
  --form 'file=@/absolute/path/application.apk;type=application/vnd.android.package-archive'
```

A `201` response includes the artifact UUID, Project UUID, detected version name/code when available, server-calculated SHA-256, filename, size, build type and creation time. It excludes raw manifest content, internal notes and storage references. Read the assessment again to obtain its incremented revision before the next lifecycle change.

An exact retry with the original key, bytes, revision and form metadata replays the same association even after that request advanced the assessment revision. Reusing that key with changed bytes or metadata returns a conflict. A replay still checks current authentication and Project access; an idempotency key never grants access. Keep the same key when retrying a request whose outcome is unknown.

The sandbox accepts bounded ZIP/APK structure containing a supported binary `AndroidManifest.xml`. It rejects malformed archives/manifests, unsafe member paths, unsupported entry types, duplicate entries, excessive expansion and configured resource-limit violations. No archive is extracted into the API filesystem, and the APK is never launched as an application.

## Queue and worker lifecycle

Link a verified authorization covering the package target (for example `package:com.example.app`) and a current testing window. Queue the assessment using its latest revision:

```http
POST /api/v1/assessments/{assessment_id}/queue
Authorization: Bearer <credential>
Idempotency-Key: <new request key>
Content-Type: application/json

{"revision": 2}
```

Queueing creates a durable job. The static worker claims Static assessments and dispatches the pinned manifest, DEX or MobSF engine. Dynamic assessments require a separately created lab session and the dynamic worker. API baselines require a target/execution configuration and the API worker; Full jobs still need a future orchestrator. The queue snapshot pins the artifact where applicable, authorization, targets and selected engine; the worker records its engine version and bounded configuration when it claims the job. Changes to access, Client/Project status, artifact integrity, scope, exclusions or authorization validity can prevent or terminate processing.

Run the worker in a separate terminal/service, with the same configured database and storage:

```sh
droidshield worker --once
```

`--once` processes one eligible Static job (or returns idle). For a continuously polling service:

```sh
droidshield worker
```

SIGTERM or Ctrl-C requests graceful shutdown and cancellation of an active attempt. A killed/crashed process cannot renew its lease; a subsequent worker marks the expired attempt Failed, without publishing or automatically retrying the interrupted scan. Non-Static jobs remain untouched.

The worker holds a bounded lease and heartbeats during processing. It revalidates current authorization before claiming a job, while the sandbox runs and before publishing results. Cancellation stops processing; failed, cancelled or lost-lease attempts cannot publish stale findings. Persisted results remain associated with the exact assessment, job, artifact and SHA-256. Crash recovery does not silently invent completed results.

The sandbox exposes the trusted runtime and engine read-only, the selected APK read-only and bounded temporary storage. It isolates network, process and user namespaces, drops capabilities, clears the environment and enforces CPU, memory, elapsed-time and output limits. It shares the host kernel; process isolation does not protect against a kernel exploit or certify deployment security. Use a hardened host and VM/container deployment boundaries appropriate to the environment.

The `droidshield-manifest-2` engine detects package/version/SDK metadata, permission identifiers, application manifest flags and components. It emits candidates for explicitly enabled debugging, cleartext traffic, backup and exported components without a declared permission. These flags can require context; their severity never establishes exploitability or analyst confirmation. Missing metadata is reported without invented values; malformed or unsupported values can reject the APK. For APK and AAB metadata, `version_code` is Android's composed long value `(versionCodeMajor << 32) | versionCode`; each component is bounded to 0–2,147,483,647. An absent/zero major retains the prior value, while unresolved or out-of-range components are rejected. Signing certificates/signature validity, DEX, secrets and dependencies are outside this engine. AAB intake remains metadata-only and does not queue automated APK analysis.

## Protected reads

All reads require authentication and current workspace/Project access:

| Endpoint | Result |
| --- | --- |
| `GET /api/v1/projects/{id}/versions` | Safe immutable artifact summaries |
| `GET /api/v1/artifacts/{id}` | Safe artifact summary plus allowlisted manifest metadata |
| `GET /api/v1/artifacts/{id}/download` | Attachment download after stored-byte integrity verification |
| `GET /api/v1/assessments/{id}/job` | Safe job status, timestamps and sanitized failure/cancellation information |
| `GET /api/v1/assessments/{id}/analysis` | Persisted allowlisted metadata, indicators, engine version and explicit limitations |
| `GET /api/v1/assessments/{id}/findings` | Finding summaries; new scanner candidates are Unreviewed/Open |
| `GET /api/v1/authorizations/{id}/attachments` | Project-scoped authorization attachment metadata; no storage references |
| `POST /api/v1/authorizations/{id}/attachments` | Writer upload of a pending authorization document, up to 8 MiB |
| `GET /api/v1/authorization-attachments/{id}/download` | Authenticated document attachment after size and SHA-256 verification |

Raw stdout/stderr, host paths, environment values, storage references and arbitrary engine output are not ordinary API response fields. Audit events identify the action/resource/request; they do not store APK bytes, upload notes, request bodies or credentials.

Client approval documents use a separate private `authorization-attachments/`
storage namespace with server-generated opaque references. A writer can upload
one `.pdf`, `.png`, `.jpg` or `.jpeg` file at a time, up to 8 MiB, only while its
authorization is pending. Bounded multipart transfer, filename/type/signature
checks, server-side byte hashing, fresh authentication and project authorization
are required before publication. The upload never parses or renders the document.
Attachments are immutable at the database layer. Metadata GET responses omit
object references and audit events omit filenames and file content; downloads
recheck current project visibility, stored size and digest and use `nosniff` and
`no-store`. Verification remains an independent ADMIN action and adding a file
does not verify its authenticity or scope.

Common responses: `401` missing/invalid authentication; `403` insufficient role; `404` missing or inaccessible resource; `408` upload transfer deadline exceeded; `409` stale revision, lifecycle or idempotency conflict; `413` size budget exceeded; `415` unsupported request/file media type; `422` invalid form, unsupported APK or package mismatch; `429` concurrent upload capacity busy; `503` required isolation unavailable. Errors carry a request correlation ID and do not echo submitted secrets or raw parser output.

## Resource configuration and recovery

These settings use the `DROIDSHIELD_` prefix; API and worker should share the same intake/engine limits:

| Setting | Default |
| --- | --- |
| `MAX_APK_BYTES` | 104,857,600 bytes |
| `MAX_CONCURRENT_UPLOADS` | 2 per API process |
| `UPLOAD_TIMEOUT_SECONDS` | 120 transfer seconds |
| `APK_MAX_ENTRIES` | 10,000 |
| `APK_MAX_UNCOMPRESSED_BYTES` | 536,870,912 bytes |
| `APK_MAX_MANIFEST_BYTES` | 4,194,304 bytes |
| `APK_MAX_COMPRESSION_RATIO` | 100 |
| `ANALYSIS_TIMEOUT_SECONDS` | 30 elapsed seconds |
| `ANALYSIS_CPU_SECONDS` | 15 CPU seconds |
| `ANALYSIS_MEMORY_MB` | 256 MiB |
| `ANALYSIS_OUTPUT_BYTES` | 1,048,576 bytes |
| `WORKER_LEASE_SECONDS` | 120 seconds |
| `WORKER_HEARTBEAT_SECONDS` | 1 second |
| `WORKER_POLL_SECONDS` | 0.5 seconds |

Interrupted intake can leave a staged file or unreferenced object after a host crash. Run trusted local maintenance to remove only stale temporary files and unreferenced APK or authorization-document objects absent from the database:

```sh
droidshield cleanup-storage --older-than-hours 24
```

The minimum age is one hour. Do not use this maintenance command as a retention policy or delete referenced files by hand. Back up the database and protected object storage together; a database record whose bytes were lost or modified fails integrity verification on download and execution. Full evidence/report retention policy administration remains planned.

## Verification and remaining work

Run the repository checks after applying migrations:

```sh
pytest
ruff check backend tests
ruff format --check backend tests
alembic check
```

The upload integration suite uses real binary-manifest APK fixtures and the real Bubblewrap sandbox. It verifies server hashes, private storage, immutable deduplication, request replay, role/tenant isolation, size limits, archive rejection, protected downloads and upload-to-analysis execution. Set `DROIDSHIELD_TEST_DATABASE_URL` to a dedicated PostgreSQL test database to exercise generated isolated schemas there; no production database is needed.

The backend does not seed dashboard values, expose a file-browser page, execute broad API attacks or confirm findings automatically. Connected upload/progress/results pages, analyst review, protected text evidence, reports and retesting are implemented. A separate exact HTTPS GET/HEAD API worker retains its own authorization and rate limits; deeper engines and broader retention/settings administration remain extensions.
