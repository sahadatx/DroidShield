# Reviewed client reports and CVSS scoring

DroidShield 0.5 creates an immutable report version from a completed, independently
reviewed assessment. A successful scanner job alone cannot create a final client
report. The report author writes the executive summary and limitations; generated
content includes only Confirmed findings within the selected assessment and
severity filter. Unreviewed, False Positive and Needs More Evidence findings are
excluded, with the exclusion count disclosed.

## Lifecycle and permissions

1. A SECURITY_ANALYST or ADMIN with Project access creates the frozen version.
2. Its initial status is `awaiting_review`; the authenticated author and authorized
   Project readers can inspect its snapshot. No PDF/JSON export is allowed yet.
3. A **different ADMIN** reviews that exact snapshot and approves it.
4. An authorized writer exports PDF or JSON into protected storage. Authorized
   Project readers, including granted VIEWERs, can download approved exports.

An administrator who authors a report needs a second administrator to approve it.
The browser never substitutes a scanner status for approval. Versions increment
within an Assessment while its row is locked. Reusing an idempotency key with the
same request returns the same record; different content conflicts. To revise a
report, create another version. There is no snapshot edit/delete API.

Reports preserve the scope, exclusions, authorization revision and testing window
from the manual execution snapshot, assessment execution snapshot or its Analysis
Job snapshot, in that order. They do not substitute a subsequently edited
Authorization's current scope. Missing historical snapshots are explicitly marked
`scope.source = "not_recorded"`; the supplied limitations must explain missing
records. Client contact details, internal Client notes, storage paths, credentials
and raw network traffic are never copied into deliverables.

## HTTP contract

All paths below are beneath `/api/v1`. Authentication and Project/workspace
visibility apply to every linked lookup. POST creation/release/export requests
require `Idempotency-Key`.

- `GET /reports`: standard Page, with optional `project_id`, `assessment_id` and
  `status` (`awaiting_review`, `approved`, `exported`) filters.
- `POST /assessments/{id}/reports`: required `title` (1–200),
  `executive_summary` and `limitations` (each 1–20,000); optional `template`
  (`executive`, `technical`, `combined`, default `combined`), unique nonempty
  `severity_filter` (default all five severities), strict Boolean
  `include_evidence` / `include_remediation` (default true), `branding_name`
  (1–200). Branding is plain text; remote images and arbitrary HTML are not loaded.
- `GET /reports/{id}`: report metadata plus frozen `snapshot` and
  `snapshot_sha256`, for review. Metadata includes project/assessment IDs, version,
  status, author/reviewer IDs and UTC approval/creation timestamps.
- `POST /reports/{id}/release`: `{ "decision": "approve" }`; ADMIN only,
  author must differ; only `awaiting_review` can advance.
- `POST /reports/{id}/exports`: `{ "format": "pdf" }` or `json`;
  approved/exported only. Response: `id`, `report_id`, `format`, `sha256`,
  `file_size`, `created_at`. Storage references stay private.
- `GET /reports/{id}/exports`: standard Page of protected export metadata.
- `GET /report-exports/{id}/download`: integrity-verified attachment with
  `X-Content-SHA256`, using an opaque file snapshot; no browser token appears in
  its URL. The filename is `DroidShield-report-v{version}.{format}`.

JSON exports contain the complete approved snapshot, its digest and release
metadata. PDF template selection controls the executive/technical presentation;
executive PDFs omit detailed technical finding sections. Technical and combined
PDFs include reproduction steps, impact, CVSS, mappings, remediation and selected
sanitized evidence excerpts. Every PDF includes the stated scope/limitations,
coverage matrix, risk summary, reviewed retest results and provenance appendix.

The coverage matrix is a versioned analyst procedure library. It includes Not Run,
Pass, Fail, N/A and Blocked records rather than inferring coverage from scanner
success. This starter library is not an exhaustive implementation of every MASVS
control or MASTG test. Framework IDs, versions and URLs are frozen with the report.
The remediation roadmap orders unfixed findings by assessed severity; owners and
due dates require client agreement, so the report invents no deadlines. The
workspace Overview counts an overdue retest only when an analyst records that
agreed date on a finding whose remediation status is `retest_required`.

Only approved Retests are included. Mobile retests retain the new immutable APK,
AAB or IPA hash/version; API-only retests retain distinct original/new release
references instead of inventing an application hash. Selected new evidence is
checked against the same Assessment/Project and its reviewed artifact/release.

## Bounds, integrity and rendering

The first implementation allows 200 findings, 20 selected evidence records per
finding/retest, 200 reviewed retests, a 2 MiB canonical snapshot and 16 MiB exports.
Oversized content is rejected explicitly. Sanitized text excerpts are included in
the snapshot. A linked PNG screenshot contributes its immutable ID, file size and
SHA-256; its pixels remain a separate protected download, not embedded in the PDF
or JSON snapshot. PDFs do not execute Markdown/HTML, fetch images, or render
uploaded application content. Report narratives containing recognized credential
patterns or control characters are rejected before persistence. Sanitization
cannot identify every possible secret: analysts must review excerpts before
approval.

PDF rendering runs in a separate unprivileged, fixed helper process. The parent
clears its environment, supplies a private temporary working directory and
bounded JSON over stdin, and reads bounded PDF bytes over stdout. There is no
shell or user-controlled command. Two renderers may run per API process; extra
requests fail without spawning work. The independent 30-second wall deadline
kills and reaps the actual process. The child additionally has 20 seconds CPU,
512 MiB address space, a 16 MiB file limit, 64 file descriptors, 64 user processes
and zero core dumps. A timeout, resource failure or excessive output publishes
no export. Narrow excessive report/evidence content and retry. Current user
status, writer role and Project access are checked again before publication.

Once an approved report format is exported, subsequent requests for that same
report/version/format reuse its immutable bytes, metadata and checksum, including
with a fresh idempotency key. They do not trigger another render or object write.
A provably pre-commit database write failure removes the new object. As with APK
intake, an ambiguous commit failure retains the private object for recovery rather
than risking deletion of an already committed export.

Snapshots and export metadata are append-only under SQLite/PostgreSQL migration
triggers. Report identity, template/filter/branding/author fields and approved
reviewer/time are frozen. SHA-256 is calculated from canonical UTF-8 JSON and
actual export bytes. Downloads verify file length and digest before responding.
Private objects use the existing hardened Storage protocol in the dedicated
`storage_root/reports` directory. Internal object suffixes are opaque and do not
specify the client download format. Orphan/retention management for report objects
is a future administrator maintenance operation; never delete immutable referenced
exports through the ordinary API.

ReportLab renders escaped narrative text with bundled FreeSans/FreeSansBold fonts
and HarfBuzz shaping. Fonts and their notices are packaged in
`backend/droidshield/report_fonts/`; GNU FreeFont is GPLv3+ with its explicit font
embedding exception. Both the copyright notice and GPLv3 text ship alongside the
font files. The independently distributed `cvss` dependency is LGPLv3+; no library
source has been copied into DroidShield.

## CVSS contract and sources

`POST /cvss/score` accepts only `{ "vector": "CVSS:4.0/..." }` (or `CVSS:3.1/...`)
and returns canonical `vector`, computed base `score`, `severity` and `version`.
This calculation needs authentication but creates no assessment or finding. The
pinned Red Hat `cvss==3.6` implementation computes the score; supplied finding
scores must match it exactly. Every required base metric must occur exactly once.
Threat/environmental/supplemental metrics and CVSS v2/v3.0 are rejected in this
first contract. Both vector and score may be absent for a finding whose risk is
not CVSS-scored. Assessed finding severity remains a separate analyst decision.

Primary references:

- [FIRST CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document)
- [FIRST examples](https://www.first.org/cvss/v4.0/examples)
- [FIRST calculator resources and linked implementations](https://github.com/FIRSTdotorg/cvss-resources)
- [Red Hat implementation and license](https://github.com/RedHatProductSecurity/cvss)

Reports support audit evidence for a scoped mobile engagement. They do **not**
certify SOC 2, ISO 27001, HIPAA, PCI DSS or Google Play compliance, guarantee zero
false positives, or establish that all vulnerabilities have been found. Those
limitations are stated in every report, not hidden in the application setup.
