# Analyst assessment, evidence and retesting

DroidShield records an authorized Android or iOS engagement from an immutable
application build or exact API endpoints through test coverage, independently
reviewed findings, assessment completion and fix verification. These operations
record the analyst's work; submitting a form does not run Objection, Burp, an
arbitrary Frida script, a jailbreak operation, a business-logic attack or an iOS
simulator/device session. The separate restricted Android and GET/HEAD API
workers keep their existing boundaries.

## Starting and completing an engagement

Create a Project with the correct Android package or iOS bundle identity and
platform. Link an administrator-verified authorization containing exact targets,
exclusions and a valid test window. A pending authorization may carry private,
immutable supporting approval documents in PDF, PNG or JPEG format; upload them
before an administrator independently verifies the authorization. Upload the tested application through protected
intake; non-API manual work requires its immutable artifact and matching identity.
An API-only assessment uses exact approved HTTPS endpoints and may omit an
application artifact.

`POST /api/v1/assessments/{id}/manual-start` requires the current revision,
platform, environment, tool names/versions and explicit limitations. The server
checks the active Client/Project, access, current authorization, exact scope,
exclusions, platform and artifact identity. It accepts Draft or Awaiting
Authorization assessments with no automated job. It records the start actor,
configuration and authorization snapshot and sets Running. It creates no worker
job. A queued/running worker assessment cannot also be started manually.

Record evidence, findings and the applicable test results. Submit with
`POST /assessments/{id}/manual-finish`, supplying revision and a meaningful summary.
At least one recorded test outcome or explicit blocked/not-applicable limitation
is required. Current authorization is checked again. This moves to Needs Review.

`POST /assessments/{id}/review` accepts `complete` or `return`. An ADMIN reviewer
must differ from the assessment creator, manual starter/submitters, all historical
coverage operators, evidence authors and finding authors/editors. Contributor
identities are retained when a later analyst edits a result, preventing review
independence from being reset by a minor later edit. Completion requires recorded
coverage and no Unreviewed/Needs More Evidence finding candidates. A completed
assessment's original finding content and coverage are frozen. Historical review
does not itself execute testing and does not require an unexpired test window.

Create an analyst account and a separate administrator reviewer with the existing
trusted CLI account setup. The same account cannot submit and approve its own work. The
workspace administrator remains responsible for assigning genuinely independent
people to these account identities.

## Pinned methodology and actual coverage

`GET /methodology` returns local procedure library version 1.1.0: 18 analyst
procedures covering all 24 MASVS 2.1.0 controls, with Mobile Top 10 2024 risk
mappings and NIST SP 800-115 (September 2008) methodology references. Each
framework includes a source revision; MASVS mappings link to the individual
control reference and pin the adopted OWASP MASVS `v2.1.0` release. Local
`DS-*` identifiers are DroidShield procedures, not invented OWASP MASTG test
identifiers. The procedure text explicitly describes manual evaluation and
missing source/device/access limitations.

`GET /assessments/{id}/coverage` returns the library and its recorded execution
state. A missing execution is shown as Not Run; it never becomes Pass because a
scanner finished. `PUT /assessments/{id}/coverage/{case_id}` records platform,
environment, tool/version, notes, linked evidence/findings and one of Not Run,
Pass, Fail, N/A or Blocked. New records omit revision; edits require the current
execution revision. Pass/Fail requires evidence; Fail also requires a scoped
finding link. Every referenced record must belong to the same assessment and
expected artifact, including an explicitly absent artifact on API-only work.
Current authorization is required when recording fresh evidence or test results.

Each execution keeps a copy of the test procedure, local library version,
framework versions and source revision references. Old reports retain their
snapshot if the methodology library changes later. A group
of generic local procedures is a coverage management aid; a populated matrix does
not automatically establish that every framework requirement was tested thoroughly.

## Protected evidence and finding verification

`POST /assessments/{id}/evidence` accepts sanitized text with an explicit
`sanitized: true` confirmation, title, platform, tool/version, environment,
optional Finding and the tested artifact. Text is bounded to 65,536 characters
and 262,144 UTF-8 bytes. Known credential patterns, bearer tokens, JWTs, private
keys and sensitive header lines are redacted before storage. This pattern filter
cannot recognize every secret; the analyst must inspect and sanitize observations
before submission. Do not paste production personal data or live credentials.
Screenshots use the separate `POST /assessments/{id}/evidence-attachments`
multipart endpoint. It accepts PNG only, up to 8 MiB, after bounded transfer and
signature/dimension checks. The server does not decode or render the image. The
file is stored as an opaque owner-only object, paired with the normal immutable
evidence record and its independently calculated digest. The upload requires the
same current project access, assessment, artifact/release, authorization and
sanitization checks as text evidence. The original upload filename is discarded.
Video, arbitrary raw tool output and other image formats are still not accepted;
record their sanitized observations as text and retain client-approved originals
under the engagement's external evidence policy.

Evidence bytes are separate private objects under the configured storage root's
`evidence/` directory; screenshot objects use the separate
`evidence-attachments/` directory. Directories are owner-only and published
objects are read-only. Metadata includes the actual SHA-256, size, redaction
count, source identity and provenance. Metadata GET/list responses expose neither
content nor storage references. `GET /evidence/{id}/content` performs current
access and integrity checks; text returns as a text attachment and screenshots
return as an opaque `application/octet-stream` attachment with `nosniff` and
`no-store`. Screenshots are never rendered inline. Database migrations reject
evidence and attachment UPDATE/DELETE; PostgreSQL also rejects TRUNCATE. An orphan
object left by a crashed database transaction remains private; it is not a public
download.

Authorization supporting files use the separate `authorization-attachments/`
directory. A writer can upload one PDF, PNG or JPEG up to 8 MiB to a pending
authorization; project viewers can list and download files when they have current
project access. The server validates the filename, declared type and basic file
signature, but does not parse, render, scan or certify the document. It stores the
actual SHA-256 with immutable metadata and excludes object references from API
responses and audit events. `GET /authorizations/{id}/attachments` lists safe
metadata, while `GET /authorization-attachments/{id}/download` verifies stored
size and digest and returns a forced attachment with `nosniff` and `no-store`.
Uploads are unavailable after verification or revocation; the administrator's
independent verification decision is not inferred from the presence of a file.
The original client filename is discarded; responses use a generic filename
based on the validated extension.
The original client filename is discarded and responses use a generic name based
on the validated extension.

`POST /assessments/{id}/findings` creates an Unreviewed/Open finding with bounded
narratives, severity, calculated CVSS v4.0 or v3.1 base vector/score, pinned MASVS
and CWE mappings and linked sanitized evidence. PATCH requires its revision and
resets verification to Unreviewed. All historical authors/editors remain recorded.
Ordinary descriptive fields reject recognizable credentials instead of storing
raw secrets. CVSS scores are recalculated by the pinned scoring implementation;
caller-supplied scores cannot override the vector.

`POST /findings/{id}/review` requires an independent ADMIN and current finding
revision. Confirmed requires meaningful reproduction, impact and remediation,
linked evidence whose bytes still match their digest, and a valid calculated
CVSS vector/score for non-informational findings. Evidence authors cannot approve
their own proof. Severity and confirmation stay separate: a High scanner candidate
still requires human verification. False Positive and Needs More Evidence are
explicit review decisions with notes. Overview confirmed finding counts update
from these persisted decisions.

For an API-only finding, original evidence must carry one exact `release_ref`
(e.g. the client's backend release identifier). Confirmation pins that reference
before assessment completion. It is an analyst-declared release reference, not a
server-verified deployment fingerprint or an invented application hash.

## Retesting and status changes

`POST /findings/{id}/retests` requires a Confirmed finding from a Completed
assessment, current verified authorization, method/environment/tool provenance,
new evidence and a result of Pass, Fail, Inconclusive or Not Reproducible. Only one
pending attempt per finding is permitted. All links are scoped to the original
assessment/project; evidence timestamps must be inside the selected authorization
window and that authorization must still be active when the retest is recorded.

For application build fixes, `new_artifact_id` is mandatory, belongs to the same
Project/platform and has a different server-derived SHA-256. Evidence must name
that exact new artifact. Upload the new build through another draft assessment's
protected intake, then attach new-build evidence to the original assessment. The
old build and its evidence remain unchanged.

For an API-only assessment with no original artifact, method must be `api` and
`new_artifact_id` is null. `original_release_ref` must match the reference pinned
on original evidence before completion. `new_release_ref` must differ and match
all new evidence exactly. New API proof is created after the original assessment
completed and is stored with that new release reference. No application hash is
fabricated for a backend-only release. These references establish the declared
release history, not cryptographic proof of what a remote server deployed.

A new attempt changes the finding to Retest Required. `POST /retests/{id}/review`
requires both current retest and finding revisions and an ADMIN distinct from the
operator and new-evidence authors. The reviewer verifies evidence integrity. An
approved Pass alone sets Fixed; approved Fail reopens; Inconclusive/Not Reproducible
remain Retest Required. Rejection does not mark a finding Fixed. Decisions cannot
be overwritten or replayed with another payload. Authenticated list/detail
endpoints retain old/new evidence IDs, build or release provenance and reviewer
notes for comparison and reporting.

## API conventions and limits

All POST operations require an Idempotency-Key. Exact retries replay the same
currently authorized resource; changed payloads conflict. PATCH/PUT and review
operations require revisions as specified. Normal pagination uses items/total/
limit/offset. Every lookup enforces current workspace and Project access; hiding
a button does not grant or revoke permission. Audit events contain actor/action/
resource/request identifiers and safe metadata, never evidence content or form
bodies. Known invalid states conflict without creating findings, jobs or retests.

The migration is `0005_delivery_workflow`; reviewed report snapshots follow in
`0006_reports`. Downgrade refuses to discard delivery evidence,
coverage or retest history. SQLite and PostgreSQL tests verify legacy reference
preservation, downgrade/upgrade behavior, metadata parity and immutable evidence.
