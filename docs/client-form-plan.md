# Create/Edit Client implementation plan

Status: adopted form specification for the first resource UI. Version 0.3 includes a real API-connected client form; see [frontend](frontend.md). This plan also records the complete intended workflow. See [API contract](api-contract.md) for the currently exposed fields and actions.

## 1. Page and form layout

The Clients page has a searchable, paginated table with Client, Contact, Active projects, Assessments, Last activity, Status and Actions columns. It supports status filtering, Create Client and opening details. Empty state: “No clients yet” with Create Client for permitted users. A filtered empty state offers Clear filters. Counts and last activity come from stored records, never fixed demo values.

Use a dedicated create/edit page or an accessible panel with these sections:

1. **Client identity:** client type, conditional required name and optional organization details.
2. **Contact information:** optional authorized contact name, email and phone.
3. **Engagement notes:** optional internal notes.
4. **Status:** Active/Archived and conditional archive reason. Create defaults to Active.
5. **Actions:** Save, Cancel and Reset; a persistent pending/success/error status.

Display immutable UUID and creation/update metadata on details/edit views as read-only data. Do not render these as writable form inputs. Client detail tabs are Overview, Projects, Assessments, Reports and Activity. Planned tabs must show a clear unavailable/empty state until their APIs exist.

## 2. Fields and conditional behavior

| UI field | Required | Validation and behavior |
| --- | --- | --- |
| Client type | Yes | Company or Individual; do not infer type from a name |
| Company name | Company only | Nonblank trimmed name; label and error use “Company name” |
| Individual name | Individual only | Nonblank trimmed name; label and error use “Individual name” |
| Organization name | No | Optional organizational affiliation for an Individual; Company identity is its company name |
| Website | No | Valid supported absolute web URL when supplied |
| Contact person | No | Authorized contact name; Individual name can be displayed as a suggestion, not silently copied |
| Contact email | No | Blank becomes null; valid email when supplied |
| Phone | No | Conservative text/length validation; support international formatting without requiring a country-specific pattern |
| Internal notes | No | Bounded plain text; no HTML execution; visible only to Client creator/ADMIN |
| Status | Yes | Active by default; Archived triggers the archive-reason requirement |
| Archive reason | Archived only | Nonblank trimmed explanation; hidden for Active and not silently submitted as a new archive action; visible only to Client creator/ADMIN |
| Client ID, created by/at, updated at | Server only | UUID and authenticated/server-generated metadata |

Use a common persisted name field with a type-specific label; do not create both a required company name and a required person name. When switching type, keep the entered name for review and update its label. Keep optional organization/contact inputs until the user deliberately clears them; explain what will be saved in review. Do not erase data silently when a control hides. For an edit, changing type is an explicit saved change and must pass the same validations as create.

UI length limits must match the server schema: name 1–200; organization/contact person 255; phone 64; website 2,048; notes 20,000; archive reason 1–2,000 characters. The API schema is authoritative. Reject empty/whitespace-only names and reasons. Trim leading/trailing whitespace without rewriting meaningful interior content. Send optional blank email/URL as null rather than an invalid empty string. Email uniqueness is not required: multiple clients may share an authorized contact address.

Never ask for passwords, payment-card details, API tokens or unnecessary personal data in this form. Do not add a generic attachment field that could bypass the controlled evidence-upload workflow.

## 3. Backend mapping

| UI data | Backend ownership and representation |
| --- | --- |
| Company / Individual | Enum stored on Client |
| Conditional name | One required persisted client name, with the type determining the label |
| Organization, website, contact person/email/phone, notes | Optional Client fields; validated by Pydantic and the service |
| Active / Archived | Client status; archival uses the archive workflow and requires a reason |
| Client ID | Server-generated UUID |
| Created by | Authenticated actor ID; not accepted from the browser |
| Created/updated at | Server-generated UTC timestamps |
| Active project/assessment counts | Computed read model scoped to the actor; not submitted |
| Last activity | Derived from relevant persisted actions; not replaced by static display content |

Use the concrete JSON field names from [API contract](api-contract.md), not labels as payload keys: `client_type`, `name`, `organization_name`, `website`, `contact_person`, `contact_email`, `phone`, `notes`, `status` and `archive_reason`. Create uses `POST /api/v1/clients`; edit uses `PATCH /api/v1/clients/{id}` with the last loaded `revision`; read uses `GET /api/v1/clients/{id}`. Create accepts archived status only with a reason. Dedicated archival uses `POST /api/v1/clients/{id}/archive` with revision/reason. Reactivation uses an authorized status patch; there is no separate restore endpoint.

The backend authenticates the actor with an opaque Bearer token, checks role and workspace, validates the body, persists Client and audit metadata transactionally, and returns the resource. Only the Client creator or ADMIN can edit/archive it; a Project grant can expose a related Client without granting edit rights. A reference to an inaccessible client is never accepted simply because its UUID is valid. Archival retains history and is blocked while the Client has non-archived Projects; guide the operator to archive those first.

Client list/detail responses redact `notes` and `archive_reason` to null for a non-owner reading through Project access. Hide those private sections for that actor or label them as restricted; a redacted null does not mean the persisted value is absent. Do not build an editable form from a grantee's read-only representation or send those nulls back as a clearing update.

## 4. Action behavior

| Action | Create behavior | Edit behavior |
| --- | --- | --- |
| Save | Validate, submit once, show pending, then open created Client | Validate only supported edits, persist, then refresh canonical server values |
| Cancel | Return to list without saving | Return to details without saving |
| Reset | Restore initial defaults; type Company, status Active, optional fields blank | Restore the last loaded server values |
| Archive | Can create as Archived with a reason; default remains Active | Confirm named client and required reason, then invoke archive endpoint |

Dirty Cancel/Reset asks before discarding changes. Archive confirmation is separate from ordinary save and names the client. A pending request disables Save and prevents duplicate clicks, but frontend disabling alone is not a duplicate-write guarantee. All POST mutations require an `Idempotency-Key`: retain the same key for retrying the same operation/body and use a new one for a different operation. PATCH uses the last observed revision; a stale revision requires refresh/reconciliation before resubmission.

Treat a network timeout after submission as an unknown outcome: preserve the form and offer a deliberate recovery path. Do not say “not saved” unless the server confirms failure. Do not promise that client-name duplication is always an error; legitimate duplicate names can exist unless a documented workspace policy forbids them.

## 5. Validation and feedback states

Validate required/format checks after blur and on submit; do not show errors before interaction. Keep a concise form-level summary and inline messages. Examples: “Enter a company name”, “Enter a valid email address”, and “Enter a reason for archiving this client.” Preserve all safe input after errors.

| State | UI result |
| --- | --- |
| Loading edit | Skeleton or progress indicator; fields unavailable until the record loads |
| Invalid body | Associate server validation paths with fields; focus first invalid field |
| Unauthenticated | Follow the application's sign-in flow; do not discard dirty input unnecessarily |
| Forbidden | Explain that the action is unavailable; do not render a misleading success |
| Missing/inaccessible record | Consistent not-found state without leaking other workspace details |
| Conflict/stale edit | Keep edits; ask user to refresh/compare when concurrency support exists |
| Request failure | Form-level message and correlation ID if supplied; safe retry only when outcome is known |
| Saving | Busy state, disabled repeated submission and announced progress |
| Success | Announced success and canonical returned values; close create only after confirmation |

VIEWER can read authorized clients and cannot create, edit or archive. An analyst can create and modify their own Clients; ADMIN can modify workspace Clients. A Project grant alone gives no right to edit its linked Client. The frontend must handle a permission changing after initial page load.

## 6. Implementation tasks

1. Finalize Client schema, enums, length bounds, error format, role checks and archive service with backend tests.
2. Expose list/detail/create/update/archive API operations and document the exact payload names.
3. Build a reusable field group, enum selector, error summary and pending-action behavior in the shared design system.
4. Implement Client list, form and details Overview using real API data. Add related tabs only as their APIs are delivered.
5. Connect server validation paths, permission failures and safe form preservation; verify keyboard/focus behavior.
6. Add related counts/activity after their persisted source workflows exist; never substitute fake values.

## 7. Acceptance and meaningful tests

Backend tests:

- Company and Individual each require a nonblank name; valid optional fields persist and round-trip.
- Missing optional email is accepted; malformed supplied email is rejected. Website validation rejects unsupported or malformed URLs.
- Invalid enum, excessive length and unknown/server-owned fields are rejected according to schema policy.
- Partial update preserves omitted values and permits explicit null only for nullable fields.
- Archive requires a reason, retains history and records actor/time; non-archived child Projects block it. Reactivation clears the old archive reason.
- Replayed POST keys cannot create a duplicate; payload mismatch and stale PATCH revisions return conflict responses.
- VIEWER cannot mutate; unauthenticated requests fail; cross-workspace reads/writes and relationship references do not expose records.
- A Project grantee can read the necessary Client identity/contact data but receives null private notes/archive reason in list and detail; the creator and ADMIN retain access to those fields.
- Validation failures do not create partial records; the returned creator and timestamps are server-controlled.

Frontend acceptance checks once the form exists:

- Type selection updates the required-name label and keeps edits for review.
- Optional email can remain blank; errors appear below fields and the summary links to them.
- Archive reason appears and is required only for an archive action; confirmation identifies the Client.
- Save prevents repeated clicks, remains busy until resolved and handles an ambiguous network failure without blind retry.
- Cancel and Reset follow their distinct definitions and protect dirty edits.
- Loading, empty, filtered-empty, success, server-error and access-denied states are usable by keyboard and announced accessibly.
- No production row or counter is populated with sample clients or hardcoded activity.
