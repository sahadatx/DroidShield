# Controlled HTTPS API testing

DroidShield's API worker performs a bounded baseline and, when configured,
primary/secondary account comparison against exact approved HTTPS endpoints.
It sends only GET or HEAD. It does not run injection, fuzzing, credential guessing,
state-changing methods, arbitrary OpenAPI operations or broad API coverage.

## Workflow

1. Create an API assessment with each exact HTTPS endpoint in `requested_targets`.
   API assessments do not require an APK. A host/base URL does not authorize
   arbitrary child paths. Queries, fragments, URL credentials and ambiguous paths
   are rejected by the same strict target contract as authorization records.
2. Obtain an ADMIN-verified authorization with those exact endpoint URLs,
   exclusions, evidence reference and an active validity window.
3. Create one immutable API target through
   `POST /api/v1/assessments/{id}/api-targets`. Supply a name, 1–20 endpoint
   objects (`url`, `method` GET/HEAD, `expect_authentication`), optional exact
   `excluded_endpoints`, `auth_method`, project-bound secret references,
   `requests_per_minute` (1–120), and offset-aware `test_window_start`/`end`.
   The target is immutable: create a new assessment to revise its scope.
4. `POST /api/v1/api-targets/{id}/execute` with the current assessment `revision`
   validates and queues the assessment and creates its one execution. Already
   queued API assessments can also create their execution. All POST requests
   require an `Idempotency-Key`; duplicate intent cannot create duplicate jobs.
5. Run `droidshield api-worker --once` or the polling `api-worker` separately
   from the HTTP application. Queueing never makes HTTP requests itself.
6. Read `/api-executions/{id}` or the assessment's `/api-executions` history.
   Cancel via `/api-executions/{id}/cancel` with a reason. The normal assessment
   cancellation and authorization revocation also stop processing.

Only project-visible users can read target configurations, credential references
or results. Writers need ADMIN or SECURITY_ANALYST role. Current workspace,
project/client activity, operator role/account/project grant, authorization
revision/scope/exclusions/window, target configuration, test window and worker
lease are checked before claiming, before every request, while waiting for a
response/rate budget, and before publishing. Expired/crashed work is failed and
never automatically replayed; a stale worker cannot publish another owner's job.

## Protected account references

The administrator sets `DROIDSHIELD_API_SECRET_STORE` to an absolute private JSON
file outside the served frontend. The worker/API account must own the regular
file; group/world permissions and symlinks are rejected. Limit: 64 KiB and 100
entries. No API creates or reveals credential values. Use a separate reference
for each test account and engagement:

```json
{
  "client-a-primary": {
    "workspace_id": "workspace-uuid",
    "project_id": "project-uuid",
    "kind": "bearer",
    "header": null,
    "value": "protected-token-value"
  }
}
```

This is a configuration example; do not commit a populated store. Set mode 0600
and keep the parent directory private. Supported kinds: `bearer` sends an
Authorization Bearer header; `cookie` sends a Cookie header; `api_key` requires
an explicit safe header name such as `X-API-Key`. Header names that alter routing,
framing, proxying or another authentication mechanism are rejected. Values cannot
contain control characters or non-ASCII header data. Each reference must match
the exact workspace and project and the target's selected kind.

`GET /api/v1/projects/{id}/api-secret-refs` returns only `ref` and `kind` for that
accessible project. Ordinary target responses expose reference names, never
values. Disabled/unavailable/misbound references block execution. OAuth clients
can supply a previously provisioned short-lived access token as a bearer
reference; interactive OAuth authorization/refresh is not implemented.

## Outbound policy and budgets

HTTPS uses the platform trust store, certificate hostname verification and TLS
1.2 or later. `DROIDSHIELD_API_CA_BUNDLE` may select an administrator-provisioned
CA bundle for a private test environment; there is no verification-disable flag.
The connection resolves once for each request, validates every returned address,
pins the actual TCP socket to one validated IP and sends TLS SNI/the Host header
for the approved hostname. Mixed public/private DNS answers fail closed.
Environment proxies are not read. Redirect responses are recorded, never followed.

Public addresses are allowed by default, but only for the exact authorized target.
Private/loopback destinations require explicit administrator CIDRs in
`DROIDSHIELD_API_ALLOWED_NETWORKS`, for example `["127.0.0.1/32"]` for the local
TLS test fixture. Link-local/cloud metadata, multicast and unspecified addresses
remain denied even under a broad configured CIDR. Configure narrow lab networks;
project inputs cannot change this policy. An administrator policy change after
queueing invalidates that execution's configuration snapshot.

Defaults: 120-second execution budget, 10-second request budget, 60 requests,
64 KiB response bodies and a 30 requests/minute target limit. Settings cap request
and execution limits; at most 20 endpoint definitions and 120 requests are
supported. Per-endpoint probes are anonymous, optional primary account and
optional secondary account. DNS resolution has a separate three-second deadline
and four shared resolver slots. Headers have a 64 KiB aggregate budget. Bodies
are streamed up to the configured cap; truncated comparisons are inconclusive.
The lab proxy reuses this transport but rejects a response instead of forwarding
truncated bytes. It retains raw bytes only transiently in memory.

A request already in flight can reach its endpoint before a concurrent revocation
commits. Cancellation closes the active socket and prevents subsequent dispatch;
results are discarded unless the current permission and lease still permit
publication. Network policy is an application boundary, not a container/firewall
replacement; deploy the worker with a restrictive network policy too.

## Results and findings

Persisted observations contain endpoint ordinal/method, HTTP status, bounded byte
count, truncation, HSTS/Content-Type presence, TLS verification and a coarse
primary/secondary bounded-response comparison. They never contain response
bodies, credential headers, cookies, raw request/response headers, raw query data
or response digests. Account equality alone does not create a vulnerability.

A configured protected endpoint returning 2xx anonymously and with the primary
account creates a cautious Medium, Unreviewed/Open candidate. It explicitly
requires an analyst to verify the actual response and expected policy; successful
status codes can be public content or a login page. No result confirms a finding,
proves sensitive data exposure or changes human review state. Source execution,
target, job, engine and endpoint index provide provenance without copying tokens
or raw data. Target configuration and published results have database history
guards; normal API users cannot rewrite them. Downgrade to the earlier schema is
allowed only while the new API/Frida/proxy feature history is empty; populated
history requires a reviewed backup instead of silent deletion. Empty-feature
round trips retain existing runtime sessions, device lease owners, quarantine
flags and expiration times.

## Verification

`pytest tests/test_api_security.py` uses an owned loopback HTTPS fixture with a
fresh temporary certificate and an explicitly configured CA/network. It verifies
actual TLS certificate checks, pinned transport, redirects not followed, body
budgets, a slow HTTP/1.0 response socket closing at the total deadline, reference
secrecy, scope, tenancy, cancellation, lease fencing and migration guards. The
full leased API worker also performs its three real HTTPS anonymous/account
requests against that owned fixture and publishes only safe observations. No test contacts external applications. PostgreSQL execution
uses `DROIDSHIELD_TEST_DATABASE_URL` and isolated schemas when configured.

Verified on 2026-10-28: `tests/test_foundation.py` and
`tests/test_api_security.py` passed together (51 tests) with the owned PostgreSQL
18 test cluster and their isolated schemas, including SQLite migration round
trips and the real local HTTPS transport/worker scenarios described above. This
is baseline/control evidence for those fixtures, not a scan of a client API or a
claim of comprehensive vulnerability coverage.
