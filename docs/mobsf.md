# Protected MobSF adapter

Static assessments can select `engine: "mobsf"` after an administrator provisions
an isolated **MobSF 4.5.3** service. DroidShield performs an actual multipart upload,
static scan and JSON report retrieval through the documented MobSF REST API.
Creating or queueing an assessment does not start it; the separate worker must
claim it and verify current project access, scope and authorization.

## Service boundary and configuration

Set these only in the service administrator's protected environment:

| Setting | Purpose |
| --- | --- |
| `DROIDSHIELD_MOBSF_URL` | Fixed service base URL; HTTPS, or HTTP restricted to loopback |
| `DROIDSHIELD_MOBSF_API_KEY` | Protected service credential; excluded from configuration repr and ordinary responses |
| `DROIDSHIELD_MOBSF_TIMEOUT_SECONDS` | Complete local attempt budget, default 180 seconds, range 10–600 |
| `DROIDSHIELD_MOBSF_MAX_REPORT_BYTES` | Maximum bytes per upload/scan/report response, default 8 MiB |

The endpoint and key never come from an assessment form or APK. URLs with embedded
credentials, query strings or fragments are rejected. The client disables
redirects and environment-derived proxies, requires JSON with identity encoding,
and enforces response-byte and elapsed-time budgets. The APK is streamed from an
already protected artifact using a pinned multipart length, not a caller-selected
remote URL. Local real/effective UID 0 is rejected, as for the local parser.

**Provision the external service as its own execution boundary.** Use a dedicated
non-root container or VM with CPU/memory/process/storage limits, no client API or
database mounts, protected persistent data and an administrator-controlled network.
Block its outbound network access to application endpoints, Internet services and
internal infrastructure. Static MobSF contains optional URL/domain/store lookups;
the adapter does not authorize those lookups. Its only permitted ingress should
be the worker's authenticated service connection. A container on an internal
network with a loopback-only access relay is one tested arrangement. Use a VM or
equivalent host boundary where kernel separation is required.

DroidShield does not launch or sandbox MobSF itself and cannot prove an arbitrary
remote service's deployment settings. Configuring the service asserts that the
administrator has supplied this isolation boundary; no local unrestricted parser
or command-line fallback exists. Keep its reports, APK cache, credentials and
service logs access-controlled. Upstream MobSF can print its API credential in
startup logs, so these are sensitive operational files.

Install the expected tools before starting the service and disabling egress.
MobSF 4.5.3 expects JADX **1.5.0** and snapshots executable/JAR integrity at startup;
adding or replacing tools afterward can correctly produce `Tampering Detected`.
Do not disable that check to make a scan pass. Use the
[official JADX 1.5.0 release](https://github.com/skylot/jadx/releases/tag/v1.5.0),
verify the trusted package and start a fresh service after provisioning tools.
Missing or failing tools produce an explicit
incomplete result, rather than a clean-analysis claim. Manage upgrades and cached
results administratively; this adapter accepts only the tested 4.5.3 report shape.

## Real request and identity checks

The worker makes exactly these fixed-path requests with the protected service key
in the `Authorization` header:

1. `POST /api/v1/upload`, multipart `file` with a fixed `application.apk` filename.
2. `POST /api/v1/scan`, with the locally derived MD5 `hash`.
3. `POST /api/v1/report_json`, with the same `hash`.

MD5 here is only the upstream API's lookup key. DroidShield still binds artifacts
and findings to SHA-256. Upload response hash/type/analyzer must match; both scan
and report must match the exact local MD5, SHA-256 and sandbox-derived package ID.
No service-provided filename, package replacement, arbitrary URL or source path is
trusted. The original allowlisted local manifest metadata remains the result's
metadata. HTTP/authentication/shape/identity failures fail the attempt with safe
generic messages; upstream error bodies and credentials are not returned or logged.

The adapter omits `re_scan`: on 4.5.3, requesting a rescan before an existing saved
analysis can return scan data without creating a retrievable JSON report. An
existing report can be reused only after all identity checks pass. Tool/settings
changes and cache invalidation belong to the isolated service administrator.

## Cancellation and publication

The local deadline independently cancels HTTP I/O, including while an authorization
callback waits on a database lock. Regular callback checks close in-flight I/O on
cancellation or revocation. The worker still fences every publication with current
authorization, access, lease ownership and artifact identity checks.

MobSF 4.5.3's synchronous REST scan has no supported remote kill operation.
Disconnecting prevents DroidShield from publishing that attempt but **does not
guarantee the remote static process stops**. Bound the service's own job/container
runtime and use administrator supervision or per-attempt disposable services when
immediate termination is required. This adapter does not claim remote cancellation
or start runtime/device/application execution.

## Sanitized result contract

`MobSFAnalysisResult` and `validate_mobsf_result` enforce schema version **3** and
engine `droidshield-mobsf-1`. The output contains the APK SHA-256/size, local
`ManifestMetadata`, exact limitation statements, up to six fixed candidates and
`mobsf_summary`:

- `service_version`: `4.5.3`;
- `manifest_findings`, `code_findings`, `certificate_findings`, `binary_findings`;
- `secret_candidates`;
- `tool_error_count` and `analysis_complete`.

Each nonempty category produces one aggregate candidate at the highest reported
severity. Good/secure observations are excluded. Evidence contains only the fixed
source category, `scanner_candidates` and a bounded reported count. Tool errors
produce an informational `MOBSF_INCOMPLETE_ANALYSIS` candidate and
`analysis_complete: false`. Candidate counts describe service observations, not
confirmed vulnerabilities; zero counts never prove an APK secure.

**Raw MobSF descriptions, rule names, class/source paths, line excerpts, URLs,
tokens, private keys and other secret literals are withheld.** The normalizer
does not store the raw service JSON. Review detailed evidence only within the
authorized protected service environment. Imported candidates remain Unreviewed
and Open, and successful assessment processing moves to Needs Review.

## Verification

Run `pytest tests/test_mobsf.py` for mocked protocol/security checks. These cover
identity mismatches at every stage, unknown report shapes/version/severity,
redirects, errors, response type/compression/byte limits, duplicate JSON keys,
unsafe configuration and file paths, cancellation/deadlines, secret redaction,
tool-failure visibility and strict normalized-output validation.

Two optional tests use a real isolated service when
`DROIDSHIELD_MOBSF_TEST_URL` and protected `DROIDSHIELD_MOBSF_TEST_KEY` are set.
They exercise real upload/scan/report retrieval and the complete protected APK
upload → authorized queue → separate worker → scoped schema-3 analysis/findings
API. Keep that service restricted to test artifacts and remove its data and
credentials after QA. The task's QA service used an internal Docker network and
a temporary loopback-only relay; neither is a production deployment.

Upstream protocol references:
[MobSF 4.5.3 API](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/v4.5.3/mobsf/MobSF/views/api/api_static_analysis.py)
and [Android result structure](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/v4.5.3/mobsf/StaticAnalyzer/views/android/db_interaction.py).
