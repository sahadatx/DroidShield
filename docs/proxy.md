# Controlled HTTPS proxy observation

Version 0.4 adds `proxy_observe` to Dynamic sessions. A short-lived loopback
HTTP/1 CONNECT proxy terminates the application's TLS using a dedicated lab CA,
then makes a separately verified, IP-pinned HTTPS request to the exact approved
endpoint. It accepts GET and HEAD only. This proxy is implemented using Python's
standard TLS/HTTP transport and cryptography; no general-purpose tunnel or
arbitrary addon/script endpoint is exposed.

## Provisioning

Create a CA in a **new** private directory with trusted local administration:

```sh
droidshield init-proxy-ca --directory /absolute/private/droidshield-lab-ca
export DROIDSHIELD_PROXY_CA_CERT=/absolute/private/droidshield-lab-ca/cert.pem
export DROIDSHIELD_PROXY_CA_KEY=/absolute/private/droidshield-lab-ca/key.pem
export DROIDSHIELD_PROXY_OBSERVATION_SECONDS=5
export DROIDSHIELD_PROXY_MAX_REQUESTS=20
```

The command refuses existing directories and does not install trust anywhere.
Private keys must be owner-only regular files. Symlinks, mismatched/expired CAs
and non-CA certificates fail closed. Configuration snapshots include public CA
fingerprints and safe bounds; private paths and keys are withheld from GET/UI.

Provide a dedicated authorized debug build that uses the proxy and trusts this
CA. The worker never changes an application's trust manager, disables hostname
verification, bypasses certificate pinning or installs a global system CA.
Applications that ignore proxies or do not trust the lab CA may produce no
traffic or a TLS failure. Neither means that the application is secure.

Upstream TLS uses the normal system trust store. An administrator may provide
`DROIDSHIELD_API_CA_BUNDLE` for a private lab CA; certificate/hostname verification
remains mandatory. Public upstream IPs are accepted by default; private lab
addresses need explicit `DROIDSHIELD_API_ALLOWED_NETWORKS` CIDRs. Metadata,
link-local, multicast and unspecified addresses remain forbidden. DNS resolution
is bounded and rejects mixed public/private answers, and each socket pins the
validated resolved IP. Redirects, environment proxies and unapproved paths are
never followed. See [API testing](api-security.md) for the shared transport limits.

## Scope and session creation

Create a Dynamic assessment whose requested targets are the exact package target
first, followed by up to ten exact HTTPS URLs. Every URL and the package must be
explicitly approved by the linked current verified authorization. Parent-path
exclusions are enforced. Wildcards, query strings, fragments, encoded/relative
paths and arbitrary destinations are rejected.

Example authorized test scope:

```json
["package:com.example.app", "https://api.example.test/profile"]
```

Create a session with the current assessment revision and an idempotency key:

```json
{
  "revision": 3,
  "device_id": "dedicated-lab",
  "scenario": "proxy_observe",
  "proxy_targets": ["https://api.example.test/profile"],
  "timeout_seconds": 90
}
```

Run `droidshield dynamic-worker` separately. The worker rechecks authorization,
scope, user/project access, immutable APK hash, device lease and configuration
before execution, while forwarding and before publication. Credentials are never
accepted through proxy configuration forms. App-provided headers are transient,
sent only to an approved endpoint and never stored as evidence.

## Device and cleanup boundary

All [disposable lab requirements](dynamic-lab.md) apply. The worker first verifies
guest IPv4/IPv6 deny-all egress and an ordinary app UID. It refuses a pre-existing
installed package, global proxy or ADB reverse on its reserved guest port.

Only the owned app UID may reach `127.0.0.1:8081`; only root ADB reply traffic from
that port is additionally permitted. IPv6 and every external guest destination
remain denied. An exact ADB reverse connects that guest loopback port to the
worker's ephemeral host-loopback listener. The global lab proxy setting is
temporary. The upstream broker, rather than the guest APK, controls approved
HTTPS egress. Operators must not share or modify a leased emulator.

Cleanup independently attempts deny-all restoration, global setting removal,
exact owned reverse removal, listener/socket shutdown and owned APK removal.
Every device mutation re-proves lease ownership. Failed or uncertain cleanup
quarantines the device; no automatic retry/reuse is permitted. Reprovision a new
disposable AVD and opaque device ID after a crash. Host callbacks are serialized
per attempt, and I/O has independent deadlines. No local HTTP parser can certify
safety against host, emulator or kernel vulnerabilities.

## Results and limits

`result_json.traffic` uses the strict `droidshield-proxy-1` contract. It contains
forwarded/blocked/TLS-failure counts, response-byte totals and bounded observations
with original target index, GET/HEAD method, status, verified TLS version and byte
count. Target URLs are the previously configured allowlist, not captured traffic.
Raw headers, request/response bodies, cookies, token values, TLS keys and arbitrary
error messages are not persisted. Ordinary GET/UI evidence cannot replay secrets.

The observation window is 1–15 seconds, default 5, after the initial launcher
observation; the overall session deadline remains authoritative. Up to 60
requests can be configured, default 20, at at most four forwards per second.
Headers and bodies have bounded budgets, malformed/duplicate framing is rejected,
and a response over the body limit is refused rather than forwarded truncated.
HTTP/2, HTTP/3, WebSocket upgrades, request bodies, mutation verbs, interception
of arbitrary background endpoints and active exploit traffic are outside scope.
No observations are promoted automatically to confirmed vulnerabilities.

## Verification

`pytest tests/test_proxy.py` exercises real local CONNECT/TLS forwarding,
scope/method/framing rejection, redirect refusal, secret redaction, CA/key
validation, socket deadlines and independent cleanup faults.

The opt-in complete Android test requires an explicitly provisioned disposable
device, Android build tools and no client application:

```sh
export DROIDSHIELD_TEST_RUNTIME_DEVICE='{"id":"dedicated-lab","label":"DroidShield lab","serial":"emulator-5562","avd_name":"DroidShield_Network","android_version":"11"}'
pytest tests/test_proxy.py::test_real_android_proxy_through_protected_worker_opt_in
```

It starts a local HTTPS fixture, creates a private temporary CA and builds a
harmless test APK with app-local CA trust using `scripts/build-proxy-smoke.py`.
It then exercises authenticated protected upload, verified scope, session creation,
real proxy worker execution, sanitized persisted traffic and cleanup. It does
not discover/start a device, modify system trust or contact third-party targets.
