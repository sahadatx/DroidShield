# Controlled Android runtime testing

Dynamic assessment sessions have a separately started worker and a narrow ADB adapter. A session installs the exact protected APK on an explicitly configured disposable Android emulator, runs one declared bounded observation and removes only its own installation. Results remain subject to analyst review.

| Scenario | Delivered coverage |
| --- | --- |
| `package_inspection` | Installed package inspection without launching the app |
| `launch_observe` | Resolved launcher execution, two-second observation and fixed exception-category counts |
| `frida_observe` | Pinned authenticated Frida server and fixed native API invocation counters; see [Frida controls](frida.md) |
| `proxy_observe` | Bounded HTTPS GET/HEAD observation for exact approved endpoints through a dedicated lab CA/proxy; see [proxy controls](proxy.md) |

The controlled scenarios do not provide arbitrary scripts, shell commands, exploit execution, sensitive-storage inspection, TLS/pinning bypass, login automation or automatic vulnerability confirmation. API assessment execution has a separate target/job/worker workflow; a Dynamic session does not silently run it or a Full assessment.

## Disposable lab requirements

Use a separate unprivileged API/worker account and an administrator-owned disposable AVD. Never configure a personal emulator or a physical device. The adapter requires an explicit `emulator-<port>` serial, an AVD name beginning `DroidShield_`, `ro.kernel.qemu=1`, an exact emulator-console AVD-name match and a completed Android boot. When the image exposes `ro.boot.qemu.avd_name`, it must match too; Android 11 images can omit that property. It never chooses devices from `adb devices`, starts an arbitrary AVD or resets an existing device.

Install Android SDK command-line tools and a non-Play Google APIs/AOSP emulator image supporting `adb root`. Create a **new** dedicated AVD and start it on its assigned port using fixed memory/CPU limits, disabled snapshots and no host shared folders, host account data or credentials. An existing AVD with the same name must be reviewed by the administrator rather than overwritten. Android guest root is used for the disposable firewall and administrator-provisioned Frida service; the host API and worker reject root execution.

Example configuration (the administrator first provisions this exact AVD):

```sh
export DROIDSHIELD_LAB_DEVICES='[{"id":"ds-lab","label":"DroidShield disposable lab","serial":"emulator-5560","avd_name":"DroidShield_Lab","android_version":"11"}]'
export DROIDSHIELD_ADB_EXECUTABLE=/usr/bin/adb
export DROIDSHIELD_DYNAMIC_TIMEOUT_SECONDS=90
export DROIDSHIELD_DYNAMIC_MAX_OUTPUT_BYTES=65536
```

`LAB_DEVICES` defaults to an empty inventory; no device is available until configured. The public capabilities response exposes only each configured device's opaque ID, label and Android version. A client cannot supply a serial, AVD name, ADB command, shell text, credentials or host path through the session API.

Before installation or launch the adapter disables guest Wi-Fi/data and installs **DROP-only IPv4 and IPv6 OUTPUT policies**. It flushes OUTPUT rules and verifies that each complete chain is exactly `-P OUTPUT DROP`. Any inability to establish or verify isolation fails closed before APK execution. The package, launch and Frida scenarios keep that exact DROP-only policy throughout; Frida uses an authenticated abstract UNIX control socket through an owned ADB forward and needs no guest IP exception. The proxy scenario temporarily permits only the installed app UID to reach `127.0.0.1:8081` and root-owned reply packets from that port, verifies the complete expected IPv4 chain and unchanged IPv6 DROP policy, and forwards only explicitly approved HTTPS endpoints through its restricted host proxy. Direct application Internet access stays denied. Cleanup restores exact DROP-only chains and removes only the session's proxy setting and owned ADB reverse mapping. No CA is automatically installed in the Android/system trust store and certificate pinning is not bypassed.

Rules stay restrictive after cleanup. The adapter does not promise security against emulator/kernel exploits; use a hardened disposable VM/host boundary for untrusted customer APKs.

After installation the package UID must be an ordinary user-0 app UID (10000–19999); root, system, shell, privileged shared identities and other users are rejected before any launch/instrumentation. Frida additionally verifies guest `/proc` uses `hidepid=2` to protect its administrator-managed server token from ordinary apps. A pre-existing installed package is never replaced or removed. An exclusive global device lease prevents concurrent DroidShield sessions from sharing an emulator. Administrators must keep other tools and operators from changing that emulator while leased.

## Session API

All paths use `/api/v1`, authenticated current workspace/Project access and server-side roles.

| Method and path | Behavior |
| --- | --- |
| `GET /assessments/{id}/dynamic-sessions` | Paginated scoped sessions |
| `POST /assessments/{id}/dynamic-sessions` | Create one runtime session per assessment job |
| `GET /dynamic-sessions/{id}` | Safe status and sanitized runtime result |
| `POST /dynamic-sessions/{id}/cancel` | Cancel queued/running work |

Create body:

```json
{"revision":2,"device_id":"ds-lab","scenario":"launch_observe","timeout_seconds":90,"notes":null}
```

Select `frida_observe` with the same shape after the administrator configures its pinned authenticated server. The request never contains a Frida token, path, script or PID.

For `proxy_observe`, additionally supply a nonempty `proxy_targets` list, at most ten exact HTTPS URLs without credentials, query strings or fragments. The assessment's `requested_targets` must equal the package target followed by that exact URL list, in order, and each target must be explicitly approved and outside exclusions. Proxy targets are rejected on every other scenario. Example:

```json
{"revision":2,"device_id":"ds-lab","scenario":"proxy_observe","timeout_seconds":90,"proxy_targets":["https://api.example.test/health"]}
```

The mutation requires `Idempotency-Key`. Exact retries return the same session after checking current access; a changed payload/key combination conflicts. Extra fields and malformed package/device identifiers are rejected. Timeout is 10–120 seconds and cannot exceed administrator configuration. The assessment must be **Dynamic**; Full assessments are not silently treated as complete runtime assessments.

A draft/awaiting assessment is queued transactionally using the supplied revision. An already queued assessment uses its current revision and existing job. Active Client/Project, protected artifact package/hash, current verified authorization, exact package scope, exclusions, valid testing window and user access are checked before creation, before claim, throughout execution and before result publication. A runtime session never grants authorization. Changes to device identity, Frida version/binary/token/interpreter/observation settings or proxy CA/trust/egress/budget configuration invalidate pinned session configuration snapshots. Configuration flags alone are not readiness evidence; execution verifies its required device and tool conditions.

Cancel body is `{"reason":"Stop the authorized runtime session"}` with its own idempotency key. Cancellation and authorization revocation stop execution and discard unpublished observations. Device cleanup remains permitted only while that exact session owns its device lease.

Run this worker separately with the same database/storage/lab configuration:

```sh
droidshield dynamic-worker --once
# Or continuously:
droidshield dynamic-worker
```

Queue records never execute APKs on their own. The static worker ignores Dynamic jobs, and this worker ignores Static/API/Full jobs. Success completes the runtime job and moves the assessment to **Needs Review**. Scanner success never marks a finding Confirmed or finishes analyst review.

## Evidence and failure behavior

ADB commands have bounded wall time and cumulative output. Cancellation is checked while commands execute and while waiting for observations; worker processes use their own process groups and terminate outstanding ADB commands when stopped. No general shell or arbitrary instrumentation endpoint exists.

Only fixed check names/statuses, whether a process was observed, bounded counts and a fixed allowlist of Java exception categories are retained by base observation. Frida adds only declared native hook categories and integer counters. Proxy evidence adds only target indexes, GET/HEAD method, HTTP status, negotiated upstream TLS version and bounded byte counts. Exact proxy targets are approved scope records; raw traffic, credential values and endpoint body content never become ordinary evidence. PID-filtered transient logcat output, package dumps, request bodies, user data, credentials and raw Android errors are discarded. The worker never clears global logcat. Responses omit serials, host paths, device configuration, worker fencing tokens, notes and raw logs.

Install/launch failures and cleanup failures cannot publish successful results. Failed lab attempts quarantine their device. Expired worker leases fail safely and quarantine the device; a stale worker cannot publish or clean up after its device lease is lost. There is **no automatic retry or device reuse after a crash**. The administrator must stop the emulator, recreate a fresh disposable AVD and configure a new opaque device ID before more sessions. Do not clear a quarantine flag while an old worker or emulator is running. Existing session history remains retained.

## Verification

`tests/test_dynamic.py` covers transactional creation, strict contracts, access/authorization/configuration rechecks, cancellation/revocation, lease exclusivity, crash quarantine, safe publication and result redaction. `tests/test_lab.py` covers physical/wrong-device refusal, firewall verification, pre-existing package protection, exact-session cleanup, lost leases, malformed shell identifiers, PID-only log handling and actual subprocess output limits. Fault injection uses simulated ADB responses and does not replace real emulator validation.

Record real runtime validation separately with the disposable AVD/image, tested scenarios, cleanup and firewall verification. An installed SDK or passing mocked tests alone does not establish that the host can run a dynamic session.

### Reproduce the real runtime check

Create the lab with Android SDK tools using a **new** name; `avdmanager` is intentionally used without `--force`:

```sh
/home/kali/Android/Sdk/cmdline-tools/latest/bin/avdmanager create avd \
  --name DroidShield_Lab --package 'system-images;android-30;google_apis;x86_64' --device pixel_4
```

Use the SDK path installed on your own host. Some distro emulator installations resolve relative image directories against a different SDK. Set the dedicated AVD's `image.sysdir.1` to the installed image's absolute directory, and set `avd.id`/`avd.name` to `DroidShield_Lab` if the SDK created `<build>` placeholders. Keep those edits confined to the newly created AVD.

```sh
ANDROID_HOME=/home/kali/Android/Sdk ANDROID_SDK_ROOT=/home/kali/Android/Sdk \
  emulator -avd DroidShield_Lab -port 5560 \
  -sysdir /home/kali/Android/Sdk/system-images/android-30/google_apis/x86_64 \
  -no-window -no-audio -no-snapshot -no-boot-anim -memory 2048 -cores 2 \
  -gpu swiftshader_indirect
```

Build the harmless fixture (displays a static text label, has no network permission or account data) into a fresh directory:

```sh
python scripts/build-runtime-smoke.py --directory /tmp/droidshield-runtime-fixture
export DROIDSHIELD_TEST_RUNTIME_APK=/tmp/droidshield-runtime-fixture/smoke.apk
export DROIDSHIELD_TEST_RUNTIME_DEVICE='{"id":"ds-lab","label":"DroidShield disposable lab","serial":"emulator-5560","avd_name":"DroidShield_Lab","android_version":"11"}'
pytest tests/test_dynamic.py::test_real_disposable_emulator_upload_to_runtime
```

The opt-in test requires both variables, and otherwise skips. It never discovers or starts an emulator. It creates only temporary test database/storage records, authenticates through the real API, uploads through the real Bubblewrap parser, queues the authorized session, runs the real ADB worker and verifies sanitized persisted results plus Needs Review status. Without additional Frida variables it covers the original package/launch scenarios and skips Frida. It verifies a live PID for launcher execution and successful own-package cleanup. The authenticated Frida variant additionally requires `DROIDSHIELD_TEST_FRIDA_HASH` and `DROIDSHIELD_TEST_FRIDA_TOKEN` for an already provisioned server; see its [verification details](frida.md). Proxy validation uses the separate HTTPS fixture/runbook and never sends customer traffic to a sample server.

Verified on **2026-10-28** with Android emulator 36.1.9, Android 11 / API 30 Google APIs x86_64 image revision 16 and the fresh `DroidShield_Lab` AVD. Both complete intake-to-worker scenarios passed. Afterward, the emulator console identity, exact IPv4/IPv6 DROP-only OUTPUT policies and absence of `dev.droidshield.smoke` were checked, then only this disposable emulator was stopped. Other AVDs/devices were not used. This evidence establishes those bounded scenarios on that host; it does not imply broader dynamic testing coverage or certify other deployments.


The 0.3 package/launch verification above remains historical. The authenticated fixed-script Frida scenario was subsequently verified on the same dedicated AVD/image and host with its complete real API intake-to-worker test; see [Frida evidence](frida.md). See [proxy verification](proxy.md) for the separately validated exact-target TLS proxy and its Android fixture. These checks do not establish arbitrary runtime coverage.
