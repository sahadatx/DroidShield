# Fixed Frida observation

The `frida_observe` Dynamic scenario launches and instruments only the assessment's
server-processed APK on its exclusively leased, explicitly configured disposable
emulator. It uses a trusted built-in script, not an analyst-supplied script. The
API accepts no Frida source, commands, server address, PID, host path or package
selection. The package comes from the integrity-verified APK and approved scope.

## Coverage and evidence

The native hooks count calls to `open`/`openat` (`filesystem_open`), `connect`
(`socket_connect`) and `getaddrinfo` (`dns_lookup`) while the launched app runs
for the configured one to ten seconds. Hooks are installed before the spawned
process resumes. Startup/framework calls contribute to these counters; they do
not establish sensitive file access, successful network connections or a
vulnerability. Missing native symbols reduce the declared `hooked_apis` coverage.

The result's optional `frida` field contains only the exact Frida version,
observation duration, fixed hook categories and bounded integer counters. No
arguments, return values, strings, paths, URLs, IP addresses, stacks, memory
contents, account data or Frida error text are retained. The original device,
installation and cleanup checks remain present. Evidence is unreviewed and a
successful job moves the assessment to Needs Review.

Java APIs, secondary/child processes, TLS/root/emulator detection bypasses,
application modifications, memory inspection and custom instrumentation are
outside this scenario's coverage. The app may detect or refuse instrumentation.
A failure does not trigger a less isolated fallback or silently claim coverage.

## Administrator prerequisites

Install the optional pinned host dependency with `pip install '.[instrumentation]'`. The
trusted host Python chosen by `DROIDSHIELD_FRIDA_PYTHON` must import exactly
Frida **17.9.10**. Configure an absolute interpreter path. The worker never installs
Frida or downloads/starts a device server.

Provision the matching official Android `frida-server` binary on the **dedicated
DroidShield AVD only**, at the fixed path:

```text
/data/local/tmp/droidshield-frida-server
```

Verify its upstream release and SHA-256 independently, keep it owned/executable
only by guest root (mode `0500` or `0700`; set this explicitly after ADB upload)
and record the binary hash in
`DROIDSHIELD_FRIDA_SERVER_SHA256`. Version selection alone does not authenticate a
binary. Before provisioning, verify that the exact configured emulator serial's
console AVD name equals its dedicated `DroidShield_*` name. Never substitute a
physical device or a developer's existing AVD.

Start the administrator-managed server with these exact arguments:

```text
/data/local/tmp/droidshield-frida-server --listen=unix:/data/local/tmp/droidshield-frida.sock --token=<protected-lab-token>
```

The token is an independently generated random value of 32–128 URL-safe ASCII
characters. Supply the same token through the protected
`DROIDSHIELD_FRIDA_TOKEN` environment setting; do not put it in a workspace form,
source file, client record, report or audit event. Guest process arguments contain
the administrator's token, so root access to this disposable lab remains trusted.
The worker reads those arguments transiently to verify the exact authenticated
server configuration; it never returns them or stores the token in a snapshot.
The guest `/proc` mount must use `hidepid=2`, and the installed APK must have an
ordinary user-0 application UID (10000–19999), excluding root, system, shell,
privileged shared identities and other Android users before launch.
The server's abstract UNIX socket has no filesystem permission boundary, so
**authentication is mandatory**, even with guest IP egress denied.

Settings:

| Environment setting | Behavior |
| --- | --- |
| `DROIDSHIELD_FRIDA_VERSION` | Pinned to `17.9.10` |
| `DROIDSHIELD_FRIDA_SERVER_SHA256` | Required lowercase SHA-256 of provisioned executable |
| `DROIDSHIELD_FRIDA_TOKEN` | Required protected random server authentication token |
| `DROIDSHIELD_FRIDA_PYTHON` | Absolute trusted Python interpreter; defaults to worker interpreter |
| `DROIDSHIELD_FRIDA_OBSERVATION_SECONDS` | Default 3; range 1–10 |

The browser capability flag means these administrator settings are configured;
it is not a readiness claim. A session independently verifies emulator identity,
root availability, exact IPv4/IPv6 DROP-only OUTPUT policies, server executable
root ownership/mode/path/hash/version, `/proc` with `hidepid=2`, running process executable and authenticated UNIX listener
arguments before installing the APK. Device, version, binary, interpreter,
observation settings and a private token fingerprint are pinned in the session's
private configuration snapshot and rechecked during processing/publication.
Rotation invalidates queued/running attempts instead of changing their meaning.

## Isolation and cleanup

ADB allocates a new host loopback TCP forward to the fixed **guest abstract UNIX
socket**, so Frida requires no guest IP firewall exception. Application IPv4 and
IPv6 egress remain denied. The worker neither replaces existing forwards nor
uses `--remove-all`; cleanup verifies and removes only its exact allocated
mapping while it still owns the device lease. It never stops the administrator's
server or instruments another preinstalled package.

The trusted host helper receives the authentication token only over its stdin
pipe, not an argument or environment variable. It uses the packaged fixed script
and a bounded output contract. Its subprocess has CPU, file-descriptor, core-dump
and virtual-address-space limits plus an independent 25-second wall watchdog;
Frida reserves substantial virtual address space, so the virtual-space cap is
8 GiB and is not an expected resident-memory footprint. Output exceeding 4 KiB,
invalid/extra fields and mismatched versions fail the attempt.

Cancellation, authorization expiry/revocation, access loss and worker shutdown
terminate observation, discard unpublished counters and clean only the session's
own installed APK and forward. Failed/uncertain cleanup or crash expiry
quarantines the device. A stale worker may neither clean up nor publish after
losing its device lease. Reprovision with a new opaque device ID after a crash;
never clear quarantine while the old worker or emulator might still be active.

## Verification

`tests/test_frida.py` covers immutable script boundaries, output redaction,
configuration/token pinning, wrong binary/version/process configuration,
preinstalled-package protection, precise forward ownership, cancellation and
actual subprocess time/output boundaries. `tests/test_dynamic.py` covers Frida
worker publication, changed administrator configuration, result substitution,
revocation and continued lease ownership for safe cleanup.

The opt-in real test requires the existing runtime fixture/device variables from
[the dynamic lab runbook](dynamic-lab.md), plus
`DROIDSHIELD_TEST_FRIDA_HASH` and `DROIDSHIELD_TEST_FRIDA_TOKEN` for an explicitly
provisioned running server. It never provisions a server, discovers a device or
starts an emulator:

```sh
pytest 'tests/test_dynamic.py::test_real_disposable_emulator_upload_to_runtime[frida_observe]'
```

Verified on 2026-10-28 using the dedicated `DroidShield_Lab` AVD at
`emulator-5560`, Android 11 / API 30 Google APIs x86_64 image revision 16,
emulator 36.1.9 and official Frida 17.9.10 Android x86_64 binary SHA-256
`b69489c17f9a56c46031c2c40f4823b78126957f46e4a604d3daa6c972ebe703`.
The authenticated complete API upload → authorized Dynamic session → worker →
immutable counter result test passed, with all three native hook categories,
nonzero filesystem counters, live app PID, owned-package cleanup, forward removal
and unchanged guest IPv4/IPv6 DROP policy. This evidence covers that bounded
scenario on this host, not general instrumentation or exploit coverage.
