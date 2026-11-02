# Delivering Android and iOS mobile penetration tests

DroidShield 0.5 combines bounded automated Android checks with an analyst-led
engagement workflow. A tester can manage authorized Android/iOS engagements,
retain exact build identities, record manual procedures and sanitized evidence,
independently review findings, release a client report and review a retest.
External testing tools and specialist devices remain part of the tester's lab.
Recording a tool name never means that DroidShield ran or verified that tool.
The supplied service descriptions are mapped one by one in the
[gig capability review](gig-capability-review.md).

## Service coverage

| Service | Implemented support | Work the tester supplies |
| --- | --- | --- |
| Android APK static testing | Protected APK intake; isolated manifest/DEX engines; administrator-configured MobSF adapter; normalized unreviewed indicators; sanitized text and protected PNG evidence | Context, source review, actual library versions/advisories, exploitability and evidence review |
| AAB static testing | Protected AAB intake; bounded base-module protobuf manifest identity/configuration; exact SHA-256 | Generate the appropriate APKs in the approved build lab for automated Android execution; record split/module and source review coverage |
| iOS IPA static testing | Protected IPA intake; bounded binary/XML Info.plist identity, build/OS labels, ATS flag, URL-scheme count, main-executable/signature-directory presence | Decompilation, entitlement/signature validity, Mach-O protections, secrets, libraries and source review with approved external tools |
| Android runtime | Dedicated disposable emulator; package/launch, pinned fixed Frida counters and restricted HTTPS interception | Rooted physical-device coverage, Objection/Burp workflows, complete runtime instrumentation and interpretation |
| iOS runtime | Platform-specific manual engagement, tool/device/version provenance, protected evidence and coverage | Authorized iOS device/macOS lab, jailbreak setup where appropriate, Frida/Objection/Burp execution |
| Local storage | Android/iOS procedure for Keychain/Keystore, SQLite, preferences/plist, files, caches, logs, backups and incidental disclosure | Device inspection with synthetic data and verified protection/access observations |
| Authentication/session | Procedures for biometrics, recovery, tokens, JWT, OAuth/SSO and logout/revocation | Controlled account-specific test execution and proof of expected behavior |
| Backend APIs | Exact authorized HTTPS GET/HEAD baseline and two-account comparison worker; manual BOLA/IDOR, role and business-logic cases | Ownership/role assertions and operation-specific controlled tests; comparison results do not establish BOLA |
| Platform boundaries | Manifest indicators plus Android/iOS deep-link, intent/IPC and WebView procedures | Controlled exploitability checks on the approved platform/build |
| Anti-tampering | Root/jailbreak, debugging, integrity and repackaging procedures with artifact provenance | Threat-model-specific external lab tests; counters alone do not establish resilience |
| Secure code/dependency review | Versioned manual coverage, narratives, reviewed findings and protected text/PNG evidence can document supplied source and inventories | Actual supplied repository/build context, dependency versions and authoritative affected-version analysis; the app does not clone repositories or run a SAST/SCA engine |
| Executive/technical reporting | Frozen versioned snapshots; confirmed findings; CVSS 4.0/3.1 base-vector scoring; coverage, scope, limitations, remediation priorities, reviewed retests and tool versions; PDF/JSON exports | Client-specific executive interpretation, limitations and an independent administrator's approval |
| Retesting | Original/new build comparison, evidence links, operator and independent reviewer; reviewed Pass can mark Fixed | New artifact and controlled test environment; developer assertions cannot close a finding |

Framework names such as Kotlin, Flutter, React Native, Kony or Volt MX describe
application technology, not guaranteed inspection coverage. Packed/encrypted
code, native libraries, cross-platform runtime internals and unavailable source
must be stated in the engagement's limitations. IPA intake does not decrypt an
App Store binary, and a signature directory does not establish signature validity.

## Operational sequence

1. Create the Client and Project; choose Android or iOS. Use the Android package
   identity or iOS bundle identity in `package_id`. Create an assessment with exact
   `package:com.example.app`, `bundle:com.example.app` and/or HTTPS target scope.
2. Upload the authorized APK/AAB/IPA to the draft assessment. The backend hashes
   actual bytes and inspects the archive in a resource-limited, network-isolated
   worker. The new `/artifact` endpoint accepts all three formats; `/apk` retains
   its original APK-only contract. Uploaded declarations never replace detected
   identity. Uploading does not authorize testing.
3. Link an independently verified authorization with the approved targets,
   exclusions and validity window. Select an existing automated Android path or
   start a manual engagement with the platform, environment, tool versions and
   limitations. Manual mode records external analyst work; it launches no tools.
4. Record coverage for the version-pinned test library. Untouched tests remain
   Not Run. Pass/Fail require evidence; Fail also links findings. N/A and Blocked
   require a reason. Evidence is bounded sanitized text in private storage with
   hash, exact build, source tool/version, environment, operator and timestamp.
   Redaction is best effort: analysts must remove sensitive client data before
   submitting it. Do not paste live tokens or production personal data.
5. Create/edit findings with reproduction steps, impact, remediation, mappings
   and validated CVSS vectors. An independent administrator reviews confirmation;
   a scanner's severity cannot confirm its own result. Fixed is unavailable as a
   direct finding edit.
6. Submit the engagement summary and complete independent assessment review.
   Generate a report snapshot, review its scope/coverage/limitations, approve it
   with a different administrator, then export PDF and/or JSON. Exported bytes,
   checksums and immutable versions remain tied to that client's project.
7. For a mobile-build fix, upload the fixed artifact to a new draft assessment
   in the same project, then record evidence naming that different immutable
   build. For an API-only finding without an app artifact, pin one exact original
   `release_ref` on evidence before confirming the original finding; retesting
   requires that original reference and a distinct new reference matching new
   proof captured after assessment completion. These are analyst-declared release
   identifiers, not verified deployment fingerprints or invented APK hashes.
   Create the retest under a current verified authorization covering its evidence
   timestamps and obtain independent review. An approved Pass alone sets Fixed;
   Fail reopens; Inconclusive/Not Reproducible remain Retest Required. Generate a
   new report version to include the reviewed outcome. See the detailed
   [analyst workflow](analyst-workflow.md) for fields, provenance and review gates.

## Standards and client-facing claims

The library pins MASVS **2.1.0**, OWASP Mobile Top 10 **2024**, and NIST SP 800-115
**September 2008** references. DroidShield procedures are locally authored and
mapped to those sources; they are not a verbatim copy of the full MASTG catalog.
Coverage is evidence-based and bounded by the selected engagement. Historical
test execution and report snapshots retain their reference versions.

These deliverables can support a customer's audit evidence. A mobile pentest
alone does not certify SOC 2, ISO 27001, HIPAA, PCI DSS or Google Play compliance,
nor guarantee store acceptance, exhaustive vulnerability discovery or zero false
positives. Do not claim tester experience, certification, client history or an
unsupported daily-hack statistic on the basis of this software.

Primary references:

- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/)
- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)
- [FIRST CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document)
- [Android App Bundle format](https://developer.android.com/guide/app-bundle/app-bundle-format)
- [AOSP protobuf XML schema](https://github.com/aosp-mirror/platform_frameworks_base/blob/master/tools/aapt2/Resources.proto)
- [Apple bundle information keys](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CoreFoundationKeys.html)

## Runtime requirements

Use separate analyst and reviewer accounts. Browser access uses the email/password
sign-in and persistent HttpOnly session; tokens remain for programmatic API clients.
Keep protected artifact, evidence and report storage
outside public web roots and back it up together with the database. The existing
Frida, proxy, API-worker and emulator runbooks retain their execution restrictions.
An inactive engine/device flag is not a readiness check, and external lab access
is not supplied by a browser checkbox.
