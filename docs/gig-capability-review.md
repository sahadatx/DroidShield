# Mobile security service capability review

This review maps the service descriptions supplied for the DroidShield workspace
to implemented analyst and delivery workflows. Repeated advertising copy is
grouped by the service promise it adds; capability claims describe the product,
not an individual tester's experience, certifications, client history, or
guaranteed outcomes.

| Gig / promise | DroidShield support | Boundary or gap |
| --- | --- | --- |
| 01 · Android pre-launch APK security audit | Protected APK intake, isolated manifest/DEX analysis, optional administrator-configured MobSF, versioned manual checks, findings review, remediation, report export, retest, and protected PNG evidence | Scanner candidates require human verification. External test account, exploitability and library/advisory review remain analyst work. |
| 02 · Full Android and iOS mobile pentest | Projects bind platform and exact app identity; manual assessments record authorization, environment, tools, coverage, findings, evidence and review for both platforms | iOS runtime and specialist rooted/jailbroken devices are analyst-lab work. DroidShield does not orchestrate a full automated pentest. |
| 03 · Vulnerability assessment, penetration testing, reporting and revalidation | Findings keep severity separate from verification; independent review gates Confirmed; reviewed reports freeze scope and evidence; a separately reviewed retest controls Fixed | “Find every issue,” “zero false positives,” and guaranteed breach claims are not product behavior and must not be promised. |
| 04 · Google Play or launch readiness | Android manifest, permissions, network configuration, storage, privacy and resilience checks are present in analysis or the manual procedure library | A security assessment is not Google Play policy approval, store acceptance, or certification. |
| 05 · MASVS / Mobile Top 10 / NIST-aligned assessment | Versioned test procedures map to pinned framework references; coverage preserves Pass, Fail, N/A, Blocked and Not Run; report snapshots retain mappings and limitations | The local procedure library is not an exhaustive MASTG catalog. Coverage is bounded by the authorized engagement. |
| 06 · Kotlin, Flutter, React Native, Kony, Volt MX and other app frameworks | Platform identity, binary metadata, manual source/dependency-review procedures, findings and evidence can document analyst work across frameworks | The product does not clone repositories, ingest source archives, or run a general SAST/SCA engine. Unsupported source or dependency access must be recorded as a limitation. |
| 07 · Local storage, encryption, authentication, sessions, APIs and business logic | Android/iOS manual coverage includes Keychain/Keystore, SQLite/preferences/plist, logs/cache, crypto, biometrics, OAuth/JWT, API authorization, BOLA/IDOR, input/output and business logic; exact-scope API workers provide bounded GET/HEAD comparisons | Protected test accounts and operation-specific authorization are required. The automated API worker does not fuzz, mutate data, execute arbitrary requests or establish BOLA by response similarity alone. |
| 08 · Deep links, WebView, IPC, permissions and anti-tampering | Versioned manual procedures cover platform boundaries, exported components, privacy and resilience; APK/IPA metadata and bounded Android runtime observations supplement them | Exploitability is analyst-verified. Fixed Frida counters are limited; custom scripts, pinning bypass, Objection/Burp orchestration and iOS runtime automation are not provided. |
| 09 · Screenshots, proof and reproducible findings | Analysts can upload sanitized PNG screenshots up to 8 MiB alongside protected text evidence. Both carry an integrity digest and remain linked to assessment/build/finding provenance; approved technical/combined PDFs can embed bounded, metadata-stripped copies | Executive PDFs omit screenshots. Source screenshots remain protected attachments; video, arbitrary tool-output imports and other image formats are not accepted. |
| 10 · Executive/technical deliverables and remediation | Reviewed PDF/JSON snapshots include scope, limitations, confirmed findings, CVSS v4.0/v3.1, coverage, remediation priorities, tool provenance and reviewed retests | Report creation requires independent approval. Deliverables support audit evidence; they do not certify SOC 2, ISO 27001, HIPAA, PCI DSS or store compliance. |
| 11 · Experience, certifications, industry track record and sales claims | DroidShield supports client, project, authorization and assessment records for fintech, healthcare, crypto/Web3 and enterprise engagements | The software cannot establish a tester's years of experience, OSCP or other certifications, number of projects, breach rate, or client references. Those claims must be independently true and supplied by the service provider. |

## Workflow used to deliver a service

1. Record the client and application project, approved targets/exclusions,
   authorization evidence and validity window.
2. Create the platform-appropriate assessment and upload its authorized APK,
   AAB or IPA. The server records the digest; automated static engines execute
   only on APKs.
3. Use bounded workers where configured and the separate authorized analyst lab
   for manual iOS, rooted/jailbroken-device, source-review, business-logic and
   specialist-tool work. Record exact coverage and limitations rather than
   implying that an external tool ran inside DroidShield.
4. Attach sanitized text/PNG evidence, write findings with reproducible steps,
   then obtain independent verification and assessment review.
5. Freeze the client report, obtain a different administrator's approval, export
   PDF/JSON and use the report template's reviewed screenshot-inclusion choices.
6. Retest a distinct authorized build or API release; preserve new evidence and
   require an independent decision before marking a finding Fixed.

The report and workflow allow a tester to deliver these scoped services with
traceable records. They do not replace authorization, analyst judgment, specialist
devices, client account setup, source access, or independent review.
