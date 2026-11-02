"""Version-pinned analyst procedures; these records never execute tools."""

from copy import deepcopy

FRAMEWORKS = [
    {
        "id": "MASVS",
        "version": "2.1.0",
        "url": "https://mas.owasp.org/MASVS/",
        "purpose": "Mobile security controls; coverage is recorded per test, never inferred from scanner success.",
    },
    {
        "id": "MOBILE-TOP-10",
        "version": "2024",
        "url": "https://owasp.org/www-project-mobile-top-10/",
        "purpose": "Risk classification, not certification or an exhaustive test plan.",
    },
    {
        "id": "NIST-SP-800-115",
        "version": "2008-09",
        "url": "https://csrc.nist.gov/pubs/sp/800/115/final",
        "purpose": "Planning, execution and post-execution reporting guidance.",
    },
]

_CASES = [
    (
        "DS-STATIC-01",
        "Secrets and credential handling",
        "static",
        ["MASVS-STORAGE-1", "MASVS-AUTH-1"],
        "M1",
        "Review application resources and decompiled code for embedded credentials. Verify reachability, privilege and exposure using authorized test accounts; keep actual credential values out of evidence.",
        "No reusable privileged credential is embedded; sensitive configuration has an appropriate trust boundary.",
    ),
    (
        "DS-STATIC-02",
        "Cryptography and key lifecycle",
        "cryptography",
        ["MASVS-CRYPTO-1", "MASVS-CRYPTO-2"],
        "M10",
        "Review algorithms, modes, randomness, key generation, rotation and deletion. Check Android Keystore or iOS Keychain/access-control use against the app threat model.",
        "Standard cryptography and protected key lifecycle meet documented requirements.",
    ),
    (
        "DS-STATIC-03",
        "Dependencies and source review",
        "supply_chain",
        ["MASVS-CODE-1", "MASVS-CODE-3"],
        "M2",
        "Review a supplied dependency inventory and source where available. Verify identified library versions against authoritative advisories; record unsupported or unavailable source and dependency inventory as limitations.",
        "Supported components and verified affected-version analysis; missing source is explicitly a coverage limitation.",
    ),
    (
        "DS-STORAGE-01",
        "Sensitive local storage",
        "storage",
        ["MASVS-STORAGE-1", "MASVS-STORAGE-2"],
        "M9",
        "Inspect authorized test data in SQLite, preferences/plist, files, Keychain/Keystore references, cache, logs, backups and screenshots. Record protection classes and access boundaries without exporting real user data.",
        "Sensitive data is minimized and protected at rest, in backups and in incidental application output.",
    ),
    (
        "DS-AUTH-01",
        "Authentication, biometrics and account recovery",
        "authentication",
        ["MASVS-AUTH-1", "MASVS-AUTH-2", "MASVS-AUTH-3"],
        "M3",
        "Exercise login, logout, account recovery and biometric step-up with approved accounts. Verify local biometric UI cannot replace server authorization and sensitive operations require the documented authentication strength.",
        "Server-side authentication and step-up checks protect the intended operations.",
    ),
    (
        "DS-AUTH-02",
        "Token, JWT and OAuth/SSO lifecycle",
        "session",
        ["MASVS-AUTH-1"],
        "M3",
        "Review token storage, expiry, refresh, rotation, revocation and logout; verify JWT validation and OAuth/SSO redirect/state/PKCE behavior with allowed accounts and approved endpoints.",
        "Tokens and redirects are scoped, validated and invalidated according to the intended session model.",
    ),
    (
        "DS-NETWORK-01",
        "Transport security and pinning assessment",
        "network",
        ["MASVS-NETWORK-1", "MASVS-NETWORK-2"],
        "M5",
        "Review endpoint TLS and application trust settings. Observe traffic only in the authorized lab using an explicitly trusted test certificate; record whether pinning could be assessed. An interception failure alone does not prove pinning.",
        "Sensitive communications use validated TLS and app trust behavior matches documented risk requirements.",
    ),
    (
        "DS-API-01",
        "Object and function authorization (BOLA/IDOR)",
        "api_authorization",
        ["MASVS-AUTH-1"],
        "M3",
        "Use two explicitly approved accounts and owned test objects to compare read/write authorization at approved endpoints. Independently confirm object ownership, expected access and business impact; equal responses alone are not a BOLA finding.",
        "Object and function access is enforced server-side for every permitted test operation.",
    ),
    (
        "DS-API-02",
        "API authentication and input/output validation",
        "api_validation",
        ["MASVS-AUTH-1", "MASVS-CODE-4"],
        "M4",
        "Review authentication enforcement, schema validation, error handling, rate controls and output filtering. Record controlled manual tests for operations outside the application's restricted automated GET/HEAD engine.",
        "Requests and responses meet their documented contract and enforce authentication and data minimization.",
    ),
    (
        "DS-API-03",
        "Business logic and transaction integrity",
        "business_logic",
        ["MASVS-AUTH-3"],
        "M3",
        "Map approved business workflows, roles and transaction invariants. With the client's explicit operation-specific permission and synthetic data, review sequence, replay, pricing, limits and concurrency assumptions. Record tests that could not be safely executed.",
        "Critical workflow invariants are enforced by the backend; untested business operations remain explicit limitations.",
    ),
    (
        "DS-PLATFORM-01",
        "Deep links and inter-application communication",
        "platform",
        ["MASVS-PLATFORM-1"],
        "M8",
        "Inspect Android exported components, intents/content providers and iOS URL schemes/universal links/app groups. Verify input handling and caller access boundaries using owned test data and devices.",
        "Untrusted cross-application input and deep links cannot access privileged data or actions.",
    ),
    (
        "DS-PLATFORM-02",
        "WebView and embedded browser boundaries",
        "platform",
        ["MASVS-PLATFORM-2"],
        "M4",
        "Review WebView navigation, JavaScript bridges, origin restrictions, file access and untrusted content. Inspect Android WebView or iOS WKWebView configuration and exercise only approved in-app routes.",
        "Untrusted browser content cannot cross native-app or privileged-origin boundaries.",
    ),
    (
        "DS-PLATFORM-03",
        "Runtime permissions and privacy",
        "privacy",
        ["MASVS-PLATFORM-3", "MASVS-PRIVACY-1", "MASVS-PRIVACY-2"],
        "M6",
        "Review permissions, tracking/analytics behavior, consent, data collection and lifecycle restrictions against the supplied requirements. Record the legal or policy review boundary; a technical test does not certify privacy compliance.",
        "Permissions and personal data collection are limited to documented functionality and requirements.",
    ),
    (
        "DS-RESILIENCE-01",
        "Root/jailbreak and instrumentation resilience",
        "resilience",
        ["MASVS-RESILIENCE-1", "MASVS-RESILIENCE-4"],
        "M7",
        "Record behavior on the client's dedicated rooted Android or jailbroken iOS lab and compare the expected threat model. Document tool/device versions and observations; resilience checks never replace server controls.",
        "Observed root/jailbreak and instrumentation behavior is assessed against the app's explicit resilience requirements.",
    ),
    (
        "DS-RESILIENCE-02",
        "Anti-debugging, signing and repackaging",
        "resilience",
        ["MASVS-RESILIENCE-2", "MASVS-RESILIENCE-3"],
        "M7",
        "Review binary protections, signing configuration, anti-debugging behavior and integrity verification using a client-approved test build. Record source/signing limitations and preserve the exact artifact digest.",
        "Binary and runtime integrity protections match documented resilience requirements; observations retain exact build provenance.",
    ),
    (
        "DS-UPDATE-01",
        "Application updates and code quality",
        "supply_chain",
        ["MASVS-CODE-2"],
        "M2",
        "Review the supported app update mechanism, supported platform versions and update enforcement for security-critical fixes. Record build provenance, release-channel assumptions and whether source/build pipelines were available for review.",
        "Security-critical fixes can reach supported users through a protected, documented update path.",
    ),
    (
        "DS-PRIVACY-01",
        "Privacy transparency, consent and user data control",
        "privacy",
        ["MASVS-PRIVACY-3", "MASVS-PRIVACY-4"],
        "M6",
        "Compare actual application data flows with supplied disclosures and in-app choices. Test consent withdrawal, permissions changes and available user controls using synthetic data. Record unavailable privacy/legal policy review as a limitation.",
        "Users receive clear data-flow information and the documented controls over their data work as specified.",
    ),
    (
        "DS-DELIVERY-01",
        "Engagement, limitations and remediation review",
        "delivery",
        [],
        "M8",
        "Review authorization, approved targets, exclusions, execution evidence, finding verification, remediation priorities and retest eligibility. Confirm untested controls and third-party dependencies are explicitly listed before client release.",
        "The reviewed deliverable clearly separates confirmed findings, tested controls, untested areas and engagement limitations.",
    ),
]


def library():
    cases = []
    for case_id, title, category, controls, top10, procedure, expected in _CASES:
        cases.append(
            {
                "id": case_id,
                "title": title,
                "category": category,
                "platforms": ["android", "ios"],
                "objective": title,
                "procedure": procedure,
                "expected_result": expected,
                "references": [
                    {
                        "framework": "MASVS",
                        "version": "2.1.0",
                        "id": control,
                        "url": "https://mas.owasp.org/MASVS/",
                    }
                    for control in controls
                ]
                + [
                    {
                        "framework": "MOBILE-TOP-10",
                        "version": "2024",
                        "id": top10,
                        "url": "https://owasp.org/www-project-mobile-top-10/",
                    },
                    {
                        "framework": "NIST-SP-800-115",
                        "version": "2008-09",
                        "id": "assessment-methodology",
                        "url": "https://csrc.nist.gov/pubs/sp/800/115/final",
                    },
                ],
            }
        )
    return {"frameworks": deepcopy(FRAMEWORKS), "cases": cases}


def test_case(case_id):
    return next((case for case in library()["cases"] if case["id"] == case_id), None)
