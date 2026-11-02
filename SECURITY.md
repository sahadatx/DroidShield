# Security policy

DroidShield handles mobile application artifacts, authorization records,
security findings, evidence, and reports. Please handle vulnerability reports
privately and avoid exposing customer data or exploit material.

## Supported code

Security fixes are evaluated against the latest code on the default branch.
Older snapshots may not receive fixes. Report the affected commit or release
when known.

## Reporting a vulnerability

Do not open a public issue or pull request containing an unpatched vulnerability,
credentials, exploit code, customer information, or sensitive evidence.

Use GitHub's private vulnerability reporting channel for this repository if it
is enabled. If it is unavailable, contact the repository owner privately through
their GitHub profile and ask for a secure channel before sending technical
details. Please do not send secrets or customer artifacts in an initial message.

Include, when safe to do so:

- The affected commit, release, component, and configuration.
- A concise description of the security impact and realistic attack
  prerequisites.
- Minimal reproduction steps using synthetic data and an authorized environment.
- Sanitized logs or screenshots with tokens, personal data, host paths, and
  customer identifiers removed.
- Any suggested mitigation, without requiring maintainers to run code against
  third-party systems.

The maintainers will acknowledge reports when practical, investigate them, and
coordinate any fix and disclosure with the reporter. No response-time or fix-time
guarantee is made. Please allow time for coordinated remediation before public
disclosure.

## Safe testing boundaries

Only assess systems, applications, APIs, emulators, and data for which you have
explicit authorization. Do not use DroidShield or a report of its behavior to
test a third-party target without that authorization. Do not submit real client
artifacts, live credentials, or unredacted traffic to a vulnerability report.

DroidShield has intentionally limited execution surfaces. Static analysis,
the configured Android lab, exact-scope API requests, and analyst-entered
engagement records have distinct limits documented in `docs/`. A configured
feature flag or scanner response does not establish that an external service is
secure, a test is complete, or a finding is confirmed.

If credentials or sensitive material are accidentally committed or disclosed,
revoke or rotate them immediately and report the exposure privately. Removing a
value from the current branch does not remove it from Git history.
