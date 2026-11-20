# Security Policy — Security Hardening Checker

## Supported version and reporting
Security fixes apply to the default branch. Report vulnerabilities privately through GitHub's security advisory feature (when enabled) or contact the maintainer privately. Never include production credentials or machine-unique identifiers in public reports.

## Safety requirements
- **Read-only guarantee:** Audits must inspect settings without altering firewall, SSH, users, registry, services, or security policies. Any remediation capability must be a separate, opt-in, reviewed operation.
- **Privilege:** Request administrative access only for checks that require it. Handle missing privileges honestly instead of reporting a false PASS.
- **Data protection:** Audit reports may reveal system configuration, local usernames, ports and weaknesses. Restrict report paths, avoid secret values and sanitize published examples.
- **GRC:** Scores and checks are diagnostic signals, **not** a compliance certification. State coverage and limitations, and compare against relevant standards only when validated.
- **IAM / Cloud:** Evaluate OS account settings and cloud contexts only where supported by the inspected platform; do not create new accounts or require API secrets.
- **AI / OT:** Outside the tool's current scope. Any future automated remediation or industrial-control check requires explicit review and safeguards.

## Release validation
Require ShellCheck, PSScriptAnalyzer and existing tests. Verify expected exit codes, safe paths, unprivileged behavior and no mutations of host configuration.
