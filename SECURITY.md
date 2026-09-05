# Security Policy

## Supported versions

Before the first stable release, security fixes are applied only to the latest
code on the default branch and, when one exists, the latest published release.
Older commits, tags, forks, and modified copies are not supported by XTN.

## Reporting a vulnerability

Use GitHub private vulnerability reporting in the Security tab of the official
repository:

https://github.com/xtnkking/fastapi-templates-xtn

If private vulnerability reporting is not available, open a public issue named
`Security contact request` without including vulnerability details. The
maintainer will arrange a private channel. Do not disclose an unpatched
vulnerability, exploit, credential, token, personal data, or destructive proof
of concept in a public issue.

Include the affected file and version or commit, impact, reproduction steps,
required preconditions, and a non-destructive proof of concept when possible.
State whether the issue is already public or has been reported elsewhere.

XTN will acknowledge receipt, assess the report, and coordinate remediation and
disclosure as availability permits. No response or resolution deadline is
guaranteed. Please allow a reasonable remediation period before disclosure.

## Scope

Reports may cover the Skill instructions, the bundled FastAPI/PostgreSQL RBAC
starter, Redis/JTI design guidance, authentication and authorization behavior,
migrations, and release automation in the canonical repository. Vulnerabilities
in third-party dependencies should also be reported to the relevant upstream
project.

The bundled starter is reference implementation material, not a hosted service
or a warranty that a generated application is secure in every deployment.
Users remain responsible for threat modeling, configuration, dependency
updates, secret management, testing, and operational controls in their own
environment.
