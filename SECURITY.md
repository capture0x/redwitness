# Security policy

AIVeritX sends adversarial prompts to systems, so its own security matters.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting: on the repository page choose *Security → Report a vulnerability* ([direct link](https://github.com/capture0x/AIVeritX/security/advisories/new)). Include what you found, how to reproduce it, and the version or commit.

You will get an answer as soon as a maintainer can read it. Please give us reasonable time to fix the problem before you disclose it.

## What is in scope

- A way around the signed-scope gate or the Governor (a request leaving the stack without a valid scope, limits that can be skipped).
- Authentication, session, RBAC or CSRF flaws.
- Leaking API keys, cookies or other credentials (they must stay in memory or `.env`).
- Escaping the sandbox runner or reaching a network from it.
- Injection into reports (PDF, CSV) or the UI through target output.
- Tampering with the audit chain without detection.

## What is not

- Findings that need `AIVERITX_INSECURE_NO_AUTH=1` (development only).
- Weaknesses in a target you scanned; those belong to that target's owner.
- Denial of service by a user who already has the admin role.

## Using the tool responsibly

Only test systems you own or are explicitly authorized to test.
