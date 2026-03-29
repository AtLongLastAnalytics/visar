# Security Policy

## Supported Versions

Only the latest release of VISaR receives security updates.

| Version | Supported |
|---------|-----------|
| 1.1.x   | Yes       |
| < 1.1   | No        |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report them privately via [GitHub's private vulnerability reporting](https://github.com/AtLongLastAnalytics/visar/security/advisories/new).

Include as much detail as possible:

- A clear description of the vulnerability and its potential impact
- The component or file(s) affected
- Steps to reproduce (proof-of-concept code or commands where applicable)
- Your assessment of severity (Critical / High / Medium / Low)
- Any suggested fixes or mitigations

You will receive an acknowledgement within **7 days** and a resolution or status update within **30 days**.

## Scope

The following are considered in scope:

- **Token leakage** — any path by which a `VISAR_AUTH_TOKEN` value could be exposed (e.g. logged to disk, included in output files, or transmitted to a third party beyond the GitHub and OSV APIs).
- **HTML dashboard injection** — XSS or script injection vulnerabilities in the generated `dashboard.html` via unsanitised vulnerability data from the OSV API.
- **Dependency vulnerabilities** — known CVEs in direct dependencies declared in `pyproject.toml` that have a credible exploitation path within VISaR's runtime context.
- **Docker container misuse** — any mechanism by which the OSSF Scorecard container invocation could be exploited to execute unintended commands on the host.

The following are **out of scope**:

- Vulnerabilities in the OSSF Scorecard tool or OSV database themselves (report those to their respective projects).
- Issues that require physical access to the user's machine.
- Self-XSS or issues requiring an attacker to have already modified local files.
- Rate-limiting or denial-of-service against the GitHub or OSV APIs.

## Disclosure Policy

Once a report is received, we will:

1. Confirm receipt within 7 days.
2. Investigate and determine severity and impact.
3. Develop and test a fix.
4. Release a patched version and publish a [GitHub Security Advisory](https://github.com/AtLongLastAnalytics/visar/security/advisories).
5. Credit the reporter in the advisory (unless they prefer to remain anonymous).

We ask that you do not publicly disclose the vulnerability until a fix has been released or 90 days have elapsed, whichever comes first.

## Security Best Practices for Users

- Store your GitHub token **only** in a `.env` file at the project root, which is gitignored by default. Never commit it.
- Use a token with the minimum required scope (`public_repo` read-only).
- Regenerate your token if you suspect it has been exposed.
- Review generated `dashboard.html` files before sharing them, as they embed raw vulnerability data from external APIs.
