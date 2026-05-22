# Reporting Security Issues

TokenFuzz is built for authorized vulnerability research in open-source
software. It produces sanitizer-backed crash reports, differential results, and
concrete non-crashing findings — memory safety, authentication, injection,
information disclosure, cryptography, races, sandbox and privilege boundaries,
and logic flaws. This page explains how to report what you find, both in the
software you audit and in TokenFuzz itself, and outlines the kinds of use this
project is meant for.

## Reporting issues in target software

When a TokenFuzz run produces a confirmed finding, send it to the upstream
project through its standard security-disclosure process. Each project differs,
so check the target's own `SECURITY.md`, advisory page, or documented security
contact rather than relying on this documentation for the address.

Use the upstream project's stated disclosure policy. Keep details private
until that process is complete: no public issue-tracker tickets, no GitHub
issues, no social-media posts. If maintainers ask for an extension, grant it
within reason — the goal is a fix shipped to users, not a calendar.

## Reporting issues in TokenFuzz itself

If you find a security-relevant bug in TokenFuzz, please report it privately:

- Open a
  [GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository, **or**
- Email the maintainer (see commit metadata for the current contact).

Please do not file public issues for harness security bugs until a fix is
available.

## Permitted use

TokenFuzz runs inputs, harnesses, and model-generated probes on your own
machine, against software you have permission to audit. In practice, that
means:

- open-source projects you maintain;
- open-source projects that explicitly welcome security research, such as most
  major browser engines, language runtimes, and parser libraries;
- software you have written authorization to test, including pentest
  engagements and internal QA on company-owned products.

Using TokenFuzz to audit software you have no authorization to test may
violate computer-fraud laws in your jurisdiction. The maintainers accept no
liability for misuse — see [LICENSE](LICENSE).
