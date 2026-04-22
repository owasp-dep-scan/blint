# SECURITY.md

## Reporting Security Issues

The OWASP dep-scan team and community take security bugs seriously. We appreciate your efforts to responsibly disclose your findings, and will make every effort to acknowledge your contri
butions.

To report a security issue, email [team@appthreat.com](mailto:team@appthreat.com) and include the word **"SECURITY"** in the subject line.

The OWASP dep-scan team will send a response indicating the next steps in handling your report. After the initial reply to your report, the security team will keep you informed of the pro
gress towards a fix and full announcement, and may ask for additional information or guidance.

Report security bugs in third-party modules to the person or team maintaining the module.

## Service Level Agreements (SLAs)

We use the following target response and resolution times for reported security issues. These SLAs are best-effort commitments, not contractual guarantees.

| Severity                                                                               | Initial Response | Triage / Confirmation | Remediation Target | Disclosure                |
| -------------------------------------------------------------------------------------- | ---------------- | --------------------- | ------------------ | ------------------------- |
| **Critical** (RCE, credential exfiltration, supply-chain compromise)                   | 48 hours         | 5 business days       | 15 business days   | Coordinated with reporter |
| **High** (sandbox escape, path traversal in server mode, command injection)            | 5 business days  | 10 business days      | 30 business days   | Coordinated with reporter |
| **Medium** (information disclosure, denial of service, bypass of secure mode controls) | 10 business days | 15 business days      | 60 business days   | Next scheduled release    |
| **Low** (verbose error messages, minor hardening improvements)                         | 15 business days | 30 business days      | Best effort        | Next scheduled release    |

After remediation is available, we will publish a GitHub Security Advisory (GHSA) with CVE assignment where appropriate.

## What Counts as a Genuine Security Issue

A genuine security issue is a weakness in `blint` itself that can be exploited to
compromise confidentiality, integrity, or availability beyond expected tool behavior.

### In scope

- Arbitrary code execution caused by parsing untrusted inputs in `blint`.
- Unsafe file writes/path handling in report, extraction, or temp-file logic.
- Vulnerabilities in `blint` command handling that allow command injection.
- Trust-boundary bypasses in `blintdb` fetch/use flow that can load attacker-controlled data unexpectedly.
- Security control bypasses where `blint` claims/exports incorrect hardening results due to a logic flaw.

### Out of scope

- Denial-of-service bugs and crashes with large payloads. User is responsible for running `blint` in appropriate isolation and with resource limits when analyzing untrusted binaries.
- False positives/false negatives in capability heuristics unless they stem from a clear exploitable bug.
- Feature requests, UX issues, or documentation mistakes without security impact.
- Findings about third-party software discovered by `blint` output (that belongs to the analyzed target).
- Build/runtime hardening gaps in user environments outside `blint` control.
- Vulnerabilities in optional external tools not bundled or maintained here (for example system-provided tooling).
- Theoretical parser concerns without a reproducible proof-of-impact.

### Grey areas

- High-amplification DoS from malformed binaries that requires unusual hardware or massive input.
- Dependency vulnerabilities where exploitability in `blint` runtime path is unclear.
- Output confusion issues that could mislead CI enforcement in security-sensitive pipelines.

When unsure, report privately with a minimal reproducer and impact narrative.

## Shared Responsibility Model

### What blint is responsible for

- Safely parsing supported binary formats and handling malformed input defensively.
- Avoiding unsafe defaults in file handling, temporary extraction, and report writing.
- Shipping fixes for confirmed vulnerabilities in maintained releases.
- Documenting security-relevant behavior and limitations clearly.

### What users are responsible for

- Running `blint` in appropriate isolation when analyzing untrusted binaries.
- Keeping `blint` up to date on supported releases.
- Verifying and pinning environment/toolchain dependencies in their own CI/CD.
- Treating analysis output as an aid, not a guarantee of absence of risk.

### What upstream projects are responsible for

- Security of upstream dependencies and libraries used by `blint` (for example parsing/disassembly ecosystems).
- Timely publication of advisories and patches for upstream CVEs.
- Correctness and security posture of external datasets/images consumed by `blint` users.

## Security Features Reference

`blint` includes the following security-relevant capabilities:

- Binary hardening checks (PIE, NX, RELRO, canary, signing, and PE-specific mitigations).
- Secret/high-entropy string detection during metadata extraction.
- Rule-based capability reviews from symbols/imports/functions.
- Optional disassembly-assisted behavior heuristics (`--disassemble`).
- CycloneDX SBOM generation for binary and Android artifacts.
- Optional `blintdb`-assisted component resolution for improved SBOM precision.

## Supported Versions (last two versions)

Security fixes are supported for the most recent two tagged versions:

- latest stable release (for example `v3.1.2` at the time of writing)
- previous (`v3.1.1` which is the previous release at the time of writing)

Older versions may not receive security fixes. Please upgrade before reporting if
you are running a release older than the two versions listed above.
