# Security Policy

## Scope

AIXV is a security-critical provenance and attestation project. Security-sensitive changes include:
- signature verification behavior,
- trust policy semantics,
- signed record parsing/validation,
- admission decision logic,
- schema compatibility handling.

## Reporting a Vulnerability

Do not open public issues for unpatched vulnerabilities.

Primary reporting channel:
- `admin@aixv.org` (subject: `AIXV Security Report`)

Include:
- affected version/commit,
- impact summary,
- reproduction steps,
- proof-of-concept artifacts (if available).

## Response Targets

Maintainer targets:
- acknowledgment within 3 business days,
- initial triage within 7 business days,
- coordinated remediation plan as soon as practical based on severity.

## Disclosure Process

1. Triage and reproduce.
2. Assign severity and affected components.
3. Develop and validate fix.
4. Coordinate release and advisory publication.
5. Publish remediation guidance and compatibility notes.

## Severity Guidance

- `critical`: enables trust bypass, false allow decisions, or silent evidence forgery acceptance.
- `high`: materially weakens verification/admission guarantees without full bypass.
- `medium`: correctness gaps with meaningful but bounded security impact.
- `low`: minor hardening gaps with limited practical exploitability.

## Security Invariants

The following are non-negotiable invariants:
- Unsigned claims must not alter admission outcomes.
- Signature verification must be identity-bound to trusted subjects.
- Admission outcomes must be deterministic and auditable.
- Schema parsing for security-critical inputs must fail closed.

## Supported Security Posture

This repository is pre-alpha. Use in production only with explicit risk acceptance.

For production pilots, minimum controls are defined in `docs/QUALITY.md`.
