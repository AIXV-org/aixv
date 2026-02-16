# AIXV Governance (v0 Draft)

This document defines how AIXV changes are proposed, reviewed, and accepted.

## Scope

Governance applies to:
- normative behavior in `docs/NORMATIVE_CORE.md`,
- schema identifiers and evolution (`aixv.policy/v1`, `aixv.signed-record/v1`),
- trust and admission semantics,
- conformance and compatibility guarantees.

## Change Classes

- Editorial: wording-only, no behavior change.
- Additive: non-breaking extensions that preserve current guarantees.
- Breaking: behavior or schema changes that alter guarantees or compatibility.

## Required PR Content

For any semantic change, PRs must include:
- problem statement,
- security/trust impact,
- compatibility impact,
- tests and conformance impact.

## Required Artifact Updates

Semantic changes must update all applicable artifacts:
- `docs/NORMATIVE_CORE.md`,
- `docs/COMPATIBILITY.md`,
- `docs/THREAT_MODEL.md` (when assumptions change),
- `docs/CONFORMANCE.md` and fixtures,
- tests.

## Review and Merge Policy

- At least one maintainer approval is required for additive changes.
- At least two maintainer approvals are required for breaking changes.
- Breaking changes require explicit migration guidance in release notes.
- Security-sensitive changes do not merge with unresolved trust bypass risks.

## Versioning Policy

- Breaking schema changes require a new schema version.
- Additive fields may be introduced without a major schema version bump.
- Behavior changes that can alter automated decisions must be documented before release.

## Decision Record

Major semantic decisions should be captured in `docs/CRITIQUES_AND_DECISIONS.md` with:
- decision,
- alternatives considered,
- rationale and tradeoffs.

## Maturity Note

AIXV is pre-alpha. Governance is operational now and expected to harden over time.
