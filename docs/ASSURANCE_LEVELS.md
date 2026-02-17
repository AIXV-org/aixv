# AIXV Assurance Levels (v1 Draft)

Assurance levels are constrained operating modes that define required controls.
Levels are ordinal only; they do not imply any specific industry, jurisdiction,
or regulatory framework.

## level-1

Required:
- Signed artifact verification bound to trusted subject identities.
- Deterministic JSON output for automation.
- Policy validation (`aixv.policy/v1`) when policy input is provided.
- Optional enforcement gate: `verify --assurance-level level-1`.

## level-2

Includes `level-1`, plus:
- Signed policy verification enabled by default.
- Signed advisory verification for policy-driven advisory enforcement.
- AdmissionDecision output persisted/logged by deployment systems.
- Enforcement gate: `verify --assurance-level level-2` requires:
  - `--policy`,
  - signed policy verification enabled,
  - `require_signed_advisories=true`,
  - configured advisory trust subjects.

## level-3

Includes `level-2`, plus:
- Evidence retention requirements for signatures, policy records, advisories, and decisions.
- Immutable audit trail integration requirements.
- Formal conformance testing requirement before production use.
- Enforcement gate: `verify --assurance-level level-3` additionally requires:
  - `max_bundle_age_days`,
  - `require_no_active_advisories=true`.
