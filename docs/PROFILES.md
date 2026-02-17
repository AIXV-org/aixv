# AIXV Profiles (v1 Draft)

Profiles are constrained operating modes that define required controls.

## core-minimal

Required:
- Signed artifact verification bound to trusted subject identities.
- Deterministic JSON output for automation.
- Policy validation (`aixv.policy/v1`) when policy input is provided.
- Optional enforcement gate: `verify --profile core-minimal`.

## core-enterprise

Includes `core-minimal`, plus:
- Signed policy verification enabled by default.
- Signed advisory verification for policy-driven advisory enforcement.
- AdmissionDecision output persisted/logged by deployment systems.
- Enforcement gate: `verify --profile core-enterprise` requires:
  - `--policy`,
  - signed policy verification enabled,
  - `require_signed_advisories=true`,
  - configured advisory trust subjects.

## core-regulated

Includes `core-enterprise`, plus:
- Evidence retention requirements for signatures, policy records, advisories, and decisions.
- Immutable audit trail integration requirements.
- Formal conformance testing requirement before production use.
- Enforcement gate: `verify --profile core-regulated` additionally requires:
  - `max_bundle_age_days`,
  - `require_no_active_advisories=true`.
