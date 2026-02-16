# AIXV Profiles (v1 Draft)

Profiles are constrained operating modes that define required controls.

## core-minimal

Required:
- Signed artifact verification bound to trusted subject identities.
- Deterministic JSON output for automation.
- Policy validation (`aixv.policy/v1`) when policy input is provided.

## core-enterprise

Includes `core-minimal`, plus:
- Signed policy verification enabled by default.
- Signed advisory verification for policy-driven advisory enforcement.
- AdmissionDecision output persisted/logged by deployment systems.

## core-regulated

Includes `core-enterprise`, plus:
- Evidence retention requirements for signatures, policy records, advisories, and decisions.
- Immutable audit trail integration requirements.
- Formal conformance testing requirement before production use.
