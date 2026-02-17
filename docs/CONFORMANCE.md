# AIXV Conformance (v1 Draft)

Conformance requires passing normative behavior tests for verification, policy, and signed records.

## Conformance Areas

1. Schema Conformance
- Reject unknown fields in strict schemas.
- Enforce canonical digest format.

2. Trust Conformance
- Fail verification when identity constraints are missing.
- Fail verification when signed-policy trust constraints are missing.

3. Decision Conformance
- Produce deterministic `AdmissionDecision` shape.
- Deny when any violation exists.

4. SignedRecord Conformance
- Validate record schema and required fields.
- Verify signatures with trusted subject constraints.

## Fixtures

Fixture directory: `docs/conformance/fixtures/`

Included fixtures:
- `policy.valid.json`
- `policy.invalid.no_subjects.json`
- `record.policy.sample.json`

## Test Execution

Reference checks should run in CI:
- `ruff check .`
- `mypy src`
- `pytest`

Runtime conformance report:
- `aixv conformance --json`

## Minimal Vector Set (Current)

- `fixtures.exist.v1`: required conformance fixtures are present.
- `policy.fixture.valid.v1`: valid policy fixture is accepted.
- `policy.fixture.invalid.v1`: invalid policy fixture is rejected.
- `record.fixture.policy.v1`: signed-record policy fixture parses with expected kind.
- `policy.unknown-field.reject.v1`: unknown policy fields are rejected.
- `policy.advisory-trust.subject-fallback.v1`: advisory trust roots fall back to policy `subject`.
- `advisory.signed-policy.filtering.v1`: when signed advisories are required, untrusted advisories are ignored and trusted advisories drive enforcement.
