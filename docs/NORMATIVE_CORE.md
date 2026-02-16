# AIXV Normative Core (v1 Draft)

This file defines stable, general primitives with normative semantics.

## 1. SignedRecord Primitive

A `SignedRecord` MUST contain:
- `schema` (`aixv.signed-record/v1`),
- `kind`,
- `record_id`,
- `created_at`,
- `payload`,
- optional `signature_bundle_path`.

`kind` is extensible and MUST NOT require cryptographic redesign.

## 2. Trust Constraint Primitive

A trust constraint set MUST include one or more trusted signer subjects.
Issuer constraints MAY be provided.

Verification MUST fail if subject constraints are absent for security-critical verification operations.

## 3. Admission Primitive

An `AdmissionDecision` MUST include:
- `decision` (`allow` or `deny`),
- `violations` (list of machine-readable reasons),
- `evidence` (machine-readable supporting context).

If any mandatory control is violated, `decision` MUST be `deny`.

## 4. Policy Primitive

A policy payload (`aixv.policy/v1`) MUST be versioned and schema-validated.
Unknown fields in critical policy sections MUST be rejected.

Policy MAY constrain:
- signer identity (`subject`, allow/deny sets),
- issuer sets,
- freshness windows,
- advisory severity thresholds,
- signed advisory requirements.

## 5. Evidence Acceptance Rules

For security-critical paths, evidence MUST satisfy:
1. structural validation,
2. cryptographic validation,
3. trust-constraint validation,
4. semantic validation.

Unsigned evidence MUST NOT change `allow`/`deny` outcomes.

## 6. Compatibility and Evolution

Breaking schema changes MUST use a new version identifier.
Implementations SHOULD continue to verify at least one prior major version during migration windows.

## 7. Determinism Requirement

JSON output used for automation SHOULD be deterministic in field naming and semantics.
Failure outputs MUST include explicit command context and error reason.
