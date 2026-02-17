# AIXV Registries (v1 Draft)

## 1. SignedRecord Kinds

Core kinds:
- `policy`
- `advisory`
- `bundle`

Provisional kinds:
- `waiver`
- `incident`
- `evidence`

Registration guidance:
- New kinds should be lowercase kebab-case.
- Kind semantics must define expected payload schema and trust implications.

## 2. Predicate URI Registry

Current predicate aliases:
- `training` -> `https://aixv.org/attestation/training/v1`
- `advisory` -> `https://aixv.org/attestation/advisory/v1`

Rules:
- Predicate URIs must be versioned (`/vN`).
- Breaking payload changes require a new major version URI.

## 3. Severity Registry

Allowed severities:
- `low`
- `medium`
- `high`
- `critical`

Ordering:
- `low < medium < high < critical`

## 4. Status Registry (Advisory)

Allowed status values:
- `active`
- `mitigated`
- `withdrawn`
