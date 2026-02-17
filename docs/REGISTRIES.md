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

Record ID guidance:
- `record_id` should match `^[A-Za-z0-9._-]{1,128}$`.

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

## 5. Advisory Feed Schema

Feed schema:
- `aixv.advisory-feed/v1`

Required fields:
- `entries[]` where each entry includes:
  - `record` (or `record_url`): advisory signed-record JSON reference
  - `bundle` (or `bundle_url`): Sigstore bundle JSON reference

Operational semantics:
- Each entry must verify against trusted signer subjects before import.
- Remote feed and entry URLs must use `https://` (or be local file paths).
- Replay/stale updates are rejected when integrated time does not advance.
- Optional freshness guard rejects bundles older than configured max age.
