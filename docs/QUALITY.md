# AIXV Quality (Core)

This document defines core quality requirements for production-grade provenance verification in AIXV.

## 1. Cryptographic Integrity

- Every critical artifact/record is verified via Sigstore bundle.
- Verification must bind to trusted signer identities (subject required).
- No unsigned control-plane input can directly alter admission decisions.

## 2. Control-Plane Integrity

- Policy is treated as a signed record (`kind=policy`) and can be verified independently.
- Advisories are treated as signed records (`kind=advisory`) and can be required-signed by policy.
- Multi-artifact bundles are represented as signed bundle records (`kind=bundle`, `aixv.bundle/v1`).
- When `require_signed_advisories=true`, only signed-and-trusted advisories influence admission outcomes.
- Rollback records are signed by default (`rollback --sign`), preserving append-only evidence.
- Admission decisions are explicit and machine-readable (`allow|deny`, violations, evidence).

## 3. Schema Stability

- Versioned schemas (`aixv.policy/v1`, `aixv.signed-record/v1`).
- Strict validation (`extra=forbid`) for critical types.
- Digest format normalized (`sha256:<hex>`) at ingestion.

## 4. Composability

- `SignedRecord` is generic over record `kind`; new kinds do not require cryptographic redesign.
- `record create` and `record verify` provide stable lifecycle operations for any record type.
- Domain-specific wrappers (`policy`, `advisory`) are convenience layers over shared primitives.

## 5. Fail-Closed Defaults

- `verify --policy` requires signed policy by default.
- Policy/advisory trust constraints must include signer subjects.
- Missing bundle or violated policy returns non-zero exit status.

## 6. Operational Determinism

- Commands support deterministic JSON output (`--json`) for CI/CD and admission hooks.
- Decision outcomes are reproducible from signed evidence + policy.
- Verifier assurance-level gates (`level-1|level-2|level-3`) provide explicit assurance mode enforcement.
