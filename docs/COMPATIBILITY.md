# AIXV Compatibility Contract (v0.1)

This document defines compatibility expectations for the current pre-alpha line.

## Scope

Applies to:
- CLI command behavior for documented commands,
- machine-readable JSON outputs (`--json`) used for automation,
- core schema identifiers (`aixv.signed-record/v1`, `aixv.policy/v1`).

## 1. Pre-Alpha Compatibility Level

AIXV is pre-alpha. Breaking changes may occur, but should be controlled and documented.

Project commitments for this line:
- security-sensitive behavior changes must be intentional and documented,
- JSON output keys used in tests/conformance should not change silently,
- schema version identifiers must be bumped for breaking schema semantics.

## 2. JSON Output Contract

For commands supporting `--json`:
- output MUST be valid JSON,
- output MUST include `ok` where applicable,
- error output MUST include `command` and `error`,
- non-zero exit status MUST accompany command-level failure.

## 3. Schema Evolution

- Breaking changes to `aixv.policy/v1` require `aixv.policy/v2`.
- Breaking changes to `aixv.signed-record/v1` require `.../v2`.
- New optional fields MAY be added without version bump.
- Unknown fields in strict security-critical schemas are rejected.

## 4. Behavioral Compatibility

Compatibility-sensitive behaviors:
- fail-closed verification when required trust constraints are absent,
- signed-policy enforcement defaults in verification flows,
- deterministic admission output shape (`decision`, `violations`, `evidence`).

## 5. Change Communication

When compatibility-affecting changes are introduced:
- update this document,
- update conformance fixtures and tests,
- note migration implications in release notes.
