# AIXV Threat Model (v1 Draft)

This model is intentionally general and evidence-centric. It is not tied to any single model family, deployment pattern, or sector.

## 1. Security Objective

Ensure that admission decisions about AI artifacts are made from authenticated, integrity-protected, policy-constrained evidence.

## 2. System Boundary

In-scope boundary:
- Artifacts and metadata under AIXV verification.
- Signed records (policy, advisory, and other kinds).
- Signature bundles and trust constraints.
- Admission decision engine.

Out-of-scope (by default):
- Model behavioral safety quality itself.
- Runtime exploit mitigation inside model-serving infrastructure.
- Human governance decisions that are not encoded as signed evidence.

## 3. Protected Assets

- Artifact integrity (content digest correctness).
- Signer identity binding and issuer binding.
- Policy integrity and semantics.
- Advisory integrity and authenticity.
- Decision integrity (allow/deny + evidence traceability).

## 4. Adversary Classes

- Supply-chain tampering adversary: swaps or modifies artifacts/metadata in transit or storage.
- Identity adversary: attempts to satisfy verification with untrusted identity.
- Control-plane adversary: tampers with policy/advisory records to force false allow/deny outcomes.
- Evidence-shaping adversary: injects malformed/ambiguous inputs to trigger parser differentials.
- Replay adversary: reuses stale but valid materials outside intended context/time windows.

## 5. Trust Assumptions

AIXV assumes:
- Sigstore trust roots and verification primitives are sound.
- Trusted subject/issuer constraints are correctly configured by operators.
- Policy and advisory trust roots are managed under local governance.

AIXV does not assume:
- Any specific storage backend is trusted.
- Any specific model provider is trusted by default.
- Any unsigned metadata source is trustworthy.

## 6. Evidence Model

Evidence is accepted only if it is:
- structurally valid,
- cryptographically valid,
- identity-valid against trust constraints,
- and semantically valid for decision evaluation.

Canonical evidence classes:
- signed artifact bundle verification result,
- signed policy record,
- signed advisory record,
- deterministic admission decision output.

## 7. Core Invariants

- Fail-closed on missing/invalid security-critical inputs.
- No unsigned control-plane input may change allow/deny decisions.
- Decision output must include machine-readable violations and evidence.
- Security-critical schemas must reject unknown fields.

## 8. Attack Surface and Controls

### 8.1 Artifact substitution
Control: digest + signature + trusted signer identity verification.

### 8.2 Policy tampering
Control: signed policy verification with trusted policy signer constraints.

### 8.3 Advisory poisoning (false recalls / false clears)
Control: signed advisory requirements and advisory trust-root constraints.

### 8.4 Parser ambiguity and schema drift
Control: strict schema validation, explicit versioned schema identifiers.

### 8.5 Replay/staleness
Control: freshness constraints (`max_bundle_age_days`) and integrated time checks.

## 9. Failure Semantics

On verification/policy error:
- default outcome is `deny` or explicit command failure (non-zero exit),
- errors must be explicit and machine-readable,
- operators can distinguish input failure from policy violation.

## 10. Residual Risks

- Misconfigured trust constraints may over-trust or over-deny.
- Organizational key/identity compromise remains an operator governance risk.
- Cross-system policy consistency requires operational controls beyond this repository.

## 11. Security Testing Requirements

Minimum test classes:
- malformed signed records and schema mismatches,
- identity mismatch and issuer mismatch,
- unsigned policy/advisory denial behavior,
- deterministic decision contract checks.
