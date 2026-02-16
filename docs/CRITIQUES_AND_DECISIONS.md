# AIXV Critiques and Design Decisions (v0.1)

This file tracks high-impact critiques and the corresponding design responses.

## 1. "Signatures without identity policy are meaningless"

Risk:
- A valid signature can still be attacker-controlled if signer identity is unconstrained.

Decision:
- Verification requires subject-based identity constraints (`subject` or `allow_subjects`).
- Issuer-only policy is not accepted as sufficient.

Status:
- Implemented in CLI and policy schema.

## 2. "Unsigned policy files are a supply-chain hole"

Risk:
- An attacker can tamper with local policy and change admission outcomes.

Decision:
- `verify` requires signed policy verification by default when `--policy` is used.
- Trust roots for policy signer identities must be provided.

Status:
- Implemented (`--require-signed-policy` default true).

## 3. "Unsigned advisories can be weaponized"

Risk:
- Anyone could inject fake critical advisories to force denial-of-service.

Decision:
- Policy supports signed advisory requirements (`require_signed_advisories`).
- Advisory trust roots can be separated from artifact signer roots.

Status:
- Implemented with advisory record signing and trust-aware advisory loading.

## 4. "Schema drift and unknown fields cause interoperability failures"

Risk:
- Producers/consumers disagree silently when fields are misspelled or extended ad hoc.

Decision:
- Core v1 schemas use strict validation (`extra=forbid`) for critical predicates/policies.
- Policy/version type fields are explicit (`policy_type: aixv.policy/v1`).

Status:
- Implemented for training/advisory/policy schemas.

## 5. "Digest ambiguity causes provenance confusion"

Risk:
- Mixed digest formats (`hex` vs `sha256:hex`) break matching and impact analysis.

Decision:
- Normalize all digests to canonical `sha256:<hex>` format at ingestion.
- Reject invalid digest strings.

Status:
- Implemented across predicates and advisory matching.

## 6. "Rollback can become audit erasure"

Risk:
- Operational rollback may delete history and weaken incident reconstruction.

Decision:
- Rollback is append-only event creation, not artifact deletion.
- Evidence remains queryable via stored attestations/advisories/signatures.

Status:
- Implemented as explicit rollback event record; lineage expansion ongoing.

## 7. "Over-flexible tooling leads to insecure defaults"

Risk:
- Convenience flags become silent bypasses in production.

Decision:
- Security-sensitive defaults are fail-closed:
  - signed policy required when policy is provided,
  - subject trust constraints required for artifact verification,
  - policy validation rejects under-specified trust roots.

Status:
- Implemented; further hardening planned with signed remote feeds.

## Next hardening steps

1. Add signed remote advisory feed ingestion with replay/freshness protection.
2. Add conformance test vectors for every failure mode above.
3. Add compatibility profile gates (`core-minimal`, `core-enterprise`, `core-regulated`).
