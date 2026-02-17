# AIXV Standard v0.1 (Draft)

Status: Draft for implementation feedback  
Scope: AI artifact attestation, provenance, compromise detection, attribution, and rollback  
Design principle: Compose Sigstore primitives; standardize AI semantics

## 1. Goals and Non-Goals

### Goals
- Provide verifiable provenance for AI artifacts across training, fine-tuning, packaging, and deployment.
- Support rollback, impact analysis, and compromise investigation with deterministic semantics.
- Remain interoperable with existing supply-chain standards (in-toto, SLSA, SPDX/CycloneDX).
- Scale from single-file artifacts to multi-artifact model bundles.

### Non-Goals
- Replacing Sigstore cryptography, trust roots, or transparency logs.
- Defining model quality policy (what score is "good").
- Mandating one model hub, framework, or registry.

## 2. Trust and Cryptographic Primitives

AIXV MUST use Sigstore primitives for signing and verification:
- Signing: Sigstore keyless (OIDC) SHOULD be default; key-pair mode MAY be supported.
- Transparency: Every production signature/attestation MUST be logged in Rekor.
- Verification: Clients MUST verify certificate identity, signature validity, inclusion proof, and integrated time.

AIXV MUST NOT define custom cryptographic algorithms.

## 3. Canonical Identity Model

Each signed statement is bound to a signer identity with this tuple:
- `issuer`: OIDC issuer URI (e.g., `https://token.actions.githubusercontent.com`)
- `subject`: principal string (email, workload identity, SPIFFE ID, etc.)
- `workflow_ref` (optional): CI workflow ref for automation identities

Verification policy MUST support allow/deny rules over `issuer` and `subject` patterns.

## 4. Artifact Model

An AIXV artifact is identified by immutable digest plus optional locators.

```json
{
  "digest": "sha256:...",
  "artifact_type": "fine-tuned-model",
  "media_type": "application/x-safetensors",
  "size_bytes": 123456789,
  "uri": "hf://org/model@sha256:...",
  "name": "model.safetensors"
}
```

### 4.1 Artifact Types (initial registry)
- `base-model`
- `fine-tuned-model`
- `lora-adapter`
- `quantized-model`
- `checkpoint`
- `dataset`
- `tokenizer`
- `training-config`
- `inference-config`
- `cl-delta`
- `eval-report`
- `prompt-pack`
- `policy-pack`

Implementations MAY extend types via namespaced identifiers (e.g., `vendor.example/rlhf-reward-model`).

## 5. Bundle Semantics

A model release SHOULD be represented as a bundle (multiple artifacts, one release identity).

```json
{
  "bundle_id": "urn:uuid:...",
  "primary": "sha256:model_digest",
  "members": [
    "sha256:model_digest",
    "sha256:tokenizer_digest",
    "sha256:config_digest"
  ],
  "bundle_type": "model-release"
}
```

Rules:
- Bundle member digests MUST be immutable.
- Any bundle mutation MUST produce a new bundle ID.
- Verification MAY require all mandatory member types by policy.

## 6. Attestation Envelope

AIXV uses DSSE + in-toto statement envelope. Predicate types are AIXV namespaced URIs.

Required top-level fields:
- `_type`: in-toto statement type
- `subject`: one or more artifacts (digest keyed)
- `predicateType`
- `predicate`

## 7. Predicate Registry (v1)

### 7.1 `.../training/v1`
Captures training/fine-tuning lineage and run context.

Required predicate fields:
- `parent_models[]`: digests + optional URIs
- `datasets[]`: digests + optional URIs + split (`train`, `eval`, `test`, `rlhf`)
- `training_run`: framework/version, code revision digest, environment digest
- `hyperparameters`: normalized map

### 7.2 `.../evaluation/v1`
Captures reproducible evaluation claims.

Required:
- `benchmarks[]` with metric names, values, confidence intervals when available
- `eval_harness_digest`
- `dataset_digests[]`
- `random_seed_policy` (`fixed`, `sweep`, `none`)

### 7.3 `.../packaging/v1`
Captures conversions and packaging transforms.

Required:
- `inputs[]` and `outputs[]` digests
- `transform_type` (`quantize`, `merge-adapter`, `export`, `prune`)
- `toolchain` identifiers and versions

### 7.4 `.../deployment/v1`
Captures deployment-time admission assertion.

Required:
- `admitted_artifact_digest`
- `policy_id`
- `policy_decision` (`allow`, `deny`)
- `evidence[]`

### 7.5 `.../advisory/v1`
Security or safety recall statement.

Required:
- `advisory_id`
- `affected[]`: artifact digests and selectors (parents, descendants, bundles)
- `severity`: `low|medium|high|critical`
- `status`: `active|mitigated|withdrawn`
- `reason_code`: enumerated taxonomy
- `recommended_actions[]`

## 8. Lineage Graph Semantics

Lineage is a directed acyclic graph over artifact digests.

Edge types:
- `derived_from`
- `trained_on`
- `packaged_from`
- `evaluated_with`
- `deployed_as`

Normative constraints:
- Graph MUST be acyclic per release lineage.
- Every `fine-tuned-model` MUST have at least one parent model edge.
- Every `lora-adapter` MUST reference exactly one compatible base model family.
- Every `cl-delta` MUST reference a single `base` digest and declare `delta_scope`.

## 9. Continual Learning and Rollback

`cl-delta` predicate additions:
- `base_digest`
- `update_type` (`sft`, `dpo`, `ppo`, `rl-online`, `hotfix`)
- `compatibility_window`
- `rollback_target_digest`
- `state_migration` (`none`, `required`)

Rollback semantics:
- A rollback event MUST be an attested operation, not a hidden deletion.
- Rollback does not erase prior attestations; it appends a corrective lineage node.
- Admission policy SHOULD reject deployment of artifacts with unresolved critical advisories.

## 10. Compromise Detection and Investigation

Investigation primitives:
- `trace`: walk ancestors to origin.
- `impact`: walk descendants from compromised digest.
- `explain`: return minimal evidence set proving why an artifact is flagged.

Evidence model:
- Signatures + Rekor inclusion proof
- Advisory statements
- Policy decisions
- Optional runtime telemetry attestations

Attribution rules:
- Attribution MUST be tied to signed identities and integrated times.
- Unsigned claims MUST NOT alter trust decisions.

## 11. Policy Model

Policy inputs:
- Identity allowlist/denylist
- Required predicate types by artifact type
- Freshness windows
- Advisory thresholds
- Mandatory bundle members

Policy outputs:
- `allow`
- `deny`
- `allow-with-waiver` (requires signed waiver attestation)

## 12. Versioning and Compatibility

- Every schema URI MUST include major version (`/v1`).
- Backward compatible additions: optional fields only.
- Breaking changes require new major version URI.
- Verifiers SHOULD support at least one prior major version during migration.

## 13. Interoperability Assurance Levels

AIXV assurance levels define strict subsets for predictable exchange:
- `level-1`: sign + verify + training lineage
- `level-2`: adds advisories, policy decisions, rollback attestations
- `level-3`: adds immutable retention and evidence export requirements

These levels are ordinal assurance tiers and do not encode assumptions about any
specific sector, procurement regime, or legal jurisdiction.

Export targets:
- in-toto statements
- SLSA provenance mappings
- ML-BOM (SPDX/CycloneDX extension format)

## 14. Security Requirements

- Offline verification MUST be supported with trusted root bootstrapping.
- Clock skew tolerance MUST be explicit in verifier config.
- Digest algorithm agility MUST be designed in (`sha256` required in v1).
- Replay protection SHOULD check transparency log integrated time and bundle uniqueness.
- Remote advisory ingestion SHOULD enforce monotonic integrated time per advisory ID and reject stale bundles by configured age.
- All critical security decisions MUST be auditable with machine-readable reason codes.

## 15. Reference CLI Contract (v1)

- `aixv sign <artifact>`
- `aixv attest <artifact> --predicate <type> --input <json>`
- `aixv verify <artifact> [--policy <file>]`
- `aixv provenance <artifact> [--depth N]`
- `aixv advisory create|verify|list|sync ...`
- `aixv policy template|migrate|create|verify ...`
- `aixv rollback <artifact> --to <digest>`
- `aixv export <artifact> --format in-toto|slsa|ml-bom|aixv`

All commands SHOULD support deterministic JSON output mode for automation.

## 16. Governance Recommendations

To become a world standard, governance matters as much as code:
- Publish open schema registry and compatibility tests.
- Define conformance test suite with mandatory vectors.
- Separate specification governance from single-vendor implementation.
- Operate transparent advisory CNA-like process for AI incidents.

## 17. Minimal Implementation Roadmap

1. Integrate `sigstore` dependency and implement production-grade `sign`/`verify` wrappers.
2. Implement `training/v1` and `advisory/v1` predicates.
3. Add local lineage graph store and deterministic graph queries (`trace`, `impact`).
4. Add admission policy engine and CI/CD hooks.
5. Add export adapters (in-toto, SLSA, ML-BOM).
6. Ship conformance tests and reference fixtures.
