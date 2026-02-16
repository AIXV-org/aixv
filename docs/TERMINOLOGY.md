# AIXV Terminology (v1)

This glossary defines canonical terms used in AIXV specifications and implementation docs.

- Artifact: A content-addressed file or bundle member (model weights, tokenizer, dataset shard, config).
- Digest: Canonical content identifier in `sha256:<hex>` format.
- Attestation: An in-toto statement about one or more subjects, optionally signed and transparency-logged.
- SignedRecord: AIXV generic signed metadata envelope (`aixv.signed-record/v1`).
- Record Kind: Semantic class of a SignedRecord payload (e.g., `policy`, `advisory`, `waiver`).
- Policy: Declarative admission constraints (`aixv.policy/v1`) used during verification.
- AdmissionDecision: Deterministic allow/deny result with machine-readable violations and evidence.
- Trust Root: Set of accepted signer identities and issuers used for verification decisions.
- Advisory: Security/safety incident notice that can affect admission decisions.
- Provenance Graph: Typed DAG linking artifacts and transformations over time.

Terminology rules:
- Use these terms consistently across docs, schema names, and CLI help text.
- Avoid introducing synonyms for existing terms without updating this glossary.
