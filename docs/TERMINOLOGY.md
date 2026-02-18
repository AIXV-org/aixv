# AIXV Terminology (v1)

This glossary defines canonical terms used in AIXV specifications, implementation docs,
and CLI output. Terms marked **normative** MUST be used consistently and MUST NOT be
replaced with synonyms without updating this document.

---

## Core Terms

**Artifact** *(normative)*
A content-addressed file or bundle member whose identity is defined by its digest.
Examples: model weights (`.safetensors`, `.bin`), tokenizer, dataset shard, config file,
container image. An artifact's identity is its digest — not its filename, URI, or location.

**Digest** *(normative)*
The canonical content identifier for an artifact, in `sha256:<hex>` form (64 hex characters).
Digests MUST include the `sha256:` prefix. A bare hex string is not a valid digest.
Do not use git commit SHAs as artifact digests — they are tree references, not file digests.

**Attestation** *(normative)*
A structured, signed claim about one or more artifacts. Technically: an in-toto Statement/v1
envelope containing a subject (artifact digest), a predicate type URI, and a predicate payload,
optionally signed via Sigstore and logged in Rekor. Distinct from an *assertion* (unsigned claim)
or a *certificate* (identity binding only).

**Predicate** *(normative)*
The typed payload inside an attestation that describes what is being claimed.
AIXV defines predicate types for training lineage, evaluation, packaging, deployment,
and advisories. Each predicate type has a versioned URI (e.g., `https://aixv.org/attestation/training/v1`).

**SignedRecord** *(normative)*
The AIXV generic signed metadata envelope (`aixv.signed-record/v1`). Wraps any payload
with a schema identifier, kind, record ID, creation timestamp, and optional Sigstore bundle path.
Used for policies, advisories, waivers, bundles, and other record kinds.

**Record Kind** *(normative)*
The semantic class of a SignedRecord payload. Examples: `policy`, `advisory`, `waiver`, `bundle`.
Kind is extensible but MUST be declared explicitly — it is not inferred from payload content.

**Bundle** *(normative)*
A signed record (`kind=bundle`) that groups multiple artifacts under a single release identity.
A bundle has a primary member and zero or more additional members, each identified by digest.
Bundle membership is immutable — any change requires a new bundle ID.

**Policy** *(normative)*
A declarative admission constraint document (`aixv.policy/v1`) that defines trust roots,
identity allowlists/denylists, freshness windows, advisory thresholds, and required controls.
Policies MUST be signed and verified against a trusted policy signer identity.

**AdmissionDecision** *(normative)*
The deterministic output of a policy evaluation: `allow` or `deny`, with machine-readable
`violations` (reasons for denial) and `evidence` (supporting context). Unsigned inputs
MUST NOT change an AdmissionDecision outcome.

**Trust Root** *(normative)*
The set of accepted signer identities (subjects) and issuers used to constrain verification.
Trust roots are operator-configured and are not global defaults. Separate trust roots
MAY be configured for artifact signers, policy signers, and advisory signers.

**Advisory** *(normative)*
A signed security or safety incident notice that identifies affected artifacts by digest
or selector, declares severity and status, and MAY trigger policy-driven denial.
Distinct from a *vulnerability* (a flaw in code) — an advisory is a claim about
an artifact's trustworthiness in a specific context.

**Provenance Graph** *(normative)*
A typed directed acyclic graph (DAG) linking artifacts and transformations over time.
Nodes are artifacts or processes; edges are typed relationships (e.g., `derived_from`,
`trained_on`). The graph is the navigable representation of training lineage.
Distinct from an *attestation* (a signed claim about one node) — the graph is the
structure; attestations are the cryptographic evidence attached to nodes within it.

**Lineage** *(normative)*
The chain of parent artifacts, datasets, and training runs that produced a given artifact.
Lineage is represented as a subgraph of the provenance graph and is the primary subject
of training attestations.

**Rollback** *(normative)*
An attested operation that records a corrective transition from a compromised or
deprecated artifact to a prior trusted artifact. Rollback is append-only — it does not
delete prior attestations or signatures. A rollback event is itself a signed record.

---

## Operational Terms

**Signer Identity**
The principal that produced a Sigstore signature, identified by subject (email, workload
identity, SPIFFE ID) and issuer (OIDC provider URI). Signer identity is the basis for
trust constraint evaluation.

**Integrated Time**
The timestamp recorded by the Rekor transparency log when a signature bundle was submitted.
Used for freshness policy evaluation. Distinct from the wall-clock time of signing.

**Assurance Level**
An ordinal tier (`level-1`, `level-2`, `level-3`) that defines a required subset of
AIXV controls. Higher levels require more controls. Levels are not sector-specific
and do not encode regulatory assumptions.

**Conformance**
The property of an implementation that satisfies all normative requirements for a given
assurance level. Conformance is verified by `aixv conformance` and the conformance test suite.

---

## Terminology Rules

- Use these terms consistently across all docs, schema names, and CLI help text.
- Do not introduce synonyms for normative terms without updating this document.
- "Assertion" is not a synonym for "attestation" in AIXV — an assertion is unsigned.
- "Provenance" is not a synonym for "lineage" — provenance is the broader graph;
  lineage is the ancestor chain for a specific artifact.
- "Vulnerability" is not a synonym for "advisory" — an advisory is a claim about
  an artifact's trustworthiness, which may or may not involve a code vulnerability.
