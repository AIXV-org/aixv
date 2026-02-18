# AIXV Design Principles

This document captures the foundational design decisions and philosophy behind AIXV.
It exists to prevent drift. As the project grows, new contributors and new features
will create pressure to make exceptions. This document is the record of why the
current design is the way it is, and the principles that should govern future changes.

Read this before proposing schema changes, new predicate types, or policy semantics.

---

## 1. Honest Evidence Over Formal Completeness

**The principle:** A weak claim that is true is more valuable than a strong claim that
is fabricated to satisfy a schema.

**What this means in practice:**
- Required fields must be things that every legitimate user actually has.
- Optional fields must be things that strengthen the attestation when present.
- The minimum valid attestation should be achievable without special tooling or
  access to information that was not recorded at training time.
- A schema that is too strict to use in the real world will be worked around —
  users will put placeholder values in required fields, which is worse than having
  no attestation at all.

**The test:** Before making a field required, ask: "Can a team attesting a model
they trained six months ago provide this value accurately?" If the answer is "rarely,"
the field should be optional.

**What this does NOT mean:** Permissiveness in descriptive schemas does not imply
permissiveness in security-critical schemas. Policy and advisory schemas must remain
strict because schema drift there creates security vulnerabilities, not just usability
friction.

---

## 2. Separate Identification from Verification

**The principle:** A URI is an identification claim. A digest is a verification claim.
They are different things and must be modeled and documented as such.

**URI (identification):**
- "I claim this artifact came from this location."
- Useful for navigation, display, and human understanding.
- Not cryptographically binding — URIs can change, be deleted, or be redirected.
- Always optional to provide, but valuable when present.

**Digest (verification):**
- "I can prove these exact bytes were used."
- Cryptographically binding — the digest is the identity of the content.
- The join key between the provenance graph and the attestation layer.
- Should be provided whenever the artifact was available at attestation time.

**The implication:** Never require a digest for something that is not a single,
stable, hashable file. Datasets are collections. Git repos are object graphs.
Docker images are manifests over layers. For these, the URI is the primary
identifier; the digest (if present) is supplementary verification.

**The corollary:** Never treat a URI as a verification claim. "I trained on
https://huggingface.co/datasets/allenai/dolma" is a navigation claim, not a
content claim. The dataset at that URL may change. Record the URI for traceability;
record the digest for verifiability. Both are valuable; neither substitutes for
the other.

---

## 3. Tiered Evidence, Not Binary Valid/Invalid

**The principle:** Provenance exists on a spectrum. The system must be able to
represent and reason about partial provenance without treating it as equivalent
to no provenance.

**The three tiers:**

| Tier | What you have | What it proves |
|---|---|---|
| **Described** | Names, URIs, framework strings | Navigation and human understanding |
| **Identified** | Digests of key artifacts | Content integrity for those artifacts |
| **Attested** | Signed, Rekor-logged bundle | Cryptographic proof with identity binding |

Every node in the provenance graph should be able to exist at any tier. A node
at the "Described" tier is not invalid — it is honest about what is known.
A node at the "Attested" tier is the goal state.

**The implication for schemas:** Fields that move a node from Described to
Identified (digests) or from Identified to Attested (signing) should be optional
but clearly documented as the path to higher assurance. The schema should make
it easy to add more evidence over time without invalidating existing attestations.

**The implication for tooling:** The CLI and UI should display the tier of each
node explicitly, so users understand what level of assurance they have and what
they would need to do to increase it.

---

## 4. Security-Critical Schemas Are Strict; Descriptive Schemas Are Permissive

**The principle:** `extra=forbid` is a security control, not a style preference.
Apply it where schema drift creates security vulnerabilities. Do not apply it
where schema drift merely creates inconsistency.

**Strict (extra=forbid):**
- `VerifyPolicy` — schema drift here can silently weaken admission decisions.
- `AdvisoryPredicate` — schema drift here can create false clears or false denials.
- `SignedRecord` — the envelope schema must be stable for verification to work.
- `AdmissionDecision` — the output schema must be stable for automation to rely on it.

**Permissive (extra=allow or extra=ignore):**
- `TrainingRun` — descriptive provenance; teams should be able to record what they
  know without being blocked by fields the schema hasn't anticipated.
- `hyperparameters` — explicitly an untyped bag for training configuration.
- `compute` — GPU type, count, duration, etc. are valuable but not standardizable
  across all training environments.

**The test:** "If an unknown field appears in this schema, does it create a security
risk?" If yes, forbid it. If no, allow it.

---

## 5. Fail-Closed on Security Decisions, Fail-Open on Evidence Collection

**The principle:** The two failure modes are asymmetric and must be treated differently.

**Security decisions (verification, policy, admission):**
- Fail-closed. Missing or invalid inputs produce `deny`, not `allow`.
- An attacker who can cause a verification to fail silently gains nothing.
- An operator who misconfigures a policy gets a loud error, not a silent pass.

**Evidence collection (attestation, provenance, export):**
- Fail-open. Missing fields produce partial attestations, not rejected attestations.
- A publisher who can only provide framework name and parent URI gets a valid
  (if weak) attestation, not a rejection.
- Partial provenance is better than no provenance.

**The corollary:** Never conflate these two modes. Do not apply fail-closed
semantics to evidence collection, and do not apply fail-open semantics to
security decisions.

---

## 6. The Digest Is the Identity; Everything Else Is Metadata

**The principle:** An artifact's identity is its SHA-256 digest. Its name, URI,
version string, and model card are all metadata — useful for humans, not binding
for machines.

**What this means:**
- Two files with the same digest are the same artifact, regardless of their names.
- Two files with different digests are different artifacts, regardless of their names.
- A URI that changes but points to the same bytes is still the same artifact.
- A URI that stays the same but serves different bytes is a different artifact
  (and a potential supply-chain attack).

**The implication for the join key:** The connection between the provenance graph
(TypeScript) and the attestation layer (Python) is `weights.digest`. This is not
a convention — it is the only correct join key. Names, URIs, and version strings
are all mutable. The digest is immutable.

**The implication for git SHAs:** A git commit SHA is not an artifact digest.
It is a reference to a tree object in a git repository. It cannot be used as a
`sha256:<hex>` digest. Record git SHAs in `code_uri` (as `repo@sha`), not in
`code_digest`. `code_digest` is reserved for the SHA-256 of a content-addressed
artifact (e.g., a repo tarball).

---

## 7. Additive Attestation, Append-Only History

**The principle:** Attestations are never deleted or modified. New information is
added as new attestations. Corrections are new records that supersede old ones,
not edits to existing records.

**What this means:**
- A rollback is a new attestation, not a deletion of the old one.
- A corrected advisory is a new advisory with `status: withdrawn` on the old one
  and `status: active` on the new one.
- An updated training predicate is a new attestation for the same artifact digest.
  Both the old and new attestations remain in the store.

**Why:** Append-only history is the foundation of forensic integrity. If attestations
can be deleted, an attacker who compromises the attestation store can erase evidence
of their actions. If attestations can be edited, the Rekor log and the local store
can diverge, breaking verification.

**The corollary:** The attestation store is a log, not a database. Queries over it
should treat it as a log (ordered, append-only) not as a mutable state store.

---

## 8. Governance Is a First-Class Design Concern

**The principle:** A standard without governance is a reference implementation.
Governance is what makes AIXV a standard rather than a tool.

**What governance means for design:**
- Schema changes require explicit versioning (`/v1`, `/v2`), not silent evolution.
- Breaking changes require a migration path, not just a new version.
- The trust roots for policy and advisory verification are operator-configured,
  not AIXV-controlled. AIXV does not have a privileged position in the trust model.
- The conformance test suite is the normative reference, not the implementation.
  If the implementation and the conformance tests disagree, the tests are right.

**What governance means for the project:**
- Design decisions that affect interoperability must be documented in
  `CRITIQUES_AND_DECISIONS.md` with alternatives considered and rationale.
- Terminology must be consistent across all docs, schemas, and CLI output.
  `TERMINOLOGY.md` is the canonical reference.
- The standard must be separable from the implementation. A third party should
  be able to implement AIXV from the docs alone, without reading the Python code.

---

## 9. Interoperability Is a Feature, Not an Afterthought

**The principle:** AIXV attestations must be consumable by systems that have never
heard of AIXV. Export to in-toto, SLSA, SPDX, CycloneDX, and SCITT is not a
nice-to-have — it is how AIXV evidence enters existing security workflows.

**What this means for schema design:**
- AIXV predicate types must map cleanly to existing standards where mappings exist.
  The `training/v1` predicate maps to SLSA `buildDefinition`. The `advisory/v1`
  predicate maps to OpenVEX. These mappings must be maintained as the schemas evolve.
- Fields that have no equivalent in any existing standard should be questioned.
  If AIXV is the only system that understands a field, that field may be premature.
- The in-toto Statement/v1 envelope is the canonical wire format. AIXV does not
  define a custom envelope.

**The corollary:** When a new predicate type is proposed, the first question is:
"What existing standard does this map to?" If the answer is "none," the second
question is: "Is this genuinely novel AI-specific provenance, or is it something
that already exists in software supply chain standards?"

---

## 10. The Provenance Graph and the Attestation Layer Are Complementary, Not Redundant

**The principle:** The TypeScript provenance graph (track.aixv.org) and the Python
attestation package serve different purposes and must not be collapsed into one.

**The graph layer:**
- Human-readable, navigable representation of training lineage.
- Declarative — describes what happened based on public information.
- Operates on template data (TypeScript objects), not artifact files.
- Does not require cryptographic operations.
- Every node is valid; attestation is additive.

**The attestation layer:**
- Machine-readable, cryptographically verifiable proof of claims.
- Imperative — requires artifact access, signing identity, and Rekor connectivity.
- Operates on artifact files and digests.
- Requires cryptographic operations.
- Attestation is the goal state, not the prerequisite.

**The join key:** `weights.digest` is the only correct connection between the two
layers. The graph node's digest must match the attestation's subject digest exactly.

**What this means for future development:** Do not add graph topology logic to the
Python package. Do not add cryptographic operations to the TypeScript app. The
boundary is the digest — everything on the graph side of the digest is description;
everything on the attestation side is proof.

---

## Applying These Principles

When evaluating a proposed change, run it through these questions:

1. **Evidence:** Does this make honest weak evidence possible, or does it require
   strong evidence that most users won't have?
2. **Identification vs verification:** Does this conflate URIs with digests?
3. **Tiering:** Does this allow partial provenance, or does it require completeness?
4. **Strictness:** Is this a security-critical schema (strict) or a descriptive
   schema (permissive)?
5. **Failure mode:** Is this a security decision (fail-closed) or evidence collection
   (fail-open)?
6. **Identity:** Is the digest the identity, or is something mutable being treated
   as identity?
7. **Append-only:** Does this require mutation of existing records?
8. **Governance:** Does this change require a new schema version?
9. **Interoperability:** What existing standard does this map to?
10. **Layer boundary:** Does this respect the graph/attestation separation?

If a proposed change violates more than one of these principles, it needs significant
redesign before it should be considered. If it violates principle 1 (honest evidence),
it should be rejected outright — a standard that cannot be used honestly is not a standard.
