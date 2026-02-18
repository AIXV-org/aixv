# AIXV Provenance Bridge

**Compatibility contract between the TypeScript provenance graph (`aixv-provenance-app`)
and the Python attestation package (`aixv`).**

This document is the authoritative reference for developers working across both systems.
Read it before touching either `types.ts`, `build-graph.ts`, or `core.py`.

---

## The Two Systems

| | Provenance App (TypeScript) | Python Package (`pip install aixv`) |
|---|---|---|
| **Repo** | `aixv-provenance-app` | `aixv` |
| **Live at** | track.aixv.org | pypi.org/project/aixv |
| **Role** | Human-readable, navigable graph | Cryptographic operations layer |
| **Describes** | What happened (stages, steps, edges) | Proves what happened (signs, verifies) |
| **Operates on** | Template data (TypeScript objects) | Artifact files + digests |
| **Output** | React graph + export formats | Sigstore bundles + attestation records |

They are **complementary layers**, not duplicates. The app is the UI and export surface.
The package is the cryptographic substrate that makes the app's claims verifiable.

---

## The Join Key

**`weights.digest` (TypeScript) ↔ `sha256_file()` (Python)**

Every artifact node in the provenance graph that represents a model weight file MAY carry
a `weights.digest` field. This field is the SHA-256 digest of the actual weight file bytes,
in `"sha256:<hex>"` form.

The Python package's `sha256_file(path)` produces the same format. When these values match,
a graph node is cryptographically grounded — the visual representation and the signed
attestation refer to the same bytes.

```
TypeScript template                    Python package
──────────────────                     ──────────────
weights: {
  digest: "sha256:f6eab253...",   ←→   sha256_file(Path("openelm-3b.safetensors"))
  uri: "https://hf.co/...",       ←→   ParentModel(digest=..., uri=...)
  attestationBundleUri: "...",    ←→   attest_provenance_node(...) → result["attestation_bundle_uri"]
}
```

### Critical: digest ≠ git commit SHA

The `source.revision` field in templates (e.g. `OPENELM_3B_SHA = "f6eab253..."`) is a
**git commit hash**, not a SHA-256 of the weight file bytes. These are different things.

- `source.revision` → git tree reference, used for `HF_MODEL_TREE()` URLs
- `weights.digest` → SHA-256 of the actual `.safetensors` / `.bin` file bytes

Only populate `weights.digest` when you have computed the real file digest.
Never copy a git commit SHA into `weights.digest`.

---

## The Three Integration Points

### 1. Subject Identity (`weights.digest` + `weights.uri`)

`build-graph.ts` automatically extracts `weights.digest` and `weights.uri` from every
artifact node and writes them into `metadata.aixv.subject`:

```typescript
// After build-graph runs, every artifact node with weights.digest has:
node.data.metadata.aixv = {
  subject: {
    digest: { sha256: "f6eab253..." },  // from weights.digest
    uri: "https://hf.co/apple/OpenELM-3B/tree/f6eab253...",  // from weights.uri
  },
  // ... other aixv fields
}
```

The Python package's `ProvenanceNodeSubject` mirrors this shape:

```python
from aixv import ProvenanceNodeSubject

subject = ProvenanceNodeSubject(
    digest="sha256:f6eab253...",   # must match weights.digest in the template
    uri="https://hf.co/apple/OpenELM-3B/tree/f6eab253...",
    name="OpenELM-3B",
)
```

### 2. Attestation Bundles (`weights.attestationBundleUri`)

When a node is cryptographically attested, the Sigstore bundle URI is stored in
`weights.attestationBundleUri` (TypeScript) / `metadata.aixv.attestationBundleUri`
(after build-graph runs).

**Setting it in a template:**
```typescript
// In a PipelineTemplate step:
weights: {
  kind: "checkpoint",
  role: "base",
  uri: "https://hf.co/apple/OpenELM-3B/tree/f6eab253...",
  digest: "sha256:f6eab253...",
  attestationBundleUri: "https://attestations.aixv.org/openelm-3b.training.v1.sigstore.json",
}
```

**Generating it with the Python package:**
```python
from pathlib import Path
from aixv import ProvenanceNodeSubject, attest_provenance_node
from aixv.core import TrainingPredicate, ParentModel, DatasetRef, TrainingRun

subject = ProvenanceNodeSubject(
    digest="sha256:f6eab253...",
    uri="https://hf.co/apple/OpenELM-3B/tree/f6eab253...",
    name="OpenELM-3B",
)
predicate = TrainingPredicate(
    parent_models=[ParentModel(digest="sha256:<parent-digest>", uri="...")],
    datasets=[DatasetRef(digest="sha256:<dataset-digest>")],
    training_run=TrainingRun(
        framework="PyTorch",
        framework_version="2.3.0",
        code_digest="sha256:<corenet-commit-hash-as-sha256>",
        environment_digest="sha256:<env-digest>",
    ),
)
result = attest_provenance_node(
    root=Path("."),
    subject=subject,
    predicate_uri="training",
    predicate_payload=predicate.model_dump(),
    identity_token_env="SIGSTORE_ID_TOKEN",
)
# result["attestation_bundle_uri"] → set as weights.attestationBundleUri in the template
print(result["attestation_bundle_uri"])
```

### 3. Incidents and Advisories (`IncidentCase` ↔ `AdvisoryPredicate`)

The app's `IncidentCase.affectedNodeIds` maps to the Python package's
`AdvisoryPredicate.affected[].digest` via `weights.digest`.

When an advisory is issued for a model:
1. Python: `AdvisoryPredicate(affected=[AdvisoryAffected(digest="sha256:f6eab253...")], ...)`
2. App: `IncidentCase(affectedNodeIds: ["tmpl-apple-openelm-openelm-3b-base"], ...)`

The connection: the node with id `tmpl-apple-openelm-openelm-3b-base` has
`weights.digest = "sha256:f6eab253..."`, which matches the advisory's `affected[].digest`.

---

## Typed Interfaces

### TypeScript (`types.ts`)

```typescript
// The cryptographic subject identity for an artifact node.
// Populated automatically by build-graph from weights.digest / weights.uri.
type AixvSubject = {
  digest?: { sha256: string };  // SHA-256 hex, no prefix
  uri?: string;
};

// Typed shape of metadata.aixv on every artifact node.
type AixvNodeMetadata = {
  subject?: AixvSubject;
  primary?: boolean;
  deliverableId?: string;
  deliverableLabel?: string;
  attestationBundleUri?: string;  // ← the attestation link
};

// On ModelWeights:
type ModelWeights = {
  // ...
  digest?: string;                  // "sha256:<hex>" — the join key
  attestationBundleUri?: string;    // URI of the Sigstore bundle
};
```

**Reading `metadata.aixv` safely:**
```typescript
import type { AixvNodeMetadata } from "@/lib/provenance/types";

const aixv = node.data.metadata.aixv as AixvNodeMetadata | undefined;
const isAttested = Boolean(aixv?.attestationBundleUri);
const digest = aixv?.subject?.digest?.sha256;
```

### Python (`core.py`)

```python
# Mirror of AixvSubject — the join key between the two systems.
subject = ProvenanceNodeSubject(
    digest="sha256:<hex>",   # must match weights.digest in the TypeScript template
    uri="https://...",       # optional but recommended
    name="ModelName",        # used as in-toto subject name
)

# Build a statement without a local file:
statement = make_provenance_node_statement(subject, "training", predicate.model_dump())

# Build, sign, and store in one call:
result = attest_provenance_node(root=Path("."), subject=subject, ...)
```

---

## Node Attestation States

Every artifact node in the graph is in one of three states:

| State | `weights.digest` | `weights.attestationBundleUri` | Meaning |
|---|---|---|---|
| **Described** | absent | absent | Navigable, sourced from public info, not cryptographically grounded |
| **Identified** | present | absent | Digest known, not yet attested |
| **Attested** | present | present | Cryptographically signed by AIXV or the publisher |

The UI should render these states distinctly. "Attested" nodes are the goal state.
"Identified" nodes are the intermediate state during AIXV-side attestation generation.
"Described" nodes are valid and useful — most historical models will remain here.

---

## Rules for Template Authors

1. **Never put a git commit SHA in `weights.digest`.** Use `source.revision` for git refs.
   Only put a real `sha256:<hex>` file digest in `weights.digest`.

2. **`weights.uri` should be a stable, content-addressed URL** when possible.
   HuggingFace tree URLs with a pinned commit SHA are acceptable:
   `https://huggingface.co/apple/OpenELM-3B/tree/f6eab253...`

3. **`weights.attestationBundleUri` is optional.** Omit it until you have a real bundle.
   Do not set it to a placeholder or a URL that doesn't resolve.

4. **`weights.digest` is the join key.** If you set it, it must match the actual file
   digest. If you're not sure, leave it absent rather than guessing.

5. **`specificFields` with `source.revision` is for display only.** It does not affect
   the cryptographic subject. Only `weights.digest` does.

---

## Rules for Python Package Users

1. **`ProvenanceNodeSubject.digest` must match `weights.digest` in the template.**
   Copy it exactly, including the `sha256:` prefix.

2. **Use `attest_provenance_node()` for published models** (where you have the digest
   but not necessarily the local file). Use `make_statement()` + `sign_artifact_with_sigstore()`
   for local files you're signing directly.

3. **The returned `attestation_bundle_uri`** from `attest_provenance_node()` is what you
   set as `weights.attestationBundleUri` in the TypeScript template. It's a file URI by
   default; publish it to a stable HTTPS URL before putting it in the template.

4. **Validate predicates before attesting.** `attest_provenance_node()` validates the
   predicate payload automatically. If validation fails, no bundle is written.

5. **`sign=False` is useful for testing.** It writes an unsigned attestation record to
   `.aixv/attestations/` without requiring a Sigstore identity token.

---

## End-to-End Flow: Attesting a Published Model

```
1. Identify the model in the TypeScript template
   └─ Find the step with the model artifact (e.g. "openelm-3b-base")
   └─ Note weights.uri (the HuggingFace URL)

2. Compute the weight file digest (if not already known)
   └─ Download the .safetensors file
   └─ Run: python -c "from aixv.core import sha256_file; from pathlib import Path; print(sha256_file(Path('model.safetensors')))"
   └─ This gives you "sha256:<hex>"

3. Set weights.digest in the template
   └─ Add digest: "sha256:<hex>" to the weights object in the TypeScript template

4. Run attest_provenance_node() in Python
   └─ Construct ProvenanceNodeSubject with the same digest
   └─ Build TrainingPredicate with parent_models, datasets, training_run
   └─ Call attest_provenance_node(root=..., subject=..., predicate_uri="training", ...)
   └─ Get back result["attestation_bundle_uri"]

5. Publish the bundle
   └─ Upload the .sigstore.json bundle to a stable HTTPS URL
   └─ (Or serve it from the AIXV attestation store)

6. Set weights.attestationBundleUri in the template
   └─ Add attestationBundleUri: "https://..." to the weights object
   └─ The node is now "attested" in the UI

7. Commit and deploy
   └─ The provenance graph now shows the node as cryptographically attested
   └─ Consumers can verify the bundle with: aixv verify <artifact> --bundle <bundle>
```

---

## What NOT to Do

- **Don't make TypeScript templates generate Python attestations.** Templates are
  declarative descriptions of historical events. Attestations require signing keys
  and live artifact access. Keep these concerns separate.

- **Don't make the Python package understand graph topology.** The package operates
  on individual artifacts and their digests. Graph structure (which node depends on
  which) is the app's concern.

- **Don't require `weights.digest` on every node.** Many historical models don't have
  easily-computable file digests. The integration is additive — nodes with digests get
  cryptographic grounding; nodes without remain navigable but unattested.

- **Don't use `metadata.aixv` as a general-purpose bag.** It has a defined schema
  (`AixvNodeMetadata`). Use `metadata` (the untyped bag) for template-specific data.

- **Don't set `attestationBundleUri` to a URL that doesn't resolve.** The UI will
  attempt to fetch or display it. Only set it when the bundle is published and stable.
