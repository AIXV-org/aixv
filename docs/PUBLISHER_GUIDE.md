# AIXV Publisher Guide

**How to add cryptographic provenance attestations to your model release.**

This guide is for teams that publish open AI models and want to make their training
lineage machine-readable, verifiable, and indexed on [track.aixv.org](https://track.aixv.org).

It takes about 30 minutes for a first attestation. Subsequent releases take under 5 minutes
once the pipeline is set up.

---

## What you get

- A signed, Rekor-logged attestation that cryptographically binds your model weights to
  their training lineage (parent models, datasets, training run).
- A provenance graph entry on track.aixv.org showing your model's full pipeline,
  navigable by anyone.
- Machine-readable export in 35+ formats: in-toto, SLSA, SPDX, CycloneDX, SCITT,
  OpenVEX, SARIF, MITRE ATT&CK, NIST AI RMF, and more.
- A verifiable record that downstream users, auditors, and procurement teams can check
  independently — without trusting you or AIXV.

---

## Prerequisites

```bash
pip install aixv
```

You need a signing identity. The simplest option is a GitHub Actions OIDC token
(no keys to manage). You can also use any OIDC provider (Google, GitHub, GitLab, etc.)
or a service account.

---

## Step 1: Compute your model's digest

The digest is the SHA-256 hash of the actual weight file bytes. This is the join key
that links your model to its attestation — it must be the real file hash, not a git
commit SHA or a HuggingFace revision.

```bash
# From the command line:
python3 -c "
from pathlib import Path
from aixv.core import sha256_file
print(sha256_file(Path('your-model.safetensors')))
"
# Output: sha256:f6eab253...
```

Save this value. You'll use it in the next step and in your model card.

---

## Step 2: Prepare your training predicate

Create a `training.json` file describing your model's lineage:

```json
{
  "parent_models": [
    {
      "digest": "sha256:<hex-of-parent-weights>",
      "uri": "https://huggingface.co/org/parent-model"
    }
  ],
  "datasets": [
    {
      "digest": "sha256:<hex-of-dataset>",
      "uri": "https://huggingface.co/datasets/org/dataset",
      "split": "train"
    }
  ],
  "training_run": {
    "framework": "PyTorch",
    "framework_version": "2.3.0",
    "code_digest": "sha256:<hex-of-training-code-commit>",
    "environment_digest": "sha256:<hex-of-container-image>"
  }
}
```

**Notes:**
- `parent_models`: include every model your weights were initialized from. For a model
  trained from scratch, this array is empty.
- `datasets`: include every dataset used in training. Use the actual file digest if
  you have it; the URI alone is acceptable for a first attestation.
- `training_run.code_digest`: the SHA-256 of your training code. If you use GitHub,
  you can use the commit SHA converted to a digest, or hash your training script.
- All digests use `sha256:<hex>` format. Unknown values can be omitted — partial
  provenance is better than no provenance.

---

## Step 3: Create and sign the attestation

```bash
# Sign and attest in one command:
aixv attest your-model.safetensors \
  --predicate training \
  --input training.json \
  --identity-token-env SIGSTORE_ID_TOKEN
```

This produces:
- A Sigstore bundle (`.sigstore.json`) logged in Rekor — permanent, public, verifiable.
- An attestation record in `.aixv/attestations/`.

**In GitHub Actions:**

```yaml
- name: Attest model
  env:
    SIGSTORE_ID_TOKEN: ${{ steps.auth.outputs.id_token }}
  run: |
    pip install aixv
    aixv attest your-model.safetensors \
      --predicate training \
      --input training.json \
      --identity-token-env SIGSTORE_ID_TOKEN
```

---

## Step 4: Publish the bundle alongside your weights

Upload the `.sigstore.json` bundle to HuggingFace alongside your model files.
Name it consistently: `<model-name>.training.sigstore.json`.

```bash
# Using huggingface_hub:
huggingface-cli upload org/model-name \
  your-model.training.sigstore.json \
  your-model.training.sigstore.json
```

The bundle URL becomes the `attestationBundleUri` that AIXV Track displays on your
model's provenance graph node.

---

## Step 5: Add an AIXV section to your model card

Add this to your `README.md` on HuggingFace:

```markdown
## Provenance & Attestation

This model's training lineage is cryptographically attested via [AIXV](https://aixv.org).

- **Provenance graph**: [track.aixv.org/?dataset=your-org-your-model](https://track.aixv.org/?dataset=your-org-your-model)
- **Artifact digest**: `sha256:<your-model-digest>`
- **Attestation bundle**: [your-model.training.sigstore.json](https://huggingface.co/your-org/your-model/blob/main/your-model.training.sigstore.json)

Verify independently:
\`\`\`bash
pip install aixv
aixv verify your-model.safetensors \
  --bundle your-model.training.sigstore.json \
  --identity your-ci@your-org.com
\`\`\`
```

---

## Step 6: Notify AIXV

Email [winston@aixv.org](mailto:winston@aixv.org) with:
- Your model name and HuggingFace URL
- The artifact digest
- The bundle URL

AIXV will update your provenance graph entry on track.aixv.org to show the node
as "attested" and link to the bundle. This typically happens within 24 hours.

---

## Verification (for downstream users)

Anyone can verify your attestation independently:

```bash
pip install aixv

# Verify the artifact matches its signed attestation:
aixv verify your-model.safetensors \
  --bundle your-model.training.sigstore.json \
  --identity your-ci@your-org.com \
  --issuer https://token.actions.githubusercontent.com \
  --json
```

Output:
```json
{
  "ok": true,
  "digest": "sha256:f6eab253...",
  "actual_subjects": ["your-ci@your-org.com"],
  "actual_issuer": "https://token.actions.githubusercontent.com",
  "integrated_time": "2026-02-17T..."
}
```

---

## Frequently asked questions

**Do I need to share my training data?**
No. The attestation records digests and URIs — not the data itself. If your dataset
is private, you can omit the URI and include only the digest (or omit the digest too,
and just record the dataset name as a string in the metadata field).

**What if I don't have all the digests?**
Partial provenance is valid and useful. Include what you have. A training attestation
with only the parent model digest and the framework version is still more verifiable
than no attestation at all.

**Does this require any changes to my training pipeline?**
No changes to training. You run `aixv attest` after training completes, as a release
step. The only requirement is that you have the weight file available when you run it.

**What if my model was trained from scratch (no parent model)?**
Set `parent_models` to an empty array `[]`. The attestation still records your datasets
and training run, which is the most valuable provenance for a base model.

**Is this compatible with HuggingFace's existing model cards?**
Yes. The AIXV section is additive — it doesn't replace anything in your existing model
card. The provenance graph on track.aixv.org links back to your HuggingFace page.

**Who controls the attestation?**
You do. The attestation is signed with your identity (your CI system's OIDC token).
AIXV does not sign on your behalf — it provides the tooling and the graph index.
The cryptographic proof is yours.

---

## Questions

[winston@aixv.org](mailto:winston@aixv.org) · [aixv.org](https://aixv.org) · [track.aixv.org](https://track.aixv.org)
