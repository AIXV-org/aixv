<p align="left">
  <img
    src="https://www.aixv.org/AIXV-3.png"
    alt="AIXV logo"
    width="350"
  />
</p>

# AIXV - AI Integrity Exchange & Verification
<!--- @begin-badges@ --->
[![CI](https://github.com/aixv-org/aixv/actions/workflows/ci.yml/badge.svg)](https://github.com/aixv-org/aixv/actions/workflows/ci.yml)
[![Conformance](https://github.com/aixv-org/aixv/actions/workflows/conformance.yml/badge.svg)](https://github.com/aixv-org/aixv/actions/workflows/conformance.yml)
[![CodeQL](https://github.com/aixv-org/aixv/actions/workflows/codeql.yml/badge.svg)](https://github.com/aixv-org/aixv/actions/workflows/codeql.yml)
[![Scorecard Workflow](https://github.com/aixv-org/aixv/actions/workflows/scorecard.yml/badge.svg)](https://github.com/aixv-org/aixv/actions/workflows/scorecard.yml)
[![PyPI version](https://badge.fury.io/py/aixv.svg)](https://pypi.org/project/aixv)
<!--- @end-badges@ --->

AIXV is an open standard for AI artifact attestation, provenance, rollback, compromise detection, and investigation.

In practical terms, AIXV helps organizations answer high-stakes questions before deploying or accepting AI artifacts:
- What exactly is this artifact?
- Who produced or approved it?
- What evidence supports trusting it?
- Is it currently affected by an advisory or policy violation?
- If compromised, what is the safest rollback path?


AIXV is built for three audiences that need shared, verifiable answers:
- Technical teams: deterministic verification and machine-readable admission decisions.
- Enterprise and public-sector risk owners: auditable evidence, policy controls, and incident traceability.
- Policy, governance, and assurance functions: explicit trust assumptions, conformance checks, and compatibility contracts.

AIXV composes Sigstore cryptographic primitives and adds AI-native semantics:
- artifact typing,
- lineage graphs,
- ML-specific attestations,
- advisory/recall workflows,
- and policy-driven verification.

## Release Posture

Current maturity: **Pre-alpha**.

This repository is a functional preview of the AIXV standard, but not yet a final ratified standard release.

### Stable enough for pilot evaluation

- Core primitives and schemas:
  - `SignedRecord` (`aixv.signed-record/v1`)
  - `VerifyPolicy` (`aixv.policy/v1`)
  - `AdmissionDecision`
- Fail-closed verification and policy semantics.
- Deterministic JSON output mode (`--json`) with tested contract behavior.
- CI quality gates (`ruff`, `mypy`, `pytest`, build).

### Still evolving

- Broader conformance vector coverage and certification workflow.
- Formal governance and external audit signals.
- Wider ecosystem integrations and migration tooling.

## Adoption Signals

For security and procurement reviews, the strongest immediate signals are:
- `aixv conformance --json` produces a machine-readable conformance report.
- `docs/THREAT_MODEL.md`, `SECURITY.md`, and `docs/COMPATIBILITY.md` define trust, reporting, and compatibility expectations.
- CI enforces lint, typing, tests, build, and dedicated conformance workflow checks.
- Scorecard and CodeQL workflows provide continuous security posture visibility in GitHub Security.

## Standards and Security Docs

- `docs/AIXV_STANDARD.md`
- `docs/NORMATIVE_CORE.md`
- `docs/QUALITY_BAR.md`
- `docs/THREAT_MODEL.md`
- `SECURITY.md`
- `docs/COMPATIBILITY.md`
- `docs/TERMINOLOGY.md`
- `docs/REGISTRIES.md`
- `docs/PROFILES.md`
- `docs/CONFORMANCE.md`
- `docs/GOVERNANCE.md`
- `docs/REPO_CONTROLS.md`
- `RELEASE.md`

## Installation

```bash
pip install aixv
```

## Quickstart (Core Flow)

```bash
# 1) Sign an artifact
aixv sign model.safetensors --identity-token-env SIGSTORE_ID_TOKEN

# 2) Create and sign a policy record
aixv policy create --input policy.json --sign

# 3) Verify artifact with signed policy + trusted policy signer
aixv verify model.safetensors \
  --policy .aixv/policies/policy.json \
  --policy-trusted-subject security-policy@aixv.org \
  --json

# 4) Run conformance checks
aixv conformance --json
```

## CLI Surface

```bash
aixv version
aixv sign model.safetensors --identity-token-env SIGSTORE_ID_TOKEN
aixv verify model.safetensors --identity alice@example.com --issuer https://accounts.google.com
aixv attest model.safetensors --predicate training --input training.json
aixv provenance model.safetensors --depth 3
aixv advisory create --advisory-id ADV-2026-0001 --severity critical --input advisory.json --sign
aixv advisory verify .aixv/advisories/ADV-2026-0001.json --trusted-subject security@aixv.org
aixv policy create --input policy.json --sign
aixv policy verify .aixv/policies/policy.json --trusted-subject security-policy@aixv.org
aixv record create --kind waiver --record-id WVR-2026-01 --input waiver.json --sign
aixv record verify .aixv/policies/policy.json --kind policy --trusted-subject security-policy@aixv.org
aixv conformance --json
aixv rollback model-v2.safetensors --to sha256:...
aixv export model.safetensors --format in-toto
```

## Policy Example

```json
{
  "policy_type": "aixv.policy/v1",
  "allow_subjects": ["alice@example.com"],
  "allow_issuers": ["https://accounts.google.com"],
  "advisory_allow_subjects": ["security@aixv.org"],
  "max_bundle_age_days": 30,
  "deny_advisory_severity_at_or_above": "high",
  "require_no_active_advisories": false,
  "require_signed_advisories": true
}
```

## Development

```bash
git clone https://github.com/aixv-org/aixv.git
cd aixv
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

## Quality Gates

```bash
ruff check .
ruff format --check .
mypy src
pytest
python -m build
```
