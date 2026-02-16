# AIXV Release Process

This process is intentionally strict to preserve trust in published semantics.

## Preconditions

- All relevant docs are updated for semantic changes:
  - `docs/NORMATIVE_CORE.md`
  - `docs/COMPATIBILITY.md`
  - `docs/THREAT_MODEL.md` (if trust assumptions changed)
  - `docs/CONFORMANCE.md` and fixtures (if behavior changed)
- `CHANGELOG.md` (or release notes draft) includes compatibility and migration notes.

## Local Release Gate

Run before creating a tag:

```bash
ruff check .
ruff format --check .
mypy src
pytest
aixv conformance --json
python -m build
```

## Tag and Publish

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

The `publish.yml` workflow reruns release gates and publishes to PyPI through trusted publishing.

## Post-Release

- Verify package exists on PyPI.
- Verify README badges and docs links are healthy.
- Publish concise release notes covering:
  - normative changes,
  - compatibility impact,
  - migration guidance.
