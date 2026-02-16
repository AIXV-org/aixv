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

## PyPI Immutability Rule

PyPI does not allow reusing a filename once it has existed, even if that file/version is later deleted.

- Never delete published files expecting to reuse the same version.
- If a publish attempt fails after artifacts are uploaded, bump to a new version and retag.
- Keep `skip-existing: true` in publish workflow to make reruns safe for partially uploaded attempts.

## Post-Release

- Verify package exists on PyPI.
- Verify README badges and docs links are healthy.
- Publish concise release notes covering:
  - normative changes,
  - compatibility impact,
  - migration guidance.
