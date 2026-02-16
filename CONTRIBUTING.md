# Contributing to AIXV

Thanks for contributing to AIXV.

## Development Setup

```bash
git clone https://github.com/aixv-org/aixv.git
cd aixv
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
```

## Required Quality Gates

Run these before opening a PR:

```bash
ruff check .
ruff format --check .
mypy src
pytest
python -m build
```

PRs should not merge with failing quality gates.

## Scope and Standards

AIXV is a standards-oriented security project. Keep changes:
- deterministic,
- schema-versioned,
- fail-closed by default,
- and backward-compatible unless a version bump is explicitly proposed.

When adding or changing semantics:
- update `docs/AIXV_STANDARD.md` and relevant supporting docs,
- update `docs/NORMATIVE_CORE.md` when normative behavior changes,
- update `docs/THREAT_MODEL.md` when trust assumptions or adversary model changes,
- update `docs/COMPATIBILITY.md` when compatibility contract assumptions change,
- update `docs/GOVERNANCE.md` when change-control expectations evolve,
- keep `docs/REPO_CONTROLS.md` aligned with required repository settings/checks,
- update conformance fixtures under `docs/conformance/fixtures/` when behavior changes,
- avoid introducing ambiguous terminology; use `docs/TERMINOLOGY.md`.

## Pull Requests

Include in PR description:
- Problem statement.
- Security/trust impact.
- Compatibility impact.
- Test evidence (commands + outcomes).

## Versioning

Version source of truth is `src/aixv/__init__.py`.
Use semantic versioning.

## Release

Tagged releases (`v*.*.*`) are published by GitHub Actions via PyPI trusted publishing.
Follow `RELEASE.md` for release gates and post-release checks.

## Security

Do not commit credentials, tokens, or private keys.
For security-sensitive findings, open a private report through project maintainers.
