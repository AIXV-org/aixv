# AIXV Repository Controls

This document defines the minimum repository controls for serious production and procurement review.

## Required Branch Protection (`main`)

- Require pull request before merge.
- Require at least 2 approvals.
- Dismiss stale approvals when new commits are pushed.
- Require conversation resolution before merge.
- Require status checks to pass before merge.
- Require branch up to date before merge.
- Restrict force pushes and deletion.

## Required Status Checks

- `CI / quality (3.10)`
- `CI / quality (3.12)`
- `Conformance / conformance`
- `Scorecard / analysis`
- `CodeQL / Analyze (Python)`

## Release and Package Controls

- Publish only from signed tags matching `v*.*.*`.
- Gate publish on lint, format, typing, tests, conformance, and build.
- Use PyPI trusted publishing (`id-token`), no API tokens in secrets.
- Protect release tags in repository settings.

## Security Controls

- Enable GitHub code scanning and secret scanning.
- Require Dependabot security updates for direct dependencies.
- Keep `SECURITY.md` disclosure and response guidance current.

## Operations Checklist

- Quarterly: validate branch protection and required checks.
- Quarterly: review GitHub action versions and upgrade.
- Every release: confirm all release gates passed in workflow logs.
