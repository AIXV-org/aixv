import json
from pathlib import Path

from typer.testing import CliRunner

from aixv.cli import app

runner = CliRunner()


FIXTURE_FILES = {
    "policy.valid.json": {
        "policy_type": "aixv.policy/v1",
        "allow_subjects": ["alice@example.com"],
        "allow_issuers": ["https://accounts.google.com"],
        "require_signed_advisories": True,
    },
    "policy.invalid.no_subjects.json": {
        "policy_type": "aixv.policy/v0",
        "allow_subjects": [],
        "allow_issuers": ["https://accounts.google.com"],
        "require_signed_advisories": True,
    },
    "record.policy.sample.json": {
        "schema": "aixv.signed-record/v1",
        "kind": "policy",
        "record_id": "policy-main",
        "created_at": "2026-02-16T00:00:00+00:00",
        "payload": {
            "policy_type": "aixv.policy/v1",
            "allow_subjects": ["alice@example.com"],
        },
        "signature_bundle_path": None,
    },
}


def _write_fixtures(root: Path) -> None:
    fixtures_dir = root / "docs" / "conformance" / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    for filename, payload in FIXTURE_FILES.items():
        (fixtures_dir / filename).write_text(json.dumps(payload), encoding="utf-8")


def test_conformance_command_passes_with_required_fixtures() -> None:
    with runner.isolated_filesystem():
        root = Path.cwd()
        _write_fixtures(root)

        result = runner.invoke(app, ["conformance", "--json"])
        assert result.exit_code == 0

        payload = json.loads(result.stdout)
        assert payload["ok"] is True
        assert payload["schema"] == "aixv.conformance-report/v1"
        assert payload["overall_status"] == "pass"
        check_ids = {c["check_id"] for c in payload["checks"]}
        assert "policy.unknown-field.reject.v1" in check_ids
        assert "policy.advisory-trust.subject-fallback.v1" in check_ids
        assert "advisory.signed-policy.filtering.v1" in check_ids


def test_conformance_command_fails_when_fixtures_missing() -> None:
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["conformance", "--json"])
        assert result.exit_code == 1

        payload = json.loads(result.stdout)
        assert payload["ok"] is False
        assert payload["overall_status"] == "fail"
        check_ids = {c["check_id"] for c in payload["checks"]}
        assert "fixtures.exist.v1" in check_ids
