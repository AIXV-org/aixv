import json
from pathlib import Path

from typer.testing import CliRunner

from aixv.cli import app

runner = CliRunner()


def test_version_json_contract() -> None:
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert isinstance(payload["version"], str)


def test_record_create_emits_signed_record_shape() -> None:
    with runner.isolated_filesystem():
        payload_path = Path("waiver.json")
        payload_path.write_text(
            json.dumps({"reason": "temporary exception", "expires_at": "2026-03-01T00:00:00Z"}),
            encoding="utf-8",
        )

        result = runner.invoke(
            app,
            [
                "record",
                "create",
                "--kind",
                "waiver",
                "--record-id",
                "WVR-1",
                "--input",
                str(payload_path),
                "--json",
            ],
        )
        assert result.exit_code == 0
        out = json.loads(result.stdout)
        record_path = Path(out["path"])
        assert record_path.exists()

        record = json.loads(record_path.read_text(encoding="utf-8"))
        assert record["schema"] == "aixv.signed-record/v1"
        assert record["kind"] == "waiver"
        assert record["record_id"] == "WVR-1"
        assert record["payload"]["reason"] == "temporary exception"


def test_policy_create_rejects_invalid_policy_payload() -> None:
    with runner.isolated_filesystem():
        invalid_policy = Path("policy.invalid.json")
        invalid_policy.write_text(
            json.dumps({"policy_type": "aixv.policy/v0", "allow_subjects": ["alice@example.com"]}),
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            ["policy", "create", "--input", str(invalid_policy), "--json"],
        )
        assert result.exit_code == 1
        out = json.loads(result.stdout)
        assert out["ok"] is False
        assert out["command"] == "policy create"


def test_policy_verify_requires_trusted_subject_constraints() -> None:
    with runner.isolated_filesystem():
        policy_record = {
            "schema": "aixv.signed-record/v1",
            "kind": "policy",
            "record_id": "policy-main",
            "created_at": "2026-02-16T00:00:00+00:00",
            "payload": {
                "policy_type": "aixv.policy/v1",
                "allow_subjects": ["alice@example.com"],
            },
            "signature_bundle_path": "policy.bundle.json",
        }
        Path("policy.json").write_text(json.dumps(policy_record), encoding="utf-8")
        Path("policy.bundle.json").write_text("{}", encoding="utf-8")

        result = runner.invoke(app, ["policy", "verify", "policy.json", "--json"])
        assert result.exit_code == 1
        out = json.loads(result.stdout)
        assert out["ok"] is False
        assert out["command"] == "policy verify"
        assert "trusted subject constraints required" in out["error"]


def test_verify_missing_bundle_json_failure_contract() -> None:
    with runner.isolated_filesystem():
        Path("model.safetensors").write_bytes(b"hello")
        result = runner.invoke(
            app, ["verify", "model.safetensors", "--identity", "alice@example.com", "--json"]
        )
        assert result.exit_code == 1

        payload = json.loads(result.stdout)
        assert payload == {
            "command": "verify",
            "error": "bundle not found: model.safetensors.sigstore.json",
            "ok": False,
        }


def test_advisory_verify_rejects_non_advisory_record() -> None:
    with runner.isolated_filesystem():
        policy_record = {
            "schema": "aixv.signed-record/v1",
            "kind": "policy",
            "record_id": "policy-main",
            "created_at": "2026-02-16T00:00:00+00:00",
            "payload": {
                "policy_type": "aixv.policy/v1",
                "allow_subjects": ["alice@example.com"],
            },
            "signature_bundle_path": "policy.bundle.json",
        }
        Path("policy.json").write_text(json.dumps(policy_record), encoding="utf-8")

        result = runner.invoke(app, ["advisory", "verify", "policy.json", "--json"])
        assert result.exit_code == 1
        out = json.loads(result.stdout)
        assert out["ok"] is False
        assert out["command"] == "advisory verify"
        assert "expected record kind advisory" in out["error"]


def test_provenance_require_signed_attestations_needs_trusted_subjects() -> None:
    with runner.isolated_filesystem():
        Path("model.safetensors").write_bytes(b"hello")
        result = runner.invoke(
            app,
            [
                "provenance",
                "model.safetensors",
                "--require-signed-attestations",
                "--json",
            ],
        )
        assert result.exit_code == 1
        out = json.loads(result.stdout)
        assert out["ok"] is False
        assert out["command"] == "provenance"
        assert "signed attestation verification requires" in out["error"]


def test_export_require_signed_attestations_needs_trusted_subjects() -> None:
    with runner.isolated_filesystem():
        Path("model.safetensors").write_bytes(b"hello")
        result = runner.invoke(
            app,
            [
                "export",
                "model.safetensors",
                "--format",
                "in-toto",
                "--require-signed-attestations",
                "--json",
            ],
        )
        assert result.exit_code == 1
        out = json.loads(result.stdout)
        assert out["ok"] is False
        assert out["command"] == "export"
        assert "signed attestation verification requires" in out["error"]


def test_rollback_default_signed_requires_identity_token() -> None:
    with runner.isolated_filesystem():
        Path("model.safetensors").write_bytes(b"hello")
        result = runner.invoke(
            app,
            ["rollback", "model.safetensors", "--to", "sha256:abc", "--json"],
        )
        assert result.exit_code == 1
        out = json.loads(result.stdout)
        assert out["ok"] is False
        assert out["command"] == "rollback"
        assert "missing OIDC token" in out["error"]


def test_rollback_no_sign_emits_plain_record() -> None:
    with runner.isolated_filesystem():
        Path("model.safetensors").write_bytes(b"hello")
        result = runner.invoke(
            app,
            [
                "rollback",
                "model.safetensors",
                "--to",
                "sha256:abc",
                "--no-sign",
                "--json",
            ],
        )
        assert result.exit_code == 0
        out = json.loads(result.stdout)
        assert out["ok"] is True
        assert out["signed"] is False
        path = Path(out["rollback_record_path"])
        assert path.exists()
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["event_type"] == "rollback"


def test_verify_level_2_requires_policy() -> None:
    with runner.isolated_filesystem():
        Path("model.safetensors").write_bytes(b"hello")
        Path("model.safetensors.sigstore.json").write_text("{}", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "verify",
                "model.safetensors",
                "--identity",
                "alice@example.com",
                "--assurance-level",
                "level-2",
                "--json",
            ],
        )
        assert result.exit_code == 1
        out = json.loads(result.stdout)
        assert out["ok"] is False
        assert out["command"] == "verify"
        assert "requires --policy" in out["error"]


def test_provenance_impact_and_explain_views() -> None:
    with runner.isolated_filesystem():
        Path("model.safetensors").write_bytes(b"hello")
        impact_result = runner.invoke(
            app,
            [
                "provenance",
                "model.safetensors",
                "--view",
                "impact",
                "--json",
            ],
        )
        assert impact_result.exit_code == 0
        impact_payload = json.loads(impact_result.stdout)
        assert impact_payload["view"] == "impact"
        assert isinstance(impact_payload["descendants"], list)

        explain_result = runner.invoke(
            app,
            [
                "provenance",
                "model.safetensors",
                "--view",
                "explain",
                "--json",
            ],
        )
        assert explain_result.exit_code == 0
        explain_payload = json.loads(explain_result.stdout)
        assert explain_payload["view"] == "explain"
        assert isinstance(explain_payload["explain"], list)


def test_export_slsa_and_ml_bom_shapes() -> None:
    with runner.isolated_filesystem():
        Path("model.safetensors").write_bytes(b"hello")

        slsa = runner.invoke(
            app,
            ["export", "model.safetensors", "--format", "slsa", "--json"],
        )
        assert slsa.exit_code == 0
        slsa_payload = json.loads(slsa.stdout)
        assert slsa_payload["ok"] is True
        assert slsa_payload["export"]["format"] == "slsa"
        assert "provenance" in slsa_payload["export"]

        ml_bom = runner.invoke(
            app,
            ["export", "model.safetensors", "--format", "ml-bom", "--json"],
        )
        assert ml_bom.exit_code == 0
        ml_bom_payload = json.loads(ml_bom.stdout)
        assert ml_bom_payload["ok"] is True
        assert ml_bom_payload["export"]["format"] == "ml-bom"
        assert "bom" in ml_bom_payload["export"]


def test_bundle_create_validates_and_normalizes_members() -> None:
    with runner.isolated_filesystem():
        payload = {
            "bundle_type": "aixv.bundle/v1",
            "bundle_id": "bundle-main",
            "primary": "1" * 64,
            "members": [f"sha256:{'2' * 64}"],
        }
        Path("bundle.json").write_text(json.dumps(payload), encoding="utf-8")
        result = runner.invoke(
            app,
            ["bundle", "create", "--input", "bundle.json", "--json"],
        )
        assert result.exit_code == 0
        out = json.loads(result.stdout)
        record = json.loads(Path(out["path"]).read_text(encoding="utf-8"))
        assert record["kind"] == "bundle"
        members = record["payload"]["members"]
        assert f"sha256:{'1' * 64}" in members
        assert f"sha256:{'2' * 64}" in members


def test_bundle_verify_requires_trusted_subject_constraints() -> None:
    with runner.isolated_filesystem():
        bundle_record = {
            "schema": "aixv.signed-record/v1",
            "kind": "bundle",
            "record_id": "bundle-main",
            "created_at": "2026-02-16T00:00:00+00:00",
            "payload": {
                "bundle_type": "aixv.bundle/v1",
                "bundle_id": "bundle-main",
                "primary": f"sha256:{'1' * 64}",
                "members": [f"sha256:{'1' * 64}", f"sha256:{'2' * 64}"],
            },
            "signature_bundle_path": "bundle.sigstore.json",
        }
        Path("bundle.record.json").write_text(json.dumps(bundle_record), encoding="utf-8")
        Path("bundle.sigstore.json").write_text("{}", encoding="utf-8")
        result = runner.invoke(
            app,
            ["bundle", "verify", "bundle.record.json", "--json"],
        )
        assert result.exit_code == 1
        out = json.loads(result.stdout)
        assert out["ok"] is False
        assert out["command"] == "bundle verify"
        assert "trusted subject constraints required" in out["error"]


def test_policy_template_level_3_requires_max_bundle_age() -> None:
    result = runner.invoke(
        app,
        ["policy", "template", "--assurance-level", "level-3", "--json"],
    )
    assert result.exit_code == 1
    out = json.loads(result.stdout)
    assert out["ok"] is False
    assert out["command"] == "policy template"
    assert "max-bundle-age-days" in out["error"]


def test_policy_migrate_level_3_requires_bundle_age_if_missing() -> None:
    with runner.isolated_filesystem():
        Path("policy.json").write_text(
            json.dumps(
                {
                    "policy_type": "aixv.policy/v1",
                    "allow_subjects": ["alice@example.com"],
                }
            ),
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "policy",
                "migrate",
                "--input",
                "policy.json",
                "--to-assurance-level",
                "level-3",
                "--json",
            ],
        )
        assert result.exit_code == 1
        out = json.loads(result.stdout)
        assert out["ok"] is False
        assert out["command"] == "policy migrate"
        assert "max_bundle_age_days" in out["error"]


def test_advisory_sync_rejects_replay_integrated_time(monkeypatch) -> None:
    with runner.isolated_filesystem():
        advisory_record = {
            "schema": "aixv.signed-record/v1",
            "kind": "advisory",
            "record_id": "ADV-2026-0001",
            "created_at": "2026-02-16T00:00:00+00:00",
            "payload": {
                "advisory_id": "ADV-2026-0001",
                "affected": [{"digest": f"sha256:{'1' * 64}"}],
                "severity": "high",
                "status": "active",
                "reason_code": "model-compromise",
                "recommended_actions": ["rollback"],
            },
            "signature_bundle_path": None,
        }
        Path("remote-advisory.json").write_text(json.dumps(advisory_record), encoding="utf-8")
        Path("remote-advisory.sigstore.json").write_text("{}", encoding="utf-8")
        Path("feed.json").write_text(
            json.dumps(
                {
                    "schema": "aixv.advisory-feed/v1",
                    "entries": [
                        {
                            "record": "remote-advisory.json",
                            "bundle": "remote-advisory.sigstore.json",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        def _fake_verify_signed_record(*args, **kwargs):
            return {
                "verified": True,
                "integrated_time": "2026-02-16T00:00:00+00:00",
                "actual_subjects": ["security@aixv.org"],
                "actual_issuer": "https://accounts.google.com",
            }

        monkeypatch.setattr("aixv.cli.verify_signed_record", _fake_verify_signed_record)

        first = runner.invoke(
            app,
            [
                "advisory",
                "sync",
                "--feed",
                "feed.json",
                "--trusted-subject",
                "security@aixv.org",
                "--json",
            ],
        )
        assert first.exit_code == 0
        first_out = json.loads(first.stdout)
        assert first_out["ok"] is True
        assert first_out["imported_count"] == 1

        second = runner.invoke(
            app,
            [
                "advisory",
                "sync",
                "--feed",
                "feed.json",
                "--trusted-subject",
                "security@aixv.org",
                "--json",
            ],
        )
        assert second.exit_code == 1
        second_out = json.loads(second.stdout)
        assert second_out["ok"] is False
        assert second_out["rejected_count"] == 1
        assert "replay/stale" in second_out["results"][0]["error"]
