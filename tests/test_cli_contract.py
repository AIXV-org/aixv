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
