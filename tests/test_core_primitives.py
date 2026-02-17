from pathlib import Path

import pytest

from aixv.core import (
    advisory_trust_constraints_from_policy,
    create_attestation_record,
    create_record,
    create_signed_record_payload,
    evaluate_admission,
    evaluate_advisory_policy,
    evaluate_assurance_level_requirements,
    export_attestations_as_ml_bom,
    export_attestations_as_slsa,
    load_attestation_records_for_digest,
    load_attestations_for_digest,
    load_signed_record,
    normalize_sha256_digest,
    sha256_file,
    trace_training_lineage_descendants,
    trace_training_lineage_parents,
    validate_policy_payload,
    validate_record_payload,
)


def test_normalize_sha256_digest_accepts_prefixed_and_plain() -> None:
    digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert normalize_sha256_digest(digest) == f"sha256:{digest}"
    assert normalize_sha256_digest(f"sha256:{digest}") == f"sha256:{digest}"


def test_normalize_sha256_digest_rejects_invalid() -> None:
    with pytest.raises(ValueError):
        normalize_sha256_digest("sha256:nothex")


def test_validate_policy_payload_requires_subject_constraints() -> None:
    payload = {
        "policy_type": "aixv.policy/v1",
        "allow_subjects": ["alice@example.com"],
    }
    validated = validate_policy_payload(payload)
    assert validated["policy_type"] == "aixv.policy/v1"
    assert validated["allow_subjects"] == ["alice@example.com"]


def test_create_and_load_signed_record_roundtrip(tmp_path: Path) -> None:
    payload = {"policy_type": "aixv.policy/v1", "allow_subjects": ["alice@example.com"]}
    record_path = create_record(
        root=tmp_path,
        kind="policy",
        record_id="policy-main",
        payload=payload,
    )
    loaded = load_signed_record(str(record_path), expected_kind="policy")
    assert loaded.record_id == "policy-main"
    assert loaded.kind == "policy"
    assert loaded.payload["allow_subjects"] == ["alice@example.com"]


def test_create_signed_record_payload_uses_schema_alias() -> None:
    payload = create_signed_record_payload(
        kind="waiver",
        record_id="WVR-1",
        payload={"reason": "temporary exception"},
    )
    assert payload["schema"] == "aixv.signed-record/v1"
    assert payload["kind"] == "waiver"


def test_evaluate_admission_returns_deny_on_policy_violation() -> None:
    decision = evaluate_admission(
        policy={"allow_subjects": ["alice@example.com"]},
        verification_result={
            "digest": "sha256:abc",
            "actual_subjects": ["mallory@example.com"],
            "actual_issuer": "https://accounts.google.com",
            "integrated_time": None,
        },
        advisories=[],
    )
    assert decision.decision == "deny"
    assert len(decision.violations) >= 1


def test_advisory_trust_constraints_fall_back_to_subject() -> None:
    constraints = advisory_trust_constraints_from_policy(
        {
            "policy_type": "aixv.policy/v1",
            "subject": "security-policy@aixv.org",
            "issuer": "https://accounts.google.com",
        }
    )
    assert constraints["subjects"] == ["security-policy@aixv.org"]
    assert constraints["issuers"] == ["https://accounts.google.com"]


def test_evaluate_advisory_policy_uses_only_trusted_when_signed_required() -> None:
    policy = {
        "policy_type": "aixv.policy/v1",
        "allow_subjects": ["security@aixv.org"],
        "require_signed_advisories": True,
        "require_no_active_advisories": True,
    }
    unsigned_active = [{"status": "active", "_trust": {"signed_and_trusted": False}}]
    trusted_active = [{"status": "active", "_trust": {"signed_and_trusted": True}}]
    assert evaluate_advisory_policy(policy=policy, advisories=unsigned_active) == []
    assert evaluate_advisory_policy(policy=policy, advisories=trusted_active) == [
        "active advisories present while require_no_active_advisories=true"
    ]


def test_attestation_record_roundtrip_preserves_statement_and_bundle(tmp_path: Path) -> None:
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(b"hello")
    digest = sha256_file(artifact)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": artifact.name, "digest": {"sha256": digest.split(":", 1)[1]}}],
        "predicateType": "https://aixv.org/attestation/training/v1",
        "predicate": {
            "parent_models": [{"digest": digest}],
            "datasets": [],
            "training_run": {
                "framework": "pytorch",
                "framework_version": "2.2.0",
                "code_digest": digest,
                "environment_digest": digest,
            },
            "hyperparameters": {},
        },
    }
    create_attestation_record(
        root=tmp_path,
        artifact=artifact,
        predicate_uri=statement["predicateType"],
        statement=statement,
        signature_bundle_path="example.statement.sigstore.json",
    )
    records = load_attestation_records_for_digest(tmp_path, digest)
    assert len(records) == 1
    assert records[0]["statement"]["predicateType"] == statement["predicateType"]
    assert records[0]["signature_bundle_path"] == "example.statement.sigstore.json"

    statements = load_attestations_for_digest(tmp_path, digest)
    assert len(statements) == 1
    assert statements[0]["subject"][0]["digest"]["sha256"] == digest.split(":", 1)[1]


def test_trace_training_lineage_parents_honors_depth(tmp_path: Path) -> None:
    leaf = tmp_path / "leaf.safetensors"
    parent = tmp_path / "parent.safetensors"
    root = tmp_path / "root.safetensors"
    leaf.write_bytes(b"leaf")
    parent.write_bytes(b"parent")
    root.write_bytes(b"root")

    leaf_digest = sha256_file(leaf)
    parent_digest = sha256_file(parent)
    root_digest = sha256_file(root)

    create_attestation_record(
        root=tmp_path,
        artifact=leaf,
        predicate_uri="https://aixv.org/attestation/training/v1",
        statement={
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": leaf.name, "digest": {"sha256": leaf_digest.split(":", 1)[1]}}],
            "predicateType": "https://aixv.org/attestation/training/v1",
            "predicate": {
                "parent_models": [{"digest": parent_digest}],
                "datasets": [],
                "training_run": {
                    "framework": "pytorch",
                    "framework_version": "2.2.0",
                    "code_digest": leaf_digest,
                    "environment_digest": leaf_digest,
                },
                "hyperparameters": {},
            },
        },
    )
    create_attestation_record(
        root=tmp_path,
        artifact=parent,
        predicate_uri="https://aixv.org/attestation/training/v1",
        statement={
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": parent.name, "digest": {"sha256": parent_digest.split(":", 1)[1]}}
            ],
            "predicateType": "https://aixv.org/attestation/training/v1",
            "predicate": {
                "parent_models": [{"digest": root_digest}],
                "datasets": [],
                "training_run": {
                    "framework": "pytorch",
                    "framework_version": "2.2.0",
                    "code_digest": parent_digest,
                    "environment_digest": parent_digest,
                },
                "hyperparameters": {},
            },
        },
    )

    one_hop = trace_training_lineage_parents(tmp_path, leaf_digest, depth=1)
    two_hop = trace_training_lineage_parents(tmp_path, leaf_digest, depth=2)

    assert len(one_hop) == 1
    assert one_hop[0]["digest"] == parent_digest
    assert one_hop[0]["depth"] == 1

    assert len(two_hop) == 2
    assert {entry["digest"] for entry in two_hop} == {parent_digest, root_digest}

    descendants = trace_training_lineage_descendants(tmp_path, root_digest, depth=2)
    assert {entry["digest"] for entry in descendants} == {parent_digest, leaf_digest}


def test_assurance_level_requirements_for_level_3_policy() -> None:
    violations = evaluate_assurance_level_requirements(
        assurance_level="level-3",
        policy_provided=True,
        require_signed_policy=True,
        policy={
            "policy_type": "aixv.policy/v1",
            "allow_subjects": ["alice@example.com"],
            "require_signed_advisories": True,
            "require_no_active_advisories": True,
            "max_bundle_age_days": 7,
        },
    )
    assert violations == []


def test_export_adapters_emit_expected_shapes() -> None:
    digest = f"sha256:{'1' * 64}"
    parent = f"sha256:{'2' * 64}"
    dataset = f"sha256:{'3' * 64}"
    attestations = [
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "model.safetensors", "digest": {"sha256": digest.split(":", 1)[1]}}
            ],
            "predicateType": "https://aixv.org/attestation/training/v1",
            "predicate": {
                "parent_models": [{"digest": parent}],
                "datasets": [{"digest": dataset, "split": "train"}],
                "training_run": {
                    "framework": "pytorch",
                    "framework_version": "2.2.0",
                    "code_digest": digest,
                    "environment_digest": digest,
                },
                "hyperparameters": {},
            },
        }
    ]
    slsa = export_attestations_as_slsa(
        artifact_digest=digest,
        artifact_name="model.safetensors",
        attestations=attestations,
    )
    assert slsa["predicateType"] == "https://slsa.dev/provenance/v1"
    assert len(slsa["buildDefinition"]["resolvedDependencies"]) == 2

    bom = export_attestations_as_ml_bom(
        artifact_digest=digest,
        artifact_name="model.safetensors",
        attestations=attestations,
    )
    assert bom["bom_format"] == "aixv.ml-bom/v1"
    assert bom["component_count"] == 3


def test_bundle_payload_validation_normalizes_primary_into_members() -> None:
    payload = validate_record_payload(
        "bundle",
        {
            "bundle_type": "aixv.bundle/v1",
            "bundle_id": "bundle-main",
            "primary": "1" * 64,
            "members": [f"sha256:{'2' * 64}"],
        },
    )
    assert payload["primary"] == f"sha256:{'1' * 64}"
    assert payload["members"] == [f"sha256:{'2' * 64}", f"sha256:{'1' * 64}"]
