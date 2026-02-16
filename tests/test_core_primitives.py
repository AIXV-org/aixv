from pathlib import Path

import pytest

from aixv.core import (
    create_record,
    create_signed_record_payload,
    evaluate_admission,
    load_signed_record,
    normalize_sha256_digest,
    validate_policy_payload,
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
