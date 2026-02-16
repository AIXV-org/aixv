import json
from pathlib import Path

import pytest

from aixv.core import load_signed_record, validate_policy_payload

FIXTURES = Path("docs/conformance/fixtures")


def test_policy_valid_fixture_passes() -> None:
    payload = json.loads((FIXTURES / "policy.valid.json").read_text(encoding="utf-8"))
    validated = validate_policy_payload(payload)
    assert validated["policy_type"] == "aixv.policy/v1"


def test_policy_invalid_fixture_fails() -> None:
    payload = json.loads((FIXTURES / "policy.invalid.no_subjects.json").read_text(encoding="utf-8"))
    with pytest.raises(ValueError):
        validate_policy_payload(payload)


def test_record_policy_sample_loads() -> None:
    record = load_signed_record(str(FIXTURES / "record.policy.sample.json"), expected_kind="policy")
    assert record.kind == "policy"
    assert record.record_id == "policy-main"
