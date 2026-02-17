from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from aixv.core import (
    advisory_trust_constraints_from_policy,
    evaluate_advisory_policy,
    evaluate_advisory_sync_guards,
    load_signed_record,
    validate_bundle_payload,
    validate_policy_payload,
    verify_artifact_with_sigstore,
    verify_statement_with_sigstore,
)

FIXTURES_DIR = Path("docs/conformance/fixtures")


class ConformanceCheck(BaseModel):
    check_id: str
    status: str
    evidence: Dict[str, Any]
    error: Optional[str] = None

    model_config = ConfigDict(extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        if self.status not in {"pass", "fail"}:
            raise ValueError("status must be pass|fail")


class ConformanceReport(BaseModel):
    schema_: str = Field(alias="schema")
    version: str
    generated_at: str
    overall_status: str
    checks: List[ConformanceCheck]

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    def model_post_init(self, __context: Any) -> None:
        if self.overall_status not in {"pass", "fail"}:
            raise ValueError("overall_status must be pass|fail")


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat()


def _check_fixtures_exist() -> ConformanceCheck:
    expected = {
        "policy.valid.json",
        "policy.invalid.no_subjects.json",
        "record.policy.sample.json",
    }
    present = {p.name for p in FIXTURES_DIR.glob("*.json")}
    missing = sorted(expected - present)
    if missing:
        return ConformanceCheck(
            check_id="fixtures.exist.v1",
            status="fail",
            evidence={"fixtures_dir": str(FIXTURES_DIR), "missing": missing},
            error="missing conformance fixtures",
        )
    return ConformanceCheck(
        check_id="fixtures.exist.v1",
        status="pass",
        evidence={"fixtures_dir": str(FIXTURES_DIR), "count": len(expected)},
    )


def _check_policy_valid_fixture() -> ConformanceCheck:
    path = FIXTURES_DIR / "policy.valid.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        validated = validate_policy_payload(payload)
    except Exception as exc:
        return ConformanceCheck(
            check_id="policy.fixture.valid.v1",
            status="fail",
            evidence={"path": str(path)},
            error=str(exc),
        )
    return ConformanceCheck(
        check_id="policy.fixture.valid.v1",
        status="pass",
        evidence={"path": str(path), "policy_type": validated.get("policy_type")},
    )


def _check_policy_invalid_fixture() -> ConformanceCheck:
    path = FIXTURES_DIR / "policy.invalid.no_subjects.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return ConformanceCheck(
            check_id="policy.fixture.invalid.v1",
            status="fail",
            evidence={"path": str(path)},
            error=str(exc),
        )

    try:
        validate_policy_payload(payload)
    except Exception:
        return ConformanceCheck(
            check_id="policy.fixture.invalid.v1",
            status="pass",
            evidence={"path": str(path), "expected_rejection": True},
        )

    return ConformanceCheck(
        check_id="policy.fixture.invalid.v1",
        status="fail",
        evidence={"path": str(path)},
        error="invalid policy fixture was accepted",
    )


def _check_signed_record_fixture() -> ConformanceCheck:
    path = FIXTURES_DIR / "record.policy.sample.json"
    try:
        record = load_signed_record(str(path), expected_kind="policy")
    except Exception as exc:
        return ConformanceCheck(
            check_id="record.fixture.policy.v1",
            status="fail",
            evidence={"path": str(path)},
            error=str(exc),
        )
    return ConformanceCheck(
        check_id="record.fixture.policy.v1",
        status="pass",
        evidence={
            "path": str(path),
            "kind": record.kind,
            "record_id": record.record_id,
        },
    )


def _check_policy_unknown_field_rejected() -> ConformanceCheck:
    payload = {
        "policy_type": "aixv.policy/v1",
        "allow_subjects": ["alice@example.com"],
        "unexpected": True,
    }
    try:
        validate_policy_payload(payload)
    except Exception:
        return ConformanceCheck(
            check_id="policy.unknown-field.reject.v1",
            status="pass",
            evidence={"expected_rejection": True},
        )
    return ConformanceCheck(
        check_id="policy.unknown-field.reject.v1",
        status="fail",
        evidence={},
        error="policy unknown field was accepted",
    )


def _check_advisory_trust_subject_fallback() -> ConformanceCheck:
    policy = {
        "policy_type": "aixv.policy/v1",
        "subject": "security-policy@aixv.org",
        "require_signed_advisories": True,
        "require_no_active_advisories": True,
    }
    constraints = advisory_trust_constraints_from_policy(policy)
    if constraints["subjects"] == ["security-policy@aixv.org"]:
        return ConformanceCheck(
            check_id="policy.advisory-trust.subject-fallback.v1",
            status="pass",
            evidence={"subjects": constraints["subjects"]},
        )
    return ConformanceCheck(
        check_id="policy.advisory-trust.subject-fallback.v1",
        status="fail",
        evidence={"subjects": constraints["subjects"]},
        error="advisory trust root fallback did not include policy subject",
    )


def _check_signed_advisory_policy_semantics() -> ConformanceCheck:
    policy = {
        "policy_type": "aixv.policy/v1",
        "allow_subjects": ["security-policy@aixv.org"],
        "require_signed_advisories": True,
        "require_no_active_advisories": True,
    }
    untrusted_only = [
        {"status": "active", "_trust": {"signed_and_trusted": False}},
    ]
    trusted_active = [
        {"status": "active", "_trust": {"signed_and_trusted": True}},
    ]
    untrusted_violations = evaluate_advisory_policy(policy=policy, advisories=untrusted_only)
    trusted_violations = evaluate_advisory_policy(policy=policy, advisories=trusted_active)
    if len(untrusted_violations) < 1 and len(trusted_violations) > 0:
        return ConformanceCheck(
            check_id="advisory.signed-policy.filtering.v1",
            status="pass",
            evidence={
                "untrusted_violations": untrusted_violations,
                "trusted_violations": trusted_violations,
            },
        )
    return ConformanceCheck(
        check_id="advisory.signed-policy.filtering.v1",
        status="fail",
        evidence={
            "untrusted_violations": untrusted_violations,
            "trusted_violations": trusted_violations,
        },
        error="signed advisory policy semantics failed",
    )


def _check_invalid_artifact_bundle_rejected() -> ConformanceCheck:
    with TemporaryDirectory() as tmp:
        artifact = Path(tmp) / "artifact.bin"
        bundle = Path(tmp) / "artifact.bin.sigstore.json"
        artifact.write_bytes(b"aixv")
        bundle.write_text("{}", encoding="utf-8")
        try:
            verify_artifact_with_sigstore(
                artifact=artifact,
                bundle_in=bundle,
                subject="alice@example.com",
                issuer=None,
                allow_subjects=[],
                allow_issuers=[],
                staging=False,
                offline=True,
            )
        except Exception:
            return ConformanceCheck(
                check_id="crypto.invalid-bundle.artifact.reject.v1",
                status="pass",
                evidence={"expected_rejection": True},
            )
    return ConformanceCheck(
        check_id="crypto.invalid-bundle.artifact.reject.v1",
        status="fail",
        evidence={},
        error="invalid artifact bundle unexpectedly verified",
    )


def _check_invalid_statement_bundle_rejected() -> ConformanceCheck:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.bin", "digest": {"sha256": "0" * 64}}],
        "predicateType": "https://aixv.org/attestation/training/v1",
        "predicate": {
            "parent_models": [{"digest": f"sha256:{'0' * 64}"}],
            "datasets": [],
            "training_run": {
                "framework": "pytorch",
                "framework_version": "2.2.0",
                "code_digest": f"sha256:{'0' * 64}",
                "environment_digest": f"sha256:{'0' * 64}",
            },
            "hyperparameters": {},
        },
    }
    with TemporaryDirectory() as tmp:
        bundle = Path(tmp) / "statement.sigstore.json"
        bundle.write_text("{}", encoding="utf-8")
        try:
            verify_statement_with_sigstore(
                statement=statement,
                bundle_in=bundle,
                subject="alice@example.com",
                issuer=None,
                allow_subjects=[],
                allow_issuers=[],
                staging=False,
                offline=True,
            )
        except Exception:
            return ConformanceCheck(
                check_id="crypto.invalid-bundle.statement.reject.v1",
                status="pass",
                evidence={"expected_rejection": True},
            )
    return ConformanceCheck(
        check_id="crypto.invalid-bundle.statement.reject.v1",
        status="fail",
        evidence={},
        error="invalid statement bundle unexpectedly verified",
    )


def _check_bundle_schema_validation() -> ConformanceCheck:
    payload = {
        "bundle_type": "aixv.bundle/v1",
        "bundle_id": "bundle-main",
        "primary": "1" * 64,
        "members": [f"sha256:{'2' * 64}"],
    }
    try:
        validated = validate_bundle_payload(payload)
    except Exception as exc:
        return ConformanceCheck(
            check_id="bundle.schema.validation.v1",
            status="fail",
            evidence={"payload": payload},
            error=str(exc),
        )
    if validated["primary"] not in validated["members"]:
        return ConformanceCheck(
            check_id="bundle.schema.validation.v1",
            status="fail",
            evidence={"validated": validated},
            error="bundle primary digest missing from members",
        )
    return ConformanceCheck(
        check_id="bundle.schema.validation.v1",
        status="pass",
        evidence={"member_count": len(validated["members"])},
    )


def _check_advisory_sync_replay_and_freshness() -> ConformanceCheck:
    replay_violations = evaluate_advisory_sync_guards(
        integrated_time="2026-02-16T00:00:00+00:00",
        previous_integrated_time="2026-02-16T00:00:00+00:00",
        max_age_days=None,
    )
    stale_violations = evaluate_advisory_sync_guards(
        integrated_time="2026-01-01T00:00:00+00:00",
        previous_integrated_time=None,
        max_age_days=7,
        now=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )
    replay_blocked = any("replay/stale" in v for v in replay_violations)
    stale_blocked = any("max_age_days" in v for v in stale_violations)
    if replay_blocked and stale_blocked:
        return ConformanceCheck(
            check_id="advisory.sync.replay-freshness.v1",
            status="pass",
            evidence={
                "replay_violations": replay_violations,
                "stale_violations": stale_violations,
            },
        )
    return ConformanceCheck(
        check_id="advisory.sync.replay-freshness.v1",
        status="fail",
        evidence={
            "replay_violations": replay_violations,
            "stale_violations": stale_violations,
        },
        error="advisory sync replay/freshness guards failed",
    )


def run_conformance_checks() -> ConformanceReport:
    checks = [
        _check_fixtures_exist(),
        _check_policy_valid_fixture(),
        _check_policy_invalid_fixture(),
        _check_signed_record_fixture(),
        _check_policy_unknown_field_rejected(),
        _check_advisory_trust_subject_fallback(),
        _check_signed_advisory_policy_semantics(),
        _check_bundle_schema_validation(),
        _check_advisory_sync_replay_and_freshness(),
        _check_invalid_artifact_bundle_rejected(),
        _check_invalid_statement_bundle_rejected(),
    ]
    overall_status = "pass" if all(c.status == "pass" for c in checks) else "fail"
    return ConformanceReport(
        schema="aixv.conformance-report/v1",
        version="0.1",
        generated_at=_now_iso(),
        overall_status=overall_status,
        checks=checks,
    )
