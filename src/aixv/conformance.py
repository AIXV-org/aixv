from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from aixv.core import load_signed_record, validate_policy_payload

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


def run_conformance_checks() -> ConformanceReport:
    checks = [
        _check_fixtures_exist(),
        _check_policy_valid_fixture(),
        _check_policy_invalid_fixture(),
        _check_signed_record_fixture(),
    ]
    overall_status = "pass" if all(c.status == "pass" for c in checks) else "fail"
    return ConformanceReport(
        schema="aixv.conformance-report/v1",
        version="0.1",
        generated_at=_now_iso(),
        overall_status=overall_status,
        checks=checks,
    )
