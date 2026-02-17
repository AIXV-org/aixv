import json
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional
from urllib.request import urlopen

import typer
from rich.console import Console

from aixv import __version__
from aixv.conformance import run_conformance_checks
from aixv.core import (
    PREDICATE_ALIASES,
    advisory_trust_constraints_from_policy,
    create_attestation_record,
    create_record,
    ensure_artifact,
    evaluate_admission,
    evaluate_advisory_sync_guards,
    evaluate_assurance_level_requirements,
    export_attestations_as_ml_bom,
    export_attestations_as_slsa,
    list_advisories,
    load_attestation_records_for_digest,
    load_signed_record,
    make_statement,
    normalize_sha256_digest,
    policy_from_file,
    read_json,
    resolve_predicate_uri,
    resolve_signature_bundle_path,
    rollback_record,
    sha256_file,
    sign_artifact_with_sigstore,
    sign_statement_with_sigstore,
    trace_training_lineage_descendants,
    trace_training_lineage_parents,
    validate_policy_payload,
    validate_predicate,
    validate_record_id,
    validate_record_payload,
    verify_artifact_with_sigstore,
    verify_signed_record,
    verify_statement_with_sigstore,
    write_json,
)

app = typer.Typer(name="aixv", help="AI Integrity & Verification Protocol CLI")
advisory_app = typer.Typer(help="Advisory and recall operations")
policy_app = typer.Typer(help="Policy operations")
record_app = typer.Typer(help="Generic signed-record operations")
bundle_app = typer.Typer(help="Multi-artifact bundle operations")
app.add_typer(advisory_app, name="advisory")
app.add_typer(policy_app, name="policy")
app.add_typer(record_app, name="record")
app.add_typer(bundle_app, name="bundle")
console = Console()


def _emit(payload: Dict[str, Any], as_json: bool) -> None:
    if as_json:
        typer.echo(json.dumps(payload, sort_keys=True))
        return
    console.print_json(data=payload)


def _root_dir() -> Path:
    return Path.cwd()


def _parse_csv_values(raw: Optional[str]) -> list:
    if not raw:
        return []
    return [s.strip() for s in raw.split(",") if s.strip()]


def _is_remote_ref(ref: str) -> bool:
    return ref.startswith("https://") or ref.startswith("http://")


def _read_bytes_from_ref(ref: str) -> bytes:
    if ref.startswith("http://"):
        raise ValueError("insecure remote reference: only https:// is allowed")
    if _is_remote_ref(ref):
        with urlopen(ref, timeout=20) as response:  # nosec B310 - expected remote feed access
            return response.read()
    return Path(ref).read_bytes()


def _read_json_from_ref(ref: str) -> Dict[str, Any]:
    raw = _read_bytes_from_ref(ref)
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("feed payload must be a JSON object")
    return payload


def _parse_advisory_feed_entries(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    entries_raw: Any = payload.get("entries")
    if isinstance(entries_raw, list):
        entries = entries_raw
    else:
        raise ValueError("feed payload must include entries[]")

    out: List[Dict[str, str]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"feed entry {index} must be an object")
        record_ref = entry.get("record") or entry.get("record_url")
        bundle_ref = entry.get("bundle") or entry.get("bundle_url")
        if not isinstance(record_ref, str) or not record_ref.strip():
            raise ValueError(f"feed entry {index} missing record reference")
        if not isinstance(bundle_ref, str) or not bundle_ref.strip():
            raise ValueError(f"feed entry {index} missing bundle reference")
        out.append({"record": record_ref.strip(), "bundle": bundle_ref.strip()})
    return out


def _advisory_sync_state_path(root: Path) -> Path:
    return root / ".aixv" / "advisory-sync-state.json"


def _load_advisory_sync_state(root: Path) -> Dict[str, Any]:
    path = _advisory_sync_state_path(root)
    if not path.exists():
        return {"schema": "aixv.advisory-sync-state/v1", "entries": {}}
    payload = read_json(str(path))
    if not isinstance(payload, dict):
        raise ValueError("invalid advisory sync state format")
    entries = payload.get("entries")
    if not isinstance(entries, dict):
        raise ValueError("invalid advisory sync state entries")
    return payload


def _save_advisory_sync_state(root: Path, payload: Dict[str, Any]) -> None:
    write_json(_advisory_sync_state_path(root), payload)


def _resolve_bundle_reference(record_path: Path, bundle_ref: Optional[str]) -> Optional[Path]:
    if not bundle_ref:
        return None
    path = Path(bundle_ref)
    if not path.is_absolute():
        path = record_path.parent / path
    return path


def _assess_attestation_trust(
    *,
    entries: list,
    require_signed: bool,
    trusted_subjects: list,
    trusted_issuers: list,
    staging: bool,
    offline: bool,
) -> Dict[str, Any]:
    if require_signed and len(trusted_subjects) < 1:
        raise ValueError(
            "signed attestation verification requires trusted_attestation_subject or trusted_attestation_subjects"
        )

    enriched: list = []
    violations: list = []
    signed_count = 0
    verified_count = 0

    for entry in entries:
        statement = entry.get("statement", {})
        attestation_path = Path(entry["path"])
        bundle_path = _resolve_bundle_reference(
            attestation_path, entry.get("signature_bundle_path")
        )

        trust: Dict[str, Any] = {
            "signed": bool(bundle_path),
            "signed_and_trusted": False,
            "signature_bundle_path": str(bundle_path) if bundle_path else None,
        }
        if bundle_path:
            signed_count += 1
            if len(trusted_subjects) > 0:
                if not bundle_path.exists():
                    trust["error"] = f"signature bundle not found: {bundle_path}"
                else:
                    try:
                        verification = verify_statement_with_sigstore(
                            statement=statement,
                            bundle_in=bundle_path,
                            subject=None,
                            issuer=None,
                            allow_subjects=trusted_subjects,
                            allow_issuers=trusted_issuers,
                            staging=staging,
                            offline=offline,
                        )
                        trust["signed_and_trusted"] = True
                        trust["signature_verification"] = verification
                        verified_count += 1
                    except Exception as exc:
                        trust["error"] = str(exc)
        if require_signed and not trust["signed_and_trusted"]:
            violations.append(f"attestation is not signed and trusted: {attestation_path}")

        statement_payload: Dict[str, Any] = (
            dict(statement) if isinstance(statement, dict) else {"statement": statement}
        )
        statement_payload["_trust"] = trust
        enriched.append(statement_payload)

    return {
        "attestations": enriched,
        "summary": {
            "total": len(entries),
            "signed": signed_count,
            "signed_and_trusted": verified_count,
            "unsigned_or_untrusted": len(entries) - verified_count,
        },
        "violations": violations,
    }


def _create_and_optionally_sign_record(
    *,
    kind: str,
    record_id: str,
    payload: Dict[str, Any],
    output: Optional[str],
    sign: bool,
    identity_token: Optional[str],
    identity_token_env: str,
    interactive_oidc: bool,
    staging: bool,
    offline: bool,
) -> Dict[str, Any]:
    bundle_path = None
    if sign:
        if output:
            bundle_path = str(Path(output).with_name(f"{Path(output).name}.sigstore.json"))
        else:
            bundle_path = str(
                (_root_dir() / ".aixv" / "records" / kind / f"{record_id}.json.sigstore.json")
            )
    record_path = create_record(
        root=_root_dir(),
        kind=kind,
        record_id=record_id,
        payload=payload,
        output_path=output,
        signature_bundle_path=bundle_path,
    )
    result: Dict[str, Any] = {
        "ok": True,
        "kind": kind,
        "record_id": record_id,
        "path": str(record_path),
    }
    if sign:
        signature = sign_artifact_with_sigstore(
            artifact=record_path,
            bundle_out=Path(bundle_path)
            if bundle_path
            else record_path.with_name(f"{record_path.name}.sigstore.json"),
            identity_token=identity_token,
            identity_token_env=identity_token_env,
            interactive_oidc=interactive_oidc,
            staging=staging,
            offline=offline,
        )
        result["signature"] = signature
    return result


@app.command()
def sign(
    artifact: str = typer.Argument(..., help="Path to artifact to sign"),
    bundle: Optional[str] = typer.Option(None, help="Output path for Sigstore bundle JSON"),
    identity_token: Optional[str] = typer.Option(None, help="OIDC token for keyless signing"),
    identity_token_env: str = typer.Option(
        "SIGSTORE_ID_TOKEN", help="Environment variable containing OIDC token"
    ),
    interactive_oidc: bool = typer.Option(
        False, help="Acquire OIDC token interactively via browser"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Sign an artifact with Sigstore and write a bundle file."""
    try:
        artifact_path = ensure_artifact(artifact)
        bundle_out = (
            Path(bundle)
            if bundle
            else artifact_path.with_name(f"{artifact_path.name}.sigstore.json")
        )
        result = sign_artifact_with_sigstore(
            artifact=artifact_path,
            bundle_out=bundle_out,
            identity_token=identity_token,
            identity_token_env=identity_token_env,
            interactive_oidc=interactive_oidc,
            staging=staging,
            offline=offline,
        )
        result["ok"] = True
        _emit(result, json_output)
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "sign"}, json_output)
        raise typer.Exit(code=1)


@app.command()
def verify(
    artifact: str = typer.Argument(..., help="Path to artifact to verify"),
    bundle: Optional[str] = typer.Option(None, help="Path to Sigstore bundle JSON"),
    identity: Optional[str] = typer.Option(None, help="Expected signer subject identity"),
    issuer: Optional[str] = typer.Option(None, help="Expected signer OIDC issuer"),
    policy: Optional[str] = typer.Option(
        None,
        help=("Policy JSON (identity allow/deny lists, freshness windows, advisory thresholds)"),
    ),
    policy_bundle: Optional[str] = typer.Option(None, help="Sigstore bundle for policy file"),
    require_signed_policy: bool = typer.Option(
        True, help="Require Sigstore verification of policy file"
    ),
    policy_trusted_subject: Optional[str] = typer.Option(
        None, help="Trusted signer subject for policy file"
    ),
    policy_trusted_subjects: Optional[str] = typer.Option(
        None, help="Comma-separated trusted signer subjects for policy file"
    ),
    policy_trusted_issuers: Optional[str] = typer.Option(
        None, help="Comma-separated trusted signer issuers for policy file"
    ),
    assurance_level: Optional[str] = typer.Option(
        None,
        "--assurance-level",
        help="Assurance level gate: level-1|level-2|level-3",
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Verify artifact signature, identity policy, and transparency evidence."""
    try:
        artifact_path = ensure_artifact(artifact)
        bundle_in = (
            Path(bundle)
            if bundle
            else artifact_path.with_name(f"{artifact_path.name}.sigstore.json")
        )
        if not bundle_in.exists():
            raise FileNotFoundError(f"bundle not found: {bundle_in}")

        policy_data: Dict[str, Any] = {}
        if policy:
            policy_path = ensure_artifact(policy)
            if require_signed_policy:
                policy_bundle_in = resolve_signature_bundle_path(policy_path, policy_bundle)
                if not policy_bundle_in.exists():
                    raise FileNotFoundError(f"policy bundle not found: {policy_bundle_in}")
                policy_subjects = []
                if policy_trusted_subject:
                    policy_subjects.append(policy_trusted_subject)
                policy_subjects.extend(_parse_csv_values(policy_trusted_subjects))
                policy_issuers = _parse_csv_values(policy_trusted_issuers)
                if len(policy_subjects) < 1:
                    raise ValueError(
                        "signed policy verification requires policy_trusted_subject or policy_trusted_subjects"
                    )
                verify_signed_record(
                    record_path=policy_path,
                    bundle_path=policy_bundle_in,
                    trusted_subjects=policy_subjects,
                    trusted_issuers=policy_issuers,
                    staging=staging,
                    offline=offline,
                )
            policy_data = policy_from_file(policy)
        subject = identity or policy_data.get("subject")
        policy_issuer = issuer if issuer is not None else policy_data.get("issuer")
        effective_policy: Dict[str, Any] = dict(policy_data)
        if identity is not None:
            effective_policy["subject"] = identity
        if issuer is not None:
            effective_policy["issuer"] = issuer

        assurance_level_violations = evaluate_assurance_level_requirements(
            assurance_level=assurance_level,
            policy_provided=policy is not None,
            require_signed_policy=require_signed_policy,
            policy=effective_policy,
        )
        if assurance_level_violations:
            raise ValueError("; ".join(assurance_level_violations))

        identity_constraints_present = bool(subject or effective_policy.get("allow_subjects"))
        if not identity_constraints_present:
            raise ValueError(
                "subject identity constraints required: set --identity or policy.subject/allow_subjects"
            )

        result = verify_artifact_with_sigstore(
            artifact=artifact_path,
            bundle_in=bundle_in,
            subject=subject,
            issuer=policy_issuer,
            allow_subjects=effective_policy.get("allow_subjects", []),
            allow_issuers=effective_policy.get("allow_issuers", []),
            staging=staging,
            offline=offline,
        )
        advisory_trust = advisory_trust_constraints_from_policy(effective_policy)
        advisory_trusted_subjects = advisory_trust["subjects"]
        advisory_trusted_issuers = advisory_trust["issuers"]
        if (
            bool(effective_policy.get("require_signed_advisories", False))
            and (
                effective_policy.get("require_no_active_advisories")
                or effective_policy.get("deny_advisory_severity_at_or_above") is not None
            )
            and len(advisory_trusted_subjects) < 1
        ):
            raise ValueError(
                "policy requires advisory trust roots; set advisory_allow_subjects "
                "or subject/allow_subjects"
            )
        advisories = list_advisories(
            _root_dir(),
            result["digest"],
            require_signed=False,
            trusted_subjects=advisory_trusted_subjects,
            trusted_issuers=advisory_trusted_issuers,
            staging=staging,
            offline=offline,
        )
        decision = evaluate_admission(
            policy=effective_policy,
            verification_result=result,
            advisories=advisories,
        )
        result["policy_violations"] = decision.violations
        result["admission_decision"] = decision.decision
        result["admission_evidence"] = decision.evidence
        if assurance_level:
            result["assurance_level"] = assurance_level

        if decision.decision != "allow":
            result["ok"] = False
            _emit(result, json_output)
            raise typer.Exit(code=1)

        result["ok"] = True
        _emit(result, json_output)
    except typer.Exit:
        raise
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "verify"}, json_output)
        raise typer.Exit(code=1)


@app.command()
def attest(
    artifact: str = typer.Argument(..., help="Path to artifact being attested"),
    predicate: str = typer.Option(..., help="Predicate alias or full URI"),
    input: str = typer.Option(..., "--input", "-i", help="Path to predicate JSON payload"),
    output: Optional[str] = typer.Option(None, help="Output path for in-toto statement JSON"),
    sign: bool = typer.Option(False, help="Sign DSSE statement with Sigstore"),
    identity_token: Optional[str] = typer.Option(None, help="OIDC token for keyless signing"),
    identity_token_env: str = typer.Option(
        "SIGSTORE_ID_TOKEN", help="Environment variable containing OIDC token"
    ),
    interactive_oidc: bool = typer.Option(
        False, help="Acquire OIDC token interactively via browser"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Validate predicate payload and emit/store an in-toto attestation statement."""
    try:
        artifact_path = ensure_artifact(artifact)
        payload = read_json(input)
        predicate_uri = resolve_predicate_uri(predicate)
        validated = validate_predicate(predicate_uri, payload)
        statement = make_statement(artifact_path, predicate_uri, validated)

        statement_path = (
            Path(output)
            if output
            else artifact_path.with_name(f"{artifact_path.name}.aixv.statement.json")
        )
        write_json(statement_path, statement)

        result: Dict[str, Any] = {
            "ok": True,
            "artifact": str(artifact_path),
            "artifact_digest": sha256_file(artifact_path),
            "predicate": predicate,
            "predicate_uri": predicate_uri,
            "statement_path": str(statement_path),
            "schema_validated": predicate_uri in PREDICATE_ALIASES.values(),
        }

        signature_bundle_path: Optional[str] = None
        if sign:
            bundle_out = statement_path.with_name(f"{statement_path.name}.sigstore.json")
            signature = sign_statement_with_sigstore(
                statement=statement,
                bundle_out=bundle_out,
                identity_token=identity_token,
                identity_token_env=identity_token_env,
                interactive_oidc=interactive_oidc,
                staging=staging,
                offline=offline,
            )
            signature_bundle_path = signature["bundle_path"]
            result["signature"] = signature

        stored_path = create_attestation_record(
            root=_root_dir(),
            artifact=artifact_path,
            predicate_uri=predicate_uri,
            statement=statement,
            signature_bundle_path=signature_bundle_path,
        )
        result["attestation_store_path"] = str(stored_path)

        _emit(result, json_output)
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "attest"}, json_output)
        raise typer.Exit(code=1)


@app.command()
def provenance(
    artifact: str = typer.Argument(..., help="Path to artifact"),
    depth: int = typer.Option(3, help="Lineage traversal depth"),
    view: str = typer.Option("trace", help="Lineage view: trace|impact|explain"),
    require_signed_attestations: bool = typer.Option(
        False, help="Require all matching attestations to be signed and trusted"
    ),
    trusted_attestation_subject: Optional[str] = typer.Option(
        None, help="Trusted attestation signer subject"
    ),
    trusted_attestation_subjects: Optional[str] = typer.Option(
        None, help="Comma-separated trusted attestation signer subjects"
    ),
    trusted_attestation_issuers: Optional[str] = typer.Option(
        None, help="Comma-separated trusted attestation signer issuers"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Return local lineage view from stored attestations."""
    try:
        if view not in {"trace", "impact", "explain"}:
            raise ValueError(f"unsupported provenance view: {view}")
        artifact_path = ensure_artifact(artifact)
        digest = sha256_file(artifact_path)
        entries = load_attestation_records_for_digest(_root_dir(), digest)
        subject_list = []
        if trusted_attestation_subject:
            subject_list.append(trusted_attestation_subject)
        subject_list.extend(_parse_csv_values(trusted_attestation_subjects))
        issuer_list = _parse_csv_values(trusted_attestation_issuers)
        trust_report = _assess_attestation_trust(
            entries=entries,
            require_signed=require_signed_attestations,
            trusted_subjects=subject_list,
            trusted_issuers=issuer_list,
            staging=staging,
            offline=offline,
        )
        attestations = trust_report["attestations"]
        advisories = list_advisories(_root_dir(), digest)
        trusted_active_advisories = [
            a
            for a in advisories
            if a.get("status") == "active"
            and isinstance(a.get("_trust"), dict)
            and a.get("_trust", {}).get("signed_and_trusted") is True
        ]
        payload: Dict[str, Any] = {
            "ok": len(trust_report["violations"]) < 1,
            "view": view,
            "artifact": str(artifact_path),
            "artifact_digest": digest,
            "attestation_count": len(attestations),
            "attestation_trust": trust_report["summary"],
            "attestation_violations": trust_report["violations"],
            "advisory_count": len(advisories),
            "trusted_active_advisory_count": len(trusted_active_advisories),
        }

        if view in {"trace", "explain"}:
            payload["parents"] = trace_training_lineage_parents(_root_dir(), digest, depth)
        if view in {"impact", "explain"}:
            payload["descendants"] = trace_training_lineage_descendants(_root_dir(), digest, depth)
        if view == "explain":
            explanation: List[str] = []
            if trust_report["violations"]:
                explanation.append("attestation trust violations present")
            if trusted_active_advisories:
                explanation.append("trusted active advisories present")
            if not explanation:
                explanation.append("no immediate trust or advisory blockers detected")
            payload["explain"] = explanation
        _emit(payload, json_output)
        if trust_report["violations"]:
            raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "provenance"}, json_output)
        raise typer.Exit(code=1)


@app.command("sign-delta")
def sign_delta(
    artifact: str = typer.Argument(..., help="Path to delta artifact"),
    base: str = typer.Option(..., help="Base artifact digest or path"),
    update_type: str = typer.Option(..., help="sft|dpo|ppo|rl-online|hotfix"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Create a continual-learning delta attestation payload."""
    try:
        artifact_path = ensure_artifact(artifact)
        if update_type not in {"sft", "dpo", "ppo", "rl-online", "hotfix"}:
            raise ValueError(f"invalid update_type: {update_type}")
        payload = {
            "base_digest": base,
            "update_type": update_type,
            "rollback_target_digest": base,
            "state_migration": "none",
        }
        statement = make_statement(
            artifact_path, "https://aixv.org/attestation/cl-delta/v1", payload
        )
        path = artifact_path.with_name(f"{artifact_path.name}.delta.statement.json")
        write_json(path, statement)
        _emit(
            {"ok": True, "artifact": str(artifact_path), "statement_path": str(path)}, json_output
        )
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "sign-delta"}, json_output)
        raise typer.Exit(code=1)


@app.command()
def rollback(
    artifact: str = typer.Argument(..., help="Artifact being rolled back"),
    to: str = typer.Option(..., help="Target digest or artifact path"),
    sign: bool = typer.Option(
        True,
        "--sign/--no-sign",
        help="Sign rollback record with Sigstore (default: enabled)",
    ),
    identity_token: Optional[str] = typer.Option(None, help="OIDC token for keyless signing"),
    identity_token_env: str = typer.Option(
        "SIGSTORE_ID_TOKEN", help="Environment variable containing OIDC token"
    ),
    interactive_oidc: bool = typer.Option(
        False, help="Acquire OIDC token interactively via browser"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Create a rollback event record (signed by default)."""
    try:
        artifact_path = ensure_artifact(artifact)
        rollback_payload = rollback_record(artifact_path, to)
        out = artifact_path.with_name(f"{artifact_path.name}.rollback.json")
        if not sign:
            write_json(out, rollback_payload)
            _emit(
                {
                    "ok": True,
                    "rollback_record_path": str(out),
                    "record": rollback_payload,
                    "signed": False,
                },
                json_output,
            )
            return

        timestamp_token = (
            rollback_payload["timestamp"]
            .replace(":", "")
            .replace("-", "")
            .replace("+", "")
            .replace("T", "t")
        )
        digest_token = rollback_payload["artifact_digest"].split(":", 1)[1][:12]
        record_id = f"RBK-{timestamp_token}-{digest_token}"
        result = _create_and_optionally_sign_record(
            kind="rollback",
            record_id=record_id,
            payload=rollback_payload,
            output=str(out),
            sign=True,
            identity_token=identity_token,
            identity_token_env=identity_token_env,
            interactive_oidc=interactive_oidc,
            staging=staging,
            offline=offline,
        )
        result["rollback_record_path"] = result["path"]
        result["signed"] = True
        _emit(result, json_output)
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "rollback"}, json_output)
        raise typer.Exit(code=1)


@app.command()
def export(
    artifact: str = typer.Argument(..., help="Path to artifact"),
    format: str = typer.Option(..., help="Export format: in-toto|slsa|ml-bom|aixv"),
    require_signed_attestations: bool = typer.Option(
        False, help="Require all exported attestations to be signed and trusted"
    ),
    trusted_attestation_subject: Optional[str] = typer.Option(
        None, help="Trusted attestation signer subject"
    ),
    trusted_attestation_subjects: Optional[str] = typer.Option(
        None, help="Comma-separated trusted attestation signer subjects"
    ),
    trusted_attestation_issuers: Optional[str] = typer.Option(
        None, help="Comma-separated trusted attestation signer issuers"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Export locally available evidence in requested format."""
    try:
        artifact_path = ensure_artifact(artifact)
        digest = sha256_file(artifact_path)
        entries = load_attestation_records_for_digest(_root_dir(), digest)
        subject_list = []
        if trusted_attestation_subject:
            subject_list.append(trusted_attestation_subject)
        subject_list.extend(_parse_csv_values(trusted_attestation_subjects))
        issuer_list = _parse_csv_values(trusted_attestation_issuers)
        trust_report = _assess_attestation_trust(
            entries=entries,
            require_signed=require_signed_attestations,
            trusted_subjects=subject_list,
            trusted_issuers=issuer_list,
            staging=staging,
            offline=offline,
        )
        attestations = trust_report["attestations"]
        if format not in {"in-toto", "slsa", "ml-bom", "aixv"}:
            raise ValueError(f"unsupported format: {format}")
        payload: Dict[str, Any]
        if format == "in-toto":
            payload = {
                "format": "in-toto",
                "artifact_digest": digest,
                "statements": attestations,
            }
        elif format == "slsa":
            payload = {
                "format": "slsa",
                "provenance": export_attestations_as_slsa(
                    artifact_digest=digest,
                    artifact_name=artifact_path.name,
                    attestations=attestations,
                ),
            }
        elif format == "ml-bom":
            payload = {
                "format": "ml-bom",
                "bom": export_attestations_as_ml_bom(
                    artifact_digest=digest,
                    artifact_name=artifact_path.name,
                    attestations=attestations,
                ),
            }
        else:
            payload = {
                "format": "aixv",
                "artifact_digest": digest,
                "attestations": attestations,
            }
        payload["attestation_trust"] = trust_report["summary"]
        payload["attestation_violations"] = trust_report["violations"]
        ok = len(trust_report["violations"]) < 1
        _emit({"ok": ok, "export": payload}, json_output)
        if not ok:
            raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "export"}, json_output)
        raise typer.Exit(code=1)


@advisory_app.command("list")
def advisory_list(
    artifact: str = typer.Argument(..., help="Path to artifact"),
    require_signed: bool = typer.Option(False, help="Return only signed-and-trusted advisories"),
    trusted_subject: Optional[str] = typer.Option(
        None, help="Trusted advisory signer subject (repeat via CSV in --trusted-subjects)"
    ),
    trusted_subjects: Optional[str] = typer.Option(
        None, help="Comma-separated trusted advisory signer subjects"
    ),
    trusted_issuers: Optional[str] = typer.Option(
        None, help="Comma-separated trusted advisory signer issuers"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """List locally stored advisories affecting this artifact digest."""
    try:
        artifact_path = ensure_artifact(artifact)
        digest = sha256_file(artifact_path)
        subject_list = []
        if trusted_subject:
            subject_list.append(trusted_subject)
        subject_list.extend(_parse_csv_values(trusted_subjects))
        issuer_list = _parse_csv_values(trusted_issuers)
        advisories = list_advisories(
            _root_dir(),
            digest,
            require_signed=require_signed,
            trusted_subjects=subject_list,
            trusted_issuers=issuer_list,
            staging=staging,
            offline=offline,
        )
        _emit({"ok": True, "artifact_digest": digest, "advisories": advisories}, json_output)
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "advisory list"}, json_output)
        raise typer.Exit(code=1)


@advisory_app.command("create")
def advisory_create(
    advisory_id: str = typer.Option(..., help="Unique advisory identifier"),
    severity: str = typer.Option(..., help="low|medium|high|critical"),
    input: str = typer.Option(..., "--input", "-i", help="Path to advisory payload JSON"),
    sign: bool = typer.Option(False, help="Sign advisory record with Sigstore"),
    identity_token: Optional[str] = typer.Option(None, help="OIDC token for keyless signing"),
    identity_token_env: str = typer.Option(
        "SIGSTORE_ID_TOKEN", help="Environment variable containing OIDC token"
    ),
    interactive_oidc: bool = typer.Option(
        False, help="Acquire OIDC token interactively via browser"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Validate and store an advisory predicate payload."""
    try:
        payload = read_json(input)
        payload["advisory_id"] = advisory_id
        payload["severity"] = severity
        affected = payload.get("affected", [])
        if isinstance(affected, list):
            for item in affected:
                if isinstance(item, dict) and isinstance(item.get("digest"), str):
                    item["digest"] = normalize_sha256_digest(item["digest"])
        validated = validate_predicate(PREDICATE_ALIASES["advisory"], payload)
        result = _create_and_optionally_sign_record(
            kind="advisory",
            record_id=advisory_id,
            payload=validated,
            output=str(_root_dir() / ".aixv" / "advisories" / f"{advisory_id}.json"),
            sign=sign,
            identity_token=identity_token,
            identity_token_env=identity_token_env,
            interactive_oidc=interactive_oidc,
            staging=staging,
            offline=offline,
        )
        result["advisory_id"] = advisory_id
        _emit(result, json_output)
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "advisory create"}, json_output)
        raise typer.Exit(code=1)


@advisory_app.command("verify")
def advisory_verify(
    advisory_record: str = typer.Argument(..., help="Path to advisory record JSON"),
    bundle: Optional[str] = typer.Option(None, help="Sigstore bundle path for advisory record"),
    trusted_subject: Optional[str] = typer.Option(None, help="Trusted advisory signer subject"),
    trusted_subjects: Optional[str] = typer.Option(
        None, help="Comma-separated trusted advisory signer subjects"
    ),
    trusted_issuers: Optional[str] = typer.Option(
        None, help="Comma-separated trusted advisory signer issuers"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Verify advisory record signature and signer trust constraints."""
    try:
        advisory_path = ensure_artifact(advisory_record)
        advisory = load_signed_record(str(advisory_path), expected_kind="advisory")
        validate_predicate(PREDICATE_ALIASES["advisory"], advisory.payload)
        bundle_in = resolve_signature_bundle_path(advisory_path, bundle)
        if not bundle_in.exists():
            raise FileNotFoundError(f"bundle not found: {bundle_in}")
        subject_list = []
        if trusted_subject:
            subject_list.append(trusted_subject)
        subject_list.extend(_parse_csv_values(trusted_subjects))
        issuer_list = _parse_csv_values(trusted_issuers)
        if len(subject_list) < 1:
            raise ValueError("trusted subject constraints required")
        result = verify_signed_record(
            record_path=advisory_path,
            bundle_path=bundle_in,
            trusted_subjects=subject_list,
            trusted_issuers=issuer_list,
            staging=staging,
            offline=offline,
        )
        result["record_kind"] = advisory.kind
        result["record_id"] = advisory.record_id
        result["ok"] = True
        _emit(result, json_output)
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "advisory verify"}, json_output)
        raise typer.Exit(code=1)


@advisory_app.command("sync")
def advisory_sync(
    feed: str = typer.Option(
        ...,
        help="Path/URL to advisory feed JSON (schema aixv.advisory-feed/v1 with entries[])",
    ),
    trusted_subject: Optional[str] = typer.Option(None, help="Trusted advisory signer subject"),
    trusted_subjects: Optional[str] = typer.Option(
        None, help="Comma-separated trusted advisory signer subjects"
    ),
    trusted_issuers: Optional[str] = typer.Option(
        None, help="Comma-separated trusted advisory signer issuers"
    ),
    max_bundle_age_days: Optional[int] = typer.Option(
        None, help="Reject advisories with bundle integrated time older than N days"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Ingest signed advisories from a feed with replay/freshness protection."""
    try:
        subject_list = []
        if trusted_subject:
            subject_list.append(trusted_subject)
        subject_list.extend(_parse_csv_values(trusted_subjects))
        issuer_list = _parse_csv_values(trusted_issuers)
        if len(subject_list) < 1:
            raise ValueError("trusted subject constraints required")
        if max_bundle_age_days is not None and max_bundle_age_days < 1:
            raise ValueError("max_bundle_age_days must be >= 1")

        feed_payload = _read_json_from_ref(feed)
        if feed_payload.get("schema") != "aixv.advisory-feed/v1":
            raise ValueError("feed schema must be aixv.advisory-feed/v1")
        entries = _parse_advisory_feed_entries(feed_payload)

        root = _root_dir()
        advisories_dir = root / ".aixv" / "advisories"
        advisories_dir.mkdir(parents=True, exist_ok=True)
        sync_state = _load_advisory_sync_state(root)
        sync_entries = sync_state.setdefault("entries", {})
        if not isinstance(sync_entries, dict):
            raise ValueError("invalid advisory sync state entries")

        results: List[Dict[str, Any]] = []
        imported = 0
        for entry in entries:
            record_ref = entry["record"]
            bundle_ref = entry["bundle"]
            try:
                record_bytes = _read_bytes_from_ref(record_ref)
                bundle_bytes = _read_bytes_from_ref(bundle_ref)
                with TemporaryDirectory() as tmp:
                    tmp_dir = Path(tmp)
                    tmp_record = tmp_dir / "record.json"
                    tmp_bundle = tmp_dir / "record.sigstore.json"
                    tmp_record.write_bytes(record_bytes)
                    tmp_bundle.write_bytes(bundle_bytes)

                    advisory = load_signed_record(str(tmp_record), expected_kind="advisory")
                    validate_predicate(PREDICATE_ALIASES["advisory"], advisory.payload)
                    verification = verify_signed_record(
                        record_path=tmp_record,
                        bundle_path=tmp_bundle,
                        trusted_subjects=subject_list,
                        trusted_issuers=issuer_list,
                        staging=staging,
                        offline=offline,
                    )

                safe_advisory_id = validate_record_id(advisory.record_id)
                previous_integrated = None
                existing = sync_entries.get(safe_advisory_id)
                if isinstance(existing, dict):
                    token = existing.get("integrated_time")
                    if isinstance(token, str):
                        previous_integrated = token
                guard_violations = evaluate_advisory_sync_guards(
                    integrated_time=verification.get("integrated_time"),
                    previous_integrated_time=previous_integrated,
                    max_age_days=max_bundle_age_days,
                )
                if guard_violations:
                    raise ValueError("; ".join(guard_violations))

                record_out = advisories_dir / f"{safe_advisory_id}.json"
                bundle_out = advisories_dir / f"{safe_advisory_id}.json.sigstore.json"
                record_out.write_bytes(record_bytes)
                bundle_out.write_bytes(bundle_bytes)

                sync_entries[safe_advisory_id] = {
                    "integrated_time": verification.get("integrated_time"),
                    "updated_at": datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat(),
                    "source_record": record_ref,
                    "source_bundle": bundle_ref,
                }
                imported += 1
                results.append(
                    {
                        "advisory_id": safe_advisory_id,
                        "status": "imported",
                        "integrated_time": verification.get("integrated_time"),
                        "path": str(record_out),
                        "bundle_path": str(bundle_out),
                    }
                )
            except Exception as exc:
                results.append(
                    {
                        "record": record_ref,
                        "bundle": bundle_ref,
                        "status": "rejected",
                        "error": str(exc),
                    }
                )

        _save_advisory_sync_state(root, sync_state)
        rejected = [r for r in results if r.get("status") == "rejected"]
        payload = {
            "ok": len(rejected) == 0,
            "feed": feed,
            "entry_count": len(entries),
            "imported_count": imported,
            "rejected_count": len(rejected),
            "results": results,
        }
        _emit(payload, json_output)
        if rejected:
            raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "advisory sync"}, json_output)
        raise typer.Exit(code=1)


@record_app.command("verify")
def record_verify(
    record: str = typer.Argument(..., help="Path to signed record JSON"),
    bundle: Optional[str] = typer.Option(None, help="Sigstore bundle path for record"),
    kind: Optional[str] = typer.Option(None, help="Expected record kind"),
    trusted_subject: Optional[str] = typer.Option(None, help="Trusted signer subject"),
    trusted_subjects: Optional[str] = typer.Option(
        None, help="Comma-separated trusted signer subjects"
    ),
    trusted_issuers: Optional[str] = typer.Option(
        None, help="Comma-separated trusted signer issuers"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Verify any SignedRecord and return normalized metadata."""
    try:
        record_path = ensure_artifact(record)
        signed_record = load_signed_record(str(record_path), expected_kind=kind)
        bundle_in = resolve_signature_bundle_path(record_path, bundle)
        if not bundle_in.exists():
            raise FileNotFoundError(f"bundle not found: {bundle_in}")
        subject_list = []
        if trusted_subject:
            subject_list.append(trusted_subject)
        subject_list.extend(_parse_csv_values(trusted_subjects))
        issuer_list = _parse_csv_values(trusted_issuers)
        if len(subject_list) < 1:
            raise ValueError("trusted subject constraints required")
        verification = verify_signed_record(
            record_path=record_path,
            bundle_path=bundle_in,
            trusted_subjects=subject_list,
            trusted_issuers=issuer_list,
            staging=staging,
            offline=offline,
        )
        _emit(
            {
                "ok": True,
                "record_path": str(record_path),
                "bundle_path": str(bundle_in),
                "record_kind": signed_record.kind,
                "record_id": signed_record.record_id,
                "record_payload": signed_record.payload,
                "signature_verification": verification,
            },
            json_output,
        )
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "record verify"}, json_output)
        raise typer.Exit(code=1)


@record_app.command("create")
def record_create(
    kind: str = typer.Option(
        ..., help="Record kind (e.g., policy, advisory, bundle, waiver, incident)"
    ),
    record_id: str = typer.Option(..., help="Record identifier"),
    input: str = typer.Option(..., "--input", "-i", help="Path to record payload JSON"),
    output: Optional[str] = typer.Option(None, help="Output path for signed record JSON"),
    validate_known_kind: bool = typer.Option(
        True,
        "--validate-known-kind/--no-validate-known-kind",
        help="Validate payload when kind has built-in schema",
    ),
    sign: bool = typer.Option(False, help="Sign record with Sigstore"),
    identity_token: Optional[str] = typer.Option(None, help="OIDC token for keyless signing"),
    identity_token_env: str = typer.Option(
        "SIGSTORE_ID_TOKEN", help="Environment variable containing OIDC token"
    ),
    interactive_oidc: bool = typer.Option(
        False, help="Acquire OIDC token interactively via browser"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Create a generic SignedRecord with optional schema-aware validation."""
    try:
        input_path = ensure_artifact(input)
        payload = read_json(str(input_path))
        if validate_known_kind:
            payload = validate_record_payload(kind, payload)
        result = _create_and_optionally_sign_record(
            kind=kind,
            record_id=record_id,
            payload=payload,
            output=output,
            sign=sign,
            identity_token=identity_token,
            identity_token_env=identity_token_env,
            interactive_oidc=interactive_oidc,
            staging=staging,
            offline=offline,
        )
        _emit(result, json_output)
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "record create"}, json_output)
        raise typer.Exit(code=1)


def _policy_template_for_assurance_level(
    *,
    assurance_level: str,
    advisory_subject_overrides: List[str],
    max_bundle_age_days: Optional[int],
) -> Dict[str, Any]:
    if assurance_level not in {"level-1", "level-2", "level-3"}:
        raise ValueError(f"unsupported assurance level: {assurance_level}")
    if max_bundle_age_days is not None and max_bundle_age_days < 1:
        raise ValueError("max_bundle_age_days must be >= 1")

    policy: Dict[str, Any] = {
        "policy_type": "aixv.policy/v1",
        "allow_subjects": ["REPLACE_WITH_TRUSTED_SUBJECT"],
    }
    if assurance_level == "level-1":
        policy["require_signed_advisories"] = False
    if assurance_level in {"level-2", "level-3"}:
        policy["require_signed_advisories"] = True
        policy["advisory_allow_subjects"] = (
            advisory_subject_overrides
            if advisory_subject_overrides
            else ["REPLACE_WITH_TRUSTED_ADVISORY_SIGNER"]
        )
    if assurance_level == "level-3":
        if max_bundle_age_days is None:
            raise ValueError("level-3 template requires --max-bundle-age-days")
        policy["max_bundle_age_days"] = max_bundle_age_days
        policy["require_no_active_advisories"] = True

    validated = validate_policy_payload(policy)
    violations = evaluate_assurance_level_requirements(
        assurance_level=assurance_level,
        policy_provided=True,
        require_signed_policy=True,
        policy=validated,
    )
    if violations:
        raise ValueError("; ".join(violations))
    return validated


def _migrate_policy_to_assurance_level(
    *,
    policy: Dict[str, Any],
    assurance_level: str,
    advisory_subject_overrides: List[str],
    max_bundle_age_days: Optional[int],
) -> Dict[str, Any]:
    if assurance_level not in {"level-1", "level-2", "level-3"}:
        raise ValueError(f"unsupported assurance level: {assurance_level}")
    if max_bundle_age_days is not None and max_bundle_age_days < 1:
        raise ValueError("max_bundle_age_days must be >= 1")

    migrated: Dict[str, Any] = dict(policy)
    if assurance_level in {"level-2", "level-3"}:
        migrated["require_signed_advisories"] = True
        if advisory_subject_overrides:
            migrated["advisory_allow_subjects"] = advisory_subject_overrides
        advisory_trust = advisory_trust_constraints_from_policy(migrated)
        if len(advisory_trust["subjects"]) < 1:
            raise ValueError(
                "level-2/level-3 migration requires advisory trust subjects; "
                "set policy subject/allow_subjects or pass --advisory-trusted-subject(s)"
            )
    if assurance_level == "level-3":
        migrated["require_no_active_advisories"] = True
        if max_bundle_age_days is not None:
            migrated["max_bundle_age_days"] = max_bundle_age_days
        elif migrated.get("max_bundle_age_days") is None:
            raise ValueError(
                "level-3 migration requires max_bundle_age_days; pass --max-bundle-age-days"
            )

    validated = validate_policy_payload(migrated)
    violations = evaluate_assurance_level_requirements(
        assurance_level=assurance_level,
        policy_provided=True,
        require_signed_policy=True,
        policy=validated,
    )
    if violations:
        raise ValueError("; ".join(violations))
    return validated


@policy_app.command("template")
def policy_template(
    assurance_level: str = typer.Option(..., "--assurance-level", help="level-1|level-2|level-3"),
    advisory_trusted_subject: Optional[str] = typer.Option(
        None, help="Trusted advisory signer subject"
    ),
    advisory_trusted_subjects: Optional[str] = typer.Option(
        None, help="Comma-separated trusted advisory signer subjects"
    ),
    max_bundle_age_days: Optional[int] = typer.Option(None, help="Required for level-3 templates"),
    output: Optional[str] = typer.Option(None, help="Optional output path for policy template"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Generate a baseline policy template for an assurance level."""
    try:
        advisory_subjects: List[str] = []
        if advisory_trusted_subject:
            advisory_subjects.append(advisory_trusted_subject)
        advisory_subjects.extend(_parse_csv_values(advisory_trusted_subjects))
        policy = _policy_template_for_assurance_level(
            assurance_level=assurance_level,
            advisory_subject_overrides=advisory_subjects,
            max_bundle_age_days=max_bundle_age_days,
        )
        out_path = Path(output) if output else None
        if out_path is not None:
            write_json(out_path, policy)
        _emit(
            {
                "ok": True,
                "assurance_level": assurance_level,
                "policy": policy,
                "path": str(out_path) if out_path else None,
            },
            json_output,
        )
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "policy template"}, json_output)
        raise typer.Exit(code=1)


@policy_app.command("migrate")
def policy_migrate(
    input: str = typer.Option(..., "--input", "-i", help="Path to policy JSON or policy record"),
    to_assurance_level: str = typer.Option(
        ..., "--to-assurance-level", help="level-1|level-2|level-3"
    ),
    advisory_trusted_subject: Optional[str] = typer.Option(
        None, help="Trusted advisory signer subject override"
    ),
    advisory_trusted_subjects: Optional[str] = typer.Option(
        None, help="Comma-separated trusted advisory signer subject overrides"
    ),
    max_bundle_age_days: Optional[int] = typer.Option(
        None, help="Required when migrating to level-3 without existing freshness policy"
    ),
    output: Optional[str] = typer.Option(None, help="Output path for migrated policy JSON"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Migrate an existing policy payload to a target assurance level."""
    try:
        input_path = ensure_artifact(input)
        base_policy = policy_from_file(str(input_path))
        advisory_subjects: List[str] = []
        if advisory_trusted_subject:
            advisory_subjects.append(advisory_trusted_subject)
        advisory_subjects.extend(_parse_csv_values(advisory_trusted_subjects))
        migrated = _migrate_policy_to_assurance_level(
            policy=base_policy,
            assurance_level=to_assurance_level,
            advisory_subject_overrides=advisory_subjects,
            max_bundle_age_days=max_bundle_age_days,
        )
        out_path = (
            Path(output)
            if output
            else input_path.with_name(f"{input_path.stem}.{to_assurance_level}.policy.json")
        )
        write_json(out_path, migrated)
        _emit(
            {
                "ok": True,
                "input": str(input_path),
                "assurance_level": to_assurance_level,
                "path": str(out_path),
                "policy": migrated,
            },
            json_output,
        )
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "policy migrate"}, json_output)
        raise typer.Exit(code=1)


@policy_app.command("create")
def policy_create(
    input: str = typer.Option(..., "--input", "-i", help="Path to policy JSON payload"),
    policy_id: Optional[str] = typer.Option(
        None, help="Policy identifier; defaults to input file stem"
    ),
    output: Optional[str] = typer.Option(None, help="Output path for policy record"),
    sign: bool = typer.Option(False, help="Sign policy record with Sigstore"),
    identity_token: Optional[str] = typer.Option(None, help="OIDC token for keyless signing"),
    identity_token_env: str = typer.Option(
        "SIGSTORE_ID_TOKEN", help="Environment variable containing OIDC token"
    ),
    interactive_oidc: bool = typer.Option(
        False, help="Acquire OIDC token interactively via browser"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Create a signed-record policy artifact from validated policy payload."""
    try:
        input_path = ensure_artifact(input)
        raw = read_json(str(input_path))
        payload = validate_policy_payload(raw)
        resolved_policy_id = policy_id or input_path.stem
        result = _create_and_optionally_sign_record(
            kind="policy",
            record_id=resolved_policy_id,
            payload=payload,
            output=output or str(_root_dir() / ".aixv" / "policies" / f"{resolved_policy_id}.json"),
            sign=sign,
            identity_token=identity_token,
            identity_token_env=identity_token_env,
            interactive_oidc=interactive_oidc,
            staging=staging,
            offline=offline,
        )
        result["policy_id"] = resolved_policy_id
        _emit(result, json_output)
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "policy create"}, json_output)
        raise typer.Exit(code=1)


@policy_app.command("verify")
def policy_verify(
    policy_record: str = typer.Argument(..., help="Path to policy record JSON"),
    bundle: Optional[str] = typer.Option(None, help="Sigstore bundle path for policy record"),
    trusted_subject: Optional[str] = typer.Option(None, help="Trusted policy signer subject"),
    trusted_subjects: Optional[str] = typer.Option(
        None, help="Comma-separated trusted policy signer subjects"
    ),
    trusted_issuers: Optional[str] = typer.Option(
        None, help="Comma-separated trusted policy signer issuers"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Verify policy record signature and validate policy payload semantics."""
    try:
        policy_path = ensure_artifact(policy_record)
        bundle_in = resolve_signature_bundle_path(policy_path, bundle)
        if not bundle_in.exists():
            raise FileNotFoundError(f"bundle not found: {bundle_in}")
        subject_list = []
        if trusted_subject:
            subject_list.append(trusted_subject)
        subject_list.extend(_parse_csv_values(trusted_subjects))
        issuer_list = _parse_csv_values(trusted_issuers)
        if len(subject_list) < 1:
            raise ValueError("trusted subject constraints required")
        verify_result = verify_signed_record(
            record_path=policy_path,
            bundle_path=bundle_in,
            trusted_subjects=subject_list,
            trusted_issuers=issuer_list,
            staging=staging,
            offline=offline,
        )
        validated_policy = policy_from_file(str(policy_path))
        _emit(
            {
                "ok": True,
                "policy_path": str(policy_path),
                "bundle_path": str(bundle_in),
                "policy": validated_policy,
                "signature_verification": verify_result,
            },
            json_output,
        )
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "policy verify"}, json_output)
        raise typer.Exit(code=1)


@bundle_app.command("create")
def bundle_create(
    input: str = typer.Option(..., "--input", "-i", help="Path to bundle payload JSON"),
    bundle_id: Optional[str] = typer.Option(None, help="Bundle identifier override"),
    output: Optional[str] = typer.Option(None, help="Output path for bundle record"),
    sign: bool = typer.Option(False, help="Sign bundle record with Sigstore"),
    identity_token: Optional[str] = typer.Option(None, help="OIDC token for keyless signing"),
    identity_token_env: str = typer.Option(
        "SIGSTORE_ID_TOKEN", help="Environment variable containing OIDC token"
    ),
    interactive_oidc: bool = typer.Option(
        False, help="Acquire OIDC token interactively via browser"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Create a strict multi-artifact bundle record."""
    try:
        input_path = ensure_artifact(input)
        payload = read_json(str(input_path))
        if bundle_id is not None:
            payload["bundle_id"] = bundle_id
        validated = validate_record_payload("bundle", payload)
        resolved_bundle_id = validated["bundle_id"]
        result = _create_and_optionally_sign_record(
            kind="bundle",
            record_id=resolved_bundle_id,
            payload=validated,
            output=output,
            sign=sign,
            identity_token=identity_token,
            identity_token_env=identity_token_env,
            interactive_oidc=interactive_oidc,
            staging=staging,
            offline=offline,
        )
        result["bundle_id"] = resolved_bundle_id
        _emit(result, json_output)
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "bundle create"}, json_output)
        raise typer.Exit(code=1)


@bundle_app.command("verify")
def bundle_verify(
    bundle_record: str = typer.Argument(..., help="Path to bundle record JSON"),
    bundle: Optional[str] = typer.Option(None, help="Sigstore bundle path for bundle record"),
    require_member: Optional[str] = typer.Option(
        None, help="Required member digest (sha256:...) or path to local file"
    ),
    trusted_subject: Optional[str] = typer.Option(None, help="Trusted bundle signer subject"),
    trusted_subjects: Optional[str] = typer.Option(
        None, help="Comma-separated trusted bundle signer subjects"
    ),
    trusted_issuers: Optional[str] = typer.Option(
        None, help="Comma-separated trusted bundle signer issuers"
    ),
    staging: bool = typer.Option(False, help="Use Sigstore staging instance"),
    offline: bool = typer.Option(False, help="Use cached trust root only"),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Verify signed bundle record and optional required membership."""
    try:
        record_path = ensure_artifact(bundle_record)
        bundle_record_obj = load_signed_record(str(record_path), expected_kind="bundle")
        validated_bundle = validate_record_payload("bundle", bundle_record_obj.payload)
        bundle_in = resolve_signature_bundle_path(record_path, bundle)
        if not bundle_in.exists():
            raise FileNotFoundError(f"bundle not found: {bundle_in}")
        subject_list = []
        if trusted_subject:
            subject_list.append(trusted_subject)
        subject_list.extend(_parse_csv_values(trusted_subjects))
        issuer_list = _parse_csv_values(trusted_issuers)
        if len(subject_list) < 1:
            raise ValueError("trusted subject constraints required")
        signature_verification = verify_signed_record(
            record_path=record_path,
            bundle_path=bundle_in,
            trusted_subjects=subject_list,
            trusted_issuers=issuer_list,
            staging=staging,
            offline=offline,
        )

        required_digest: Optional[str] = None
        if require_member:
            candidate_path = Path(require_member)
            if candidate_path.exists() and candidate_path.is_file():
                required_digest = sha256_file(candidate_path)
            else:
                required_digest = normalize_sha256_digest(require_member)
            if required_digest not in validated_bundle.get("members", []):
                raise ValueError(f"required member digest not found in bundle: {required_digest}")

        _emit(
            {
                "ok": True,
                "bundle_path": str(record_path),
                "bundle_record_id": bundle_record_obj.record_id,
                "bundle_payload": validated_bundle,
                "required_member": required_digest,
                "signature_verification": signature_verification,
            },
            json_output,
        )
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "bundle verify"}, json_output)
        raise typer.Exit(code=1)


@app.command()
def version(
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Print version information."""
    _emit({"ok": True, "version": __version__}, json_output)


@app.command()
def conformance(
    output: Optional[str] = typer.Option(
        None, help="Optional output path for conformance report JSON"
    ),
    json_output: bool = typer.Option(False, "--json", help="Deterministic JSON output"),
):
    """Run core conformance checks and emit a machine-readable report."""
    try:
        report = run_conformance_checks()
        payload = report.model_dump(by_alias=True)
        if output:
            out_path = Path(output)
            write_json(out_path, payload)
            payload["output_path"] = str(out_path)
        payload["ok"] = report.overall_status == "pass"
        _emit(payload, json_output)
        if report.overall_status != "pass":
            raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except Exception as e:
        _emit({"ok": False, "error": str(e), "command": "conformance"}, json_output)
        raise typer.Exit(code=1) from e


if __name__ == "__main__":
    app()
