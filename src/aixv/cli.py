import json
from pathlib import Path
from typing import Any, Dict, Optional

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
    trace_training_lineage_parents,
    validate_policy_payload,
    validate_predicate,
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
app.add_typer(advisory_app, name="advisory")
app.add_typer(policy_app, name="policy")
app.add_typer(record_app, name="record")
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
    _ = depth
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
        parents = trace_training_lineage_parents(_root_dir(), digest, depth)
        advisories = list_advisories(_root_dir(), digest)
        payload = {
            "ok": len(trust_report["violations"]) < 1,
            "artifact": str(artifact_path),
            "artifact_digest": digest,
            "attestation_count": len(attestations),
            "attestation_trust": trust_report["summary"],
            "attestation_violations": trust_report["violations"],
            "parents": parents,
            "advisory_count": len(advisories),
        }
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
        payload = {
            "format": format,
            "artifact_digest": digest,
            "attestations": attestations,
            "attestation_trust": trust_report["summary"],
            "attestation_violations": trust_report["violations"],
        }
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
    kind: str = typer.Option(..., help="Record kind (e.g., policy, advisory, waiver, incident)"),
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
