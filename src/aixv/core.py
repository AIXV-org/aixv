from __future__ import annotations

import hashlib
import json
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.x509 import (
    ObjectIdentifier,
    RFC822Name,
    SubjectAlternativeName,
    UniformResourceIdentifier,
)
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sigstore.dsse import Statement
from sigstore.hashes import HashAlgorithm, Hashed
from sigstore.models import Bundle, ClientTrustConfig
from sigstore.oidc import IdentityToken, Issuer
from sigstore.sign import SigningContext
from sigstore.verify import Verifier
from sigstore.verify.policy import AnyOf, Identity

PREDICATE_ALIASES: Dict[str, str] = {
    "training": "https://aixv.org/attestation/training/v1",
    "advisory": "https://aixv.org/attestation/advisory/v1",
}


ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
ALLOWED_ADVISORY_STATUS = {"active", "mitigated", "withdrawn"}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ATTESTATION_RECORD_SCHEMA = "aixv.attestation-record/v1"
ALLOWED_ASSURANCE_LEVELS = {"level-1", "level-2", "level-3"}


class ParentModel(BaseModel):
    digest: str
    uri: Optional[str] = None
    model_config = ConfigDict(extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        self.digest = normalize_sha256_digest(self.digest)


class DatasetRef(BaseModel):
    digest: str
    uri: Optional[str] = None
    split: Optional[str] = None
    model_config = ConfigDict(extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        self.digest = normalize_sha256_digest(self.digest)


class TrainingRun(BaseModel):
    framework: str
    framework_version: str
    code_digest: str
    environment_digest: str
    model_config = ConfigDict(extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        self.code_digest = normalize_sha256_digest(self.code_digest)
        self.environment_digest = normalize_sha256_digest(self.environment_digest)


class TrainingPredicate(BaseModel):
    parent_models: List[ParentModel] = Field(min_length=1)
    datasets: List[DatasetRef] = Field(default_factory=list)
    training_run: TrainingRun
    hyperparameters: Dict[str, Any] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid")


class AdvisoryAffected(BaseModel):
    digest: Optional[str] = None
    selector: Optional[str] = None
    model_config = ConfigDict(extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        if self.digest is None and self.selector is None:
            raise ValueError("affected entry requires at least one of digest or selector")
        if self.digest is not None:
            self.digest = normalize_sha256_digest(self.digest)


class AdvisoryPredicate(BaseModel):
    advisory_id: str
    affected: List[AdvisoryAffected] = Field(min_length=1)
    severity: str
    status: str
    reason_code: str
    recommended_actions: List[str] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity}")
        if self.status not in ALLOWED_ADVISORY_STATUS:
            raise ValueError(f"invalid status: {self.status}")


class ArtifactBundle(BaseModel):
    bundle_type: str = "aixv.bundle/v1"
    bundle_id: str
    primary: str
    members: List[str] = Field(min_length=1)

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        self.primary = normalize_sha256_digest(self.primary)
        normalized_members: List[str] = []
        for member in self.members:
            digest = normalize_sha256_digest(member)
            if digest not in normalized_members:
                normalized_members.append(digest)
        if self.primary not in normalized_members:
            normalized_members.append(self.primary)
        self.members = normalized_members


class VerifyPolicy(BaseModel):
    policy_type: str = "aixv.policy/v1"
    subject: Optional[str] = None
    issuer: Optional[str] = None
    allow_subjects: List[str] = Field(default_factory=list)
    deny_subjects: List[str] = Field(default_factory=list)
    allow_issuers: List[str] = Field(default_factory=list)
    deny_issuers: List[str] = Field(default_factory=list)
    max_bundle_age_days: Optional[int] = None
    deny_advisory_severity_at_or_above: Optional[str] = None
    require_no_active_advisories: bool = False
    require_signed_advisories: bool = True
    advisory_allow_subjects: List[str] = Field(default_factory=list)
    advisory_allow_issuers: List[str] = Field(default_factory=list)

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        if self.policy_type != "aixv.policy/v1":
            raise ValueError("unsupported policy_type; expected aixv.policy/v1")
        if self.max_bundle_age_days is not None and self.max_bundle_age_days < 1:
            raise ValueError("max_bundle_age_days must be >= 1")
        if self.deny_advisory_severity_at_or_above is not None:
            value = self.deny_advisory_severity_at_or_above.lower()
            if value not in ALLOWED_SEVERITIES:
                raise ValueError(
                    "deny_advisory_severity_at_or_above must be one of low|medium|high|critical"
                )
            self.deny_advisory_severity_at_or_above = value
        if (
            self.require_signed_advisories
            and (
                self.require_no_active_advisories
                or self.deny_advisory_severity_at_or_above is not None
            )
            and len(self.advisory_allow_subjects) < 1
            and self.subject is None
            and len(self.allow_subjects) < 1
        ):
            raise ValueError(
                "policy requires signed advisory trust roots; set advisory_allow_subjects "
                "or subject/allow_subjects"
            )


class SignedRecord(BaseModel):
    schema_: str = Field("aixv.signed-record/v1", alias="schema")
    kind: str
    record_id: str
    created_at: str
    payload: Dict[str, Any]
    signature_bundle_path: Optional[str] = None

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class AdmissionDecision(BaseModel):
    decision: str
    violations: List[str]
    evidence: Dict[str, Any]
    model_config = ConfigDict(extra="forbid")

    def model_post_init(self, __context: Any) -> None:
        if self.decision not in {"allow", "deny"}:
            raise ValueError("decision must be allow|deny")


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat()


def normalize_sha256_digest(value: str) -> str:
    token = value.strip().lower()
    if token.startswith("sha256:"):
        token = token.split(":", 1)[1]
    if len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
        raise ValueError(f"invalid sha256 digest: {value}")
    return f"sha256:{token}"


def _normalize_string_list(raw: Any) -> List[str]:
    if not isinstance(raw, list):
        return []
    out: List[str] = []
    for item in raw:
        if not isinstance(item, str):
            continue
        value = item.strip()
        if value and value not in out:
            out.append(value)
    return out


def ensure_artifact(path: str) -> Path:
    artifact = Path(path)
    if not artifact.exists():
        raise FileNotFoundError(f"artifact not found: {artifact}")
    if not artifact.is_file():
        raise ValueError(f"artifact is not a file: {artifact}")
    return artifact


def read_json(path: str) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def _sha256_file_digest(path: Path) -> bytes:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


def sha256_file(path: Path) -> str:
    return f"sha256:{_sha256_file_digest(path).hex()}"


def sigstore_hashed_input(path: Path) -> Hashed:
    return Hashed(algorithm=HashAlgorithm.SHA2_256, digest=_sha256_file_digest(path))


def bundle_path_for(artifact: Path) -> Path:
    return artifact.with_name(f"{artifact.name}.sigstore.json")


def aixv_dir(root: Path) -> Path:
    return root / ".aixv"


def advisory_store(root: Path) -> Path:
    return aixv_dir(root) / "advisories"


def attestation_store(root: Path) -> Path:
    return aixv_dir(root) / "attestations"


def policy_store(root: Path) -> Path:
    return aixv_dir(root) / "policies"


def record_store(root: Path, kind: str) -> Path:
    return aixv_dir(root) / "records" / kind


def policy_from_file(path: str) -> Dict[str, Any]:
    raw = read_json(path)
    if isinstance(raw, dict) and raw.get("schema") == "aixv.signed-record/v1":
        record = SignedRecord.model_validate(raw)
        if record.kind != "policy":
            raise ValueError(f"expected signed policy record, got kind={record.kind}")
        raw = record.payload
    return validate_policy_payload(raw)


def validate_policy_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    try:
        parsed = VerifyPolicy.model_validate(raw)
    except ValidationError as e:
        raise ValueError(str(e))
    return parsed.model_dump()


def validate_bundle_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    try:
        parsed = ArtifactBundle.model_validate(raw)
    except ValidationError as e:
        raise ValueError(str(e))
    return parsed.model_dump()


def advisory_trust_constraints_from_policy(policy: Dict[str, Any]) -> Dict[str, List[str]]:
    subjects = _normalize_string_list(policy.get("advisory_allow_subjects"))
    issuers = _normalize_string_list(policy.get("advisory_allow_issuers"))

    if not subjects:
        subjects = _normalize_string_list(policy.get("allow_subjects"))
    if not subjects:
        subject = policy.get("subject")
        if isinstance(subject, str) and subject.strip():
            subjects = [subject.strip()]

    if not issuers:
        issuers = _normalize_string_list(policy.get("allow_issuers"))
    if not issuers:
        issuer = policy.get("issuer")
        if isinstance(issuer, str) and issuer.strip():
            issuers = [issuer.strip()]

    return {"subjects": subjects, "issuers": issuers}


def evaluate_assurance_level_requirements(
    *,
    assurance_level: Optional[str],
    policy_provided: bool,
    require_signed_policy: bool,
    policy: Dict[str, Any],
) -> List[str]:
    if assurance_level is None:
        return []
    if assurance_level not in ALLOWED_ASSURANCE_LEVELS:
        return [f"unsupported assurance level: {assurance_level}"]

    violations: List[str] = []
    if assurance_level in {"level-2", "level-3"}:
        if not policy_provided:
            violations.append(f"assurance level {assurance_level} requires --policy")
        if not require_signed_policy:
            violations.append(
                f"assurance level {assurance_level} requires signed policy verification"
            )
        if not bool(policy.get("require_signed_advisories", False)):
            violations.append(
                f"assurance level {assurance_level} requires require_signed_advisories=true"
            )
        advisory_trust = advisory_trust_constraints_from_policy(policy)
        if len(advisory_trust["subjects"]) < 1:
            violations.append(
                f"assurance level {assurance_level} requires advisory trust subjects via "
                "advisory_allow_subjects or subject/allow_subjects"
            )

    if assurance_level == "level-3":
        if policy.get("max_bundle_age_days") is None:
            violations.append("assurance level level-3 requires max_bundle_age_days")
        if not bool(policy.get("require_no_active_advisories", False)):
            violations.append("assurance level level-3 requires require_no_active_advisories=true")

    return violations


def resolve_predicate_uri(predicate: str) -> str:
    return PREDICATE_ALIASES.get(predicate, predicate)


def validate_predicate(predicate: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    uri = resolve_predicate_uri(predicate)
    try:
        if uri == PREDICATE_ALIASES["training"]:
            return TrainingPredicate.model_validate(payload).model_dump()
        if uri == PREDICATE_ALIASES["advisory"]:
            return AdvisoryPredicate.model_validate(payload).model_dump()
    except ValidationError as e:
        raise ValueError(str(e))
    return payload


def make_statement(
    artifact: Path, predicate_uri: str, predicate_payload: Dict[str, Any]
) -> Dict[str, Any]:
    digest = sha256_file(artifact).split(":", 1)[1]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": artifact.name, "digest": {"sha256": digest}}],
        "predicateType": predicate_uri,
        "predicate": predicate_payload,
    }


def load_identity_token(
    *,
    identity_token: Optional[str],
    identity_token_env: str,
    interactive_oidc: bool,
    staging: bool,
    offline: bool,
) -> IdentityToken:
    token = identity_token or os.getenv(identity_token_env)
    if token:
        return IdentityToken(token)

    if not interactive_oidc:
        raise ValueError(
            "missing OIDC token: pass --identity-token, set SIGSTORE_ID_TOKEN, or use --interactive-oidc"
        )

    trust_config = (
        ClientTrustConfig.staging(offline=offline)
        if staging
        else ClientTrustConfig.production(offline=offline)
    )
    issuer = Issuer(trust_config.signing_config.get_oidc_url())
    return issuer.identity_token()


def sign_artifact_with_sigstore(
    *,
    artifact: Path,
    bundle_out: Path,
    identity_token: Optional[str],
    identity_token_env: str,
    interactive_oidc: bool,
    staging: bool,
    offline: bool,
) -> Dict[str, Any]:
    token = load_identity_token(
        identity_token=identity_token,
        identity_token_env=identity_token_env,
        interactive_oidc=interactive_oidc,
        staging=staging,
        offline=offline,
    )
    trust_config = (
        ClientTrustConfig.staging(offline=offline)
        if staging
        else ClientTrustConfig.production(offline=offline)
    )
    ctx = SigningContext.from_trust_config(trust_config)
    hashed_input = sigstore_hashed_input(artifact)
    with ctx.signer(token, cache=True) as signer:
        bundle = signer.sign_artifact(hashed_input)
    bundle_out.write_text(bundle.to_json(), encoding="utf-8")
    return {
        "bundle_path": str(bundle_out),
        "digest": f"sha256:{hashed_input.digest.hex()}",
        "identity": {"subject": token.identity, "issuer": token.issuer},
        "staging": staging,
    }


def sign_statement_with_sigstore(
    *,
    statement: Dict[str, Any],
    bundle_out: Path,
    identity_token: Optional[str],
    identity_token_env: str,
    interactive_oidc: bool,
    staging: bool,
    offline: bool,
) -> Dict[str, Any]:
    token = load_identity_token(
        identity_token=identity_token,
        identity_token_env=identity_token_env,
        interactive_oidc=interactive_oidc,
        staging=staging,
        offline=offline,
    )
    trust_config = (
        ClientTrustConfig.staging(offline=offline)
        if staging
        else ClientTrustConfig.production(offline=offline)
    )
    ctx = SigningContext.from_trust_config(trust_config)
    statement_bytes = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
    statement_obj = Statement(statement_bytes)
    with ctx.signer(token, cache=True) as signer:
        bundle = signer.sign_dsse(statement_obj)
    bundle_out.write_text(bundle.to_json(), encoding="utf-8")
    return {
        "bundle_path": str(bundle_out),
        "identity": {"subject": token.identity, "issuer": token.issuer},
        "staging": staging,
    }


def _bundle_integrated_time(bundle: Bundle) -> Optional[str]:
    if bundle.log_entry and bundle.log_entry._inner.integrated_time:
        return (
            datetime.fromtimestamp(
                bundle.log_entry._inner.integrated_time,
                tz=timezone.utc,
            )
            .replace(microsecond=0)
            .isoformat()
        )
    return None


def verify_artifact_with_sigstore(
    *,
    artifact: Path,
    bundle_in: Path,
    subject: Optional[str],
    issuer: Optional[str],
    allow_subjects: Optional[List[str]] = None,
    allow_issuers: Optional[List[str]] = None,
    staging: bool,
    offline: bool,
) -> Dict[str, Any]:
    bundle = Bundle.from_json(bundle_in.read_text(encoding="utf-8"))
    verifier = (
        Verifier.staging(offline=offline) if staging else Verifier.production(offline=offline)
    )
    identity_policy = build_sigstore_identity_policy(
        subject=subject,
        issuer=issuer,
        allow_subjects=allow_subjects or [],
        allow_issuers=allow_issuers or [],
    )
    hashed_input = sigstore_hashed_input(artifact)
    verifier.verify_artifact(hashed_input, bundle, identity_policy)
    cert = bundle.signing_certificate
    subject_candidates = _extract_subject_candidates(cert)
    issuer_value = _extract_oidc_issuer(cert)
    integrated_time = _bundle_integrated_time(bundle)
    return {
        "verified": True,
        "digest": f"sha256:{hashed_input.digest.hex()}",
        "bundle_path": str(bundle_in),
        "expected_subject": subject,
        "expected_issuer": issuer,
        "actual_subjects": subject_candidates,
        "actual_issuer": issuer_value,
        "integrated_time": integrated_time,
        "staging": staging,
    }


def verify_statement_with_sigstore(
    *,
    statement: Dict[str, Any],
    bundle_in: Path,
    subject: Optional[str],
    issuer: Optional[str],
    allow_subjects: Optional[List[str]] = None,
    allow_issuers: Optional[List[str]] = None,
    staging: bool,
    offline: bool,
) -> Dict[str, Any]:
    bundle = Bundle.from_json(bundle_in.read_text(encoding="utf-8"))
    verifier = (
        Verifier.staging(offline=offline) if staging else Verifier.production(offline=offline)
    )
    identity_policy = build_sigstore_identity_policy(
        subject=subject,
        issuer=issuer,
        allow_subjects=allow_subjects or [],
        allow_issuers=allow_issuers or [],
    )
    payload_type, payload_bytes = verifier.verify_dsse(bundle, identity_policy)
    try:
        verified_statement = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"verified DSSE payload is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(verified_statement, dict):
        raise ValueError("verified DSSE payload is not a JSON object statement")
    if verified_statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise ValueError("verified DSSE payload is not an in-toto Statement/v1")
    if verified_statement != statement:
        raise ValueError("verified DSSE payload does not match expected statement content")

    cert = bundle.signing_certificate
    subject_candidates = _extract_subject_candidates(cert)
    issuer_value = _extract_oidc_issuer(cert)
    integrated_time = _bundle_integrated_time(bundle)
    return {
        "verified": True,
        "bundle_path": str(bundle_in),
        "payload_type": payload_type,
        "expected_subject": subject,
        "expected_issuer": issuer,
        "actual_subjects": subject_candidates,
        "actual_issuer": issuer_value,
        "integrated_time": integrated_time,
        "staging": staging,
    }


def build_sigstore_identity_policy(
    *,
    subject: Optional[str],
    issuer: Optional[str],
    allow_subjects: List[str],
    allow_issuers: List[str],
) -> Any:
    if subject:
        # Strongest match: explicit identity, optional explicit issuer.
        return Identity(identity=subject, issuer=issuer)

    if not allow_subjects:
        # Should be precluded by VerifyPolicy validation.
        raise ValueError("allow_subjects cannot be empty when subject is not set")

    # Build an OR policy over allowed identities.
    candidates: List[Any] = []
    if allow_issuers:
        for s in allow_subjects:
            for i in allow_issuers:
                candidates.append(Identity(identity=s, issuer=i))
    else:
        for s in allow_subjects:
            candidates.append(Identity(identity=s))
    return AnyOf(candidates)


def create_attestation_record(
    *,
    root: Path,
    artifact: Path,
    predicate_uri: str,
    statement: Dict[str, Any],
    signature_bundle_path: Optional[str] = None,
) -> Path:
    digest = sha256_file(artifact).replace(":", "_")
    parts = predicate_uri.rstrip("/").split("/")
    key = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else parts[-1]
    path = attestation_store(root) / f"{digest}.{key}.json"
    write_json(
        path,
        {
            "schema": ATTESTATION_RECORD_SCHEMA,
            "created_at": now_iso(),
            "predicate_type": predicate_uri,
            "statement": statement,
            "signature_bundle_path": signature_bundle_path,
        },
    )
    return path


def _statement_has_subject_digest(statement: Dict[str, Any], digest: str) -> bool:
    target = normalize_sha256_digest(digest)
    subjects = statement.get("subject", [])
    if not isinstance(subjects, list):
        return False
    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        subject_digest = subject.get("digest")
        if not isinstance(subject_digest, dict):
            continue
        token = subject_digest.get("sha256")
        if not isinstance(token, str):
            continue
        try:
            if normalize_sha256_digest(token) == target:
                return True
        except ValueError:
            continue
    return False


def load_attestation_records_for_digest(root: Path, digest: str) -> List[Dict[str, Any]]:
    needle = digest.replace(":", "_")
    target = normalize_sha256_digest(digest)
    results: List[Dict[str, Any]] = []
    store = attestation_store(root)
    if not store.exists():
        return results
    for path in sorted(store.glob(f"{needle}.*.json")):
        try:
            raw = read_json(str(path))
        except Exception:
            continue
        statement: Optional[Dict[str, Any]] = None
        signature_bundle_path: Optional[str] = None
        if isinstance(raw, dict) and raw.get("schema") == ATTESTATION_RECORD_SCHEMA:
            statement_candidate = raw.get("statement")
            if isinstance(statement_candidate, dict):
                statement = statement_candidate
            bundle_candidate = raw.get("signature_bundle_path")
            if isinstance(bundle_candidate, str) and bundle_candidate.strip():
                signature_bundle_path = bundle_candidate
        elif isinstance(raw, dict):
            statement = raw
            bundle_candidate = raw.get("signature_bundle_path")
            if isinstance(bundle_candidate, str) and bundle_candidate.strip():
                signature_bundle_path = bundle_candidate
        if not isinstance(statement, dict):
            continue
        if not _statement_has_subject_digest(statement, target):
            continue
        if not signature_bundle_path:
            default_bundle = path.with_name(f"{path.name}.sigstore.json")
            if default_bundle.exists():
                signature_bundle_path = str(default_bundle)
        results.append(
            {
                "path": str(path),
                "statement": statement,
                "signature_bundle_path": signature_bundle_path,
            }
        )
    return results


def load_attestations_for_digest(root: Path, digest: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for entry in load_attestation_records_for_digest(root, digest):
        statement = entry.get("statement")
        if isinstance(statement, dict):
            results.append(statement)
    return results


def load_all_attestation_records(root: Path) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    store = attestation_store(root)
    if not store.exists():
        return results
    for path in sorted(store.glob("*.json")):
        try:
            raw = read_json(str(path))
        except Exception:
            continue
        statement: Optional[Dict[str, Any]] = None
        signature_bundle_path: Optional[str] = None
        if isinstance(raw, dict) and raw.get("schema") == ATTESTATION_RECORD_SCHEMA:
            candidate = raw.get("statement")
            if isinstance(candidate, dict):
                statement = candidate
            bundle_candidate = raw.get("signature_bundle_path")
            if isinstance(bundle_candidate, str) and bundle_candidate.strip():
                signature_bundle_path = bundle_candidate
        elif isinstance(raw, dict):
            statement = raw
            bundle_candidate = raw.get("signature_bundle_path")
            if isinstance(bundle_candidate, str) and bundle_candidate.strip():
                signature_bundle_path = bundle_candidate
        if not isinstance(statement, dict):
            continue
        if not signature_bundle_path:
            default_bundle = path.with_name(f"{path.name}.sigstore.json")
            if default_bundle.exists():
                signature_bundle_path = str(default_bundle)
        results.append(
            {
                "path": str(path),
                "statement": statement,
                "signature_bundle_path": signature_bundle_path,
            }
        )
    return results


def summarize_training_lineage_from_attestations(
    attestations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    parent_digests: List[str] = []
    dataset_digests: List[str] = []
    training_runs: List[Dict[str, Any]] = []

    for att in attestations:
        if att.get("predicateType") != PREDICATE_ALIASES["training"]:
            continue
        predicate = att.get("predicate", {})
        if not isinstance(predicate, dict):
            continue
        for parent in predicate.get("parent_models", []):
            if not isinstance(parent, dict):
                continue
            token = parent.get("digest")
            if not isinstance(token, str):
                continue
            try:
                digest = normalize_sha256_digest(token)
            except ValueError:
                continue
            if digest not in parent_digests:
                parent_digests.append(digest)
        for dataset in predicate.get("datasets", []):
            if not isinstance(dataset, dict):
                continue
            token = dataset.get("digest")
            if not isinstance(token, str):
                continue
            try:
                digest = normalize_sha256_digest(token)
            except ValueError:
                continue
            if digest not in dataset_digests:
                dataset_digests.append(digest)
        run = predicate.get("training_run")
        if isinstance(run, dict):
            training_runs.append(run)

    return {
        "parent_digests": parent_digests,
        "dataset_digests": dataset_digests,
        "training_run_count": len(training_runs),
        "training_runs": training_runs,
    }


def create_advisory_record(
    *,
    root: Path,
    advisory: Dict[str, Any],
    signature_bundle_path: Optional[str] = None,
) -> Path:
    advisory_id = advisory["advisory_id"]
    return create_record(
        root=root,
        kind="advisory",
        record_id=advisory_id,
        payload=advisory,
        output_path=str(advisory_store(root) / f"{advisory_id}.json"),
        signature_bundle_path=signature_bundle_path,
    )


def list_advisories(
    root: Path,
    digest: str,
    *,
    require_signed: bool = False,
    trusted_subjects: Optional[List[str]] = None,
    trusted_issuers: Optional[List[str]] = None,
    staging: bool = False,
    offline: bool = False,
) -> List[Dict[str, Any]]:
    target = normalize_sha256_digest(digest)
    out: List[Dict[str, Any]] = []
    store = advisory_store(root)
    if not store.exists():
        return out
    for path in sorted(store.glob("*.json")):
        try:
            raw = read_json(str(path))
        except Exception:
            continue
        advisory: Dict[str, Any]
        bundle_path: Optional[str] = None
        if isinstance(raw, dict) and raw.get("schema") == "aixv.signed-record/v1":
            try:
                record = SignedRecord.model_validate(raw)
            except Exception:
                continue
            if record.kind != "advisory":
                continue
            advisory = record.payload
            bundle_path = record.signature_bundle_path
        else:
            # Backward compatibility with earlier advisory-record shape.
            advisory_candidate = (
                raw.get("advisory") if isinstance(raw, dict) and "advisory" in raw else raw
            )
            if not isinstance(advisory_candidate, dict):
                continue
            advisory = advisory_candidate
            if isinstance(raw, dict):
                candidate_bundle = raw.get("signature_bundle_path")
                if isinstance(candidate_bundle, str):
                    bundle_path = candidate_bundle
        affected = advisory.get("affected", [])
        for item in affected:
            candidate = item.get("digest")
            if not isinstance(candidate, str):
                continue
            try:
                normalized_candidate = normalize_sha256_digest(candidate)
            except ValueError:
                continue
            if normalized_candidate == target:
                signed_and_trusted = False
                if bundle_path and isinstance(bundle_path, str):
                    bundle_ref = Path(bundle_path)
                    if not bundle_ref.is_absolute():
                        bundle_ref = path.parent / bundle_ref
                    if bundle_ref.exists():
                        try:
                            verify_artifact_with_sigstore(
                                artifact=path,
                                bundle_in=bundle_ref,
                                subject=None,
                                issuer=None,
                                allow_subjects=trusted_subjects or [],
                                allow_issuers=trusted_issuers or [],
                                staging=staging,
                                offline=offline,
                            )
                            signed_and_trusted = True
                        except Exception:
                            signed_and_trusted = False
                if require_signed and not signed_and_trusted:
                    break
                advisory = dict(advisory)
                advisory["_trust"] = {
                    "signed_and_trusted": signed_and_trusted,
                    "signature_bundle_path": bundle_path,
                }
                out.append(advisory)
                break
    return out


def verify_signed_record(
    *,
    record_path: Path,
    bundle_path: Path,
    trusted_subjects: List[str],
    trusted_issuers: List[str],
    staging: bool,
    offline: bool,
) -> Dict[str, Any]:
    if len(trusted_subjects) < 1:
        raise ValueError("trusted_subjects cannot be empty")
    return verify_artifact_with_sigstore(
        artifact=record_path,
        bundle_in=bundle_path,
        subject=None,
        issuer=None,
        allow_subjects=trusted_subjects,
        allow_issuers=trusted_issuers,
        staging=staging,
        offline=offline,
    )


def resolve_signature_bundle_path(record_path: Path, explicit_bundle: Optional[str] = None) -> Path:
    if explicit_bundle:
        return Path(explicit_bundle)
    try:
        raw = read_json(str(record_path))
        if isinstance(raw, dict) and raw.get("schema") == "aixv.signed-record/v1":
            record = SignedRecord.model_validate(raw)
            if record.signature_bundle_path:
                bundle_ref = Path(record.signature_bundle_path)
                if not bundle_ref.is_absolute():
                    bundle_ref = record_path.parent / bundle_ref
                return bundle_ref
    except Exception:
        pass
    return record_path.with_name(f"{record_path.name}.sigstore.json")


def create_policy_record(
    *,
    root: Path,
    policy_id: str,
    policy_payload: Dict[str, Any],
    output_path: Optional[str] = None,
    signature_bundle_path: Optional[str] = None,
) -> Path:
    return create_record(
        root=root,
        kind="policy",
        record_id=policy_id,
        payload=policy_payload,
        output_path=output_path or str(policy_store(root) / f"{policy_id}.json"),
        signature_bundle_path=signature_bundle_path,
    )


def load_signed_record(path: str, expected_kind: Optional[str] = None) -> SignedRecord:
    raw = read_json(path)
    record = SignedRecord.model_validate(raw)
    if expected_kind and record.kind != expected_kind:
        raise ValueError(f"expected record kind {expected_kind}, got {record.kind}")
    return record


def validate_record_payload(kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if kind == "policy":
        return validate_policy_payload(payload)
    if kind == "advisory":
        return validate_predicate(PREDICATE_ALIASES["advisory"], payload)
    if kind == "bundle":
        return validate_bundle_payload(payload)
    return payload


def evaluate_admission(
    *,
    policy: Dict[str, Any],
    verification_result: Dict[str, Any],
    advisories: List[Dict[str, Any]],
) -> AdmissionDecision:
    identity_violations = evaluate_identity_policy(
        policy=policy,
        actual_subjects=verification_result.get("actual_subjects", []),
        actual_issuer=verification_result.get("actual_issuer"),
    )
    freshness_violations = evaluate_freshness_policy(
        policy=policy,
        integrated_time=verification_result.get("integrated_time"),
    )
    advisory_violations = evaluate_advisory_policy(
        policy=policy,
        advisories=advisories,
    )
    violations = identity_violations + freshness_violations + advisory_violations
    return AdmissionDecision(
        decision="deny" if violations else "allow",
        violations=violations,
        evidence={
            "artifact_digest": verification_result.get("digest"),
            "advisory_count": len(advisories),
            "verified_subjects": verification_result.get("actual_subjects", []),
            "verified_issuer": verification_result.get("actual_issuer"),
            "integrated_time": verification_result.get("integrated_time"),
        },
    )


def create_signed_record_payload(
    *,
    kind: str,
    record_id: str,
    payload: Dict[str, Any],
    signature_bundle_path: Optional[str] = None,
) -> Dict[str, Any]:
    return SignedRecord(
        schema="aixv.signed-record/v1",
        kind=kind,
        record_id=record_id,
        created_at=now_iso(),
        payload=payload,
        signature_bundle_path=signature_bundle_path,
    ).model_dump(by_alias=True)


def create_record(
    *,
    root: Path,
    kind: str,
    record_id: str,
    payload: Dict[str, Any],
    output_path: Optional[str] = None,
    signature_bundle_path: Optional[str] = None,
) -> Path:
    record = create_signed_record_payload(
        kind=kind,
        record_id=record_id,
        payload=payload,
        signature_bundle_path=signature_bundle_path,
    )
    path = Path(output_path) if output_path else record_store(root, kind) / f"{record_id}.json"
    write_json(path, record)
    return path


def rollback_record(artifact: Path, target: str) -> Dict[str, Any]:
    return {
        "event_type": "rollback",
        "artifact_digest": sha256_file(artifact),
        "rollback_target": target,
        "timestamp": now_iso(),
    }


def detect_parents_from_training_attestations(
    attestations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    parents: List[Dict[str, Any]] = []
    for att in attestations:
        if att.get("predicateType") != PREDICATE_ALIASES["training"]:
            continue
        predicate = att.get("predicate", {})
        for parent in predicate.get("parent_models", []):
            parents.append(parent)
    return parents


def trace_training_lineage_parents(
    root: Path, artifact_digest: str, depth: int
) -> List[Dict[str, Any]]:
    if depth < 1:
        return []
    start = normalize_sha256_digest(artifact_digest)
    visited = {start}
    frontier = deque([(start, 1)])
    out: List[Dict[str, Any]] = []

    while frontier:
        child_digest, current_depth = frontier.popleft()
        attestations = load_attestations_for_digest(root, child_digest)
        parents = detect_parents_from_training_attestations(attestations)
        for parent in parents:
            if not isinstance(parent, dict):
                continue
            candidate = parent.get("digest")
            if not isinstance(candidate, str):
                continue
            try:
                normalized_parent = normalize_sha256_digest(candidate)
            except ValueError:
                continue
            entry = dict(parent)
            entry["digest"] = normalized_parent
            entry["child_digest"] = child_digest
            entry["depth"] = current_depth
            out.append(entry)
            if current_depth < depth and normalized_parent not in visited:
                visited.add(normalized_parent)
                frontier.append((normalized_parent, current_depth + 1))

    return out


def trace_training_lineage_descendants(
    root: Path, artifact_digest: str, depth: int
) -> List[Dict[str, Any]]:
    if depth < 1:
        return []
    start = normalize_sha256_digest(artifact_digest)
    edges: Dict[str, List[str]] = {}
    for entry in load_all_attestation_records(root):
        statement = entry.get("statement")
        if not isinstance(statement, dict):
            continue
        subjects = statement.get("subject", [])
        if not isinstance(subjects, list):
            continue
        subject_digests: List[str] = []
        for subject in subjects:
            if not isinstance(subject, dict):
                continue
            digest_map = subject.get("digest")
            if not isinstance(digest_map, dict):
                continue
            token = digest_map.get("sha256")
            if not isinstance(token, str):
                continue
            try:
                subject_digests.append(normalize_sha256_digest(token))
            except ValueError:
                continue
        if not subject_digests:
            continue
        summary = summarize_training_lineage_from_attestations([statement])
        parent_digests = summary["parent_digests"]
        for parent in parent_digests:
            edges.setdefault(parent, [])
            for child in subject_digests:
                if child not in edges[parent]:
                    edges[parent].append(child)

    visited = {start}
    frontier = deque([(start, 1)])
    out: List[Dict[str, Any]] = []

    while frontier:
        parent, current_depth = frontier.popleft()
        for child in edges.get(parent, []):
            out.append({"digest": child, "parent_digest": parent, "depth": current_depth})
            if current_depth < depth and child not in visited:
                visited.add(child)
                frontier.append((child, current_depth + 1))

    return out


def _sha256_hex_token(digest: str) -> str:
    return normalize_sha256_digest(digest).split(":", 1)[1]


def export_attestations_as_slsa(
    *, artifact_digest: str, artifact_name: str, attestations: List[Dict[str, Any]]
) -> Dict[str, Any]:
    summary = summarize_training_lineage_from_attestations(attestations)
    materials = summary["parent_digests"] + summary["dataset_digests"]
    out_materials: List[Dict[str, Any]] = []
    for digest in materials:
        out_materials.append({"uri": digest, "digest": {"sha256": _sha256_hex_token(digest)}})
    return {
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
            {"name": artifact_name, "digest": {"sha256": _sha256_hex_token(artifact_digest)}}
        ],
        "buildDefinition": {
            "buildType": "aixv/training",
            "externalParameters": {"attestation_count": len(attestations)},
            "resolvedDependencies": out_materials,
        },
        "runDetails": {
            "builder": {"id": "aixv"},
            "metadata": {"training_run_count": summary["training_run_count"]},
        },
    }


def export_attestations_as_ml_bom(
    *, artifact_digest: str, artifact_name: str, attestations: List[Dict[str, Any]]
) -> Dict[str, Any]:
    summary = summarize_training_lineage_from_attestations(attestations)
    components: List[Dict[str, Any]] = [
        {"name": artifact_name, "digest": artifact_digest, "role": "model"}
    ]
    for digest in summary["parent_digests"]:
        components.append({"digest": digest, "role": "parent-model"})
    for digest in summary["dataset_digests"]:
        components.append({"digest": digest, "role": "dataset"})
    return {
        "bom_format": "aixv.ml-bom/v1",
        "component_count": len(components),
        "components": components,
    }


def _extract_subject_candidates(cert: Any) -> List[str]:
    out: List[str] = []
    try:
        sans = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        out.extend(sans.get_values_for_type(RFC822Name))
        out.extend(sans.get_values_for_type(UniformResourceIdentifier))
    except Exception:
        pass
    try:
        email_attrs = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        for attr in email_attrs:
            value = str(attr.value)
            if value and value not in out:
                out.append(value)
    except Exception:
        pass
    return out


def _extract_oidc_issuer(cert: Any) -> Optional[str]:
    # Fulcio v1 issuer extension.
    v1_oid = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
    # Fulcio v2 DER UTF8String issuer extension.
    v2_oid = ObjectIdentifier("1.3.6.1.4.1.57264.1.8")
    for oid in (v1_oid, v2_oid):
        try:
            ext = cert.extensions.get_extension_for_oid(oid).value
            raw = ext.value
            if oid == v1_oid:
                return raw.decode()
            decoded = _decode_der_utf8(raw)
            if decoded:
                return decoded
        except Exception:
            continue
    return None


def _decode_der_utf8(raw: bytes) -> Optional[str]:
    # Basic DER UTF8String decoder.
    if len(raw) < 2 or raw[0] != 0x0C:
        return None
    length = raw[1]
    idx = 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or len(raw) < 2 + n:
            return None
        length = int.from_bytes(raw[idx : idx + n], "big")
        idx += n
    if len(raw) < idx + length:
        return None
    try:
        return raw[idx : idx + length].decode("utf-8")
    except Exception:
        return None


def evaluate_identity_policy(
    *,
    policy: Dict[str, Any],
    actual_subjects: List[str],
    actual_issuer: Optional[str],
) -> List[str]:
    violations: List[str] = []
    subject = policy.get("subject")
    issuer = policy.get("issuer")
    allow_subjects = set(policy.get("allow_subjects", []))
    deny_subjects = set(policy.get("deny_subjects", []))
    allow_issuers = set(policy.get("allow_issuers", []))
    deny_issuers = set(policy.get("deny_issuers", []))

    if subject and subject not in actual_subjects:
        violations.append(f"subject mismatch: expected {subject}")
    if issuer and issuer != actual_issuer:
        violations.append(f"issuer mismatch: expected {issuer}")
    if allow_subjects and not any(s in allow_subjects for s in actual_subjects):
        violations.append("signer subject is not in allow_subjects")
    if deny_subjects and any(s in deny_subjects for s in actual_subjects):
        violations.append("signer subject is in deny_subjects")
    if allow_issuers and (not actual_issuer or actual_issuer not in allow_issuers):
        violations.append("signer issuer is not in allow_issuers")
    if actual_issuer and deny_issuers and actual_issuer in deny_issuers:
        violations.append("signer issuer is in deny_issuers")

    return violations


def evaluate_freshness_policy(
    *,
    policy: Dict[str, Any],
    integrated_time: Optional[str],
) -> List[str]:
    violations: List[str] = []
    max_age_days = policy.get("max_bundle_age_days")
    if not max_age_days:
        return violations
    if not integrated_time:
        violations.append("freshness policy set but bundle integrated time is unavailable")
        return violations
    try:
        signed_at = datetime.fromisoformat(integrated_time)
    except Exception:
        violations.append("invalid integrated_time format")
        return violations
    age = datetime.now(tz=timezone.utc) - signed_at
    if age.total_seconds() > int(max_age_days) * 86400:
        violations.append(f"bundle age exceeds max_bundle_age_days ({max_age_days})")
    return violations


def evaluate_advisory_policy(
    *,
    policy: Dict[str, Any],
    advisories: List[Dict[str, Any]],
) -> List[str]:
    violations: List[str] = []
    require_signed = bool(policy.get("require_signed_advisories", False))
    considered = advisories
    if require_signed:
        considered = [
            a
            for a in advisories
            if isinstance(a.get("_trust"), dict)
            and a.get("_trust", {}).get("signed_and_trusted") is True
        ]

    active = [a for a in considered if a.get("status") == "active"]
    if policy.get("require_no_active_advisories") and active:
        violations.append("active advisories present while require_no_active_advisories=true")

    threshold = policy.get("deny_advisory_severity_at_or_above")
    if threshold:
        threshold_rank = SEVERITY_RANK[threshold]
        for advisory in active:
            severity = advisory.get("severity")
            if isinstance(severity, str) and SEVERITY_RANK.get(severity, 0) >= threshold_rank:
                violations.append(f"advisory severity {severity} meets deny threshold {threshold}")
                break
    return violations
