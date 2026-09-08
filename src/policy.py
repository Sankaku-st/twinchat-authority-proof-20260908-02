"""Small, fail-closed merge decision for the synthetic test fixture."""

import hashlib
import json
import re
import subprocess
from pathlib import Path


SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def decision(verdict, live, *, level, evaluator_id, approver_id):
    """Return a reason, or None. Call only after signature verification."""
    if level not in ("L1", "L2"):
        return "investigation-only"
    for field in ("head", "base"):
        if not isinstance(verdict.get(field), str) or not SHA.fullmatch(verdict[field]):
            return "incomplete-commit-identifier"
        if verdict[field] != live.get(field):
            return "changed-" + field
    for field in ("request_digest", "policy_digest"):
        if (not isinstance(verdict.get(field), str) or not DIGEST.fullmatch(verdict[field])
                or verdict[field] != live.get(field)):
            return "changed-" + field.removesuffix("_digest")
    for field in ("repository", "pull_number"):
        if verdict.get(field) is None or verdict[field] != live.get(field):
            return "changed-" + field
    if verdict.get("evaluator_id") != evaluator_id or verdict.get("result") != "passed":
        return "missing-independent-evaluation"
    if verdict.get("findings") != []:
        return "unresolved-findings"
    if live.get("hold") or live.get("revoked"):
        return "human-hold-or-revocation"
    if not live.get("checks_passed"):
        return "checks-not-passed"
    if not live.get("evaluation_passed"):
        return "current-evaluator-review-required"
    if not live.get("paths_allowed"):
        return "outside-authorized-paths"
    if level == "L1":
        approval = live.get("approval") or {}
        if (approval.get("user_id") != approver_id or approval.get("state") != "APPROVED"
                or approval.get("commit_id") != live["head"]):
            return "current-fixed-approver-required"
    return None


def verify_signature(payload_bytes, signature_path, public_key_path):
    """No private key is needed by the verifier."""
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key_path),
         "-signature", str(signature_path)],
        input=payload_bytes, capture_output=True, timeout=10,
    )
    return result.returncode == 0


def load_verdict(payload_path, signature_path, public_key_path):
    payload_bytes = Path(payload_path).read_bytes()
    if not verify_signature(payload_bytes, signature_path, public_key_path):
        raise ValueError("Untrusted evaluation signature")
    return json.loads(payload_bytes)
