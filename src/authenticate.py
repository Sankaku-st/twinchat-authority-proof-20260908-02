"""Mint fixture-only installation tokens and non-secret provenance receipts."""

import base64
import hashlib
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

from src.github import REPOSITORY


APPS = {"developer": (4873210, 160060459), "evaluator": (4873223, 160064114), "merger": (4873237, 160061682)}


def call(path, token, body=None):
    request = urllib.request.Request(
        "https://api.github.com" + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "User-Agent": "synthetic-authority-proof", "X-GitHub-Api-Version": "2022-11-28"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def mint(role, app_id, installation_id, key_dir, token_dir, receipt_dir):
    key = key_dir / f"authority-proof-{role}-20260908.2026-09-08.private-key.pem"
    encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=")
    now = int(time.time())
    message = encode(b'{"alg":"RS256","typ":"JWT"}') + b"." + encode(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}).encode())
    signed = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key)],
                            input=message, capture_output=True, check=True, timeout=10).stdout
    jwt = (message + b"." + encode(signed)).decode()
    app = call("/app", jwt)
    installation = call(f"/app/installations/{installation_id}", jwt)
    if app["id"] != app_id or app["owner"]["login"] != "Sankaku-st" or installation["account"]["login"] != "Sankaku-st":
        raise ValueError("Unexpected GitHub App or installation owner")
    credential = call(f"/app/installations/{installation_id}/access_tokens", jwt, {"repositories": [REPOSITORY.split("/")[1]]})
    repositories = [item["full_name"] for item in call("/installation/repositories", credential["token"])["repositories"]]
    writable = {"developer": {"contents", "pull_requests"}, "evaluator": {"issues", "pull_requests"}, "merger": {"contents"}}[role]
    expected = {name: "write" if name in writable else "read"
                for name in ("contents", "pull_requests", "issues", "checks", "statuses", "actions", "metadata")}
    if repositories != [REPOSITORY] or credential["permissions"] != expected or app["permissions"] != expected:
        raise ValueError("Unexpected installation scope or permissions")
    token_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = token_dir / f"{role}-token.json"
    temporary = destination.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(credential, output)
    temporary.replace(destination)
    receipt = {"app_id": app_id, "slug": app["slug"], "owner": app["owner"]["login"],
               "installation_id": installation_id, "permissions": credential["permissions"],
               "repositories": repositories, "expires_at": credential["expires_at"], "authentication": "passed",
               "token_sha256": hashlib.sha256(credential["token"].encode()).hexdigest()}
    receipt_dir.mkdir(parents=True, exist_ok=True)
    (receipt_dir / f"{role}-auth-readback.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"role": role, "app_id": app_id, "authentication": "passed", "repositories": repositories}), flush=True)


if __name__ == "__main__":
    for role, identifiers in APPS.items():
        mint(role, *identifiers, Path(os.environ["PROOF_KEY_DIR"]),
             Path(os.environ["PROOF_TOKEN_DIR"]), Path(os.environ["PROOF_RECEIPT_DIR"]))
