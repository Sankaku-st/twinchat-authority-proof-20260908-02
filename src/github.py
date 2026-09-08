"""Bounded GitHub API client for this disposable fixture repository."""

import base64
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


REPOSITORY = "Sankaku-st/twinchat-authority-proof-20260908-02"
AUTHOR = {
    "name": "Sankaku-st",
    "email": "274508574+Sankaku-st@users.noreply.github.com",
}


@dataclass(frozen=True)
class Response:
    status: int
    data: dict


class GitHub:
    def __init__(self, token, actor, timeout_seconds=30):
        self._token = token
        self.actor = actor
        self.timeout_seconds = timeout_seconds
        self.history = []

    def request(self, method, route, body=None):
        if (route and not route.startswith("/")) or route.startswith("//") or ".." in route:
            raise ValueError("Only repository-relative API routes are allowed")
        url = "https://api.github.com/repos/" + REPOSITORY + route
        request = urllib.request.Request(
            url,
            method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "synthetic-authority-proof",
            },
        )
        # Mutations are never retried blindly. A caller must read back first.
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as result:
                raw = result.read()
                response = Response(result.status, json.loads(raw) if raw else {})
        except urllib.error.HTTPError as error:
            raw = error.read()
            response = Response(error.code, json.loads(raw) if raw else {})
        self.history.append({"actor": self.actor, "method": method, "route": route,
                             "status": response.status})
        return response

    def require(self, method, route, body=None, expected=(200, 201)):
        response = self.request(method, route, body)
        if response.status not in expected:
            message = response.data.get("message", "unexpected response")
            raise RuntimeError(f"{self.actor}: {method} {route}: {response.status}: {message}")
        return response.data

    def head(self, branch="develop"):
        return self.require("GET", "/git/ref/heads/" + branch)["object"]["sha"]

    def branch(self, name, sha):
        return self.require("POST", "/git/refs", {"ref": "refs/heads/" + name, "sha": sha})

    def write(self, branch, path, content, message):
        current = self.request("GET", "/contents/" + path + "?ref=" + branch)
        if current.status not in (200, 404):
            raise RuntimeError("Cannot determine current file version")
        body = {
            "branch": branch,
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "author": AUTHOR,
            "committer": AUTHOR,
        }
        if current.status == 200:
            body["sha"] = current.data["sha"]
        return self.request("PUT", "/contents/" + path, body)

    def pull(self, number):
        return self.require("GET", "/pulls/" + str(number))

    def create_pull(self, branch, title, issue=1):
        return self.require("POST", "/pulls", {
            "base": "develop", "head": branch, "title": title,
            "body": f"Synthetic permission test only. Refs #{issue}.",
        })

    def checks(self, sha):
        result = self.require("GET", "/commits/" + sha + "/check-runs?per_page=100")
        if result["total_count"] > len(result["check_runs"]):
            raise RuntimeError("Incomplete check run collection")
        return result["check_runs"]

    def wait_check(self, number, expected="success", timeout_seconds=240):
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            pull = self.pull(number)
            shas = [pull["head"]["sha"], pull.get("merge_commit_sha")]
            for sha in dict.fromkeys(shas):
                if not sha:
                    continue
                if sha != pull["head"]["sha"]:
                    commit = self.require("GET", "/git/commits/" + sha)
                    parents = {parent["sha"] for parent in commit["parents"]}
                    if not {pull["head"]["sha"], pull["base"]["sha"]}.issubset(parents):
                        continue
                for check in self.checks(sha):
                    if check["name"] == "proof-integration" and check["status"] == "completed":
                        if check["app"]["id"] != 15368:
                            raise RuntimeError("Unexpected check issuer")
                        if check["conclusion"] != expected:
                            raise RuntimeError("Unexpected integration check conclusion: " + str(check["conclusion"]))
                        return {"check_id": check["id"], "sha": sha, "issuer": 15368,
                                "conclusion": check["conclusion"], "url": check["html_url"]}
            time.sleep(4)
        raise TimeoutError("Integration check did not finish before the deadline")

    def merge_once(self, number, head):
        current = self.pull(number)
        if current["merged"]:
            return {"merged": True, "recovered": True, "sha": current["merge_commit_sha"]}
        return self.require("PUT", f"/pulls/{number}/merge", {"sha": head, "merge_method": "merge"})
