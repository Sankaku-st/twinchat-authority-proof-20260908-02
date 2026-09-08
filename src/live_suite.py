"""Run live, synthetic GitHub cases. Never target another repository.

Required: three installation tokens in PROOF_TOKEN_DIR, a fixed evaluator key
in PROOF_EVALUATOR_KEY, and the owner already authenticated with gh. The owner
is used only for the explicitly authorized fixture approval and cancel cases.
No production source, data or service is read by this suite.
"""

import base64
import http.client
import hashlib
import json
import os
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from src.github import AUTHOR, REPOSITORY, GitHub, Response
from src.policy import decision, digest, load_verdict
from src.state import Claims
from src.merge_service import MergeService


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence"
EVALUATOR_ID = 4873223
APPROVER_ID = 274508574


class Owner(GitHub):
    """Use the existing CLI session without copying its credential."""
    def __init__(self):
        super().__init__("", "Sankaku-st")

    def request(self, method, route, body=None):
        if (route and not route.startswith("/")) or ".." in route or route.startswith("//"):
            raise ValueError("Invalid fixture route")
        args = ["gh", "api", "--method", method, "repos/" + REPOSITORY + route]
        if body is not None:
            args += ["--input", "-"]
        result = subprocess.run(args, input=None if body is None else json.dumps(body),
                                text=True, capture_output=True, timeout=40)
        data = json.loads(result.stdout or "{}")
        status = 200 if result.returncode == 0 else int(data.get("status", 500))
        self.history.append({"actor": self.actor, "method": method, "route": route, "status": status})
        return Response(status, data)


class Suite:
    def __init__(self):
        token_dir = Path(os.environ.get("PROOF_TOKEN_DIR", ROOT / ".local"))
        receipt_dir = Path(os.environ.get("PROOF_RECEIPT_DIR", token_dir.parent))
        self.clients = {}
        for role, app_id in (("developer", 4873210), ("evaluator", EVALUATOR_ID), ("merger", 4873237)):
            credential = json.loads((token_dir / f"{role}-token.json").read_text())
            receipt = json.loads((receipt_dir / f"{role}-auth-readback.json").read_text())
            if (receipt["app_id"] != app_id or receipt["owner"] != "Sankaku-st"
                    or receipt["repositories"] != [REPOSITORY]
                    or receipt["token_sha256"] != hashlib.sha256(credential["token"].encode()).hexdigest()):
                raise ValueError("Installation token does not match its actual issuance receipt")
            self.clients[role] = GitHub(credential["token"], f"app:{receipt['app_id']}")
        self.dev, self.evaluator, self.merger = [self.clients[k] for k in ("developer", "evaluator", "merger")]
        self.owner = Owner()
        self.results = []
        self.run_id = str(int(time.time()))
        self.key = Path(os.environ["PROOF_EVALUATOR_KEY"])
        self.private = ROOT / ".local"
        self.private.mkdir(mode=0o700, exist_ok=True)
        self.public_key = self.private / "evaluator-public.pem"
        subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout", "-out", str(self.public_key)],
                       capture_output=True, check=True, timeout=10)
        self.claims = Claims(self.private / "claims.sqlite")
        self.service = MergeService(self.merger, self.claims, self.public_key, EVALUATOR_ID,
                                    "authority-proof-evaluator-20260908[bot]", APPROVER_ID)
        self.authorities = {}

    def save(self):
        EVIDENCE.mkdir(exist_ok=True)
        data = {"repository": REPOSITORY, "run_id": self.run_id, "results": self.results,
                "requests": [entry for client in [*self.clients.values(), self.owner] for entry in client.history]}
        temporary = EVIDENCE / "live-results.json.tmp"
        temporary.write_text(json.dumps(data, indent=2) + "\n")
        temporary.replace(EVIDENCE / "live-results.json")

    def record(self, name, condition, **evidence):
        self.results.append({"case": name, "status": "passed" if condition else "failed", **evidence})
        self.save()
        print(json.dumps({"case": name, "status": self.results[-1]["status"]}), flush=True)
        if not condition:
            raise AssertionError(name)

    def pull(self, suffix, path, content, author=None):
        branch = f"proof/{self.run_id}-{suffix}"
        if path.endswith(".md"):
            content += f"\nSynthetic run: {self.run_id}.\n"
        elif path.endswith(".sql"):
            content += f"\n-- Synthetic run: {self.run_id}.\n"
        base = self.dev.head()
        self.dev.branch(branch, base)
        written = self.dev.write(branch, path, content, f"test: synthetic {suffix}; Refs #1")
        self.record(suffix + "-branch-write", written.status == 200 or written.status == 201,
                    actor=self.dev.actor, http=written.status, branch=branch)
        pull = (author or self.dev).create_pull(branch, "Synthetic " + suffix)
        self.authorities[pull["number"]] = {"issue": 1, "level": "L2" if path.endswith(".md") else "L1",
                                             "allowed_paths": [path], "hold": False, "revoked": False}
        return {"number": pull["number"], "branch": branch, "head": pull["head"]["sha"],
                "base": base, "url": pull["html_url"]}

    def review(self, pull, client=None, event="APPROVE"):
        client = client or self.evaluator
        return client.require("POST", f"/pulls/{pull['number']}/reviews", {
            "commit_id": self.dev.pull(pull["number"])["head"]["sha"],
            "event": event, "body": "Synthetic fixture review: " + event,
        })

    def wait_written_head(self, pull, response):
        deadline = time.monotonic() + 60
        expected = response.data["commit"]["sha"]
        while self.dev.pull(pull["number"])["head"]["sha"] != expected:
            if time.monotonic() > deadline:
                raise TimeoutError("Written fixture head was not visible on the PR")
            time.sleep(2)

    def live(self, pull):
        return self.service.snapshot(pull["number"], self.authorities[pull["number"]])

    def signed(self, live):
        verdict = {k: live[k] for k in ("head", "base", "request_digest", "policy_digest", "repository", "pull_number")}
        verdict.update(evaluator_id=EVALUATOR_ID, result="passed", findings=[])
        payload = self.private / "verdict.json"
        signature = self.private / "verdict.sig"
        payload.write_text(json.dumps(verdict, sort_keys=True))
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.key),
                        "-out", str(signature), str(payload)], capture_output=True, check=True, timeout=10)
        trusted = load_verdict(payload, signature, self.public_key)
        return trusted, payload, signature

    def deny_merge(self, name, pull, client=None, expected_reasons=()):
        client = client or self.merger
        before = self.merger.head()
        response = client.request("PUT", f"/pulls/{pull['number']}/merge",
                                  {"sha": self.dev.pull(pull["number"])["head"]["sha"], "merge_method": "merge"})
        after = self.merger.head()
        message = response.data.get("message", "").lower()
        reason_matches = bool(expected_reasons) and any(reason in message for reason in expected_reasons)
        self.record(name, response.status in (403, 405, 409) and reason_matches and before == after and not self.merger.pull(pull["number"])["merged"],
                    actor=client.actor, http=response.status, reason=response.data.get("message"),
                    before=before, after=after, pull=pull["url"])

    def merge(self, name, pull):
        head = self.merger.pull(pull["number"])["head"]["sha"]
        _, payload, signature = self.signed(self.live(pull))
        result = self.authorized_merge(pull, payload, signature)
        actual = self.merger.pull(pull["number"])
        self.record(name, result.get("merged") is True and actual["merged"] and self.merger.head() == actual["merge_commit_sha"],
                    actor=self.merger.actor, head=head, merged_sha=actual["merge_commit_sha"], pull=pull["url"])

    def authorized_merge(self, pull, payload, signature):
        authority = self.authorities[pull["number"]]
        owner = self.run_id + ":" + str(pull["number"])
        generation = self.claims.claim(str(authority["issue"]), owner, ttl=600)
        if generation is None:
            raise RuntimeError("The fixture issue already has an active execution")
        try:
            return self.service.merge(pull["number"], authority, payload, signature, owner, generation)
        finally:
            self.claims.release(str(authority["issue"]), owner, generation)

    def blocked_service(self, name, pull, payload, signature, expected):
        before = self.merger.head()
        offset = len(self.merger.history)
        reason = None
        try:
            self.authorized_merge(pull, payload, signature)
        except (PermissionError, ValueError) as error:
            reason = str(error)
        writes = [request for request in self.merger.history[offset:] if request["method"] != "GET"]
        after = self.merger.head()
        self.record(name, reason in expected and not writes and before == after,
                    reason=reason, mutation_requests=len(writes), before=before, after=after, pull=pull["url"])

    def permissions_and_lost_response(self):
        pull = self.pull("roles", "docs/roles.md", "# Synthetic document\n\nA harmless fixture.\n")
        before = self.dev.head(pull["branch"])
        blocked = self.evaluator.write(pull["branch"], "docs/roles.md", "Not allowed\n", "test: denied evaluator write")
        self.record("evaluator-cannot-write-code", blocked.status == 403 and self.dev.head(pull["branch"]) == before,
                    actor=self.evaluator.actor, http=blocked.status, before=before, after=self.dev.head(pull["branch"]))
        for role, client in self.clients.items():
            blocked = client.request("PATCH", "", {"description": "Synthetic fixtures for permission and merge verification"})
            self.record(role + "-cannot-administer", blocked.status == 403, actor=client.actor, http=blocked.status)
            blocked = client.request("POST", "/statuses/" + pull["head"], {"state": "success", "context": "forged-proof"})
            self.record(role + "-cannot-forge-status", blocked.status == 403, actor=client.actor, http=blocked.status)
            blocked = client.request("POST", "/check-runs", {"name": "forged-proof", "head_sha": pull["head"], "status": "completed", "conclusion": "success"})
            self.record(role + "-cannot-forge-check", blocked.status == 403, actor=client.actor, http=blocked.status)
        blocked = self.dev.write(pull["branch"], ".github/workflows/injected.yml", "name: forbidden\n", "test: denied workflow write")
        self.record("developer-cannot-rewrite-workflow", blocked.status == 403 and self.dev.head(pull["branch"]) == before,
                    http=blocked.status, before=before, after=self.dev.head(pull["branch"]))
        blocked = self.merger.request("POST", f"/pulls/{pull['number']}/reviews", {"event": "APPROVE", "commit_id": pull["head"]})
        self.record("merger-cannot-write-review", blocked.status == 403, http=blocked.status)
        review = self.review(pull)
        check = self.dev.wait_check(pull["number"])
        self.record("independent-review-and-check", review["state"] == "APPROVED", review_id=review["id"],
                    reviewer=review["user"]["login"], reviewed_head=review["commit_id"], check=check, pull=pull["url"])
        human = self.review(pull, self.owner)
        self.record("developer-denial-has-current-human-approval-control", human["state"] == "APPROVED" and human["commit_id"] == pull["head"], review_id=human["id"], head=pull["head"])
        self.deny_merge("developer-cannot-merge-otherwise-green-pr", pull, self.dev,
                        expected_reasons=("cannot update", "restricted", "not allowed to update"))
        live = self.live(pull)
        verdict, payload, signature = self.signed(live)
        forged = dict(verdict, head="c" * 40)
        payload.write_text(json.dumps(forged))
        self.blocked_service("forged-evaluation-signature-rejected", pull, payload, signature, ("Untrusted evaluation signature",))
        verdict, _, _ = self.signed(live)
        self.record("current-signed-evaluation-allowed", decision(verdict, live, level="L2", evaluator_id=EVALUATOR_ID, approver_id=APPROVER_ID) is None)
        for field in ("hold", "revoked"):
            self.authorities[pull["number"]][field] = True
            self.blocked_service("changed-authority-" + field + "-prevents-api-write", pull, payload, signature, ("changed-policy",))
            self.authorities[pull["number"]][field] = False
        issue = self.owner.require("GET", "/issues/1")
        self.owner.require("PATCH", "/issues/1", {"body": issue["body"] + "\nSynthetic revision during evaluation.\n"})
        self.blocked_service("changed-live-issue-invalidates-evaluation", pull, payload, signature, ("changed-request",))
        self.owner.require("PATCH", "/issues/1", {"body": issue["body"]})
        live = self.live(pull)
        _, payload, signature = self.signed(live)
        # The relay executes the real merge and drops its HTTP response. A new
        # process must recover through GET rather than sending another merge.
        remote = {}
        merge_operation = lambda: self.authorized_merge(pull, payload, signature)
        class DropResponse(BaseHTTPRequestHandler):
            def do_POST(handler):
                remote.update(merge_operation())
                handler.connection.shutdown(socket.SHUT_RDWR)
                handler.connection.close()
            def log_message(handler, *_args):
                pass
        server = HTTPServer(("127.0.0.1", 0), DropResponse)
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=40)
        lost = False
        try:
            connection.request("POST", "/merge")
            connection.getresponse()
        except http.client.RemoteDisconnected:
            lost = True
        finally:
            connection.close()
            thread.join(timeout=45)
            server.server_close()
        recovered = subprocess.run(["python3", "-m", "src.recover", str(pull["number"]), live["head"]],
                                   cwd=ROOT, capture_output=True, text=True, timeout=40, check=True)
        recovery = json.loads(recovered.stdout)
        self.record("lost-merge-response-recovered-in-new-process", lost and remote.get("merged") and recovery["recovered"] and recovery["head_matches"] and recovery["mutation_count"] == 0,
                    recovery=recovery, pull=pull["url"])

    def approval_and_sql(self):
        pull = self.pull("approval", "docs/approval.md", "# Synthetic approval fixture\n")
        self.authorities[pull["number"]]["level"] = "L1"
        self.dev.wait_check(pull["number"])
        app_review = self.review(pull)
        live = self.live(pull)
        verdict, payload, signature = self.signed(live)
        self.blocked_service("l1-rejects-app-approval-instead-of-fixed-human", pull, payload, signature, ("current-fixed-approver-required",))
        self.dev.require("POST", f"/issues/{pull['number']}/labels", {"labels": ["auto-merge"]})
        self.blocked_service("label-does-not-elevate-l1-authority", pull, payload, signature, ("current-fixed-approver-required",))
        human = self.review(pull, self.owner)
        written = self.dev.write(pull["branch"], "docs/approval.md", f"# Synthetic approval fixture\n\nNew revision for {self.run_id}.\n", "test: invalidate old approval; Refs #1")
        self.record("approval-fixture-update", written.status == 200, http=written.status)
        # Content writes and PR metadata become visible separately. Compare the
        # old verdict only after the PR exposes the exact newly written commit.
        self.wait_written_head(pull, written)
        self.blocked_service("new-head-invalidates-old-signed-evaluation", pull, payload, signature, ("changed-head",))
        self.dev.wait_check(pull["number"])
        self.review(pull)
        live = self.live(pull)
        verdict, payload, signature = self.signed(live)
        self.blocked_service("l1-rejects-stale-human-approval", pull, payload, signature, ("current-fixed-approver-required", "human-hold-or-revocation"))
        human = self.review(pull, self.owner)
        live = self.live(pull)
        self.record("l1-accepts-current-fixed-human", decision(verdict, live, level="L1", evaluator_id=EVALUATOR_ID, approver_id=APPROVER_ID) is None, review_id=human["id"])
        self.merge("approved-l1-merged", pull)
        sql = self.pull("sql", "supabase/migrations/0001_dummy.sql", "-- Synthetic only; never executed against a database.\nSELECT 1;\n")
        self.dev.wait_check(sql["number"])
        self.review(sql)
        self.deny_merge("sql-floor-not-bypassed-by-merger", sql, expected_reasons=("code owner", "review is required", "reviews are required"))
        self.review(sql, self.owner)
        self.merge("sql-floor-allows-fixed-owner-approval", sql)

    def race_and_failure(self):
        first = self.pull("race-a", "docs/race-a.md", "# Independent change A\n")
        second = self.pull("race-b", "docs/race-b.md", "# Independent change B\n")
        self.record("race-starts-from-same-base", first["base"] == second["base"], base=first["base"])
        checks = [self.dev.wait_check(p["number"]) for p in (first, second)]
        for pull in (first, second):
            self.review(pull)
        self.merge("first-concurrent-pr-merged", first)
        self.review(second, self.owner)
        self.deny_merge("stale-base-checks-cannot-merge-second-pr", second,
                        expected_reasons=("up to date", "base branch", "required status check"))
        result = self.dev.request("PUT", f"/pulls/{second['number']}/update-branch", {"expected_head_sha": second["head"]})
        self.record("stale-branch-update-requested", result.status == 202, http=result.status, prior_checks=checks)
        deadline = time.monotonic() + 90
        while self.dev.pull(second["number"])["head"]["sha"] == second["head"]:
            if time.monotonic() > deadline:
                raise TimeoutError("Branch update did not complete")
            time.sleep(2)
        self.dev.wait_check(second["number"])
        self.review(second)
        self.review(second, self.owner)
        self.merge("second-pr-merged-after-current-base-check", second)
        broken = self.pull("broken", "fixtures/value.py", "VALUE = 2\n")
        failed_check = self.dev.wait_check(broken["number"], expected="failure")
        self.deny_merge("failed-ci-blocks-merger", broken, expected_reasons=("status check", "checks must", "check failed"))
        self.review(broken, event="REQUEST_CHANGES")
        repaired = self.dev.write(broken["branch"], "fixtures/value.py", f'"""Repaired synthetic invariant, run {self.run_id}."""\nVALUE = 1\n', "test: repair fixture; Refs #1")
        self.record("failed-fixture-repaired", repaired.status == 200, http=repaired.status, failed_check=failed_check)
        self.wait_written_head(broken, repaired)
        current = self.dev.wait_check(broken["number"])
        review = self.review(broken)
        self.record("repair-reviewed-at-new-head", review["commit_id"] != broken["head"] and review["state"] == "APPROVED", check=current, review_id=review["id"])
        self.review(broken, self.owner)
        self.merge("repaired-pr-merged", broken)

    def canceled_check(self):
        pull = self.pull("canceled", "fixtures/value.py", "import time\ntime.sleep(30)\nVALUE = 1\n")
        deadline = time.monotonic() + 120
        run = None
        while time.monotonic() < deadline:
            runs = self.owner.require("GET", "/actions/runs?head_sha=" + pull["head"])["workflow_runs"]
            run = next((item for item in runs if item["event"] == "pull_request" and item["status"] == "in_progress"), None)
            if run:
                break
            time.sleep(3)
        if run is None:
            raise TimeoutError("No running fixture workflow to cancel")
        blocked = self.dev.request("POST", f"/actions/runs/{run['id']}/cancel")
        self.record("developer-cannot-cancel-required-ci", blocked.status == 403, http=blocked.status, run_id=run["id"])
        self.owner.require("POST", f"/actions/runs/{run['id']}/cancel")
        check = self.dev.wait_check(pull["number"], expected="cancelled")
        self.deny_merge("canceled-ci-blocks-merger", pull, expected_reasons=("status check", "checks must", "check failed"))
        self.record("cancellation-readback", check["conclusion"] == "cancelled", check=check)
        self.dev.require("PATCH", f"/pulls/{pull['number']}", {"state": "closed"})

    def expected_issuer_and_fencing(self):
        workflow = self.owner.require("GET", "/actions/workflows/proof.yml")
        if workflow["state"] != "active":
            raise RuntimeError("Fixture workflow was not active before the test")
        self.owner.require("PUT", f"/actions/workflows/{workflow['id']}/disable")
        try:
            pull = self.pull("issuer", "docs/issuer.md", "# Synthetic issuer fixture\n")
            self.review(pull, event="COMMENT")
            forged = self.owner.require("POST", "/statuses/" + pull["head"], {
                "state": "success", "context": "proof-integration", "description": "Synthetic wrong-issuer control",
            })
            checks = self.dev.checks(pull["head"])
            self.record("same-named-success-from-different-issuer", forged["creator"]["id"] == APPROVER_ID
                        and not any(item["name"] == "proof-integration" and item["app"]["id"] == 15368 for item in checks),
                        status_id=forged["id"], creator_id=forged["creator"]["id"], head=pull["head"])
            self.deny_merge("wrong-issuer-success-cannot-satisfy-required-check", pull,
                            expected_reasons=("expected github app", "status check", "checks must"))
        finally:
            self.owner.require("PUT", f"/actions/workflows/{workflow['id']}/enable")
        # GitHub retains the wrong-issuer status on that SHA. Recover on a new
        # revision, with a new genuine check and a new independent evaluation.
        written = self.dev.write(pull["branch"], "docs/issuer.md", f"# Clean issuer revision\n\nRun {self.run_id}.\n", "test: reevaluate clean revision; Refs #1")
        self.record("issuer-recovery-creates-new-revision", written.status == 200 and written.data["commit"]["sha"] != pull["head"], http=written.status)
        self.wait_written_head(pull, written)
        check = self.dev.wait_check(pull["number"])
        self.review(pull, event="COMMENT")
        _, payload, signature = self.signed(self.live(pull))
        issue = "1"
        old = self.claims.claim(issue, "expired", ttl=0)
        current = self.claims.claim(issue, "replacement", ttl=300)
        if old is None or current is None:
            raise RuntimeError("Could not construct the expired execution fixture")
        before = self.merger.head()
        offset = len(self.merger.history)
        try:
            self.service.merge(pull["number"], self.authorities[pull["number"]], payload, signature, "expired", old)
            blocked = False
        except PermissionError as error:
            blocked = str(error) == "Expired execution generation"
        writes = [item for item in self.merger.history[offset:] if item["method"] != "GET"]
        self.record("expired-execution-cannot-send-merge", blocked and not writes and self.merger.head() == before,
                    old_generation=old, current_generation=current, mutation_requests=len(writes))
        try:
            merged = self.service.merge(pull["number"], self.authorities[pull["number"]], payload, signature, "replacement", current)
        finally:
            self.claims.release(issue, "replacement", current)
        self.record("replacement-merges-with-real-check-and-no-human-approval", merged["merged"] and self.merger.pull(pull["number"])["merged"],
                    check=check, merged_sha=merged["sha"], pull=pull["url"])

    def fixed_owner_exception(self):
        pull = self.pull("owner", "docs/owner.md", "# Synthetic owner-authored fixture\n", author=self.owner)
        actual = self.owner.pull(pull["number"])
        self.record("owner-exception-uses-actual-owner-author", actual["user"]["id"] == APPROVER_ID, author_id=actual["user"]["id"])
        check = self.dev.wait_check(pull["number"])
        self.review(pull, event="COMMENT")
        query = """mutation($id:ID!, $head:GitObjectID!, $email:String!) {
            mergePullRequest(input:{pullRequestId:$id, expectedHeadOid:$head,
              mergeMethod:MERGE, authorEmail:$email, commitHeadline:"Synthetic owner exception; Refs #1"}) {
                pullRequest { merged mergeCommit { oid author { email } committer { email } } }
            }
        }"""
        body = {"query": query, "variables": {"id": actual["node_id"], "head": actual["head"]["sha"], "email": AUTHOR["email"]}}
        response = subprocess.run(["gh", "api", "graphql", "--method", "POST", "--input", "-"],
                                  input=json.dumps(body), text=True, capture_output=True, timeout=40, check=True)
        data = json.loads(response.stdout)
        if data.get("errors"):
            raise RuntimeError("Owner exception GraphQL merge was rejected")
        result = data["data"]["mergePullRequest"]["pullRequest"]
        after = self.merger.pull(pull["number"])
        self.record("fixed-owner-self-merge-exception", result["merged"] and after["merged"] and after["merge_commit_sha"] == self.merger.head(),
                    actor_id=APPROVER_ID, head=actual["head"]["sha"], merged_sha=after["merge_commit_sha"], check=check, pull=pull["url"])
        self.record("owner-merge-preserves-noreply-author", result["mergeCommit"]["author"]["email"] == AUTHOR["email"],
                    author_is_noreply=result["mergeCommit"]["author"]["email"].endswith("@users.noreply.github.com"),
                    committer_is_noreply="noreply" in result["mergeCommit"]["committer"]["email"])

    def comments_preserve_change_requests(self):
        pull = self.pull("review-history", "docs/review-history.md", "# Review state fixture\n")
        self.dev.wait_check(pull["number"])
        self.review(pull)
        self.review(pull, self.owner, event="REQUEST_CHANGES")
        self.review(pull, self.owner, event="COMMENT")
        _, payload, signature = self.signed(self.live(pull))
        self.blocked_service("human-comment-does-not-clear-change-request", pull, payload, signature, ("human-hold-or-revocation",))
        self.review(pull, self.owner)
        self.review(pull, event="REQUEST_CHANGES")
        self.review(pull, event="COMMENT")
        _, payload, signature = self.signed(self.live(pull))
        self.blocked_service("evaluator-comment-does-not-clear-change-request", pull, payload, signature, ("current-evaluator-review-required",))
        self.review(pull)
        self.merge("formal-approvals-resolve-change-requests", pull)

    def run(self):
        try:
            self.permissions_and_lost_response()
            self.approval_and_sql()
            self.race_and_failure()
            self.canceled_check()
            self.expected_issuer_and_fencing()
            self.fixed_owner_exception()
            self.comments_preserve_change_requests()
        finally:
            self.save()


if __name__ == "__main__":
    Suite().run()
