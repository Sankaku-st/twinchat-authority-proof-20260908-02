"""The trusted merge entry point. Untrusted PR code is never imported here."""

from src.github import REPOSITORY
from src.policy import decision, digest, load_verdict


class MergeBlocked(PermissionError):
    pass


class MergeService:
    def __init__(self, client, claims, public_key, evaluator_id, evaluator_login, approver_id):
        self.client = client
        self.claims = claims
        self.public_key = public_key
        self.evaluator_id = evaluator_id
        self.evaluator_login = evaluator_login
        self.approver_id = approver_id

    def snapshot(self, number, authority):
        pull = self.client.pull(number)
        if pull["state"] != "open" or pull["draft"] or pull["base"]["ref"] != "develop":
            raise MergeBlocked("Not an open develop pull request")
        issue = self.client.require("GET", "/issues/" + str(authority["issue"]))
        reviews = self.client.require("GET", f"/pulls/{number}/reviews?per_page=100")
        files = self.client.require("GET", f"/pulls/{number}/files?per_page=100")
        if len(reviews) >= 100 or len(files) >= 100 or len(files) != pull["changed_files"]:
            raise MergeBlocked("Incomplete fixture input collection")
        latest = {}
        for review in sorted(reviews, key=lambda item: item["id"]):
            latest[review["user"]["id"]] = review
        human = latest.get(self.approver_id)
        evaluation = next((item for item in latest.values()
                           if item["user"]["login"] == self.evaluator_login), None)
        checks = self.client.checks(pull["head"]["sha"])
        matching = [check for check in checks if check["name"] == "proof-integration" and check["app"]["id"] == 15368]
        current_check = max(matching, key=lambda item: item["id"], default=None)
        paths = [path for item in files for path in (item["filename"], item.get("previous_filename")) if path]
        allowed = set(authority["allowed_paths"])
        head = pull["head"]["sha"]
        return {
            "repository": REPOSITORY, "pull_number": number,
            "head": head, "base": self.client.head(),
            "request_digest": digest({"title": issue["title"], "body": issue["body"], "updated_at": issue["updated_at"]}),
            "policy_digest": digest(authority),
            "checks_passed": bool(current_check and current_check["status"] == "completed" and current_check["conclusion"] == "success"),
            "evaluation_passed": bool(evaluation and evaluation["state"] in ("APPROVED", "COMMENTED") and evaluation["commit_id"] == head),
            "paths_allowed": bool(paths) and all(path in allowed for path in paths),
            "hold": authority.get("hold", False) or bool(human and human["state"] in ("CHANGES_REQUESTED", "DISMISSED")),
            "revoked": authority.get("revoked", False) or issue["state"] != "open",
            "approval": None if not human else {"user_id": human["user"]["id"], "state": human["state"], "commit_id": human["commit_id"]},
        }

    def merge(self, number, authority, payload, signature, owner, generation):
        def operation():
            verdict = load_verdict(payload, signature, self.public_key)
            live = self.snapshot(number, authority)
            reason = decision(verdict, live, level=authority["level"],
                              evaluator_id=self.evaluator_id, approver_id=self.approver_id)
            if reason:
                raise MergeBlocked(reason)
            return self.client.merge_once(number, live["head"])
        return self.claims.perform_current(str(authority["issue"]), owner, generation, operation)
