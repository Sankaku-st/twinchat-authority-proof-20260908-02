import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.merge_service import MergeBlocked, MergeService
from src.state import Claims


class Client:
    def __init__(self):
        self.mutations = []

    def merge_once(self, number, head):
        self.mutations.append((number, head))
        return {"merged": True}


class SnapshotClient:
    def __init__(self):
        self.reviews = []

    def pull(self, number):
        return {"state": "open", "draft": False, "base": {"ref": "develop"},
                "head": {"sha": "a" * 40}, "changed_files": 1}

    def require(self, method, route):
        if route == "/issues/1":
            return {"title": "fixture", "body": "fixed request", "updated_at": "fixed", "state": "open"}
        if route == "/pulls/1/reviews?per_page=100":
            return self.reviews
        if route == "/pulls/1/files?per_page=100":
            return [{"filename": "docs/example.md"}]
        raise AssertionError(route)

    def checks(self, sha):
        return [{"id": 1, "name": "proof-integration", "app": {"id": 15368},
                 "status": "completed", "conclusion": "success"}]

    def head(self):
        return "b" * 40

    def review(self, user_id, state):
        self.reviews.append({"id": len(self.reviews) + 1, "user": {
            "id": user_id, "login": "reviewer[bot]" if user_id == 20 else "owner"},
            "state": state, "commit_id": "a" * 40})


class ReviewHistoryTest(unittest.TestCase):
    def setUp(self):
        self.client = SnapshotClient()
        self.service = MergeService(self.client, None, None, 20, "reviewer[bot]", 30)
        self.authority = {"issue": 1, "level": "L2", "allowed_paths": ["docs/example.md"]}

    def snapshot(self):
        return self.service.snapshot(1, self.authority)

    def test_human_comments_preserve_formal_change_request_and_approval(self):
        self.client.review(30, "CHANGES_REQUESTED")
        self.client.review(30, "COMMENTED")
        self.assertTrue(self.snapshot()["hold"])
        self.client.review(30, "APPROVED")
        self.client.review(30, "COMMENTED")
        self.assertFalse(self.snapshot()["hold"])
        self.assertEqual(self.snapshot()["approval"]["state"], "APPROVED")

    def test_evaluator_comment_cannot_resolve_requested_changes(self):
        self.client.review(20, "CHANGES_REQUESTED")
        self.client.review(20, "COMMENTED")
        self.assertFalse(self.snapshot()["evaluation_passed"])
        self.client.review(20, "APPROVED")
        self.client.review(20, "COMMENTED")
        self.assertTrue(self.snapshot()["evaluation_passed"])

    def test_comment_without_prior_change_request_can_accompany_signed_evaluation(self):
        self.client.review(20, "COMMENTED")
        self.assertTrue(self.snapshot()["evaluation_passed"])


class MergeBoundaryTest(unittest.TestCase):
    def test_every_rejected_condition_prevents_the_external_write(self):
        with tempfile.TemporaryDirectory() as directory:
            claims = Claims(Path(directory) / "claims.sqlite")
            generation = claims.claim("1", "worker")
            client = Client()
            service = MergeService(client, claims, "unused-public-key", 20, "reviewer[bot]", 30)
            authority = {"issue": 1, "level": "L2"}
            verdict = {"head": "a" * 40, "base": "b" * 40, "request_digest": "1" * 64,
                       "policy_digest": "2" * 64, "repository": "fixture", "pull_number": 1,
                       "evaluator_id": 20, "result": "passed", "findings": []}
            live = dict(verdict, checks_passed=True, evaluation_passed=True, paths_allowed=True, hold=False, revoked=False)
            for field, value in (("head", "c" * 40), ("base", "c" * 40), ("request_digest", "3" * 64),
                                 ("policy_digest", "3" * 64), ("checks_passed", False), ("evaluation_passed", False),
                                 ("paths_allowed", False), ("hold", True), ("revoked", True)):
                with self.subTest(field=field), patch("src.merge_service.load_verdict", return_value=verdict), \
                        patch.object(service, "snapshot", return_value=dict(live, **{field: value})):
                    with self.assertRaises(MergeBlocked):
                        service.merge(1, authority, "payload", "signature", "worker", generation)
                    self.assertEqual(client.mutations, [])
            with patch("src.merge_service.load_verdict", side_effect=ValueError("Untrusted evaluation signature")):
                with self.assertRaises(ValueError):
                    service.merge(1, authority, "payload", "signature", "worker", generation)
                self.assertEqual(client.mutations, [])
            with patch("src.merge_service.load_verdict", return_value=verdict), patch.object(service, "snapshot", return_value=live):
                self.assertEqual(service.merge(1, authority, "payload", "signature", "worker", generation), {"merged": True})
                self.assertEqual(client.mutations, [(1, "a" * 40)])
