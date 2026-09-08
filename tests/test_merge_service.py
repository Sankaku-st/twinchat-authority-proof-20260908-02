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
