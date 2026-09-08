import copy
import multiprocessing
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from src.policy import decision, load_verdict
from src.state import Claims


def claim_in_process(path, owner, queue):
    queue.put(Claims(path, clock=lambda: 100).claim("issue-1", owner))


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.verdict = {"head": "a" * 40, "base": "b" * 40, "request_digest": "1" * 64,
                        "policy_digest": "2" * 64, "repository": "fixture", "pull_number": 1,
                        "evaluator_id": 20, "result": "passed", "findings": []}
        self.live = {"head": "a" * 40, "base": "b" * 40, "request_digest": "1" * 64,
                     "policy_digest": "2" * 64, "repository": "fixture", "pull_number": 1,
                     "checks_passed": True, "evaluation_passed": True, "paths_allowed": True,
                     "hold": False, "revoked": False}

    def decide(self, level="L2"):
        return decision(self.verdict, self.live, level=level, evaluator_id=20, approver_id=30)

    def test_current_evaluated_change_is_allowed(self):
        self.assertIsNone(self.decide())

    def test_l0_never_enters_merge(self):
        self.assertEqual(self.decide("L0"), "investigation-only")

    def test_every_commit_identifier_must_be_complete_and_current(self):
        for field in ("head", "base"):
            original = self.verdict[field]
            for invalid in (original[:7], "c" * 40, None):
                with self.subTest(field=field, invalid=invalid):
                    self.verdict[field] = invalid
                    self.assertIsNotNone(self.decide())
            self.verdict[field] = original

    def test_missing_request_version_is_not_a_valid_match(self):
        self.verdict.pop("request_digest")
        self.live.pop("request_digest")
        self.assertEqual(self.decide(), "changed-request")

    def test_changed_request_revocation_and_hold_prevent_merge(self):
        for field, value in (("request_digest", "request-2"), ("hold", True), ("revoked", True), ("checks_passed", False)):
            with self.subTest(field=field):
                original = self.live[field]
                self.live[field] = value
                self.assertIsNotNone(self.decide())
                self.live[field] = original

    def test_unresolved_or_different_evaluator_prevents_merge(self):
        original = copy.deepcopy(self.verdict)
        for field, value in (("evaluator_id", 10), ("result", "failed"), ("findings", ["still broken"]), ("findings", None)):
            with self.subTest(field=field):
                self.verdict = dict(original, **{field: value})
                self.assertIsNotNone(self.decide())

    def test_l1_requires_current_fixed_approver(self):
        self.assertIsNotNone(self.decide("L1"))
        for approval in ({"user_id": 31, "state": "APPROVED", "commit_id": "a" * 40},
                         {"user_id": 30, "state": "APPROVED", "commit_id": "c" * 40},
                         {"user_id": 30, "state": "CHANGES_REQUESTED", "commit_id": "a" * 40}):
            self.live["approval"] = approval
            self.assertIsNotNone(self.decide("L1"))
        self.live["approval"] = {"user_id": 30, "state": "APPROVED", "commit_id": "a" * 40}
        self.assertIsNone(self.decide("L1"))

    def test_verifier_parses_exactly_the_bytes_it_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verdict.json"
            path.write_text('{"result":"original"}')
            def replace_path_after_verification(payload, *_):
                self.assertEqual(payload, b'{"result":"original"}')
                path.write_text('{"result":"replaced"}')
                return True
            with patch("src.policy.verify_signature", side_effect=replace_path_after_verification):
                self.assertEqual(load_verdict(path, "signature", "key"), {"result": "original"})


class ClaimsTest(unittest.TestCase):
    def test_two_processes_claim_once_and_restart_fences_the_old_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "claims.sqlite")
            Claims(path)
            context = multiprocessing.get_context("spawn")
            queue = context.Queue()
            processes = [context.Process(target=claim_in_process, args=(path, str(i), queue)) for i in range(2)]
            for process in processes:
                process.start()
            results = [queue.get(timeout=15) for _ in processes]
            for process in processes:
                process.join(timeout=15)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual(sum(result is not None for result in results), 1)
            restarted = Claims(path, clock=lambda: 161)
            generation = restarted.claim("issue-1", "replacement")
            self.assertEqual(generation, 2)
            self.assertTrue(restarted.current("issue-1", "replacement", 2))
            for owner in ("0", "1"):
                self.assertFalse(restarted.current("issue-1", owner, 1))
            calls = []
            with self.assertRaises(PermissionError):
                restarted.perform_current("issue-1", "0", 1, lambda: calls.append("stale write"))
            restarted.perform_current("issue-1", "replacement", 2, lambda: calls.append("current write"))
            self.assertEqual(calls, ["current write"])


if __name__ == "__main__":
    unittest.main()
