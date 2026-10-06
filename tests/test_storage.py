"""Sealed-store tests: replay of equivalent input and id conflicts."""

import json
import os
import tempfile
import unittest

from app.storage import ConflictError, SealedStore, canonical_fingerprint


def payload_a():
    return {
        "audit_id": "audit-A",
        "start": "S",
        "nonterminals": ["S"],
        "productions": [{"id": 2, "lhs": "S", "rhs": ["a"]},
                        {"id": 1, "lhs": "S", "rhs": ["a", "b"]}],
        "tokens": ["a", "b"],
    }


class TestFingerprint(unittest.TestCase):
    def test_order_independent(self):
        p1 = payload_a()
        p2 = json.loads(json.dumps(p1))
        # Reorder declarations and productions (ids stay attached).
        p2["productions"] = list(reversed(p2["productions"]))
        self.assertEqual(canonical_fingerprint(p1)[0],
                         canonical_fingerprint(p2)[0])

    def test_token_order_significant(self):
        p1 = payload_a()
        p2 = json.loads(json.dumps(p1))
        p2["tokens"] = ["b", "a"]
        self.assertNotEqual(canonical_fingerprint(p1)[0],
                            canonical_fingerprint(p2)[0])

    def test_production_content_significant(self):
        p1 = payload_a()
        p2 = json.loads(json.dumps(p1))
        p2["productions"][0]["rhs"] = ["c"]
        self.assertNotEqual(canonical_fingerprint(p1)[0],
                            canonical_fingerprint(p2)[0])


class TestSealReplayConflict(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sealed.json")
        self.store = SealedStore(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_seal_replay_conflict_keeps_original(self):
        calls = []

        def compute():
            calls.append(1)
            return {"verdict": "UNIQUE_ACCEPTED", "n": len(calls)}

        entry, status = self.store.submit("audit-A", payload_a(), compute)
        self.assertEqual(status, "SEALED")
        self.assertEqual(entry["conclusion"]["n"], 1)

        # Semantically equivalent retransmission (reordered productions).
        again = json.loads(json.dumps(payload_a()))
        again["productions"] = list(reversed(again["productions"]))
        replay, status2 = self.store.submit("audit-A", again, compute)
        self.assertEqual(status2, "REPLAYED")
        self.assertEqual(replay["conclusion"], entry["conclusion"])
        # The conclusion must not be recomputed on replay.
        self.assertEqual(len(calls), 1)

        # Different input under the same id -> conflict, original kept.
        diff = json.loads(json.dumps(payload_a()))
        diff["tokens"] = ["a"]
        with self.assertRaises(ConflictError) as ctx:
            self.store.submit("audit-A", diff, compute)
        self.assertEqual(ctx.exception.existing["conclusion"],
                         entry["conclusion"])

        replay2, status3 = self.store.submit("audit-A", again, compute)
        self.assertEqual(status3, "REPLAYED")
        self.assertEqual(replay2["conclusion"]["n"], 1)

    def test_persistence_across_instances(self):
        self.store.submit("audit-A", payload_a(),
                          lambda: {"verdict": "UNIQUE_ACCEPTED"})
        store2 = SealedStore(self.path)
        got = store2.get("audit-A")
        self.assertIsNotNone(got)
        self.assertEqual(got["conclusion"]["verdict"], "UNIQUE_ACCEPTED")


if __name__ == "__main__":
    unittest.main()
