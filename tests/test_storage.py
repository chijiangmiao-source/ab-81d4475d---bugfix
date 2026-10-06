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


def unique_conclusion():
    return {
        "verdict": "UNIQUE_ACCEPTED",
        "input_length": 2,
        "production_sequence": [1],
        "tree": {
            "symbol": "S", "production": 1, "span": [0, 2],
            "children": [{"token": "a", "span": [0, 1]},
                         {"token": "b", "span": [1, 2]}],
        },
    }


def ambiguous_conclusion():
    return {
        "verdict": "AMBIGUOUS_ACCEPTED",
        "input_length": 1,
        "production_sequences": {"first": [1], "second": [2]},
        "trees": {
            "first": {"symbol": "S", "production": 1, "span": [0, 1],
                      "children": [{"token": "a", "span": [0, 1]}]},
            "second": {"symbol": "S", "production": 2, "span": [0, 1],
                       "children": [{"token": "a", "span": [0, 1]}]},
        },
        "selection_rule": "stable-order",
    }


def legacy_archive(conclusion):
    """Simulate the pre-fix on-disk format (tree evidence stripped)."""
    archived = json.loads(json.dumps(conclusion))
    if archived["verdict"] == "UNIQUE_ACCEPTED":
        archived.pop("tree")
        archived["archived_tree"] = True
    elif archived["verdict"] == "AMBIGUOUS_ACCEPTED":
        trees = archived.pop("trees")
        archived["archived_witnesses"] = sorted(trees)
    return archived


class TestFullEvidencePersistence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sealed.json")
        self.store = SealedStore(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_unique_tree_survives_restart(self):
        self.store.submit("audit-U", payload_a(), unique_conclusion)
        got = SealedStore(self.path).get("audit-U")
        self.assertEqual(got["conclusion"], unique_conclusion())
        self.assertNotIn("archived_tree", got["conclusion"])

    def test_ambiguous_witnesses_survive_restart(self):
        self.store.submit("audit-W", payload_a(), ambiguous_conclusion)
        got = SealedStore(self.path).get("audit-W")
        self.assertEqual(got["conclusion"], ambiguous_conclusion())
        trees = got["conclusion"]["trees"]
        self.assertNotEqual(trees["first"], trees["second"])

    def test_on_disk_file_contains_full_evidence(self):
        self.store.submit("audit-U", payload_a(), unique_conclusion)
        with open(self.path, encoding="utf-8") as fh:
            raw = json.load(fh)
        self.assertEqual(raw["audit-U"]["conclusion"]["tree"],
                         unique_conclusion()["tree"])


class TestLegacyRecovery(unittest.TestCase):
    """Pre-fix entries archived without trees are recovered safely."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sealed.json")

    def tearDown(self):
        self.tmp.cleanup()

    def _seed_legacy(self, entries):
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, ensure_ascii=False)

    def _legacy_entry(self, audit_id, conclusion, sealed_at):
        request_hash, canonical = canonical_fingerprint(payload_a())
        return {
            "audit_id": audit_id,
            "request_hash": request_hash,
            "canonical_request": canonical,
            "sealed_at": sealed_at,
            "conclusion": legacy_archive(conclusion),
        }

    def test_recovery_restores_unique_tree_and_persists(self):
        sealed_at = "2026-01-01T00:00:00Z"
        entry = self._legacy_entry("audit-U", unique_conclusion(), sealed_at)
        self._seed_legacy({"audit-U": entry})

        def recompute(canonical):
            self.assertEqual(canonical, entry["canonical_request"])
            return unique_conclusion()

        store = SealedStore(self.path, recompute=recompute)
        got = store.get("audit-U")
        self.assertEqual(got["conclusion"], unique_conclusion())
        self.assertNotIn("archived_tree", got["conclusion"])
        # Identity fields are untouched.
        self.assertEqual(got["request_hash"], entry["request_hash"])
        self.assertEqual(got["sealed_at"], sealed_at)
        self.assertEqual(got["canonical_request"], entry["canonical_request"])

        # The recovery is persisted: a store without recompute (and the
        # raw file itself) now hold the complete evidence.
        got2 = SealedStore(self.path).get("audit-U")
        self.assertEqual(got2["conclusion"], unique_conclusion())
        with open(self.path, encoding="utf-8") as fh:
            raw = json.load(fh)
        self.assertEqual(raw["audit-U"]["conclusion"], unique_conclusion())
        self.assertEqual(raw["audit-U"]["sealed_at"], sealed_at)

    def test_recovery_restores_ambiguous_witnesses(self):
        entry = self._legacy_entry("audit-W", ambiguous_conclusion(),
                                   "2026-01-02T00:00:00Z")
        self._seed_legacy({"audit-W": entry})
        store = SealedStore(self.path, recompute=lambda c: ambiguous_conclusion())
        got = store.get("audit-W")
        self.assertEqual(got["conclusion"], ambiguous_conclusion())
        self.assertNotIn("archived_witnesses", got["conclusion"])

    def test_recovery_rejected_on_verdict_mismatch(self):
        entry = self._legacy_entry("audit-U", unique_conclusion(),
                                   "2026-01-03T00:00:00Z")
        self._seed_legacy({"audit-U": entry})

        def bad_recompute(canonical):
            wrong = unique_conclusion()
            wrong["verdict"] = "AMBIGUOUS_ACCEPTED"
            return wrong

        store = SealedStore(self.path, recompute=bad_recompute)
        got = store.get("audit-U")
        # Original (incomplete) evidence preserved verbatim, file untouched.
        self.assertEqual(got, entry)
        with open(self.path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["audit-U"], entry)

    def test_recovery_rejected_on_sequence_mismatch(self):
        entry = self._legacy_entry("audit-U", unique_conclusion(),
                                   "2026-01-04T00:00:00Z")
        self._seed_legacy({"audit-U": entry})

        def bad_recompute(canonical):
            wrong = unique_conclusion()
            wrong["production_sequence"] = [2]
            return wrong

        store = SealedStore(self.path, recompute=bad_recompute)
        self.assertEqual(store.get("audit-U"), entry)

    def test_recovery_failure_keeps_original(self):
        entry = self._legacy_entry("audit-U", unique_conclusion(),
                                   "2026-01-05T00:00:00Z")
        self._seed_legacy({"audit-U": entry})

        def boom(canonical):
            raise RuntimeError("engine unavailable")

        store = SealedStore(self.path, recompute=boom)
        self.assertEqual(store.get("audit-U"), entry)

    def test_rejected_and_complete_entries_untouched(self):
        rejected = {
            "audit_id": "audit-R",
            "request_hash": "f" * 64,
            "canonical_request": {"start": "S"},
            "sealed_at": "2026-01-06T00:00:00Z",
            "conclusion": {"verdict": "REJECTED",
                           "rejection": {"reason": "INPUT_NOT_ACCEPTED",
                                         "detail": "d"}},
        }
        complete = self._legacy_entry("audit-C", unique_conclusion(),
                                      "2026-01-07T00:00:00Z")
        complete["conclusion"] = unique_conclusion()  # already complete
        legacy = self._legacy_entry("audit-L", unique_conclusion(),
                                    "2026-01-08T00:00:00Z")
        self._seed_legacy({"audit-R": rejected, "audit-C": complete,
                           "audit-L": legacy})
        store = SealedStore(self.path, recompute=lambda c: unique_conclusion())
        self.assertEqual(store.get("audit-R"), rejected)
        self.assertEqual(store.get("audit-C"), complete)
        self.assertEqual(store.get("audit-L")["conclusion"], unique_conclusion())

    def test_conflict_still_reports_recovered_original(self):
        entry = self._legacy_entry("audit-U", unique_conclusion(),
                                   "2026-01-09T00:00:00Z")
        self._seed_legacy({"audit-U": entry})
        store = SealedStore(self.path, recompute=lambda c: unique_conclusion())
        diff = json.loads(json.dumps(payload_a()))
        diff["tokens"] = ["a"]
        with self.assertRaises(ConflictError) as ctx:
            store.submit("audit-U", diff, unique_conclusion)
        self.assertEqual(ctx.exception.existing["conclusion"],
                         unique_conclusion())
        self.assertEqual(ctx.exception.existing["request_hash"],
                         entry["request_hash"])


if __name__ == "__main__":
    unittest.main()
