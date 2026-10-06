"""Sealed-store tests: replay of equivalent input, id conflicts,
persistence of complete derivation evidence across restarts, and safe
recovery of legacy records whose on-disk evidence was stripped."""

import copy
import json
import os
import tempfile
import unittest

from app import engine
from app.grammar import build_grammar
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


def unique_payload(audit_id="audit-U"):
    return {
        "audit_id": audit_id,
        "start": "S",
        "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": ["a", "b"]}],
        "tokens": ["a", "b"],
    }


def ambiguous_payload(audit_id="audit-M"):
    return {
        "audit_id": audit_id,
        "start": "E",
        "nonterminals": ["E"],
        "productions": [
            {"id": 1, "lhs": "E", "rhs": ["E", "+", "E"]},
            {"id": 2, "lhs": "E", "rhs": ["E", "*", "E"]},
            {"id": 3, "lhs": "E", "rhs": ["id"]},
        ],
        "tokens": ["id", "+", "id", "*", "id"],
    }


def compute(payload):
    """Real engine conclusion (the same callable the service uses)."""
    grammar = build_grammar(payload)
    try:
        return engine.analyze(grammar)
    except engine.EngineError as exc:
        return {
            "verdict": engine.REJECTED,
            "rejection": {
                "reason": exc.reason,
                "detail": exc.detail,
                **({"evidence": exc.extra} if exc.extra else {}),
            },
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
                          lambda: compute(payload_a()))
        store2 = SealedStore(self.path)
        got = store2.get("audit-A")
        self.assertIsNotNone(got)
        self.assertEqual(got["conclusion"]["verdict"], "UNIQUE_ACCEPTED")

    def test_unique_tree_survives_restart(self):
        payload = unique_payload()
        entry, _ = self.store.submit("audit-U", payload,
                                     lambda: compute(payload))
        tree = entry["conclusion"]["tree"]
        self.assertEqual(tree["span"], [0, 2])

        # Reopen the same on-disk store: full tree must come back.
        reopened = SealedStore(self.path)
        got = reopened.get("audit-U")
        self.assertEqual(got["conclusion"]["tree"], tree)
        self.assertEqual(got["conclusion"]["production_sequence"], [1])
        self.assertNotIn("archived_tree", got["conclusion"])
        self.assertEqual(got["request_hash"], entry["request_hash"])
        self.assertEqual(got["sealed_at"], entry["sealed_at"])

        # A second reopen stays complete (recovery is not re-triggered by
        # a fully-persisted record).
        reopened2 = SealedStore(self.path)
        self.assertEqual(reopened2.get("audit-U")["conclusion"]["tree"],
                         tree)

    def test_ambiguous_witnesses_survive_restart_and_replay(self):
        payload = ambiguous_payload()
        entry, _ = self.store.submit("audit-M", payload,
                                     lambda: compute(payload))
        res = entry["conclusion"]
        first, second = res["trees"]["first"], res["trees"]["second"]
        seqs = res["production_sequences"]
        self.assertNotEqual(first, second)
        self.assertEqual(first["span"], [0, 5])
        self.assertEqual(second["span"], [0, 5])

        reopened = SealedStore(self.path)
        got = reopened.get("audit-M")["conclusion"]
        self.assertEqual(got["trees"]["first"], first)
        self.assertEqual(got["trees"]["second"], second)
        self.assertEqual(got["production_sequences"], seqs)
        self.assertNotIn("archived_witnesses", got)

        # Equivalent retransmission with shuffled declarations after the
        # restart replays verbatim, never recomputing.
        calls = []

        def must_not_run():  # pragma: no cover - must never be invoked
            calls.append(1)
            return {}

        shuffled = copy.deepcopy(payload)
        shuffled["productions"] = list(reversed(shuffled["productions"]))
        replay, status = reopened.submit("audit-M", shuffled, must_not_run)
        self.assertEqual(status, "REPLAYED")
        self.assertEqual(calls, [])
        self.assertEqual(replay["conclusion"]["trees"]["first"], first)
        self.assertEqual(replay["conclusion"]["trees"]["second"], second)
        self.assertEqual(
            replay["conclusion"]["production_sequences"]["second"],
            seqs["second"])

    def test_on_disk_payload_contains_full_trees(self):
        payload = unique_payload()
        self.store.submit("audit-U", payload, lambda: compute(payload))
        with open(self.path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        conclusion = raw["audit-U"]["conclusion"]
        self.assertIn("tree", conclusion)
        self.assertEqual(conclusion["tree"]["span"], [0, 2])
        self.assertNotIn("archived_tree", conclusion)


def _legacy_entry(payload, verdict, conclusion):
    """Build an old-build on-disk record (trees stripped on persist)."""
    fp, canonical = canonical_fingerprint(payload)
    return {
        "audit_id": payload["audit_id"],
        "request_hash": fp,
        "canonical_request": canonical,
        "sealed_at": "2026-01-02T03:04:05Z",
        "conclusion": conclusion,
    }


class TestLegacyRecovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sealed.json")

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, entries):
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(entries, fh)

    def test_unique_legacy_record_is_restored_and_persisted(self):
        payload = unique_payload("legacy-U")
        old_concl = {
            "verdict": "UNIQUE_ACCEPTED",
            "input_length": 2,
            "production_sequence": [1],
            "archived_tree": True,
        }
        self._write({"legacy-U": _legacy_entry(payload, "UNIQUE", old_concl)})

        store = SealedStore(self.path)
        got = store.get("legacy-U")
        self.assertEqual(got["conclusion"]["verdict"], "UNIQUE_ACCEPTED")
        self.assertEqual(got["conclusion"]["tree"]["span"], [0, 2])
        self.assertEqual(got["conclusion"]["production_sequence"], [1])
        self.assertNotIn("archived_tree", got["conclusion"])
        # Immutable audit metadata.
        self.assertEqual(got["request_hash"],
                         canonical_fingerprint(payload)[0])
        self.assertEqual(got["sealed_at"], "2026-01-02T03:04:05Z")

        # Persisted complete; a second reopen needs no reconstruction.
        store2 = SealedStore(self.path)
        got2 = store2.get("legacy-U")
        self.assertEqual(got2["conclusion"]["tree"],
                         got["conclusion"]["tree"])
        self.assertEqual(got2["sealed_at"], "2026-01-02T03:04:05Z")

    def test_ambiguous_legacy_record_restores_two_distinct_witnesses(self):
        payload = ambiguous_payload("legacy-M")
        fresh = compute(payload)
        old_concl = {
            "verdict": "AMBIGUOUS_ACCEPTED",
            "input_length": 5,
            "production_sequences": fresh["production_sequences"],
            "archived_witnesses": ["first", "second"],
        }
        self._write({"legacy-M": _legacy_entry(payload, "AMB", old_concl)})

        store = SealedStore(self.path)
        got = store.get("legacy-M")["conclusion"]
        self.assertEqual(got["trees"]["first"], fresh["trees"]["first"])
        self.assertEqual(got["trees"]["second"], fresh["trees"]["second"])
        self.assertNotEqual(got["trees"]["first"], got["trees"]["second"])
        self.assertEqual(got["trees"]["first"]["span"], [0, 5])
        self.assertEqual(got["trees"]["second"]["span"], [0, 5])
        self.assertNotIn("archived_witnesses", got)

    def test_tampered_frozen_input_is_never_rebuilt(self):
        payload = unique_payload("legacy-T")
        entry = _legacy_entry(
            payload, "UNIQUE",
            {"verdict": "UNIQUE_ACCEPTED", "production_sequence": [1],
             "archived_tree": True})
        # Corrupt the frozen input while keeping the sealed fingerprint.
        entry["canonical_request"]["tokens"] = ["a"]
        self._write({"legacy-T": entry})

        store = SealedStore(self.path)
        got = store.get("legacy-T")
        self.assertNotIn("tree", got["conclusion"])
        self.assertTrue(got["conclusion"]["archived_tree"])
        self.assertEqual(got["sealed_at"], "2026-01-02T03:04:05Z")

    def test_sequence_mismatch_blocks_recovery(self):
        # An ambiguous grammar whose retained sequences disagree with the
        # frozen input's recomputed sequences must be left untouched.
        payload = ambiguous_payload("legacy-S")
        entry = _legacy_entry(
            payload, "AMBIGUOUS",
            {"verdict": "AMBIGUOUS_ACCEPTED",
             "production_sequences": {"first": [9], "second": [99]},
             "archived_witnesses": ["first", "second"]})
        self._write({"legacy-S": entry})

        store = SealedStore(self.path)
        got = store.get("legacy-S")["conclusion"]
        self.assertNotIn("trees", got)
        self.assertTrue(got["archived_witnesses"])

    def test_rejected_legacy_record_is_untouched(self):
        payload = {
            "audit_id": "legacy-R",
            "start": "S", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]}],
            "tokens": ["z"],
        }
        concl = {
            "verdict": "REJECTED",
            "rejection": {"reason": "INPUT_NOT_ACCEPTED", "detail": "d"},
        }
        self._write({"legacy-R": _legacy_entry(payload, "REJ", concl)})
        store = SealedStore(self.path)
        got = store.get("legacy-R")["conclusion"]
        self.assertEqual(got["verdict"], "REJECTED")
        self.assertEqual(got["rejection"]["reason"], "INPUT_NOT_ACCEPTED")


if __name__ == "__main__":
    unittest.main()
