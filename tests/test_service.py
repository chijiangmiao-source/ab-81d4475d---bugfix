"""In-process HTTP service tests (no network fixtures required)."""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from app.service import _compute, make_server, open_store
from app.storage import canonical_fingerprint


class ServiceHarness:
    def __init__(self, store_path=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.store_path = store_path or os.path.join(self.tmp.name, "sealed.json")
        self.httpd, _ = make_server("127.0.0.1", 0, open_store(self.store_path))
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def post(self, payload):
        req = urllib.request.Request(
            self.base + "/api/v1/analyze",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


class TestService(unittest.TestCase):
    def setUp(self):
        self.h = ServiceHarness()

    def tearDown(self):
        self.h.stop()

    def test_health_and_404(self):
        s, b = self.h.get("/healthz")
        self.assertEqual(s, 200)
        self.assertEqual(b["status"], "ok")
        s, _ = self.h.get("/nope")
        self.assertEqual(s, 404)

    def test_full_lifecycle(self):
        payload = {
            "audit_id": "A-1", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]}],
            "start": "S", "tokens": ["a"],
        }
        s, b = self.h.post(payload)
        self.assertEqual(s, 200)
        self.assertEqual(b["seal_status"], "SEALED")
        self.assertEqual(b["result"]["verdict"], "UNIQUE_ACCEPTED")

        # replay
        s, b = self.h.post(payload)
        self.assertEqual(s, 200)
        self.assertEqual(b["seal_status"], "REPLAYED")

        # conflict
        bad = dict(payload, tokens=[])
        s, b = self.h.post(bad)
        self.assertEqual(s, 409)
        self.assertEqual(b["error"], "AUDIT_ID_CONFLICT")
        self.assertEqual(
            b["original_evidence"]["conclusion"]["verdict"], "UNIQUE_ACCEPTED")

    def test_malformed_new_id_is_400_not_500(self):
        s, b = self.h.post({"audit_id": "A-2", "nonterminals": "S"})
        self.assertEqual(s, 400)
        self.assertIn("error", b)
        # Nothing sealed.
        s, b = self.h.get("/api/v1/conclusion/A-2")
        self.assertEqual(s, 404)

    def test_rejected_verdict_is_still_sealed(self):
        payload = {
            "audit_id": "A-3", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]}],
            "start": "S", "tokens": ["z"],
        }
        s, b = self.h.post(payload)
        self.assertEqual(s, 200)
        self.assertEqual(b["result"]["verdict"], "REJECTED")
        self.assertEqual(b["result"]["rejection"]["reason"], "INPUT_NOT_ACCEPTED")
        s2, b2 = self.h.get("/api/v1/conclusion/A-3")
        self.assertEqual(s2, 200)
        self.assertEqual(b2["conclusion"]["verdict"], "REJECTED")

    def test_ambiguous_returns_two_trees(self):
        payload = {
            "audit_id": "A-4", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]},
                            {"id": 2, "lhs": "S", "rhs": ["a"]}],
            "start": "S", "tokens": ["a"],
        }
        s, b = self.h.post(payload)
        self.assertEqual(s, 200)
        self.assertEqual(b["result"]["verdict"], "AMBIGUOUS_ACCEPTED")
        self.assertEqual(b["result"]["production_sequences"],
                         {"first": [1], "second": [2]})


def unique_payload(audit_id):
    return {
        "audit_id": audit_id, "nonterminals": ["S"],
        "productions": [{"id": 1, "lhs": "S", "rhs": ["a", "b"]}],
        "start": "S", "tokens": ["a", "b"],
    }


def ambiguous_payload(audit_id):
    return {
        "audit_id": audit_id, "nonterminals": ["E"],
        "productions": [{"id": 1, "lhs": "E", "rhs": ["E", "+", "E"]},
                        {"id": 2, "lhs": "E", "rhs": ["E", "*", "E"]},
                        {"id": 3, "lhs": "E", "rhs": ["id"]}],
        "start": "E", "tokens": ["id", "+", "id", "*", "id"],
    }


def assert_full_unique(testcase, conclusion):
    testcase.assertEqual(conclusion["verdict"], "UNIQUE_ACCEPTED")
    testcase.assertEqual(conclusion["production_sequence"], [1])
    tree = conclusion.get("tree")
    testcase.assertIsInstance(tree, dict)
    testcase.assertEqual(tree["symbol"], "S")
    testcase.assertEqual(tree["span"], [0, 2])
    testcase.assertEqual([c["token"] for c in tree["children"]], ["a", "b"])


def assert_full_ambiguous(testcase, conclusion):
    testcase.assertEqual(conclusion["verdict"], "AMBIGUOUS_ACCEPTED")
    seqs = conclusion["production_sequences"]
    testcase.assertEqual(seqs["first"], [1, 3, 2, 3, 3])
    testcase.assertEqual(seqs["second"], [2, 1, 3, 3, 3])
    trees = conclusion.get("trees")
    testcase.assertIsInstance(trees, dict)
    first, second = trees["first"], trees["second"]
    testcase.assertNotEqual(first, second)
    for tree in (first, second):
        testcase.assertEqual(tree["symbol"], "E")
        testcase.assertEqual(tree["span"], [0, 5])
        # Every token position is covered exactly once by the leaves.
        leaves = []

        def walk(node):
            if "token" in node:
                leaves.append((node["span"][0], node["token"]))
            else:
                for child in node["children"]:
                    walk(child)

        walk(tree)
        testcase.assertEqual(leaves,
                             [(i, t) for i, t in enumerate(
                                 ["id", "+", "id", "*", "id"])])


class TestRestartPersistence(unittest.TestCase):
    """A restart over the same data volume must replay full evidence."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.tmp.name, "sealed.json")
        self.h = ServiceHarness(self.store_path)

    def tearDown(self):
        self.h.stop()
        self.tmp.cleanup()

    def restart(self):
        self.h.stop()
        self.h = ServiceHarness(self.store_path)

    def test_restart_keeps_unique_and_ambiguous_trees(self):
        s, b = self.h.post(unique_payload("R-1"))
        self.assertEqual(s, 200)
        assert_full_unique(self, b["result"])
        sealed_at_u = b["sealed_at"]
        hash_u = b["request_hash"]

        s, b = self.h.post(ambiguous_payload("R-2"))
        self.assertEqual(s, 200)
        assert_full_ambiguous(self, b["result"])
        sealed_at_a = b["sealed_at"]
        hash_a = b["request_hash"]

        self.restart()

        # Reads by audit id return the complete evidence.
        s, b = self.h.get("/api/v1/conclusion/R-1")
        self.assertEqual(s, 200)
        assert_full_unique(self, b["conclusion"])
        self.assertEqual(b["sealed_at"], sealed_at_u)
        self.assertEqual(b["request_hash"], hash_u)

        s, b = self.h.get("/api/v1/conclusion/R-2")
        self.assertEqual(s, 200)
        assert_full_ambiguous(self, b["conclusion"])
        self.assertEqual(b["sealed_at"], sealed_at_a)
        self.assertEqual(b["request_hash"], hash_a)

        # Equivalent retransmission (production order shuffled) replays
        # the full evidence without recomputation.
        shuffled = ambiguous_payload("R-2")
        shuffled["productions"] = list(reversed(shuffled["productions"]))
        s, b = self.h.post(shuffled)
        self.assertEqual(s, 200)
        self.assertEqual(b["seal_status"], "REPLAYED")
        assert_full_ambiguous(self, b["result"])

        # A second restart keeps everything (recovery is persisted).
        self.restart()
        s, b = self.h.get("/api/v1/conclusion/R-2")
        self.assertEqual(s, 200)
        assert_full_ambiguous(self, b["conclusion"])

        # Conflict behaviour is unchanged: original evidence, with trees.
        conflict = unique_payload("R-1")
        conflict["tokens"] = ["a"]
        s, b = self.h.post(conflict)
        self.assertEqual(s, 409)
        self.assertEqual(b["error"], "AUDIT_ID_CONFLICT")
        assert_full_unique(self, b["original_evidence"]["conclusion"])


class TestLegacyStoreRecovery(unittest.TestCase):
    """Stores sealed before the fix (trees archived away) are recovered."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.tmp.name, "sealed.json")

    def tearDown(self):
        self.tmp.cleanup()

    def _write_legacy_store(self):
        entries = {}
        for audit_id, payload in (("L-U", unique_payload("L-U")),
                                  ("L-A", ambiguous_payload("L-A"))):
            request_hash, canonical = canonical_fingerprint(payload)
            conclusion = _compute(payload)
            archived = json.loads(json.dumps(conclusion))
            if archived["verdict"] == "UNIQUE_ACCEPTED":
                archived.pop("tree")
                archived["archived_tree"] = True
            else:
                trees = archived.pop("trees")
                archived["archived_witnesses"] = sorted(trees)
            entries[audit_id] = {
                "audit_id": audit_id,
                "request_hash": request_hash,
                "canonical_request": canonical,
                "sealed_at": "2026-01-01T00:00:00Z",
                "conclusion": archived,
            }
        with open(self.store_path, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, ensure_ascii=False)
        return entries

    def test_legacy_entries_recovered_on_boot_and_persisted(self):
        entries = self._write_legacy_store()
        h = ServiceHarness(self.store_path)
        try:
            s, b = h.get("/api/v1/conclusion/L-U")
            self.assertEqual(s, 200)
            assert_full_unique(self, b["conclusion"])
            self.assertEqual(b["sealed_at"], "2026-01-01T00:00:00Z")
            self.assertEqual(b["request_hash"],
                             entries["L-U"]["request_hash"])

            s, b = h.get("/api/v1/conclusion/L-A")
            self.assertEqual(s, 200)
            assert_full_ambiguous(self, b["conclusion"])
            self.assertEqual(b["sealed_at"], "2026-01-01T00:00:00Z")

            # Equivalent retransmission of a legacy id replays fully.
            shuffled = ambiguous_payload("L-A")
            shuffled["productions"] = list(reversed(shuffled["productions"]))
            s, b = h.post(shuffled)
            self.assertEqual(s, 200)
            self.assertEqual(b["seal_status"], "REPLAYED")
            assert_full_ambiguous(self, b["result"])
        finally:
            h.stop()

        # The recovery survived the restart: boot a fresh server on the
        # same volume and the evidence is still complete.
        h2 = ServiceHarness(self.store_path)
        try:
            s, b = h2.get("/api/v1/conclusion/L-U")
            self.assertEqual(s, 200)
            assert_full_unique(self, b["conclusion"])
            s, b = h2.get("/api/v1/conclusion/L-A")
            self.assertEqual(s, 200)
            assert_full_ambiguous(self, b["conclusion"])
        finally:
            h2.stop()


if __name__ == "__main__":
    unittest.main()
