"""In-process HTTP service tests (no network fixtures required)."""

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from app.service import make_server
from app.storage import SealedStore


class ServiceHarness:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        store_path = os.path.join(self.tmp.name, "sealed.json")
        self.httpd, _ = make_server("127.0.0.1", 0, SealedStore(store_path))
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


class TestPersistenceAcrossRestart(unittest.TestCase):
    """A reopened server over the same store must return full trees."""

    def _serve(self, tmp):
        path = os.path.join(tmp, "sealed.json")
        httpd, _ = make_server("127.0.0.1", 0, SealedStore(path))
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        return httpd, thread, f"http://127.0.0.1:{httpd.server_address[1]}"

    @staticmethod
    def _post(base, payload):
        req = urllib.request.Request(
            base + "/api/v1/analyze",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    @staticmethod
    def _get(base, path):
        with urllib.request.urlopen(base + path, timeout=5) as r:
            return r.status, json.loads(r.read())

    def test_full_trees_survive_server_restart(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, True))

        unique = {
            "audit_id": "R-U", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a", "b"]}],
            "start": "S", "tokens": ["a", "b"],
        }
        ambiguous = {
            "audit_id": "R-A", "nonterminals": ["S"],
            "productions": [{"id": 1, "lhs": "S", "rhs": ["a"]},
                            {"id": 2, "lhs": "S", "rhs": ["a"]}],
            "start": "S", "tokens": ["a"],
        }

        httpd, thread, base = self._serve(tmp)
        try:
            s, b1 = self._post(base, unique)
            self.assertEqual(s, 200)
            s, b2 = self._post(base, ambiguous)
            self.assertEqual(s, 200)
            tree = b1["result"]["tree"]
            witnesses = b2["result"]["trees"]
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)

        # Reopen: brand new process-equivalent server over the same file.
        httpd, thread, base = self._serve(tmp)
        try:
            s, body = self._get(base, "/api/v1/conclusion/R-U")
            self.assertEqual(s, 200)
            self.assertEqual(body["conclusion"]["tree"], tree)
            self.assertEqual(
                body["conclusion"]["production_sequence"], [1])

            s, body = self._get(base, "/api/v1/conclusion/R-A")
            self.assertEqual(s, 200)
            self.assertEqual(body["conclusion"]["trees"], witnesses)

            # Equivalent retransmission after restart replays full trees.
            s, body = self._post(base, ambiguous)
            self.assertEqual(s, 200)
            self.assertEqual(body["seal_status"], "REPLAYED")
            self.assertEqual(body["result"]["trees"], witnesses)
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
