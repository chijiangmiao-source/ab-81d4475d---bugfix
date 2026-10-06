#!/usr/bin/env python3
"""Seed *legacy* sealed records into the arbiter data volume.

Older builds persisted verdicts and stable production-id sequences but
stripped the actual derivation trees on disk (``archived_tree`` /
``archived_witnesses`` markers).  Recovery is the process of rebuilding
the missing trees from the frozen canonical input at startup.

This script writes two such legacy records (one unique, one ambiguous)
into ``$ARBITER_STORE`` (default ``/data/sealed.json``) and is meant to
run against the data volume while the arbiter container is stopped.

The frozen input is stored verbatim alongside the original request
fingerprint; the arbiter must restore complete, reviewable trees on its
next start without changing audit id, fingerprint or seal timestamp.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.getcwd())

from app import engine  # noqa: E402
from app.grammar import build_grammar  # noqa: E402
from app.storage import canonical_fingerprint  # noqa: E402

STORE = os.environ.get("ARBITER_STORE", "/data/sealed.json")

UNIQUE_ID = "legacy-unique-restore"
AMBIGUOUS_ID = "legacy-amb-restore"

UNIQUE_PAYLOAD = {
    "audit_id": UNIQUE_ID,
    "start": "S",
    "nonterminals": ["S"],
    "productions": [{"id": 5, "lhs": "S", "rhs": ["a", "b"]}],
    "tokens": ["a", "b"],
}

AMBIGUOUS_PAYLOAD = {
    "audit_id": AMBIGUOUS_ID,
    "start": "E",
    "nonterminals": ["E"],
    "productions": [
        {"id": 1, "lhs": "E", "rhs": ["E", "+", "E"]},
        {"id": 2, "lhs": "E", "rhs": ["E", "*", "E"]},
        {"id": 4, "lhs": "E", "rhs": ["id"]},
    ],
    "tokens": ["id", "+", "id", "*", "id"],
}


def compute(payload: dict) -> dict:
    grammar = build_grammar(payload)
    try:
        return engine.analyze(grammar)
    except engine.EngineError as exc:  # pragma: no cover - seed is valid
        return {
            "verdict": engine.REJECTED,
            "rejection": {"reason": exc.reason, "detail": exc.detail},
        }


def legacy_entry(payload: dict, sealed_at: str) -> dict:
    fp, canonical = canonical_fingerprint(payload)
    conclusion = compute(payload)
    verdict = conclusion["verdict"]
    # Emulate the old build: keep verdict and stable sequences, drop the
    # node-by-node trees.
    if verdict == "UNIQUE_ACCEPTED":
        del conclusion["tree"]
        conclusion["archived_tree"] = True
    elif verdict == "AMBIGUOUS_ACCEPTED":
        del conclusion["trees"]
        conclusion["archived_witnesses"] = ["first", "second"]
    return {
        "audit_id": payload["audit_id"],
        "request_hash": fp,
        "canonical_request": canonical,
        "sealed_at": sealed_at,
        "conclusion": conclusion,
    }


def main() -> int:
    entries = {}
    if os.path.exists(STORE):
        with open(STORE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        if isinstance(loaded, dict):
            entries = loaded
        for legacy_id in (UNIQUE_ID, AMBIGUOUS_ID):
            if legacy_id in entries:
                print(f"legacy id {legacy_id} already present; aborting seed")
                return 1

    entries[UNIQUE_ID] = legacy_entry(UNIQUE_PAYLOAD, "2025-12-31T23:59:00Z")
    entries[AMBIGUOUS_ID] = legacy_entry(AMBIGUOUS_PAYLOAD, "2025-12-31T23:59:01Z")

    tmp = STORE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp, STORE)
    print(f"seeded legacy records {UNIQUE_ID!r}, {AMBIGUOUS_ID!r} into {STORE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
