"""Sealed-conclusion store keyed by stable audit identifiers.

Every well-formed submission is reduced to a canonical semantic
fingerprint.  Rules:

* a new audit id               -> the conclusion is computed, sealed and
                                  returned (``SEALED``);
* the same id, semantically
  equivalent retransmission    -> the sealed conclusion is replayed
                                  verbatim (``REPLAYED``);
* the same id, different input -> ``AUDIT_ID_CONFLICT``; the original
                                  evidence is retained untouched and
                                  reported back alongside the new
                                  fingerprint.

The store is a single JSON file replaced atomically; a process-wide lock
serializes writes.  Sealed entries are immutable.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple


class ConflictError(Exception):
    def __init__(self, detail: str, existing: dict, incoming_hash: str) -> None:
        super().__init__(detail)
        self.detail = detail
        self.existing = existing
        self.incoming_hash = incoming_hash


def canonical_fingerprint(payload: dict) -> Tuple[str, dict]:
    """Return ``(sha256_hex, canonical_object)`` for a submission.

    Only semantic content participates: declaration ordering is
    irrelevant; productions are keyed by their unique ids; the input
    token sequence order is significant.
    """
    productions = sorted(
        (
            {"id": int(p["id"]), "lhs": p["lhs"], "rhs": list(p["rhs"])}
            for p in payload["productions"]
        ),
        key=lambda p: p["id"],
    )
    canonical = {
        "start": payload["start"],
        "nonterminals": sorted(payload["nonterminals"]),
        "terminals": (
            sorted(payload["terminals"]) if payload.get("terminals") is not None else None
        ),
        "tokens": list(payload.get("tokens", [])),
        "productions": productions,
    }
    blob = json.dumps(
        canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest(), canonical


class SealedStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._entries: Dict[str, dict] = {}
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    self._entries = data
            except (json.JSONDecodeError, OSError):
                # Corrupt store: quarantine rather than destroy evidence.
                qpath = path + ".corrupt." + datetime.now(timezone.utc).strftime(
                    "%Y%m%dT%H%M%SZ"
                )
                os.replace(path, qpath)
                self._entries = {}

    def _persist_locked(self) -> None:
        archived_entries = {
            audit_id: self._archive_entry(entry)
            for audit_id, entry in self._entries.items()
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(archived_entries, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    @staticmethod
    def _archive_entry(entry: dict) -> dict:
        archived = json.loads(json.dumps(entry))
        conclusion = archived.get("conclusion", {})
        verdict = conclusion.get("verdict")
        if verdict == "UNIQUE_ACCEPTED":
            tree = conclusion.pop("tree", None)
            if tree is not None:
                conclusion["archived_tree"] = True
        elif verdict == "AMBIGUOUS_ACCEPTED":
            trees = conclusion.pop("trees", None)
            if trees is not None:
                conclusion["archived_witnesses"] = sorted(trees)
        return archived

    def get(self, audit_id: str) -> Optional[dict]:
        with self._lock:
            entry = self._entries.get(audit_id)
            return json.loads(json.dumps(entry)) if entry else None

    def submit(
        self, audit_id: str, payload: dict, compute_conclusion
    ) -> Tuple[dict, str]:
        """Seal/replay a submission.

        ``compute_conclusion`` is called with no arguments only for a
        genuinely new id and must return a JSON-serializable conclusion.
        Returns ``(envelope, status)`` where status is ``SEALED`` or
        ``REPLAYED``; raises :class:`ConflictError` on id reuse with
        different semantics.
        """
        incoming_hash, canonical = canonical_fingerprint(payload)
        with self._lock:
            existing = self._entries.get(audit_id)
            if existing is not None:
                if existing["request_hash"] == incoming_hash:
                    return json.loads(json.dumps(existing)), "REPLAYED"
                raise ConflictError(
                    f"审计标识 {audit_id!r} 已封存于 {existing['sealed_at']}，"
                    f"本次输入语义指纹 {incoming_hash[:12]} 与原证据 "
                    f"{existing['request_hash'][:12]} 不一致；原证据保留不变，"
                    "请使用新的审计标识提交，或重传语义等价的原始输入",
                    existing=json.loads(json.dumps(existing)),
                    incoming_hash=incoming_hash,
                )

            conclusion = compute_conclusion()
            entry = {
                "audit_id": audit_id,
                "request_hash": incoming_hash,
                "canonical_request": canonical,
                "sealed_at": datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                "conclusion": conclusion,
            }
            self._entries[audit_id] = entry
            self._persist_locked()
            return json.loads(json.dumps(entry)), "SEALED"
