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

The full reviewable evidence (the unique derivation tree, or the two
stable witness trees of an ambiguous acceptance) is part of the sealed
conclusion and is persisted verbatim, so a restart over the same data
volume replays byte-identical evidence.

Stores written by older revisions may hold *incomplete* accept
conclusions (the trees were stripped at archive time, leaving
``archived_tree`` / ``archived_witnesses`` markers behind).  When the
store is opened with a ``recompute`` callable, such legacy entries are
safely recovered from their frozen canonical request: the recomputed
conclusion is only adopted when its verdict and production-id
sequence(s) exactly match the sealed remnants; otherwise the original
entry is kept untouched.  Successful recoveries are persisted, so later
restarts keep the restored evidence.  Recovery never changes audit ids,
request fingerprints, seal timestamps, rejection conclusions, or the
original evidence reported on conflicts.
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
    def __init__(self, path: str, recompute=None) -> None:
        """Open the store at ``path``.

        ``recompute`` (optional) is called with a frozen
        ``canonical_request`` and must return the full conclusion for
        it; it is used to recover legacy entries whose accept evidence
        was archived without derivation trees.
        """
        self.path = path
        self._lock = threading.Lock()
        self._recompute = recompute
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
        self._recover_incomplete_entries()

    # ------------------------------------------------------------------
    # Legacy recovery
    # ------------------------------------------------------------------

    @staticmethod
    def _missing_accept_evidence(conclusion: Any) -> bool:
        """True for accept conclusions stripped of their tree evidence."""
        if not isinstance(conclusion, dict):
            return False
        verdict = conclusion.get("verdict")
        if verdict == "UNIQUE_ACCEPTED":
            return not isinstance(conclusion.get("tree"), dict)
        if verdict == "AMBIGUOUS_ACCEPTED":
            trees = conclusion.get("trees")
            return not (isinstance(trees, dict)
                        and isinstance(trees.get("first"), dict)
                        and isinstance(trees.get("second"), dict))
        return False

    def _recover_entry(self, entry: dict) -> Optional[dict]:
        """Rebuild a legacy entry's full conclusion from its frozen input.

        Returns the recovered entry, or ``None`` when recovery is not
        possible or the recomputed evidence does not exactly match the
        sealed remnants (in which case the original entry must be kept
        untouched).
        """
        if self._recompute is None:
            return None
        conclusion = entry.get("conclusion")
        canonical = entry.get("canonical_request")
        if not isinstance(conclusion, dict) or not isinstance(canonical, dict):
            return None
        try:
            fresh = self._recompute(canonical)
        except Exception:  # noqa: BLE001 - never let recovery break startup
            return None
        if not isinstance(fresh, dict):
            return None
        verdict = conclusion.get("verdict")
        if fresh.get("verdict") != verdict:
            return None
        # Safety anchor: the recomputed conclusion must reproduce the
        # sealed production-id sequence(s) exactly before its trees are
        # trusted as the original evidence.
        if verdict == "UNIQUE_ACCEPTED":
            if fresh.get("production_sequence") != conclusion.get("production_sequence"):
                return None
        elif verdict == "AMBIGUOUS_ACCEPTED":
            if (fresh.get("production_sequences")
                    != conclusion.get("production_sequences")):
                return None
        else:
            return None
        if self._missing_accept_evidence(fresh):
            return None
        recovered = json.loads(json.dumps(entry))
        recovered["conclusion"] = fresh
        return recovered

    def _recover_incomplete_entries(self) -> None:
        """Restore tree evidence for legacy archived entries, once."""
        changed = False
        for audit_id, entry in list(self._entries.items()):
            if not isinstance(entry, dict):
                continue
            if not self._missing_accept_evidence(entry.get("conclusion")):
                continue
            recovered = self._recover_entry(entry)
            if recovered is not None:
                self._entries[audit_id] = recovered
                changed = True
        if changed:
            # Persist the recovery so subsequent restarts stay complete.
            with self._lock:
                self._persist_locked()

    # ------------------------------------------------------------------

    def _persist_locked(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._entries, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

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
