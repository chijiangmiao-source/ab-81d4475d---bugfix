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

Persistence preserves the *complete* reviewable evidence -- verdict,
preorder production-id sequences, spans and full derivation trees -- so a
reviewer reopening the service after a restart gets node-by-node
identical conclusions.  Records sealed by older builds that persisted
verdicts without trees are recovered at load time from their frozen
canonical input (audit id, request fingerprint, seal timestamp and the
adjudicated verdict are never altered).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from . import engine
from .grammar import ValidationError, build_grammar

# Conclusions carry node-by-node derivation evidence that must survive
# sealing and process restarts.
_UNIQUE = "UNIQUE_ACCEPTED"
_AMBIGUOUS = "AMBIGUOUS_ACCEPTED"


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
            else:
                # Records sealed by older builds may lack derivation
                # trees; safely rebuild them from the frozen input so the
                # evidence stays reviewable across every later reopen.
                with self._lock:
                    if self._recover_incomplete_locked():
                        try:
                            self._persist_locked()
                        except OSError:
                            # Read-only volume: the recovery still holds
                            # for this process; a later writable reopen
                            # retries the same reconstruction.
                            pass

    # ------------------------------------------------------------------
    # Evidence completeness and recovery
    # ------------------------------------------------------------------

    @staticmethod
    def _evidence_complete(entry: dict) -> bool:
        """A sealed entry is reviewable only with its full trees."""
        conclusion = entry.get("conclusion") or {}
        verdict = conclusion.get("verdict")
        if verdict == _UNIQUE:
            return isinstance(conclusion.get("tree"), dict)
        if verdict == _AMBIGUOUS:
            trees = conclusion.get("trees")
            return (
                isinstance(trees, dict)
                and isinstance(trees.get("first"), dict)
                and isinstance(trees.get("second"), dict)
            )
        # REJECTED conclusions carry no derivation trees.
        return True

    @staticmethod
    def _recompute_conclusion(canonical: dict) -> dict:
        """Recompute a conclusion from a frozen canonical request.

        The canonical object has exactly the submission shape (it was the
        input of :func:`canonical_fingerprint`), so it rebuilds the
        grammar directly.
        """
        grammar = build_grammar(canonical)
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

    def _recover_incomplete_locked(self) -> bool:
        """Restore missing trees of legacy records from frozen input.

        Only the ``conclusion`` is rebuilt.  Audit id, request
        fingerprint, seal timestamp and the adjudicated verdict are
        immutable: a reconstructed conclusion is accepted only when its
        verdict and the previously stored stable production-id sequences
        match exactly, otherwise the record is left untouched.
        """
        recovered_any = False
        for audit_id, entry in list(self._entries.items()):
            if self._evidence_complete(entry):
                continue
            old = entry.get("conclusion") or {}
            canonical = entry.get("canonical_request")
            try:
                if not isinstance(canonical, dict):
                    continue
                # The frozen input must still hash to the sealed
                # fingerprint; otherwise it is not safe to rebuild.
                fp, _ = canonical_fingerprint(canonical)
                if fp != entry.get("request_hash"):
                    continue
                rebuilt = self._recompute_conclusion(canonical)
            except (ValidationError, KeyError, TypeError, ValueError):
                continue
            if rebuilt.get("verdict") != old.get("verdict"):
                continue
            if not self._sequences_match(old, rebuilt):
                continue
            restored = json.loads(json.dumps(entry))
            restored["conclusion"] = rebuilt
            self._entries[audit_id] = restored
            recovered_any = True
        return recovered_any

    @staticmethod
    def _sequences_match(old: dict, rebuilt: dict) -> bool:
        """Guard stability using the sequences the old record retained."""
        verdict = rebuilt.get("verdict")
        if verdict == _UNIQUE:
            return (
                old.get("production_sequence")
                == rebuilt.get("production_sequence")
            )
        if verdict == _AMBIGUOUS:
            return (
                old.get("production_sequences")
                == rebuilt.get("production_sequences")
            )
        return True

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist_locked(self) -> None:
        # Complete evidence is persisted verbatim: verdict, production-id
        # sequences, spans and every derivation tree must survive a
        # restart for node-by-node re-review.
        stored_entries = json.loads(json.dumps(self._entries))
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(stored_entries, fh, ensure_ascii=False, indent=2,
                      sort_keys=True)
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
