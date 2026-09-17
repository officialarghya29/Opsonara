"""Idempotency for consequential firewall calls (spec §24).

A retried POST must never execute a second refund. Clients send an
``Idempotency-Key`` header; the first call's verdict is stored and replayed
verbatim for duplicate keys:

* first call with a key        → processed normally, response cached;
* duplicate while in flight    → **409 Conflict** (the caller must wait, not
  assume) — two concurrent calls with one key can never both execute;
* duplicate after completion   → the *original* response is replayed with
  ``Idempotency-Replayed: true``, indistinguishable from the first call.

A **key mismatch** (same key, different request fingerprint) is a client
bug or an attempted abuse — rejected with 422 rather than silently
re-processing under the wrong identity. Fingerprints hash the exact
evaluate payload, so a tampered amount cannot ride on a cached verdict.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import Any

_DEFAULT_TTL = 24 * 3600
"""Default replay window: 24 h of idempotency guarantees per key."""
_MAX_KEY_LENGTH = 256


def fingerprint_payload(payload: Any) -> str:
    """Stable SHA-256 of the exact request body (spec §24 tamper guard).

    Sorted keys + compact separators so the same JSON object always hashes
    identically regardless of dict insertion order.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(slots=True)
class _Entry:
    fingerprint: str
    response: dict[str, Any] | None = None
    done: bool = False
    created_at: float = 0.0


class MemoryIdempotencyStore:
    """Thread-safe in-memory idempotency store (single process).

    Contract (used by the ``/v1/evaluate`` endpoint):

    * ``claim(key, fingerprint)``     → True if this call is the processor;
    * ``get(key)``                    → ``{"fingerprint", "response"}`` for a
      completed call, else None;
    * ``complete(key, fp, response)`` → cache the verdict for replay;
    * ``release(key)``                → give the key back after a failure so
      the client can retry cleanly.

    A durable (SQLite/Postgres) backend can implement the same four methods
    to make guarantees survive restarts and span workers.
    """

    def __init__(self, *, ttl_seconds: int = _DEFAULT_TTL, max_entries: int = 10_000) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}
        self._ttl = max(int(ttl_seconds), 1)
        self._max_entries = max(int(max_entries), 1)

    # -- contract ---------------------------------------------------------------

    def claim(self, key: str, fingerprint: str) -> bool:
        """Atomically reserve ``key`` for this (key, fingerprint) pair.

        Returns ``False`` when the key is already claimed (caller answers
        409). Expired entries are evicted lazily here, on the hot path.
        """
        with self._lock:
            self._evict_expired()
            if key in self._entries:
                return False
            if len(self._entries) >= self._max_entries:
                # Bounded memory under key-flood: evict the oldest entry.
                oldest_key = min(self._entries, key=lambda k: self._entries[k].created_at)
                del self._entries[oldest_key]
            self._entries[key] = _Entry(
                fingerprint=fingerprint, created_at=time.time()
            )
            return True

    def get(self, key: str) -> dict[str, Any] | None:
        """Stored verdict for a *completed* call, else ``None``."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or not entry.done or entry.response is None:
                return None
            return {"fingerprint": entry.fingerprint, "response": entry.response}

    def complete(self, key: str, fingerprint: str, response: dict[str, Any]) -> None:
        """Mark the call finished and cache its response for replay."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and entry.fingerprint == fingerprint:
                entry.response = response
                entry.done = True

    def release(self, key: str) -> None:
        """Give the key back after a processing failure (client may retry)."""
        with self._lock:
            self._entries.pop(key, None)

    # -- internals -------------------------------------------------------------

    def _evict_expired(self) -> None:
        """Drop entries past the TTL. Caller must hold the lock."""
        now = time.time()
        expired = [k for k, e in self._entries.items() if now - e.created_at > self._ttl]
        for k in expired:
            del self._entries[k]

    # -- introspection (tests) -----------------------------------------------

    def fingerprint_of(self, key: str) -> str | None:
        with self._lock:
            entry = self._entries.get(key)
            return entry.fingerprint if entry else None

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


__all__ = [
    "MemoryIdempotencyStore",
    "fingerprint_payload",
    "_MAX_KEY_LENGTH",
]
