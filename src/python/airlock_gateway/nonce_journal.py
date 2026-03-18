"""
Anti-replay nonce journal. Records seen nonces and prevents replay attacks.
Entries expire after a configurable TTL and are pruned on access.
"""

import os
import threading
import time
from typing import Optional


class NonceJournal:
    """Anti-replay nonce journal with TTL-based expiration and optional file persistence."""

    def __init__(self, ttl_seconds: float = 900, persist_path: Optional[str] = None):
        """
        Args:
            ttl_seconds: How long to keep nonces (default: 15 minutes = 900s).
            persist_path: Optional file path for persisting nonces across restarts.
        """
        self._ttl = ttl_seconds
        self._persist_path = persist_path
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self._last_prune = time.time()

        if persist_path and os.path.exists(persist_path):
            self._load_from_file()

    def try_record(self, nonce: str) -> bool:
        """Check and record a nonce. Returns True if new (unseen), False if replay."""
        with self._lock:
            self._maybe_prune()
            now = time.time()
            if nonce in self._seen and now - self._seen[nonce] < self._ttl:
                return False  # replay
            self._seen[nonce] = now
            self._maybe_persist()
            return True

    def has_seen(self, nonce: str) -> bool:
        """Check whether a nonce has already been seen (without recording)."""
        with self._lock:
            if nonce in self._seen:
                return time.time() - self._seen[nonce] < self._ttl
            return False

    @property
    def count(self) -> int:
        """Number of active (non-expired) nonces."""
        with self._lock:
            self._maybe_prune()
            return len(self._seen)

    def _maybe_prune(self) -> None:
        now = time.time()
        if now - self._last_prune < 60:
            return
        self._last_prune = now
        cutoff = now - self._ttl
        expired = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in expired:
            del self._seen[k]

    def _maybe_persist(self) -> None:
        if not self._persist_path:
            return
        try:
            with open(self._persist_path, "w") as f:
                for nonce, ts in self._seen.items():
                    f.write(f"{nonce}\t{ts}\n")
        except OSError:
            pass  # best-effort

    def _load_from_file(self) -> None:
        try:
            with open(self._persist_path, "r") as f:  # type: ignore
                for line in f:
                    parts = line.strip().split("\t")
                    if len(parts) == 2:
                        try:
                            self._seen[parts[0]] = float(parts[1])
                        except ValueError:
                            pass
        except OSError:
            pass  # best-effort
