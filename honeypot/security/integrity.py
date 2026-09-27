"""SHA-256 JSONL hash chain over the exact serialized event fields.

This detects accidental or uncoordinated modification. It does not authenticate
records against an attacker able to recompute the chain; preserve external logs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> bytes:
    payload = {key: value for key, value in record.items() if key != "integrity"}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_hash(previous: str, record: dict[str, Any]) -> str:
    return hashlib.sha256(bytes.fromhex(previous) + _canonical(record)).hexdigest()


class HashChain:
    def __init__(self) -> None:
        self.previous = GENESIS

    def seal(self, record: dict[str, Any]) -> tuple[str, str]:
        """Return serialized line and digest; commit after the write succeeds."""
        digest = compute_hash(self.previous, record)
        stamped = {**record, "integrity": {"algorithm": "sha256", "prev_hash": self.previous, "hash": digest}}
        return json.dumps(stamped, ensure_ascii=False, separators=(",", ":")), digest

    def verify(self, record: dict[str, Any]) -> bool:
        stamp = record.get("integrity")
        if not isinstance(stamp, dict) or stamp.get("algorithm") != "sha256" or stamp.get("prev_hash") != self.previous:
            return False
        digest = stamp.get("hash")
        if not isinstance(digest, str) or len(digest) != 64:
            return False
        if compute_hash(self.previous, record) != digest:
            return False
        self.previous = digest
        return True
