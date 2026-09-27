"""Per-session bounded cache of *static* command analysis, never raw commands."""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AnalysisCache:
    capacity: int = 64
    _items: OrderedDict[str, Any] = field(default_factory=OrderedDict, repr=False)
    hits: int = 0
    misses: int = 0

    @staticmethod
    def key(command: str) -> str:
        return hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest()

    def get(self, command: str) -> Any | None:
        key = self.key(command)
        if key in self._items:
            self._items.move_to_end(key)
            self.hits += 1
            return self._items[key]
        self.misses += 1
        return None

    def put(self, command: str, value: Any) -> None:
        if self.capacity < 1:
            return
        key = self.key(command)
        self._items[key] = value
        self._items.move_to_end(key)
        if len(self._items) > self.capacity:
            self._items.popitem(last=False)
