"""Per-session, in-memory virtual POSIX filesystem.

This module never opens, reads, writes, stats, or removes a host file.  All
paths are normalized as POSIX strings and resolved only against Python
dictionaries owned by the current SSH session.
"""

from __future__ import annotations

import fnmatch
import posixpath
import time
from dataclasses import dataclass
from typing import Iterable

from .fake_data import SEED_DIRECTORIES, SEED_FILES


class VirtualFSError(Exception):
    """An error whose message is safe to show as a fake shell error."""


@dataclass(frozen=True, slots=True)
class VirtualStat:
    path: str
    name: str
    is_dir: bool
    size: int
    modified: float


@dataclass(frozen=True, slots=True)
class VirtualFSLimits:
    max_nodes: int = 2048
    max_total_bytes: int = 2 * 1024 * 1024
    max_file_bytes: int = 128 * 1024
    max_path_length: int = 512
    max_name_length: int = 255
    max_query_results: int = 512


class VirtualFileSystem:
    """A mutable copy-on-session virtual filesystem."""

    def __init__(
        self,
        directories: Iterable[str] | None = None,
        files: dict[str, str] | None = None,
        limits: VirtualFSLimits | None = None,
    ) -> None:
        self.limits = limits or VirtualFSLimits()
        now = time.time() - 86400
        self._directories = set(directories or SEED_DIRECTORIES)
        self._files = dict(files or SEED_FILES)
        self._modified = {
            path: now - (index * 137)
            for index, path in enumerate(sorted(self._directories | self._files.keys()))
        }
        self._directories.add("/")
        self._ensure_consistent()
        self._total_bytes = sum(len(content.encode("utf-8")) for content in self._files.values())
        if len(self._directories) + len(self._files) > self.limits.max_nodes:
            raise ValueError("seed filesystem exceeds max_nodes")
        if self._total_bytes > self.limits.max_total_bytes:
            raise ValueError("seed filesystem exceeds max_total_bytes")
        if any(len(content.encode("utf-8")) > self.limits.max_file_bytes for content in self._files.values()):
            raise ValueError("seed filesystem contains an oversized file")

    def _ensure_consistent(self) -> None:
        """Ensure every seeded node has all of its virtual parents."""
        for path in list(self._directories) + list(self._files):
            current = posixpath.dirname(path)
            while current and current != "/":
                self._directories.add(current)
                current = posixpath.dirname(current)
            self._directories.add("/")

    def _validate_path(self, path: str) -> None:
        if "\x00" in path:
            raise VirtualFSError("invalid path")
        if len(path) > self.limits.max_path_length:
            raise VirtualFSError("File name too long")
        name = posixpath.basename(path)
        if len(name) > self.limits.max_name_length:
            raise VirtualFSError("File name too long")

    def _assert_node_capacity(self, additional: int = 1) -> None:
        if len(self._directories) + len(self._files) + additional > self.limits.max_nodes:
            raise VirtualFSError("No space left on device")

    def stats(self) -> dict[str, int]:
        return {
            "nodes": len(self._directories) + len(self._files),
            "directories": len(self._directories),
            "files": len(self._files),
            "bytes": self._total_bytes,
        }

    @staticmethod
    def normalize(cwd: str, path: str | None) -> str:
        raw = path if path not in (None, "") else cwd
        if raw == "~":
            raw = "/root"
        elif raw.startswith("~/"):
            raw = "/root/" + raw[2:]
        elif not raw.startswith("/"):
            raw = posixpath.join(cwd, raw)
        normalized = posixpath.normpath(raw)
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return normalized

    def exists(self, path: str) -> bool:
        return path in self._directories or path in self._files

    def is_dir(self, path: str) -> bool:
        return path in self._directories

    def is_file(self, path: str) -> bool:
        return path in self._files

    def stat(self, path: str) -> VirtualStat:
        self._validate_path(path)
        if not self.exists(path):
            raise VirtualFSError(f"No such file or directory: {path}")
        return VirtualStat(
            path=path,
            name=posixpath.basename(path) or "/",
            is_dir=self.is_dir(path),
            size=4096 if self.is_dir(path) else len(self._files[path].encode("utf-8")),
            modified=self._modified.get(path, time.time() - 86400),
        )

    def list_dir(self, path: str, include_hidden: bool = False) -> list[VirtualStat]:
        self._validate_path(path)
        if self.is_file(path):
            return [self.stat(path)]
        if not self.is_dir(path):
            raise VirtualFSError(f"No such file or directory: {path}")

        prefix = "/" if path == "/" else path + "/"
        children: set[str] = set()
        for candidate in self._directories | self._files.keys():
            if candidate == path or not candidate.startswith(prefix):
                continue
            remainder = candidate[len(prefix) :]
            if remainder and "/" not in remainder:
                if include_hidden or not remainder.startswith("."):
                    children.add(candidate)
        ordered = sorted(children, key=lambda p: posixpath.basename(p).lower())[: self.limits.max_query_results]
        return [self.stat(item) for item in ordered]

    def expand_pattern(self, cwd: str, pattern: str) -> list[str]:
        """Expand a single-level glob exclusively inside the virtual tree."""
        normalized = self.normalize(cwd, pattern)
        self._validate_path(normalized)
        if not any(char in normalized for char in "*?["):
            return [normalized]
        parent = posixpath.dirname(normalized)
        name_pattern = posixpath.basename(normalized)
        if not self.is_dir(parent):
            return []
        return [
            item.path
            for item in self.list_dir(parent, include_hidden=name_pattern.startswith("."))
            if fnmatch.fnmatch(item.name, name_pattern)
        ][: self.limits.max_query_results]

    def read_file(self, cwd: str, path: str) -> str:
        normalized = self.normalize(cwd, path)
        self._validate_path(normalized)
        if self.is_dir(normalized):
            raise VirtualFSError(f"{path}: Is a directory")
        if not self.is_file(normalized):
            raise VirtualFSError(f"{path}: No such file or directory")
        return self._files[normalized]

    def write_file(self, cwd: str, path: str, content: str, append: bool = False) -> str:
        normalized = self.normalize(cwd, path)
        self._validate_path(normalized)
        parent = posixpath.dirname(normalized)
        if not self.is_dir(parent):
            raise VirtualFSError(f"{path}: No such file or directory")
        if self.is_dir(normalized):
            raise VirtualFSError(f"{path}: Is a directory")
        old_content = self._files.get(normalized, "")
        new_content = old_content + content if append and normalized in self._files else content
        new_size = len(new_content.encode("utf-8"))
        old_size = len(old_content.encode("utf-8")) if normalized in self._files else 0
        if new_size > self.limits.max_file_bytes:
            raise VirtualFSError(f"{path}: File too large")
        if self._total_bytes - old_size + new_size > self.limits.max_total_bytes:
            raise VirtualFSError(f"{path}: No space left on device")
        if normalized not in self._files:
            self._assert_node_capacity()
        self._files[normalized] = new_content
        self._total_bytes = self._total_bytes - old_size + new_size
        self._modified[normalized] = time.time()
        return normalized

    def touch(self, cwd: str, path: str) -> str:
        normalized = self.normalize(cwd, path)
        self._validate_path(normalized)
        if self.is_dir(normalized):
            self._modified[normalized] = time.time()
            return normalized
        if normalized not in self._files:
            self.write_file(cwd, path, "")
        else:
            self._modified[normalized] = time.time()
        return normalized

    def mkdir(self, cwd: str, path: str, parents: bool = False) -> str:
        normalized = self.normalize(cwd, path)
        self._validate_path(normalized)
        if self.is_file(normalized):
            raise VirtualFSError(f"cannot create directory '{path}': File exists")
        if self.is_dir(normalized):
            if parents:
                return normalized
            raise VirtualFSError(f"cannot create directory '{path}': File exists")

        parent = posixpath.dirname(normalized)
        if not parents and not self.is_dir(parent):
            raise VirtualFSError(f"cannot create directory '{path}': No such file or directory")

        to_create: list[str] = []
        current = normalized
        while current not in self._directories:
            to_create.append(current)
            current = posixpath.dirname(current)
            if not current:
                current = "/"
        if not parents and len(to_create) > 1:
            raise VirtualFSError(f"cannot create directory '{path}': No such file or directory")
        for item in to_create:
            self._validate_path(item)
        self._assert_node_capacity(len(to_create))
        for item in reversed(to_create):
            self._directories.add(item)
            self._modified[item] = time.time()
        return normalized

    def remove(
        self,
        cwd: str,
        path: str,
        recursive: bool = False,
        force: bool = False,
    ) -> None:
        normalized = self.normalize(cwd, path)
        self._validate_path(normalized)
        if normalized == "/":
            raise VirtualFSError("refusing to remove '/': use --no-preserve-root")
        if not self.exists(normalized):
            if force:
                return
            raise VirtualFSError(f"cannot remove '{path}': No such file or directory")
        if self.is_file(normalized):
            self._total_bytes -= len(self._files[normalized].encode("utf-8"))
            del self._files[normalized]
            self._modified.pop(normalized, None)
            return
        descendants = [
            item
            for item in self._directories | self._files.keys()
            if item.startswith(normalized + "/")
        ]
        if descendants and not recursive:
            raise VirtualFSError(f"cannot remove '{path}': Is a directory")
        for item in descendants:
            removed = self._files.pop(item, None)
            if removed is not None:
                self._total_bytes -= len(removed.encode("utf-8"))
            self._directories.discard(item)
            self._modified.pop(item, None)
        self._directories.remove(normalized)
        self._modified.pop(normalized, None)

    def find(
        self,
        cwd: str,
        start: str,
        name_pattern: str | None = None,
        node_type: str | None = None,
        limit: int = 500,
    ) -> list[str]:
        root = self.normalize(cwd, start)
        self._validate_path(root)
        if not self.exists(root):
            raise VirtualFSError(f"'{start}': No such file or directory")
        candidates = [root]
        if self.is_dir(root):
            candidates.extend(
                item
                for item in self._directories | self._files.keys()
                if item.startswith(root.rstrip("/") + "/")
            )
        result: list[str] = []
        effective_limit = min(max(1, limit), self.limits.max_query_results)
        for item in sorted(set(candidates)):
            if node_type == "f" and not self.is_file(item):
                continue
            if node_type == "d" and not self.is_dir(item):
                continue
            if name_pattern and not fnmatch.fnmatch(posixpath.basename(item), name_pattern):
                continue
            result.append(item)
            if len(result) >= effective_limit:
                break
        return result

    def disk_usage(self, path: str) -> int:
        self._validate_path(path)
        if self.is_file(path):
            return len(self._files[path].encode("utf-8"))
        if not self.is_dir(path):
            raise VirtualFSError(f"{path}: No such file or directory")
        prefix = path.rstrip("/") + "/"
        return sum(
            len(content.encode("utf-8"))
            for name, content in self._files.items()
            if name.startswith(prefix)
        )

    def complete(self, cwd: str, token: str, directories_only: bool = False) -> list[str]:
        """Return shell-style path candidates without consulting the host."""
        expanded = token
        base_token = token
        if token.startswith("~/"):
            expanded = "/root/" + token[2:]
        if "/" in expanded:
            typed_parent, partial = expanded.rsplit("/", 1)
            if typed_parent == "":
                typed_parent = "/"
            parent = self.normalize(cwd, typed_parent)
            display_prefix = base_token[: len(base_token) - len(partial)]
        else:
            parent = cwd
            partial = expanded
            display_prefix = ""
        if not self.is_dir(parent):
            return []
        self._validate_path(parent)
        matches: list[str] = []
        for entry in self.list_dir(parent, include_hidden=partial.startswith(".")):
            if not entry.name.startswith(partial):
                continue
            if directories_only and not entry.is_dir:
                continue
            value = display_prefix + entry.name
            if entry.is_dir:
                value += "/"
            matches.append(value)
        return sorted(matches)[: self.limits.max_query_results]
