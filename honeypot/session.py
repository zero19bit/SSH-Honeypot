"""Independent state associated with one authenticated SSH connection."""

from __future__ import annotations

import re
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from .intelligence.analyzer import Analysis, Analyzer

from .fake_data import DEFAULT_PACKAGES, DEFAULT_SERVICES
from .filesystem import VirtualFileSystem


@dataclass(slots=True)
class SessionState:
    client_ip: str
    client_port: int
    hostname: str = "server01"
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    username: str = ""
    client_version: str = "unknown"
    terminal_type: str = "xterm-256color"
    terminal_width: int = 80
    terminal_height: int = 24
    cwd: str = "/root"
    previous_cwd: str = "/root"
    history: list[str] = field(default_factory=list)
    filesystem: VirtualFileSystem = field(default_factory=VirtualFileSystem)
    services: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_SERVICES))
    packages: set[str] = field(default_factory=lambda: set(DEFAULT_PACKAGES))
    intelligence: Analyzer = field(default_factory=Analyzer)
    threat_score: int = 0
    behaviors: list[str] = field(default_factory=list)
    detections: list[dict[str, object]] = field(default_factory=list)
    first_command: str = ""
    last_command: str = ""
    command_history: deque[dict[str, object]] = field(default_factory=lambda: deque(maxlen=500))
    max_session_history: int = 500
    history_limit: int = 200
    max_commands: int = 500
    max_chain_commands: int = 32
    max_packages: int = 256
    started_monotonic: float = field(default_factory=time.monotonic)
    started_epoch: float = field(default_factory=time.time)
    command_count: int = 0

    def __post_init__(self) -> None:
        if self.command_history.maxlen != self.max_session_history:
            self.command_history = deque(self.command_history, maxlen=self.max_session_history)

    def record_analysis(self, command: str, analysis: Analysis) -> None:
        bounded = command[:4096]
        if not self.first_command:
            self.first_command = bounded
        self.last_command = bounded
        self.command_history.append({
            "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "command": bounded,
            "score": analysis.risk_score,
            "category": analysis.category,
        })
        for detection in analysis.detections:
            name = str(detection["rule"])
            if name not in self.behaviors and len(self.behaviors) < 64:
                self.behaviors.append(name)
                self.detections.append(dict(detection))
                self.threat_score = min(self.intelligence.max_score, self.threat_score + int(detection["score"]))

    def add_history(self, command: str) -> bool:
        if not command:
            return True
        if self.command_count >= self.max_commands:
            return False
        self.history.append(command)
        if len(self.history) > self.history_limit:
            del self.history[: len(self.history) - self.history_limit]
        self.command_count += 1
        return True

    def prompt(self) -> str:
        if self.cwd == "/root":
            display_path = "~"
        elif self.cwd.startswith("/root/"):
            display_path = "~" + self.cwd[len("/root") :]
        else:
            display_path = self.cwd
        user = self.display_username
        marker = "#" if user == "root" else "$"
        return f"{user}@{self.hostname}:{display_path}{marker} "

    @property
    def display_username(self) -> str:
        """Return a terminal-safe username while preserving the raw value in logs."""
        raw = self.username or "root"
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", raw)[:32]
        return safe or "user"

    @property
    def duration_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.started_monotonic)
