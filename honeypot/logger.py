"""Bounded, non-blocking JSON Lines event logging.

Session threads only serialize and enqueue records. A dedicated daemon writer
owns stdout so a slow log collector cannot block SSH sessions indefinitely.
The application itself never opens a host log file.
"""

from __future__ import annotations

import hashlib
import json
import queue
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, TextIO

from .intelligence.analyzer import Analysis
from .intelligence.indicators import ioc_list
from .intelligence.threat_score import threat_level
from .security.integrity import HashChain
from .session import SessionState


def _bounded(value: Any, limit: int) -> Any:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        value = "".join(char if char >= " " and char != "\x7f" else " " for char in value)
        if len(value) > limit:
            return value[:limit] + "...<truncated>"
    return value


@dataclass(slots=True)
class _FlushRequest:
    completed: threading.Event


_STOP = object()


class JsonEventLogger:
    """Emit JSONL synchronously for tests or asynchronously in production."""

    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        queue_size: int = 10000,
        field_limit: int = 4096,
        credential_mode: str = "sha256",
        asynchronous: bool = True,
        log_hashing: bool = True,
    ) -> None:
        if queue_size < 1:
            raise ValueError("queue_size must be positive")
        if credential_mode not in {"plain", "sha256", "redact"}:
            raise ValueError("credential_mode must be plain, sha256, or redact")
        self._stream = stream or sys.stdout
        self._field_limit = field_limit
        self._credential_mode = credential_mode
        self._asynchronous = asynchronous
        self._chain = HashChain() if log_hashing else None
        self._write_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self._dropped = 0
        self._write_errors = 0
        self._closed = False
        self._queue: queue.Queue[str | _FlushRequest | object] | None = None
        self._worker: threading.Thread | None = None
        if asynchronous:
            self._queue = queue.Queue(maxsize=queue_size)
            self._worker = threading.Thread(
                target=self._writer_loop,
                name="json-log-writer",
                daemon=True,
            )
            self._worker.start()

    @property
    def dropped_records(self) -> int:
        with self._counter_lock:
            return self._dropped

    @property
    def write_errors(self) -> int:
        with self._counter_lock:
            return self._write_errors

    def _write(self, line: str) -> None:
        try:
            with self._write_lock:
                digest = None
                if self._chain is not None:
                    line, digest = self._chain.seal(json.loads(line))
                self._stream.write(line + "\n")
                self._stream.flush()
                if digest is not None:
                    self._chain.previous = digest
        except Exception:
            with self._counter_lock:
                self._write_errors += 1

    def _writer_loop(self) -> None:
        assert self._queue is not None
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                if isinstance(item, _FlushRequest):
                    try:
                        self._stream.flush()
                    except Exception:
                        with self._counter_lock:
                            self._write_errors += 1
                    finally:
                        item.completed.set()
                else:
                    self._write(item)
            finally:
                self._queue.task_done()

    def _enqueue(self, line: str) -> None:
        if self._closed:
            return
        if not self._asynchronous:
            self._write(line)
            return
        assert self._queue is not None
        try:
            self._queue.put_nowait(line)
        except queue.Full:
            with self._counter_lock:
                self._dropped += 1

    def emit(self, event: str, session: SessionState | None = None, **fields: Any) -> None:
        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            "session_id": None,
            "attacker_ip": None,
            "threat": {"score": 0, "severity": "NONE"},
            "detections": [],
            "ioc": [],
        }
        if session is not None:
            record.update(
                {
                    "session_id": session.session_id,
                    "ip": session.client_ip,
                    "attacker_ip": session.client_ip,
                    "source_port": session.client_port,
                    "username": _bounded(session.username, 256),
                    "ssh_client_version": _bounded(session.client_version, 512),
                }
            )
        record.update({key: _bounded(value, self._field_limit) for key, value in fields.items()})
        if session is None and "ip" in fields:
            record["attacker_ip"] = _bounded(fields["ip"], self._field_limit)
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        self._enqueue(line)

    def authentication(self, session: SessionState, password: str) -> None:
        if self._credential_mode == "plain":
            credential_fields: dict[str, Any] = {"password": _bounded(password, 1024)}
        elif self._credential_mode == "sha256":
            credential_fields = {
                "password_sha256": hashlib.sha256(password.encode("utf-8", errors="replace")).hexdigest(),
                "password_length": len(password),
            }
        else:
            credential_fields = {"password": "[REDACTED]", "password_length": len(password)}
        self.emit("authentication", session, method="password", result="accepted", **credential_fields)

    def command(
        self,
        session: SessionState,
        command: str,
        cwd_before: str,
        exit_status: int,
        analysis: Mapping[str, object] | None = None,
    ) -> None:
        fields: dict[str, Any] = {
            "command": command,
            "cwd_before": cwd_before,
            "cwd_after": session.cwd,
            "exit_status": exit_status,
        }
        if analysis is not None:
            fields["analysis"] = dict(analysis)
            fields["threat"] = {"score": analysis.get("risk_score", 0), "severity": analysis.get("threat", {}).get("level", "NONE")}
            fields["detections"] = analysis.get("detections", [])
            fields["ioc"] = ioc_list(analysis.get("indicators", {}))
        self.emit("command", session, **fields)

    def intelligence_alert(self, session: SessionState, analysis: Analysis) -> None:
        """Emit a bounded, deduplicated alert without duplicating the command."""
        self.emit(
            "intelligence_alert",
            session,
            primary_rule=analysis.primary_rule,
            category=analysis.category,
            risk_score=analysis.risk_score,
            risk_level=analysis.risk_level,
            matched_rules=list(analysis.matched_rules),
            stages=list(analysis.stages),
            indicators={key: list(values) for key, values in analysis.indicators.items()},
            threat={"score": analysis.risk_score, "severity": analysis.threat["level"]},
            detections=[dict(item) for item in analysis.detections],
            ioc=ioc_list(analysis.indicators),
        )

    def disconnect(self, session: SessionState, reason: str) -> None:
        self.emit(
            "disconnect",
            session,
            reason=reason,
            command_count=session.command_count,
            duration_seconds=round(session.duration_seconds, 3),
            vfs=session.filesystem.stats(),
            intelligence=session.intelligence.summary(),
            threat={"score": session.threat_score, "severity": threat_level(session.threat_score)},
            behaviors=list(session.behaviors),
        )

    def flush(self, timeout: float = 2.0) -> bool:
        if not self._asynchronous:
            try:
                self._stream.flush()
                return True
            except Exception:
                return False
        if self._closed or self._queue is None:
            return False
        request = _FlushRequest(threading.Event())
        try:
            self._queue.put(request, timeout=min(timeout, 0.25))
        except queue.Full:
            return False
        return request.completed.wait(timeout)

    def close(self, timeout: float = 2.0) -> None:
        if self._closed:
            return
        self.flush(timeout)
        self._closed = True
        if self._asynchronous and self._queue is not None and self._worker is not None:
            try:
                self._queue.put(_STOP, timeout=min(timeout, 0.25))
            except queue.Full:
                return
            self._worker.join(timeout)
