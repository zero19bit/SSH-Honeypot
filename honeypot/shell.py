"""PTY-aware fake terminal with line editing and session history."""

from __future__ import annotations

import codecs
import random
import socket
import time
from datetime import datetime, timedelta
from typing import Protocol

from .commands import CommandSimulator
from .config import HoneypotConfig
from .intelligence.analyzer import Analysis, sanitize_command
from .logger import JsonEventLogger
from .session import SessionState


class ChannelLike(Protocol):
    def sendall(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def settimeout(self, timeout: float) -> None: ...

    def send_exit_status(self, status: int) -> None: ...

    def close(self) -> None: ...


def _last_login(client_ip: str) -> str:
    previous = datetime.now().astimezone() - timedelta(seconds=random.randint(3600, 7 * 86400))
    return f"Last login: {previous.strftime('%a %b %e %H:%M:%S %Y')} from {client_ip}"


def _bounded_output(text: str, maximum_bytes: int) -> str:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= maximum_bytes:
        return text
    marker = b"\n... output truncated by terminal ..."
    budget = max(0, maximum_bytes - len(marker))
    return encoded[:budget].decode("utf-8", errors="ignore") + marker.decode("ascii")


def _record_command(
    session: SessionState,
    command: str,
    cwd_before: str,
    exit_status: int,
    logger: JsonEventLogger,
    config: HoneypotConfig,
) -> None:
    safe_command = sanitize_command(command, config.max_line_length)
    session.intelligence.enabled = config.intelligence_enabled
    session.intelligence.ioc_enabled = config.ioc_enabled
    session.intelligence.max_score = config.max_score
    try:
        analysis = session.intelligence.analyze(safe_command)
    except Exception as exc:  # Analyzer errors must not terminate simulated SSH sessions.
        logger.emit("analyzer_error", session, component="rules", error=type(exc).__name__)
        analysis = Analysis()
    session.record_analysis(safe_command, analysis)
    logger.command(session, safe_command, cwd_before, exit_status, analysis.to_dict())
    if session.intelligence.claim_alert(analysis, config.alert_min_risk):
        logger.intelligence_alert(session, analysis)


class FakeShell:
    """A small readline-style terminal that never delegates to a real shell."""

    def __init__(
        self,
        channel: ChannelLike,
        session: SessionState,
        config: HoneypotConfig,
        logger: JsonEventLogger,
        pty_enabled: bool,
    ) -> None:
        self.channel = channel
        self.session = session
        self.config = config
        self.logger = logger
        self.pty_enabled = pty_enabled
        self.simulator = CommandSimulator(session)
        self.line = ""
        self.cursor = 0
        self.history_index = len(session.history)
        self.saved_line = ""
        self.escape_sequence = ""
        self.last_was_cr = False
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def _send_raw(self, text: str) -> None:
        if text:
            self.channel.sendall(text.encode("utf-8", errors="replace"))

    def _send_text(self, text: str) -> None:
        if not text:
            return
        if self.pty_enabled:
            normalized = text.replace("\r\n", "\n").replace("\r", "\n")
            text = normalized.replace("\n", "\r\n")
        self._send_raw(text)

    def _render_line(self) -> None:
        if not self.pty_enabled:
            return
        prompt = self.session.prompt()
        self._send_raw("\r\x1b[2K" + prompt + self.line)
        distance = len(self.line) - self.cursor
        if distance > 0:
            self._send_raw(f"\x1b[{distance}D")

    def _replace_line(self, value: str) -> None:
        self.line = value[: self.config.max_line_length]
        self.cursor = len(self.line)
        self._render_line()

    def _history_up(self) -> None:
        if not self.session.history:
            self._send_raw("\a")
            return
        if self.history_index == len(self.session.history):
            self.saved_line = self.line
        if self.history_index > 0:
            self.history_index -= 1
        self._replace_line(self.session.history[self.history_index])

    def _history_down(self) -> None:
        if self.history_index < len(self.session.history) - 1:
            self.history_index += 1
            self._replace_line(self.session.history[self.history_index])
        elif self.history_index == len(self.session.history) - 1:
            self.history_index = len(self.session.history)
            self._replace_line(self.saved_line)
        else:
            self._send_raw("\a")

    def _handle_escape(self, sequence: str) -> None:
        if sequence == "\x1b[A":
            self._history_up()
        elif sequence == "\x1b[B":
            self._history_down()
        elif sequence == "\x1b[C":
            if self.cursor < len(self.line):
                self.cursor += 1
                self._send_raw("\x1b[C")
        elif sequence == "\x1b[D":
            if self.cursor > 0:
                self.cursor -= 1
                self._send_raw("\x1b[D")
        elif sequence == "\x1b[H":
            self.cursor = 0
            self._render_line()
        elif sequence == "\x1b[F":
            self.cursor = len(self.line)
            self._render_line()
        elif sequence == "\x1b[3~" and self.cursor < len(self.line):
            self.line = self.line[: self.cursor] + self.line[self.cursor + 1 :]
            self._render_line()

    def _tab_complete(self) -> None:
        new_line, new_cursor, matches = self.simulator.complete(self.line, self.cursor)
        if not matches:
            self._send_raw("\a")
            return
        changed = new_line != self.line
        self.line, self.cursor = new_line, new_cursor
        if len(matches) > 1 and not changed:
            self._send_text("\n" + "  ".join(matches) + "\n")
        self._render_line()

    def _ctrl_w(self) -> None:
        if self.cursor == 0:
            return
        left = self.line[: self.cursor]
        trimmed = left.rstrip()
        word_start = len(trimmed)
        while word_start > 0 and not trimmed[word_start - 1].isspace():
            word_start -= 1
        self.line = left[:word_start] + self.line[self.cursor :]
        self.cursor = word_start
        self._render_line()

    def _backspace(self) -> None:
        if self.cursor == 0:
            return
        self.line = self.line[: self.cursor - 1] + self.line[self.cursor :]
        self.cursor -= 1
        self._render_line()

    def _insert(self, char: str) -> None:
        if len(self.line) >= self.config.max_line_length:
            self._send_raw("\a")
            return
        self.line = self.line[: self.cursor] + char + self.line[self.cursor :]
        self.cursor += len(char)
        if self.pty_enabled:
            if self.cursor == len(self.line):
                self._send_raw(char)
            else:
                self._render_line()

    def _execute_line(self) -> bool:
        raw = sanitize_command(self.line.strip(), self.config.max_line_length)
        self.line = ""
        self.cursor = 0
        self.saved_line = ""
        if self.pty_enabled:
            self._send_raw("\r\n")
        if not raw:
            if self.pty_enabled:
                self._send_raw(self.session.prompt())
            return False

        if not self.session.add_history(raw):
            self.logger.emit("session_limit", self.session, limit="max_commands")
            self._send_text("bash: maximum command count reached\nlogout\n")
            return True
        self.history_index = len(self.session.history)
        delay = random.uniform(self.config.command_delay_min, self.config.command_delay_max)
        if delay > 0:
            time.sleep(delay)
        cwd_before = self.session.cwd
        result = self.simulator.execute(raw)
        _record_command(self.session, raw, cwd_before, result.exit_status, self.logger, self.config)
        output = _bounded_output(result.output, self.config.max_command_output_bytes)
        if output:
            self._send_text(output)
            if not output.endswith("\n"):
                self._send_text("\n")
        if result.close_session:
            self._send_text("logout\n")
            return True
        if self.pty_enabled:
            self._send_raw(self.session.prompt())
        return False

    def _feed_character(self, char: str) -> bool:
        if self.escape_sequence:
            self.escape_sequence += char
            complete = (
                self.escape_sequence in {"\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D", "\x1b[H", "\x1b[F", "\x1b[3~"}
                or len(self.escape_sequence) >= 8
                or (len(self.escape_sequence) >= 3 and char.isalpha())
            )
            if complete:
                sequence, self.escape_sequence = self.escape_sequence, ""
                self._handle_escape(sequence)
            return False
        if char == "\x1b":
            self.escape_sequence = char
            return False

        if char == "\n" and self.last_was_cr:
            self.last_was_cr = False
            return False
        self.last_was_cr = char == "\r"
        if char in "\r\n":
            return self._execute_line()
        if char in {"\x7f", "\x08"}:
            self._backspace()
        elif char == "\x03":  # Ctrl+C
            self.line = ""
            self.cursor = 0
            self.history_index = len(self.session.history)
            self._send_text("^C\n")
            if self.pty_enabled:
                self._send_raw(self.session.prompt())
        elif char == "\x04":  # Ctrl+D
            if not self.line:
                self._send_text("logout\n")
                return True
            if self.cursor < len(self.line):
                self.line = self.line[: self.cursor] + self.line[self.cursor + 1 :]
                self._render_line()
        elif char == "\x0c":  # Ctrl+L
            self._send_raw("\x1b[2J\x1b[H")
            self._render_line()
        elif char == "\x17":  # Ctrl+W
            self._ctrl_w()
        elif char == "\t":
            self._tab_complete()
        elif char >= " ":
            self._insert(char)
        return False

    def run(self) -> str:
        if self.pty_enabled:
            self._send_text(
                f"Welcome to {self.config.welcome_release} "
                f"(GNU/Linux {self.config.kernel} x86_64)\n\n"
                " * Documentation:  https://help.ubuntu.com\n"
                " * Management:     https://landscape.canonical.com\n"
                " * Support:        https://ubuntu.com/advantage\n\n"
                f"{_last_login(self.session.client_ip)}\n"
            )
            self._send_raw(self.session.prompt())
        self.channel.settimeout(self.config.idle_timeout)
        deadline = time.monotonic() + self.config.max_session_seconds
        while time.monotonic() < deadline:
            try:
                data = self.channel.recv(self.config.receive_size)
            except socket.timeout:
                self._send_text("\nConnection timed out.\n")
                return "idle_timeout"
            if not data:
                return "client_closed"
            for char in self.decoder.decode(data):
                if self._feed_character(char):
                    return "logout"
        self._send_text("\nSession terminated: timeout.\n")
        return "session_timeout"


def run_exec_request(
    channel: ChannelLike,
    session: SessionState,
    raw_command: bytes,
    config: HoneypotConfig,
    logger: JsonEventLogger,
) -> str:
    command = sanitize_command(raw_command.decode("utf-8", errors="replace").strip(), config.max_line_length)
    channel.settimeout(config.channel_io_timeout)
    if not session.add_history(command):
        logger.emit("session_limit", session, limit="max_commands")
        channel.sendall(b"bash: maximum command count reached\n")
        channel.send_exit_status(126)
        channel.close()
        return "command_limit"
    delay = random.uniform(config.command_delay_min, config.command_delay_max)
    if delay > 0:
        time.sleep(delay)
    simulator = CommandSimulator(session)
    cwd_before = session.cwd
    result = simulator.execute(command)
    _record_command(session, command, cwd_before, result.exit_status, logger, config)
    output = _bounded_output(result.output, config.max_command_output_bytes)
    if output:
        channel.sendall((output + ("" if output.endswith("\n") else "\n")).encode("utf-8", errors="replace"))
    channel.send_exit_status(result.exit_status)
    channel.close()
    return "exec_complete"
