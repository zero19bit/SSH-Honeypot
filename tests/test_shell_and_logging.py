import io
import json

from honeypot.config import HoneypotConfig
from honeypot.logger import JsonEventLogger
from honeypot.session import SessionState
from honeypot.shell import FakeShell


class MemoryChannel:
    def __init__(self) -> None:
        self.output = bytearray()

    def sendall(self, data: bytes) -> None:
        self.output.extend(data)

    def recv(self, size: int) -> bytes:
        return b""

    def settimeout(self, timeout: float) -> None:
        pass

    def send_exit_status(self, status: int) -> None:
        pass

    def close(self) -> None:
        pass


def make_shell() -> tuple[SessionState, FakeShell, MemoryChannel, io.StringIO]:
    stream = io.StringIO()
    logger = JsonEventLogger(stream, asynchronous=False)
    session = SessionState("192.0.2.10", 49152, username="root")
    channel = MemoryChannel()
    config = HoneypotConfig(command_delay_min=0, command_delay_max=0)
    return session, FakeShell(channel, session, config, logger, True), channel, stream


def type_text(shell: FakeShell, value: str) -> None:
    for char in value:
        shell._feed_character(char)


def test_tab_completion_history_and_ctrl_w() -> None:
    session, shell, _, _ = make_shell()
    type_text(shell, "pw")
    shell._feed_character("\t")
    assert shell.line == "pwd "
    shell._feed_character("\r")
    assert session.history == ["pwd"]
    shell._feed_character("\x1b")
    shell._feed_character("[")
    shell._feed_character("A")
    assert shell.line == "pwd"
    type_text(shell, " extra")
    shell._feed_character("\x17")
    assert shell.line == "pwd "


def test_ctrl_c_ctrl_l_and_dynamic_prompt() -> None:
    session, shell, channel, _ = make_shell()
    type_text(shell, "cd /etc")
    shell._feed_character("\r")
    assert session.cwd == "/etc"
    type_text(shell, "unfinished")
    shell._feed_character("\x03")
    assert shell.line == ""
    shell._feed_character("\x0c")
    text = channel.output.decode("utf-8")
    assert "root@server01:/etc#" in text
    assert "\x1b[2J\x1b[H" in text


def test_json_logger_escapes_attacker_controlled_text() -> None:
    session, shell, _, stream = make_shell()
    type_text(shell, "echo bad\\nvalue")
    shell._feed_character("\r")
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert records[-1]["event"] == "command"
    assert records[-1]["session_id"] == session.session_id
    assert records[-1]["ip"] == "192.0.2.10"
    assert records[-1]["exit_status"] == 127
