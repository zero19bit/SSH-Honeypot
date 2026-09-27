import base64
import hashlib
import io
import json
import socket
import threading
import time
from dataclasses import replace

import paramiko
import pytest

from honeypot.config import HoneypotConfig
from honeypot.filesystem import VirtualFSError, VirtualFSLimits, VirtualFileSystem
from honeypot.keygen import generate_host_key_b64
from honeypot.logger import JsonEventLogger
from honeypot.rate_limit import ConnectionGate
from honeypot.session import SessionState
from honeypot.shell import _bounded_output
from honeypot.ssh_server import SSHHoneypot, _load_host_key


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_rate_gate_limits_active_connections_and_refills() -> None:
    clock = Clock()
    gate = ConnectionGate(
        max_total=3,
        max_per_ip=2,
        global_rate_per_minute=60,
        global_burst=3,
        per_ip_rate_per_minute=60,
        per_ip_burst=2,
        bucket_ttl_seconds=60,
        clock=clock,
    )
    assert gate.try_acquire("192.0.2.1") == (True, "accepted")
    assert gate.try_acquire("192.0.2.1") == (True, "accepted")
    assert gate.try_acquire("192.0.2.1") == (False, "per_ip_connection_limit")
    gate.release("192.0.2.1")
    assert gate.try_acquire("192.0.2.1") == (False, "per_ip_rate_limit")
    clock.now += 1.0
    assert gate.try_acquire("192.0.2.1") == (True, "accepted")
    assert gate.snapshot()["active_connections"] == 2


def test_vfs_enforces_file_byte_and_node_limits() -> None:
    baseline = VirtualFileSystem()
    seed = baseline.stats()
    limits = VirtualFSLimits(
        max_nodes=seed["nodes"] + 1,
        max_total_bytes=seed["bytes"] + 2048,
        max_file_bytes=1024,
    )
    fs = VirtualFileSystem(limits=limits)
    fs.write_file("/root", "/tmp/one", "1234567890")
    with pytest.raises(VirtualFSError, match="File too large"):
        fs.write_file("/root", "/tmp/one", "x" * 1025)
    with pytest.raises(VirtualFSError, match="No space left"):
        fs.touch("/root", "/tmp/two")


def test_history_command_and_output_bounds() -> None:
    session = SessionState("127.0.0.1", 50000, history_limit=1, max_commands=2)
    assert session.add_history("one")
    assert session.add_history("two")
    assert session.history == ["two"]
    assert not session.add_history("three")
    bounded = _bounded_output("الف" * 100, 64)
    assert len(bounded.encode("utf-8")) <= 64
    assert "truncated" in bounded


def test_production_config_requires_nonprivileged_port_and_stable_key() -> None:
    with pytest.raises(ValueError, match="HOST_KEY"):
        HoneypotConfig(production=True).validate()
    with pytest.raises(ValueError, match="non-privileged"):
        HoneypotConfig(production=True, port=22, host_key_b64="present").validate()
    config = HoneypotConfig.from_env(
        {
            "HONEYPOT_PRODUCTION": "true",
            "HONEYPOT_PORT": "2222",
            "HONEYPOT_HOST_KEY_B64": "present",
        }
    )
    assert config.production
    assert config.credential_log_mode == "sha256"
    assert "present" not in repr(config)


def test_production_never_accepts_plain_credentials_and_development_keeps_the_option() -> None:
    config = HoneypotConfig.from_env({"HONEYPOT_PRODUCTION": "true", "HONEYPOT_HOST_KEY_B64": "present"})
    assert config.credential_log_mode == "sha256"
    with pytest.raises(ValueError, match="plain is not allowed in production"):
        replace(config, credential_log_mode="plain").validate()
    with pytest.raises(ValueError, match="plain is not allowed in production"):
        HoneypotConfig.from_env({"HONEYPOT_PRODUCTION": "true", "HONEYPOT_HOST_KEY_B64": "present", "HONEYPOT_CREDENTIAL_LOG_MODE": "plain"})
    replace(config, credential_log_mode="redact").validate()
    assert HoneypotConfig.from_env({"HONEYPOT_CREDENTIAL_LOG_MODE": "plain"}).credential_log_mode == "plain"


def test_sha256_authentication_does_not_log_password() -> None:
    config = HoneypotConfig.from_env({"HONEYPOT_PRODUCTION": "true", "HONEYPOT_HOST_KEY_B64": "present"})
    stream = io.StringIO()
    logger = JsonEventLogger(stream, credential_mode=config.credential_log_mode, asynchronous=False)
    logger.authentication(SessionState("192.0.2.10", 4444, username="root"), "secret-value")
    record = json.loads(stream.getvalue())
    assert record["password_sha256"] == hashlib.sha256(b"secret-value").hexdigest()
    assert record["password_length"] == len("secret-value")
    assert "password" not in record
    assert "secret-value" not in stream.getvalue()


def test_production_server_rejects_injected_plain_logger() -> None:
    config = HoneypotConfig(production=True, host_key_b64="present")
    logger = JsonEventLogger(io.StringIO(), credential_mode="plain", asynchronous=False)
    with pytest.raises(ValueError, match="plain credential logging is not allowed"):
        SSHHoneypot(config, logger)


def test_environment_limits_are_parsed_and_unsafe_hostname_is_rejected() -> None:
    config = HoneypotConfig.from_env(
        {
            "HONEYPOT_MAX_CHAIN_COMMANDS": "7",
            "HONEYPOT_VFS_MAX_QUERY_RESULTS": "64",
            "HONEYPOT_LOG_FIELD_LIMIT": "2048",
        }
    )
    assert config.max_chain_commands == 7
    assert config.vfs_max_query_results == 64
    assert config.log_field_limit == 2048
    with pytest.raises(ValueError, match="DNS-style"):
        replace(config, hostname="server01\nmalicious").validate()


def test_terminal_username_and_log_are_sanitized() -> None:
    session = SessionState("192.0.2.10", 4444, username="root\x1b[31m")
    assert session.display_username == "root__31m"
    assert "\x1b" not in session.prompt()
    stream = io.StringIO()
    logger = JsonEventLogger(stream, asynchronous=False)
    logger.authentication(session, "secret")
    record = json.loads(stream.getvalue())
    assert record["username"] == "root [31m"
    assert "\x1b" not in stream.getvalue()


def test_stable_host_key_round_trip() -> None:
    encoded = generate_host_key_b64(2048)
    decoded = base64.b64decode(encoded)
    assert decoded.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    key_one, stable_one = _load_host_key(HoneypotConfig(host_key_b64=encoded))
    key_two, stable_two = _load_host_key(HoneypotConfig(host_key_b64=encoded))
    assert stable_one and stable_two
    assert key_one.asbytes() == key_two.asbytes()


def test_credential_log_modes_do_not_leak_when_disabled() -> None:
    session = SessionState("192.0.2.10", 4444, username="root")
    for mode, forbidden in (("sha256", "secret-value"), ("redact", "secret-value")):
        stream = io.StringIO()
        logger = JsonEventLogger(stream, credential_mode=mode, asynchronous=False)
        logger.authentication(session, "secret-value")
        record = json.loads(stream.getvalue())
        assert forbidden not in json.dumps(record)
        assert record["event"] == "authentication"


def test_async_logger_flushes_complete_json_records() -> None:
    stream = io.StringIO()
    logger = JsonEventLogger(stream, queue_size=100, asynchronous=True)
    for index in range(50):
        logger.emit("load_test", index=index)
    assert logger.flush(2.0)
    logger.close(2.0)
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert len(records) == 50
    assert records[-1]["index"] == 49


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return int(port)


def _receive_until(channel: paramiko.Channel, marker: bytes, timeout: float = 3.0) -> bytes:
    received = bytearray()
    deadline = time.monotonic() + timeout
    while marker not in received and time.monotonic() < deadline:
        if channel.recv_ready():
            received.extend(channel.recv(4096))
        else:
            time.sleep(0.01)
    return bytes(received)


def test_real_paramiko_exec_request_with_production_config() -> None:
    stream = io.StringIO()
    config = replace(
        HoneypotConfig(),
        host="127.0.0.1",
        port=_free_port(),
        production=True,
        host_key_b64=generate_host_key_b64(2048),
        command_delay_min=0,
        command_delay_max=0,
    )
    logger = JsonEventLogger(stream, credential_mode=config.credential_log_mode, asynchronous=False)
    server = SSHHoneypot(config, logger)
    session = server._new_session(("127.0.0.1", 50000))
    assert session.filesystem.read_file("/", "/etc/hostname") == config.hostname + "\n"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.15)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "127.0.0.1",
        port=config.port,
        username="root",
        password="integration-test",
        look_for_keys=False,
        allow_agent=False,
        timeout=5,
    )
    _, stdout, _ = client.exec_command("cd /var/log && pwd && tail -n 1 auth.log")
    output = stdout.read().decode("utf-8")
    status = stdout.channel.recv_exit_status()
    client.close()

    interactive_client = paramiko.SSHClient()
    interactive_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    interactive_client.connect(
        "127.0.0.1",
        port=config.port,
        username="root",
        password="interactive-test",
        look_for_keys=False,
        allow_agent=False,
        timeout=5,
    )
    channel = interactive_client.invoke_shell(term="xterm-256color", width=80, height=24)
    welcome = _receive_until(channel, b"root@server01:~# ")
    channel.sendall(b"cd /etc\r")
    navigation = _receive_until(channel, b"root@server01:/etc# ")
    channel.sendall(b"cat hostname\r")
    hostname_output = _receive_until(channel, b"root@server01:/etc# ")
    channel.sendall(b"\x04")
    interactive_client.close()
    time.sleep(0.05)
    server.stop()
    thread.join(3)
    assert status == 0
    assert "/var/log" in output
    assert "pam_unix" in output
    assert b"Welcome to Ubuntu 22.04.5 LTS" in welcome
    assert b"root@server01:/etc# " in navigation
    assert b"server01" in hostname_output
    assert not thread.is_alive()
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    events = [record["event"] for record in records]
    assert {"listener_started", "authentication", "command", "disconnect", "listener_stopped"} <= set(events)
    authentication = next(
        record
        for record in records
        if record["event"] == "authentication" and record.get("password_sha256") == hashlib.sha256(b"integration-test").hexdigest()
    )
    assert "integration-test" not in stream.getvalue()
    assert "interactive-test" not in stream.getvalue()
    assert authentication["username"] == "root"
    assert authentication["ssh_client_version"].startswith("SSH-2.0-paramiko_")
