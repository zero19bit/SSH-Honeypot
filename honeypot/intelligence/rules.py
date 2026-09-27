"""Small, auditable rules for classifying attempted attacker actions.

Rules operate on parsed command arguments, not on arbitrary quoted text. Their
scores are heuristic priorities; a match does not prove an action succeeded.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Callable

from .patterns import DOWNLOAD_PIPE, OBFUSCATION, REVERSE_SHELL, match_patterns


@dataclass(frozen=True, slots=True)
class Invocation:
    argv: tuple[str, ...]
    connector: str = ";"  # Operator preceding this invocation.

    @property
    def program(self) -> str:
        return posixpath.basename(self.argv[0]).lower()

    @property
    def args(self) -> tuple[str, ...]:
        return self.argv[1:]


Matcher = Callable[[tuple[Invocation, ...]], bool]


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    patterns: tuple[str, ...]
    type: str
    score: int
    severity: str
    category: str
    mitre: str
    confidence: float
    description: str
    matcher: Matcher | None = None

    @property
    def rule_id(self) -> str:  # v3.0.0 compatibility
        return self.name

    def matches(self, commands: tuple[Invocation, ...]) -> bool:
        if self.matcher and not self.matcher(commands):
            return False
        return match_patterns(self.name, self.patterns, self.type, commands) if self.type == "regex" or not self.matcher else True


def _rule(name: str, category: str, score: int, description: str, matcher: Matcher, confidence: float = 0.85) -> Rule:
    return Rule(name, (name,), "string", score, "HIGH" if score >= 60 else "MEDIUM", category, "", confidence, description, matcher)


def _program(*names: str) -> Matcher:
    allowed = frozenset(names)
    return lambda commands: any(command.program in allowed for command in commands)


def _sensitive_file(commands: tuple[Invocation, ...]) -> bool:
    readers = {"cat", "head", "tail", "grep", "less", "more", "find"}
    pattern = re.compile(r"(?:^|/)(?:etc/shadow|\.ssh/id_(?:rsa|ed25519)|\.env)(?:$|[/?.])", re.I)
    return any(
        command.program in readers and any(pattern.search(arg) for arg in command.args)
        for command in commands
    )


def _passwd_file_access(commands: tuple[Invocation, ...]) -> bool:
    readers = {"cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "sed", "awk", "cut"}
    for command in commands:
        if command.program not in readers:
            continue
        if command.program not in {"grep", "egrep", "fgrep"}:
            if "/etc/passwd" in command.args:
                return True
            continue
        # For grep, a search pattern mentioning the path is not a file read.
        args = command.args
        positions: list[str] = []
        pattern_given = False
        end_options = False
        skip_next = False
        for index, arg in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if not end_options and arg == "--":
                end_options = True
            elif not end_options and arg in {"-e", "--regexp", "-f", "--file"}:
                if arg in {"-f", "--file"} and index + 1 < len(args) and args[index + 1] == "/etc/passwd":
                    return True
                pattern_given = True
                skip_next = True
            elif not end_options and arg.startswith(("-e", "-f", "--regexp=", "--file=")):
                if arg.startswith("--file=") and arg.partition("=")[2] == "/etc/passwd":
                    return True
                pattern_given = True
            elif end_options or not arg.startswith("-"):
                positions.append(arg)
        if not pattern_given and positions:
            positions.pop(0)
        if "/etc/passwd" in positions:
            return True
    return False


def _payload_download(commands: tuple[Invocation, ...]) -> bool:
    return any(
        command.program in {"curl", "wget"}
        and any(arg.lower().startswith(("http://", "https://", "ftp://")) for arg in command.args)
        for command in commands
    )


def _download_pipe_shell(commands: tuple[Invocation, ...]) -> bool:
    return any(
        previous.program in {"curl", "wget"}
        and current.connector == "|"
        and current.program in {"sh", "bash", "dash", "zsh"}
        for previous, current in zip(commands, commands[1:])
    )


def _local_payload_execution(commands: tuple[Invocation, ...]) -> bool:
    return any(
        command.argv[0].startswith(("./", "/tmp/", "/var/tmp/"))
        or (
            command.program in {"sh", "bash", "python", "python3", "perl"}
            and any(arg.startswith(("./", "/tmp/", "/var/tmp/")) for arg in command.args)
        )
        for command in commands
    )


def _ssh_persistence(commands: tuple[Invocation, ...]) -> bool:
    return any(
        any("authorized_keys" in arg for arg in command.args)
        and (
            command.program in {"tee", "cp", "install"}
            or (command.program in {"echo", "printf", "cat"} and any(">>" in arg for arg in command.args))
        )
        for command in commands
    )


def _cron_persistence(commands: tuple[Invocation, ...]) -> bool:
    return any(
        command.program == "crontab" and bool(command.args) and command.args != ("-l",)
        for command in commands
    )


def _privilege_escalation(commands: tuple[Invocation, ...]) -> bool:
    return any(
        command.program in {"sudo", "su", "setcap"}
        or (command.program == "chmod" and any("+s" in arg or arg in {"4755", "4777"} for arg in command.args))
        for command in commands
    )


def _defense_evasion(commands: tuple[Invocation, ...]) -> bool:
    return any(
        (command.program == "history" and "-c" in command.args)
        or (command.program == "unset" and "HISTFILE" in command.args)
        or (command.program == "export" and any(arg.startswith("HISTFILE=/dev/null") for arg in command.args))
        for command in commands
    )


def _destructive_action(commands: tuple[Invocation, ...]) -> bool:
    return any(
        command.program.startswith("mkfs.")
        or (command.program == "dd" and any(arg.startswith("of=/dev/") for arg in command.args))
        or (
            command.program == "rm"
            and "r" in "".join(arg.lower() for arg in command.args if arg.startswith("-") and not arg.startswith("--"))
            and "f" in "".join(arg.lower() for arg in command.args if arg.startswith("-") and not arg.startswith("--"))
            and any(arg in {"/", "/*", "/etc", "/root"} for arg in command.args)
        )
        for command in commands
    )


def _crypto_mining(commands: tuple[Invocation, ...]) -> bool:
    return any(
        command.program in {"xmrig", "minerd", "cpuminer"}
        or any("stratum+tcp://" in arg.lower() for arg in command.args)
        for command in commands
    )


def _data_exfiltration(commands: tuple[Invocation, ...]) -> bool:
    return any(
        (
            command.program in {"scp", "rsync"}
            and any(re.search(r"[^/:\s]+@[^/:\s]+:", arg) for arg in command.args)
        )
        or (
            command.program == "curl"
            and (
                (
                    any(arg in {"-d", "--data", "--data-binary", "--upload-file", "-T"} for arg in command.args)
                    and any(arg.startswith("@") or arg.startswith("/") for arg in command.args)
                )
                or any(arg.startswith(("--data=@", "--data-binary=@", "--upload-file=")) for arg in command.args)
            )
        )
        for command in commands
    )


RULES: tuple[Rule, ...] = (
    _rule("system_discovery", "reconnaissance", 15, "Inspected system or processes", _program("id", "whoami", "uname", "hostname", "ls", "ps", "find"), 0.8),
    _rule("network_discovery", "reconnaissance", 20, "Inspected network state", _program("ip", "ifconfig", "ss", "netstat", "ping")),
    _rule("sensitive_file_access", "credential_access", 65, "Read a sensitive file", _sensitive_file),
    Rule("passwd_file_access", ("/etc/passwd",), "string", 20, "LOW", "discovery", "", 0.85, "Accessed local account database", _passwd_file_access),
    _rule("payload_download", "delivery", 35, "Requested a remote payload", _payload_download),
    Rule("download_pipe_shell", DOWNLOAD_PIPE, "regex", 90, "CRITICAL", "execution", "", 0.95, "Piped a downloader into a shell", _download_pipe_shell),
    _rule("local_payload_execution", "execution", 60, "Attempted to run a local payload", _local_payload_execution),
    _rule("ssh_key_persistence", "persistence", 75, "Attempted to write SSH authorized keys", _ssh_persistence),
    _rule("cron_persistence", "persistence", 65, "Attempted to change a crontab", _cron_persistence),
    _rule("privilege_escalation", "privilege_escalation", 60, "Requested elevated privileges", _privilege_escalation),
    _rule("defense_evasion", "defense_evasion", 60, "Attempted to clear command history", _defense_evasion),
    _rule("destructive_action", "impact", 85, "Attempted a destructive operation", _destructive_action),
    _rule("crypto_mining", "resource_abuse", 80, "Used a cryptomining tool or pool", _crypto_mining),
    _rule("data_exfiltration", "exfiltration", 75, "Attempted to send local data away", _data_exfiltration),
    Rule("reverse_shell", REVERSE_SHELL, "regex", 80, "HIGH", "execution", "", 0.9, "Attempted a reverse shell"),
    Rule("obfuscation", OBFUSCATION, "regex", 55, "MEDIUM", "defense_evasion", "", 0.75, "Attempted encoded or evaluated code"),
    Rule("download_chmod_chain", (r"(?:curl|wget).*chmod",), "regex", 75, "HIGH", "execution", "", 0.85, "Downloaded then changed payload permissions"),
)
