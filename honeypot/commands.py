"""Safe command parser and Ubuntu-like response simulator.

The module contains no process execution, host filesystem access, DNS lookup,
or outbound network client.  Every side effect targets only SessionState and
its VirtualFileSystem.
"""

from __future__ import annotations

import ast
import hashlib
import posixpath
import random
import re
import shlex
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from .fake_data import (
    FAKE_CONNECTIONS,
    FAKE_DOCKER_PS,
    FAKE_INTERFACES,
    FAKE_PROCESSES,
)
from .filesystem import VirtualFSError, VirtualStat
from .session import SessionState


@dataclass(frozen=True, slots=True)
class CommandResult:
    output: str = ""
    exit_status: int = 0
    close_session: bool = False


Handler = Callable[[list[str]], CommandResult]


class CommandSimulator:
    """Interpret a deliberately small shell language without executing it."""

    COMMANDS = (
        "apt",
        "apt-get",
        "cat",
        "cd",
        "clear",
        "curl",
        "date",
        "df",
        "docker",
        "du",
        "exit",
        "find",
        "free",
        "git",
        "head",
        "history",
        "hostname",
        "id",
        "ifconfig",
        "ip",
        "ll",
        "logout",
        "ls",
        "mkdir",
        "nano",
        "netstat",
        "ping",
        "ps",
        "pwd",
        "python3",
        "rm",
        "service",
        "ss",
        "systemctl",
        "tail",
        "top",
        "touch",
        "uname",
        "uptime",
        "vim",
        "wget",
        "whoami",
    )

    def __init__(self, session: SessionState) -> None:
        self.session = session
        self.fs = session.filesystem
        self._handlers: dict[str, Handler] = {
            "whoami": self._whoami,
            "id": self._id,
            "hostname": self._hostname,
            "uname": self._uname,
            "uptime": self._uptime,
            "date": self._date,
            "history": self._history,
            "ls": self._ls,
            "ll": self._ll,
            "cd": self._cd,
            "pwd": self._pwd,
            "cat": self._cat,
            "head": self._head,
            "tail": self._tail,
            "find": self._find,
            "nano": self._editor,
            "vim": self._editor,
            "touch": self._touch,
            "mkdir": self._mkdir,
            "rm": self._rm,
            "ip": self._ip,
            "ifconfig": self._ifconfig,
            "netstat": self._netstat,
            "ss": self._ss,
            "ping": self._ping,
            "ps": self._ps,
            "top": self._top,
            "free": self._free,
            "df": self._df,
            "du": self._du,
            "systemctl": self._systemctl,
            "service": self._service,
            "apt": self._apt,
            "apt-get": self._apt,
            "wget": self._wget,
            "curl": self._curl,
            "python3": self._python3,
            "git": self._git,
            "docker": self._docker,
            "clear": self._clear,
        }

    def execute(self, raw_command: str) -> CommandResult:
        """Parse one line, including safe ``;``, ``&&`` and ``||`` chains."""
        if not raw_command.strip():
            return CommandResult()
        try:
            segments = self._split_chain(raw_command)
        except ValueError as exc:
            return CommandResult(f"bash: {exc}", 2)
        if len(segments) > self.session.max_chain_commands:
            return CommandResult("bash: too many commands in one request", 2)

        collected: list[str] = []
        previous_status = 0
        previous_operator = ";"
        for operator, argv in segments:
            should_run = (
                previous_operator == ";"
                or (previous_operator == "&&" and previous_status == 0)
                or (previous_operator == "||" and previous_status != 0)
            )
            previous_operator = operator
            if not should_run:
                continue
            result = self._execute_argv(argv)
            previous_status = result.exit_status
            if result.output:
                collected.append(result.output)
            if result.close_session:
                return CommandResult("\n".join(collected), previous_status, True)
        return CommandResult("\n".join(collected), previous_status)

    @staticmethod
    def _split_chain(raw_command: str) -> list[tuple[str, list[str]]]:
        lexer = shlex.shlex(raw_command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
        if not tokens:
            return [(";", [])]
        result: list[tuple[str, list[str]]] = []
        current: list[str] = []
        pending_operator = ";"
        for token in tokens:
            if token in {";", "&&", "||"}:
                if not current:
                    raise ValueError(f"syntax error near unexpected token `{token}'")
                result.append((token, current))
                current = []
                pending_operator = token
            elif token == "|":
                # Pipelines are accepted syntactically but remain simulated.
                current.append(token)
            else:
                current.append(token)
        if not current:
            if pending_operator in {"&&", "||"}:
                raise ValueError("syntax error: unexpected end of file")
        else:
            result.append((";", current))
        return result

    def _execute_argv(self, argv: list[str]) -> CommandResult:
        if not argv:
            return CommandResult()
        if "|" in argv:
            return self._pipeline(argv)
        command = posixpath.basename(argv[0])
        if command in {"exit", "logout"}:
            return CommandResult(close_session=True)
        handler = self._handlers.get(command)
        if handler is None:
            return CommandResult(f"bash: {command}: command not found", 127)
        try:
            return handler([command, *argv[1:]])
        except VirtualFSError as exc:
            return CommandResult(f"{command}: {exc}", 1)
        except (ValueError, IndexError) as exc:
            return CommandResult(f"{command}: {exc}", 1)

    def _pipeline(self, argv: list[str]) -> CommandResult:
        """Support a tiny fake pipeline subset, chiefly ``... | grep text``."""
        pieces: list[list[str]] = [[]]
        for token in argv:
            if token == "|":
                pieces.append([])
            else:
                pieces[-1].append(token)
        if any(not part for part in pieces):
            return CommandResult("bash: syntax error near unexpected token `|'", 2)
        first = self._execute_argv(pieces[0])
        if first.exit_status != 0:
            return first
        output = first.output
        for stage in pieces[1:]:
            name = posixpath.basename(stage[0])
            if name == "grep" and len(stage) >= 2:
                ignore_case = "-i" in stage[1:-1]
                pattern = stage[-1]
                if ignore_case:
                    output = "\n".join(line for line in output.splitlines() if pattern.lower() in line.lower())
                else:
                    output = "\n".join(line for line in output.splitlines() if pattern in line)
            elif name == "head":
                count = self._line_count(stage, 10)
                output = "\n".join(output.splitlines()[:count])
            elif name == "tail":
                count = self._line_count(stage, 10)
                output = "\n".join(output.splitlines()[-count:])
            else:
                return CommandResult(f"bash: {name}: command not found", 127)
        return CommandResult(output, 0 if output else 1)

    def complete(self, line: str, cursor: int) -> tuple[str, int, list[str]]:
        """Return an edited line and possible completions for the Tab key."""
        prefix = line[:cursor]
        token_start = max(prefix.rfind(" "), prefix.rfind("\t")) + 1
        token = prefix[token_start:]
        before_token = prefix[:token_start]
        if token_start == 0:
            matches = [item for item in self.COMMANDS if item.startswith(token)]
        else:
            first = line.lstrip().split(maxsplit=1)[0] if line.strip() else ""
            matches = self.fs.complete(self.session.cwd, token, directories_only=first == "cd")
        if not matches:
            return line, cursor, []
        replacement = self._common_prefix(matches)
        if len(matches) == 1 and not replacement.endswith("/"):
            replacement += " "
        new_prefix = before_token + replacement
        new_line = new_prefix + line[cursor:]
        return new_line, len(new_prefix), matches

    @staticmethod
    def _common_prefix(values: list[str]) -> str:
        if not values:
            return ""
        prefix = values[0]
        for value in values[1:]:
            while prefix and not value.startswith(prefix):
                prefix = prefix[:-1]
        return prefix

    # --------------------------------------------------------------- system
    def _whoami(self, argv: list[str]) -> CommandResult:
        return CommandResult(self.session.display_username)

    def _id(self, argv: list[str]) -> CommandResult:
        user = self.session.display_username
        if user == "root":
            return CommandResult("uid=0(root) gid=0(root) groups=0(root)")
        return CommandResult(f"uid=1000({user}) gid=1000({user}) groups=1000({user}),27(sudo)")

    def _hostname(self, argv: list[str]) -> CommandResult:
        if len(argv) > 1 and argv[1] in {"-I", "--all-ip-addresses"}:
            return CommandResult("10.20.0.15 172.17.0.1")
        if len(argv) > 1 and argv[1] in {"-f", "--fqdn"}:
            return CommandResult(f"{self.session.hostname}.internal")
        return CommandResult(self.session.hostname)

    def _uname(self, argv: list[str]) -> CommandResult:
        kernel = "5.15.0-122-generic"
        if "-a" in argv[1:] or "--all" in argv[1:]:
            return CommandResult(
                f"Linux {self.session.hostname} {kernel} #132-Ubuntu SMP "
                "Thu Aug 29 13:45:52 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
            )
        if "-r" in argv[1:] or "--kernel-release" in argv[1:]:
            return CommandResult(kernel)
        if "-m" in argv[1:] or "--machine" in argv[1:]:
            return CommandResult("x86_64")
        if "-n" in argv[1:] or "--nodename" in argv[1:]:
            return CommandResult(self.session.hostname)
        return CommandResult("Linux")

    def _uptime(self, argv: list[str]) -> CommandResult:
        if "-p" in argv[1:]:
            return CommandResult("up 18 days, 7 hours, 42 minutes")
        current = datetime.now().strftime("%H:%M:%S")
        return CommandResult(f" {current} up 18 days,  7:42,  1 user,  load average: 0.08, 0.04, 0.01")

    def _date(self, argv: list[str]) -> CommandResult:
        now = datetime.now().astimezone()
        if len(argv) > 1 and argv[1] == "+%s":
            return CommandResult(str(int(now.timestamp())))
        return CommandResult(now.strftime("%a %b %e %H:%M:%S %Z %Y"))

    def _history(self, argv: list[str]) -> CommandResult:
        if "-c" in argv[1:]:
            self.session.history.clear()
            return CommandResult()
        start = max(0, len(self.session.history) - 100)
        lines = [f"{index + 1:5d}  {command}" for index, command in enumerate(self.session.history[start:], start)]
        return CommandResult("\n".join(lines))

    def _clear(self, argv: list[str]) -> CommandResult:
        return CommandResult("\x1b[2J\x1b[H")

    # ----------------------------------------------------------- filesystem
    def _ls(self, argv: list[str], force_long: bool = False, force_all: bool = False) -> CommandResult:
        long_format = force_long
        include_hidden = force_all
        paths: list[str] = []
        for arg in argv[1:]:
            if arg.startswith("-") and arg != "-":
                long_format = long_format or "l" in arg
                include_hidden = include_hidden or "a" in arg
            else:
                paths.append(arg)
        paths = paths or ["."]
        blocks: list[str] = []
        multiple = len(paths) > 1
        for raw_path in paths:
            expanded = self.fs.expand_pattern(self.session.cwd, raw_path)
            if not expanded:
                blocks.append(f"ls: cannot access '{raw_path}': No such file or directory")
                continue
            for path in expanded:
                if not self.fs.exists(path):
                    blocks.append(f"ls: cannot access '{raw_path}': No such file or directory")
                    continue
                if self.fs.is_file(path):
                    entries = [self.fs.stat(path)]
                else:
                    entries = self.fs.list_dir(path, include_hidden=include_hidden)
                    if include_hidden:
                        entries = [
                            VirtualStat(path, ".", True, 4096, time.time() - 86400),
                            VirtualStat(posixpath.dirname(path), "..", True, 4096, time.time() - 86400),
                            *entries,
                        ]
                rendered = [self._format_long(item) for item in entries] if long_format else [item.name for item in entries]
                body = "\n".join(rendered)
                if multiple or len(expanded) > 1:
                    body = f"{path}:\n{body}"
                blocks.append(body)
        status = 1 if any(block.startswith("ls: cannot") for block in blocks) else 0
        return CommandResult("\n\n".join(blocks), status)

    def _ll(self, argv: list[str]) -> CommandResult:
        return self._ls(["ls", *argv[1:]], force_long=True, force_all=True)

    @staticmethod
    def _format_long(entry: VirtualStat) -> str:
        if entry.is_dir:
            mode, links = "drwxr-xr-x", 2
        else:
            executable = entry.name.endswith((".sh", ".py"))
            mode, links = ("-rwxr-xr-x" if executable else "-rw-r--r--"), 1
        modified = datetime.fromtimestamp(entry.modified).strftime("%b %e %H:%M")
        suffix = "/" if entry.is_dir and entry.name not in {".", ".."} else ""
        return f"{mode} {links:>2} root root {entry.size:>8} {modified} {entry.name}{suffix}"

    def _cd(self, argv: list[str]) -> CommandResult:
        target_arg = argv[1] if len(argv) > 1 else "/root"
        if target_arg == "-":
            target = self.session.previous_cwd
        else:
            target = self.fs.normalize(self.session.cwd, target_arg)
        if not self.fs.exists(target):
            return CommandResult(f"bash: cd: {target_arg}: No such file or directory", 1)
        if not self.fs.is_dir(target):
            return CommandResult(f"bash: cd: {target_arg}: Not a directory", 1)
        old = self.session.cwd
        self.session.cwd = target
        self.session.previous_cwd = old
        return CommandResult(target if target_arg == "-" else "")

    def _pwd(self, argv: list[str]) -> CommandResult:
        return CommandResult(self.session.cwd)

    def _cat(self, argv: list[str]) -> CommandResult:
        paths = [arg for arg in argv[1:] if not arg.startswith("-")]
        if not paths:
            return CommandResult()
        output: list[str] = []
        status = 0
        number = "-n" in argv[1:]
        for path in paths:
            try:
                content = self.fs.read_file(self.session.cwd, path)
                if number:
                    content = "\n".join(f"{i:6d}\t{line}" for i, line in enumerate(content.splitlines(), 1))
                output.append(content.rstrip("\n"))
            except VirtualFSError as exc:
                output.append(f"cat: {exc}")
                status = 1
        return CommandResult("\n".join(output), status)

    @staticmethod
    def _line_count(argv: list[str], default: int) -> int:
        for index, arg in enumerate(argv[1:], 1):
            if arg == "-n" and index + 1 < len(argv):
                return max(0, int(argv[index + 1]))
            if arg.startswith("-n") and arg[2:].isdigit():
                return int(arg[2:])
            if arg.startswith("-") and arg[1:].isdigit():
                return int(arg[1:])
        return default

    def _head(self, argv: list[str]) -> CommandResult:
        return self._head_tail(argv, head=True)

    def _tail(self, argv: list[str]) -> CommandResult:
        return self._head_tail(argv, head=False)

    def _head_tail(self, argv: list[str], head: bool) -> CommandResult:
        count = self._line_count(argv, 10)
        paths: list[str] = []
        skip_next = False
        for arg in argv[1:]:
            if skip_next:
                skip_next = False
            elif arg == "-n":
                skip_next = True
            elif not arg.startswith("-"):
                paths.append(arg)
        if not paths:
            return CommandResult()
        chunks: list[str] = []
        status = 0
        for path in paths:
            try:
                lines = self.fs.read_file(self.session.cwd, path).splitlines()
                selected = lines[:count] if head else lines[-count:]
                prefix = f"==> {path} <==\n" if len(paths) > 1 else ""
                chunks.append(prefix + "\n".join(selected))
            except VirtualFSError as exc:
                chunks.append(f"{argv[0]}: {exc}")
                status = 1
        return CommandResult("\n\n".join(chunks), status)

    def _find(self, argv: list[str]) -> CommandResult:
        start = "."
        name_pattern: str | None = None
        node_type: str | None = None
        index = 1
        if index < len(argv) and not argv[index].startswith("-"):
            start = argv[index]
            index += 1
        while index < len(argv):
            if argv[index] == "-name" and index + 1 < len(argv):
                name_pattern = argv[index + 1]
                index += 2
            elif argv[index] == "-type" and index + 1 < len(argv):
                node_type = argv[index + 1]
                if node_type not in {"f", "d"}:
                    return CommandResult(f"find: Unknown argument to -type: {node_type}", 1)
                index += 2
            else:
                index += 1
        items = self.fs.find(self.session.cwd, start, name_pattern, node_type)
        root = self.fs.normalize(self.session.cwd, start)
        if not start.startswith("/"):
            display: list[str] = []
            for item in items:
                relative = posixpath.relpath(item, root)
                display.append(start.rstrip("/") if relative == "." else start.rstrip("/") + "/" + relative)
            items = display
        return CommandResult("\n".join(items))

    def _editor(self, argv: list[str]) -> CommandResult:
        command = argv[0]
        if "--version" in argv[1:] or "-v" in argv[1:]:
            version = "GNU nano, version 6.2" if command == "nano" else "VIM - Vi IMproved 8.2"
            return CommandResult(version)
        path = argv[-1] if len(argv) > 1 and not argv[-1].startswith("-") else "[New Buffer]"
        try:
            content = "" if path == "[New Buffer]" else self.fs.read_file(self.session.cwd, path)
            line_count = len(content.splitlines())
            if command == "nano":
                return CommandResult(f"  GNU nano 6.2                 {path}\n[ Read {line_count} lines ]\n^G Help  ^O Write Out  ^W Where Is  ^K Cut  ^X Exit")
            return CommandResult(f'VIM - Vi IMproved 8.2\n"{path}" {line_count}L, {len(content)}B')
        except VirtualFSError:
            return CommandResult(f"  GNU nano 6.2                 {path}\n[ New File ]" if command == "nano" else f'VIM - Vi IMproved 8.2\n"{path}" [New]')

    def _touch(self, argv: list[str]) -> CommandResult:
        paths = [arg for arg in argv[1:] if not arg.startswith("-")]
        if not paths:
            return CommandResult("touch: missing file operand", 1)
        for path in paths:
            self.fs.touch(self.session.cwd, path)
        return CommandResult()

    def _mkdir(self, argv: list[str]) -> CommandResult:
        parents = "-p" in argv[1:] or "--parents" in argv[1:]
        paths = [arg for arg in argv[1:] if not arg.startswith("-")]
        if not paths:
            return CommandResult("mkdir: missing operand", 1)
        errors: list[str] = []
        for path in paths:
            try:
                self.fs.mkdir(self.session.cwd, path, parents=parents)
            except VirtualFSError as exc:
                errors.append(f"mkdir: {exc}")
        return CommandResult("\n".join(errors), 1 if errors else 0)

    def _rm(self, argv: list[str]) -> CommandResult:
        recursive = any("r" in arg or "R" in arg for arg in argv[1:] if arg.startswith("-"))
        force = any("f" in arg for arg in argv[1:] if arg.startswith("-"))
        paths = [arg for arg in argv[1:] if not arg.startswith("-")]
        if not paths:
            return CommandResult("rm: missing operand", 1)
        errors: list[str] = []
        for raw in paths:
            expanded = self.fs.expand_pattern(self.session.cwd, raw)
            targets = expanded or [raw]
            for target in targets:
                try:
                    self.fs.remove(self.session.cwd, target, recursive=recursive, force=force)
                except VirtualFSError as exc:
                    errors.append(f"rm: {exc}")
        return CommandResult("\n".join(errors), 1 if errors else 0)

    # --------------------------------------------------------------- network
    def _ip(self, argv: list[str]) -> CommandResult:
        subcommand = argv[1] if len(argv) > 1 else ""
        if subcommand in {"a", "addr", "address"}:
            return CommandResult(FAKE_INTERFACES)
        if subcommand in {"r", "route"}:
            return CommandResult("default via 10.20.0.1 dev eth0 proto dhcp src 10.20.0.15 metric 100\n10.20.0.0/24 dev eth0 proto kernel scope link src 10.20.0.15")
        if subcommand in {"link", "l"}:
            return CommandResult("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP")
        return CommandResult("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }", 1)

    def _ifconfig(self, argv: list[str]) -> CommandResult:
        return CommandResult(
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.20.0.15  netmask 255.255.255.0  broadcast 10.20.0.255\n"
            "        inet6 fe80::5054:ff:fe9a:317c  prefixlen 64  scopeid 0x20<link>\n"
            "        ether 52:54:00:9a:31:7c  txqueuelen 1000  (Ethernet)\n"
            "        RX packets 182914  bytes 238190442 (238.1 MB)\n"
            "        TX packets 102884  bytes 19422011 (19.4 MB)\n\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
            "        loop  txqueuelen 1000  (Local Loopback)"
        )

    def _netstat(self, argv: list[str]) -> CommandResult:
        body = FAKE_CONNECTIONS.replace("Netid State  Recv-Q Send-Q", "Proto Recv-Q Send-Q")
        return CommandResult("Active Internet connections (only servers)\n" + body)

    def _ss(self, argv: list[str]) -> CommandResult:
        return CommandResult(FAKE_CONNECTIONS)

    @staticmethod
    def _fake_ip(host: str) -> str:
        if host in {"localhost", "127.0.0.1"}:
            return "127.0.0.1"
        if host == "example.com":
            return "93.184.216.34"
        digest = hashlib.sha256(host.encode("utf-8", errors="replace")).digest()
        return f"203.0.113.{1 + digest[0] % 253}"

    def _ping(self, argv: list[str]) -> CommandResult:
        count = 4
        host = ""
        index = 1
        while index < len(argv):
            if argv[index] in {"-c", "--count"} and index + 1 < len(argv):
                count = min(10, max(1, int(argv[index + 1])))
                index += 2
            elif argv[index].startswith("-"):
                index += 1
            else:
                host = argv[index]
                index += 1
        if not host:
            return CommandResult("ping: usage error: Destination address required", 2)
        ip = self._fake_ip(host)
        lines = [f"PING {host} ({ip}) 56(84) bytes of data."]
        samples: list[float] = []
        seed = int(hashlib.sha256(host.encode()).hexdigest()[:8], 16)
        rng = random.Random(seed)
        for sequence in range(1, count + 1):
            latency = round(rng.uniform(18.0, 42.0), 1)
            samples.append(latency)
            lines.append(f"64 bytes from {ip}: icmp_seq={sequence} ttl=53 time={latency:.1f} ms")
        average = sum(samples) / len(samples)
        lines.extend(
            [
                f"\n--- {host} ping statistics ---",
                f"{count} packets transmitted, {count} received, 0% packet loss, time {(count - 1) * 1001}ms",
                f"rtt min/avg/max/mdev = {min(samples):.3f}/{average:.3f}/{max(samples):.3f}/2.241 ms",
            ]
        )
        return CommandResult("\n".join(lines))

    # -------------------------------------------------------------- process
    def _ps(self, argv: list[str]) -> CommandResult:
        if "aux" in argv[1:] or any("a" in arg and "x" in arg for arg in argv[1:] if arg.startswith("-")):
            header = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
            rows = ["{:<10} {:>5} {:>4} {:>4} {:>7} {:>6} {:<8} {:<4} {:<5} {:>5} {}".format(*row) for row in FAKE_PROCESSES]
            return CommandResult("\n".join([header, *rows]))
        return CommandResult("    PID TTY          TIME CMD\n   1184 pts/0    00:00:00 bash\n   1197 pts/0    00:00:00 ps")

    def _top(self, argv: list[str]) -> CommandResult:
        return CommandResult(
            "top - 00:14:21 up 18 days,  7:42,  1 user,  load average: 0.08, 0.04, 0.01\n"
            "Tasks: 112 total,   1 running, 111 sleeping,   0 stopped,   0 zombie\n"
            "%Cpu(s):  1.2 us,  0.6 sy,  0.0 ni, 98.0 id,  0.1 wa,  0.0 hi,  0.1 si,  0.0 st\n"
            "MiB Mem :   7957.4 total,   4261.2 free,   1120.8 used,   2575.4 buff/cache\n"
            "MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   6423.2 avail Mem\n\n"
            "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
            "    567 root      20   0 1842636 118212  43120 S   0.7   1.5   2:41.22 dockerd\n"
            "    900 www-data  20   0   55240   6820   3920 S   0.0   0.1   0:00.18 nginx"
        )

    def _free(self, argv: list[str]) -> CommandResult:
        return CommandResult(
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:         8148376     1147692     4363468       12732     2637216     6575920\n"
            "Swap:        2097148           0     2097148"
        )

    def _df(self, argv: list[str]) -> CommandResult:
        return CommandResult(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/vda1        79G   17G   59G  23% /\n"
            "tmpfs           799M  1.2M  798M   1% /run\n"
            "tmpfs           3.9G     0  3.9G   0% /dev/shm\n"
            "/dev/vda15      105M  6.1M   99M   6% /boot/efi\n"
            "overlay          79G   17G   59G  23% /var/lib/docker/overlay2/8c30a1cf91e2/merged"
        )

    def _du(self, argv: list[str]) -> CommandResult:
        human = any("h" in arg for arg in argv[1:] if arg.startswith("-"))
        summary = any("s" in arg for arg in argv[1:] if arg.startswith("-"))
        paths = [arg for arg in argv[1:] if not arg.startswith("-")] or ["."]
        lines: list[str] = []
        for raw in paths:
            path = self.fs.normalize(self.session.cwd, raw)
            size = max(4096, self.fs.disk_usage(path))
            if human:
                shown = f"{max(4, (size + 1023) // 1024)}K"
            else:
                shown = str(max(4, (size + 1023) // 1024))
            lines.append(f"{shown}\t{raw}")
            if not summary and self.fs.is_dir(path):
                pass
        return CommandResult("\n".join(lines))

    # ----------------------------------------------------------- management
    def _systemctl(self, argv: list[str]) -> CommandResult:
        if len(argv) == 1 or argv[1] in {"list-units", "--type=service"}:
            rows = [
                f"{name}.service loaded {'active running' if state == 'active' else 'inactive dead'} {name} service"
                for name, state in sorted(self.session.services.items())
            ]
            return CommandResult("UNIT LOAD ACTIVE SUB DESCRIPTION\n" + "\n".join(rows) + f"\n\n{len(rows)} loaded units listed.")
        action = argv[1]
        if action in {"is-active", "status", "start", "stop", "restart", "reload"}:
            if len(argv) < 3:
                return CommandResult("Too few arguments.", 1)
            service = argv[2].removesuffix(".service")
            if service not in self.session.services:
                return CommandResult(f"Unit {service}.service could not be found.", 4)
            if action in {"start", "restart", "reload"}:
                self.session.services[service] = "active"
                return CommandResult()
            if action == "stop":
                self.session.services[service] = "inactive"
                return CommandResult()
            state = self.session.services[service]
            if action == "is-active":
                return CommandResult(state, 0 if state == "active" else 3)
            active_line = (
                "active (running) since Thu 2026-09-18 03:10:01 UTC; 1 day 21h ago"
                if state == "active"
                else "inactive (dead)"
            )
            return CommandResult(
                f"● {service}.service - {service.capitalize()} service\n"
                f"     Loaded: loaded (/lib/systemd/system/{service}.service; enabled; vendor preset: enabled)\n"
                f"     Active: {active_line}\n"
                f"   Main PID: 900 ({service})\n"
                "      Tasks: 3 (limit: 9460)\n"
                "     Memory: 8.4M\n"
                "        CPU: 1.281s",
                0 if state == "active" else 3,
            )
        return CommandResult(f"Unknown command verb {action}.", 1)

    def _service(self, argv: list[str]) -> CommandResult:
        if len(argv) < 3:
            return CommandResult("Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]", 1)
        return self._systemctl(["systemctl", argv[2], argv[1]])

    def _apt(self, argv: list[str]) -> CommandResult:
        program = argv[0]
        if len(argv) < 2:
            return CommandResult("apt 2.4.13 (amd64)\nUsage: apt [options] command", 0)
        action = argv[1]
        packages = [arg for arg in argv[2:] if not arg.startswith("-")]
        if action == "update":
            return CommandResult(
                "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n"
                "Get:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [128 kB]\n"
                "Hit:3 http://security.ubuntu.com/ubuntu jammy-security InRelease\n"
                "Fetched 128 kB in 1s (186 kB/s)\n"
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "Reading state information... Done\n"
                "3 packages can be upgraded. Run 'apt list --upgradable' to see them."
            )
        if action in {"install", "reinstall"}:
            if not packages:
                return CommandResult(f"E: No packages found", 100)
            new_packages = set(packages) - self.session.packages
            if len(self.session.packages) + len(new_packages) > self.session.max_packages:
                return CommandResult("E: You don't have enough free space in /var/cache/apt/archives/.", 100)
            for package in packages:
                self.session.packages.add(package)
            package_list = " ".join(packages)
            return CommandResult(
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "Reading state information... Done\n"
                f"The following NEW packages will be installed:\n  {package_list}\n"
                f"0 upgraded, {len(packages)} newly installed, 0 to remove and 3 not upgraded.\n"
                "Need to get 1,284 kB of archives.\n"
                "After this operation, 4,812 kB of additional disk space will be used.\n"
                "Get:1 http://archive.ubuntu.com/ubuntu jammy/main amd64 package amd64 1.0 [1,284 kB]\n"
                "Fetched 1,284 kB in 1s (1,742 kB/s)\n"
                "Selecting previously unselected package...\n"
                "Preparing to unpack ...\n"
                "Unpacking...\n"
                f"Setting up {packages[-1]} (1.0) ...\n"
                "Processing triggers for man-db (2.10.2-1) ..."
            )
        if action in {"remove", "purge"}:
            if not packages:
                return CommandResult("E: No packages found", 100)
            for package in packages:
                self.session.packages.discard(package)
            return CommandResult(
                "Reading package lists... Done\nBuilding dependency tree... Done\n"
                f"Removing {' '.join(packages)} ...\nProcessing triggers for man-db (2.10.2-1) ..."
            )
        if action == "list" and "--installed" in argv[2:]:
            rows = [f"{package}/jammy,now 1.0 amd64 [installed]" for package in sorted(self.session.packages)]
            return CommandResult("Listing... Done\n" + "\n".join(rows))
        if action in {"upgrade", "full-upgrade", "dist-upgrade"}:
            return CommandResult("Reading package lists... Done\nBuilding dependency tree... Done\nCalculating upgrade... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")
        return CommandResult(f"E: Invalid operation {action}", 100)

    # --------------------------------------------------------------- tools
    @staticmethod
    def _url_filename(url: str) -> str:
        clean = url.split("?", 1)[0].rstrip("/")
        name = clean.rsplit("/", 1)[-1] if "/" in clean else "index.html"
        return name or "index.html"

    def _wget(self, argv: list[str]) -> CommandResult:
        output_path: str | None = None
        urls: list[str] = []
        index = 1
        while index < len(argv):
            if argv[index] in {"-O", "--output-document"} and index + 1 < len(argv):
                output_path = argv[index + 1]
                index += 2
            elif argv[index].startswith("-"):
                index += 1
            else:
                urls.append(argv[index])
                index += 1
        if not urls:
            return CommandResult("wget: missing URL\nUsage: wget [OPTION]... [URL]...", 1)
        url = urls[-1]
        filename = output_path or self._url_filename(url)
        if filename != "/dev/null":
            self.fs.write_file(self.session.cwd, filename, f"Simulated download payload for {url}\n")
        ip = self._fake_ip(url.split("://")[-1].split("/", 1)[0])
        return CommandResult(
            f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
            f"Resolving {url.split('://')[-1].split('/', 1)[0]}... {ip}\n"
            f"Connecting to {ip}:443... connected.\n"
            "HTTP request sent, awaiting response... 200 OK\n"
            "Length: 2048 (2.0K) [application/octet-stream]\n"
            f"Saving to: ‘{filename}’\n\n"
            f"{filename:<24} 100%[===================>]   2.00K  --.-KB/s    in 0s\n\n"
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (18.2 MB/s) - ‘{filename}’ saved [2048/2048]"
        )

    def _curl(self, argv: list[str]) -> CommandResult:
        output_path: str | None = None
        include_headers = "-i" in argv[1:] or "--include" in argv[1:]
        head_only = "-I" in argv[1:] or "--head" in argv[1:]
        urls: list[str] = []
        index = 1
        while index < len(argv):
            if argv[index] in {"-o", "--output"} and index + 1 < len(argv):
                output_path = argv[index + 1]
                index += 2
            elif argv[index] in {"-H", "--header", "-d", "--data", "-X", "--request"} and index + 1 < len(argv):
                index += 2
            elif argv[index].startswith("-"):
                index += 1
            else:
                urls.append(argv[index])
                index += 1
        if not urls:
            return CommandResult("curl: try 'curl --help' or 'curl --manual' for more information", 2)
        url = urls[-1]
        headers = "HTTP/1.1 200 OK\nserver: nginx/1.24.0 (Ubuntu)\ncontent-type: text/html\ncontent-length: 72\n"
        body = '{"status":"ok","host":"server01"}' if "health" in url else "<html><body><h1>Welcome to nginx!</h1></body></html>"
        content = headers if head_only else (headers + "\n" + body if include_headers else body)
        if output_path:
            self.fs.write_file(self.session.cwd, output_path, content + "\n")
            return CommandResult()
        return CommandResult(content)

    def _python3(self, argv: list[str]) -> CommandResult:
        if len(argv) == 1:
            return CommandResult("Python 3.10.12 (main, Nov 20 2025, 15:14:05) [GCC 11.4.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n>>>")
        if argv[1] in {"--version", "-V"}:
            return CommandResult("Python 3.10.12")
        if argv[1] == "-c" and len(argv) > 2:
            # Support only a literal print expression.  Never eval or exec code.
            match = re.fullmatch(r"\s*print\((.*)\)\s*", argv[2], flags=re.DOTALL)
            if match:
                try:
                    value = ast.literal_eval(match.group(1))
                    return CommandResult(str(value))
                except (ValueError, SyntaxError):
                    return CommandResult()
            return CommandResult()
        path = argv[1]
        try:
            content = self.fs.read_file(self.session.cwd, path)
        except VirtualFSError:
            return CommandResult(f"python3: can't open file '{path}': [Errno 2] No such file or directory", 2)
        match = re.search(r"^print\((['\"])(.*?)\1\)\s*$", content.strip())
        return CommandResult(match.group(2) if match else "")

    def _git(self, argv: list[str]) -> CommandResult:
        if len(argv) == 1 or argv[1] in {"--version", "version"}:
            return CommandResult("git version 2.34.1")
        action = argv[1]
        if action == "status":
            return CommandResult("On branch main\nYour branch is up to date with 'origin/main'.\n\nnothing to commit, working tree clean")
        if action == "log":
            return CommandResult("commit 4d2f811a33c9b781d0bc550e73c85a894f4c11b2 (HEAD -> main, origin/main)\nAuthor: deploy <deploy@server01>\nDate:   Wed Sep 17 21:44:18 2026 +0000\n\n    update production compose file")
        if action in {"branch", "status"}:
            return CommandResult("* main")
        if action == "remote":
            return CommandResult("origin\thttps://github.com/example/web-stack.git (fetch)\norigin\thttps://github.com/example/web-stack.git (push)")
        if action == "clone" and len(argv) > 2:
            repo = argv[2]
            destination = argv[3] if len(argv) > 3 else repo.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            self.fs.mkdir(self.session.cwd, destination, parents=True)
            self.fs.mkdir(self.session.cwd, destination.rstrip("/") + "/.git", parents=True)
            return CommandResult(f"Cloning into '{destination}'...\nremote: Enumerating objects: 42, done.\nremote: Total 42 (delta 8), reused 39 (delta 7)\nReceiving objects: 100% (42/42), 18.42 KiB | 3.68 MiB/s, done.\nResolving deltas: 100% (8/8), done.")
        return CommandResult()

    def _docker(self, argv: list[str]) -> CommandResult:
        if len(argv) == 1:
            return CommandResult("Usage:  docker [OPTIONS] COMMAND\n\nA self-sufficient runtime for containers")
        if argv[1] in {"--version", "version"}:
            return CommandResult("Docker version 24.0.7, build afdd53b")
        if argv[1] == "ps":
            return CommandResult(FAKE_DOCKER_PS)
        if argv[1] == "images":
            return CommandResult("REPOSITORY   TAG       IMAGE ID       CREATED        SIZE\nnginx        1.24      6c7be49d2a11   3 months ago   187MB\nredis        7         0ec8ab59a35f   2 months ago   117MB")
        if argv[1] == "info":
            return CommandResult("Client:\n Context:    default\n Debug Mode: false\n\nServer:\n Containers: 2\n  Running: 2\n Images: 4\n Server Version: 24.0.7\n Storage Driver: overlay2")
        if argv[1] == "compose":
            if len(argv) > 2 and argv[2] == "ps":
                return CommandResult("NAME          IMAGE        COMMAND                  SERVICE   CREATED       STATUS       PORTS\nweb-nginx-1   nginx:1.24   \"/docker-entrypoint.…\"   web       12 days ago   Up 12 days   0.0.0.0:80->80/tcp\nweb-redis-1   redis:7      \"docker-entrypoint.s…\"   redis     12 days ago   Up 12 days   6379/tcp")
            if len(argv) > 2 and argv[2] in {"up", "start", "restart"}:
                return CommandResult("[+] Running 2/2\n ✔ Container web-redis-1  Running\n ✔ Container web-nginx-1  Running")
        if argv[1] in {"start", "restart"} and len(argv) > 2:
            return CommandResult("\n".join(argv[2:]))
        return CommandResult(f"docker: '{argv[1]}' is not a docker command.\nSee 'docker --help'", 1)
