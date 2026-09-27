"""Precompiled, bounded regex rules over parsed invocations only."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .rules import Invocation


@lru_cache(maxsize=64)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.ASCII)


def match_patterns(name: str, patterns: tuple[str, ...], kind: str, commands: tuple[Invocation, ...]) -> bool:
    if name == "download_pipe_shell":
        return any(current.connector == "|" and any(_compile(p).search(f"{previous.program} | {current.program}") for p in patterns)
                   for previous, current in zip(commands, commands[1:]))
    if name == "download_chmod_chain":
        from .indicators import download_artifacts

        available: dict[str, str] = {}
        for command in commands:
            if command.program in {"curl", "wget"}:
                for artifact in download_artifacts(command):
                    available[artifact] = command.program
            if command.program == "chmod":
                for arg in command.args:
                    program = available.get(arg.rsplit("/", 1)[-1])
                    if program and any(_compile(pattern).search(f"{program} chmod") for pattern in patterns):
                        return True
        return False
    relevant = {
        "reverse_shell": {"nc", "netcat", "ncat", "bash", "sh", "dash", "python", "python3", "perl"},
        "obfuscation": {"base64", "eval", "python", "python3", "perl", "bash", "sh"},
    }.get(name, set())
    for command in commands:
        if command.program not in relevant:
            continue
        if name == "obfuscation" and command.program == "base64":
            return True
        # Never inspect quoted text from echo/printf or an unrelated program.
        haystack = " ".join(command.argv)[:4096]
        if any((_compile(p).search(haystack) if kind == "regex" else p.lower() in haystack.lower()) for p in patterns):
            return True
    return False


REVERSE_SHELL = (
    r"\b(?:nc|netcat|ncat)\s+(?:-[a-z]*e\b|--exec\b)",
    r"\b(?:bash|sh|dash)\s+-[a-z]*i\b",
    r"/dev/tcp/[a-z0-9.:-]+/[0-9]{1,5}",
    r"\b(?:python3?|perl)\s+(?:-c|-e)\s+.*\bsocket\b.*\bconnect\b",
)
OBFUSCATION = (
    r"\bbase64\s+(?:-[a-z]*d\b|--decode\b)",
    r"\beval\s+[^\s]",
    r"\b(?:python3?|perl)\s+-[ce]\s+.*\b(?:b64decode|fromhex|decode)\s*\(",
    r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2})+",
)
DOWNLOAD_PIPE = (r"\b(?:curl|wget)\s*\|\s*(?:bash|sh|dash|zsh)\b",)
