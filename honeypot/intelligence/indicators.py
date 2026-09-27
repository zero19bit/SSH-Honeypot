"""Extract bounded, credential-free indicators from fake command arguments.

No URL is fetched or resolved. Hosts are extracted without URL paths, queries,
userinfo or headers, which may contain credentials and tokens.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re

from .rules import Invocation


MAX_INDICATORS = 8
MAX_ARTIFACT_NAME = 128
_URL_AUTHORITY = re.compile(r"^(?:https?|ftp)://([^/?#]+)", re.I)
_URL = re.compile(r"^(https?|ftp)://([^/?#]+)([^?#]*)", re.I)
_HOSTNAME = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$", re.I)
_ARTIFACT = re.compile(r"^[a-zA-Z0-9._-]+$")
_DOMAIN = re.compile(r"(?<![a-z0-9._-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![a-z0-9._-])", re.I)
_IP = re.compile(r"(?<![a-z0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![a-z0-9.])")
_HASH = re.compile(r"(?<![a-f0-9])(?:[a-f0-9]{64}|[a-f0-9]{32})(?![a-f0-9])", re.I)
_FILE_SUFFIX = re.compile(r"\.(?:sh|py|pl|elf|bin|exe|so|jar)$", re.I)


def empty_indicators() -> dict[str, list[str]]:
    return {key: [] for key in ("hosts", "ips", "artifacts", "domains", "urls", "md5", "sha256", "files")}


def _add_unique(items: list[str], value: str) -> None:
    if value and value not in items and len(items) < MAX_INDICATORS:
        items.append(value)


def _safe_host(authority: str) -> str:
    value = authority.rsplit("@", 1)[-1]
    if value.startswith("["):
        host = value.partition("]")[0][1:]
    else:
        host = value.split(":", 1)[0].strip(".").lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if host and len(host) <= 253 and _HOSTNAME.fullmatch(host) and ".." not in host:
            return host
        return ""


def _safe_artifact(path: str) -> str:
    # Names only: no traversal, directory paths, URLs, or attacker text in state.
    name = posixpath.basename(path.split("?", 1)[0].rstrip("/"))
    return name if name not in {".", ".."} and len(name) <= MAX_ARTIFACT_NAME and _ARTIFACT.fullmatch(name) else ""


def _url_hosts(command: Invocation) -> list[str]:
    hosts: list[str] = []
    if command.program not in {"curl", "wget"}:
        return hosts
    for arg in command.args:
        match = _URL_AUTHORITY.match(arg)
        if match:
            _add_unique(hosts, _safe_host(match.group(1)))
    return hosts


def download_artifacts(command: Invocation) -> tuple[str, ...]:
    """Artifact names a downloader tried to write; not proof of a download."""
    if command.program not in {"curl", "wget"}:
        return ()
    args = command.args
    targets: list[str] = []
    explicit: str | None = None
    remote_name = False
    for index, arg in enumerate(args):
        if arg in {"-o", "--output", "--output-document", "-O"} and index + 1 < len(args):
            if command.program == "curl" and arg == "-O":
                remote_name = True
            else:
                explicit = args[index + 1]
        elif arg.startswith(("--output=", "--output-document=")):
            explicit = arg.split("=", 1)[1]
        elif command.program == "curl" and arg == "-O":
            remote_name = True
    if explicit == "-":
        return ()  # stdout is not a downloaded file in the virtual filesystem.
    if explicit:
        _add_unique(targets, _safe_artifact(explicit))
    elif command.program == "wget" or remote_name:
        for arg in args:
            if _URL_AUTHORITY.match(arg):
                _add_unique(targets, _safe_artifact(arg))
    return tuple(targets)


def executed_artifacts(command: Invocation) -> tuple[str, ...]:
    """Names explicitly invoked from a local path or through an interpreter."""
    targets: list[str] = []
    if command.argv[0].startswith(("./", "/tmp/", "/var/tmp/")):
        _add_unique(targets, _safe_artifact(command.argv[0]))
    if command.program in {"sh", "bash", "dash", "python", "python3", "perl"}:
        for arg in command.args:
            if not arg.startswith("-"):
                _add_unique(targets, _safe_artifact(arg))
                break
    return tuple(targets)


def extract_indicators(commands: tuple[Invocation, ...]) -> dict[str, list[str]]:
    result = empty_indicators()
    for command in commands:
        for host in _url_hosts(command):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                _add_unique(result["hosts"], host)
                _add_unique(result["domains"], host)
            else:
                _add_unique(result["ips"], host)
        for artifact in download_artifacts(command):
            _add_unique(result["artifacts"], artifact)
            _add_unique(result["files"], artifact)
        # Quoted demonstrations and arbitrary arguments to echo/printf are not IOCs.
        if command.program in {"echo", "printf", "history"}:
            continue
        for arg in command.args:
            url = _URL.match(arg)
            if url and command.program in {"curl", "wget", "bash", "sh", "python", "python3"}:
                host = _safe_host(url.group(2))
                path = url.group(3)
                # Only a short, single known artifact name may survive; path tokens
                # and URL userinfo/query/fragment never enter the intelligence state.
                safe_path = path if len(path) <= 36 and path.startswith("/") and "/" not in path[1:] and _FILE_SUFFIX.search(path) and _safe_artifact(path) else ""
                if host:
                    _add_unique(result["urls"], f"{url.group(1).lower()}://{host}{safe_path}")
            for ip in _IP.findall(arg[:4096]):
                try:
                    _add_unique(result["ips"], str(ipaddress.ip_address(ip)))
                except ValueError:
                    pass
            for domain in _DOMAIN.findall(arg[:4096]):
                _add_unique(result["domains"], domain.lower())
            for digest in _HASH.findall(arg[:4096]):
                _add_unique(result["sha256" if len(digest) == 64 else "md5"], digest.lower())
            if not url and not arg.startswith("-"):
                filename = _safe_artifact(arg)
                if filename and _FILE_SUFFIX.search(filename):
                    _add_unique(result["files"], filename)
    return result


def ioc_list(indicators: dict[str, list[str]]) -> list[dict[str, str]]:
    return [{"type": key, "value": value} for key in ("ips", "domains", "urls", "md5", "sha256", "files") for value in indicators.get(key, [])[:MAX_INDICATORS]]
