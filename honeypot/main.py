"""Production command-line entry point for the fake Ubuntu SSH server."""

from __future__ import annotations

import argparse
import signal
from dataclasses import replace

from . import __version__
from .config import HoneypotConfig
from .logger import JsonEventLogger
from .ssh_server import SSHHoneypot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fully simulated Ubuntu 22.04 SSH honeypot")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--host", default=None, help="inbound bind address")
    parser.add_argument("--port", type=int, default=None, help="non-privileged inbound SSH port")
    parser.add_argument("--hostname", default=None, help="fake hostname shown inside sessions")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--production", dest="production", action="store_true", help="enable production validation")
    mode.add_argument("--development", dest="production", action="store_false", help="allow ephemeral development key")
    parser.set_defaults(production=None)
    parser.add_argument(
        "--credential-log-mode",
        choices=("plain", "sha256", "redact"),
        default=None,
        help="how attempted passwords are represented in JSON logs",
    )
    parser.add_argument("--alert-min-risk", type=int, default=None, help="minimum risk score for a JSONL alert")
    return parser


def resolve_config(args: argparse.Namespace) -> HoneypotConfig:
    config = HoneypotConfig.from_env()
    updates: dict[str, object] = {}
    for field_name in ("host", "port", "hostname", "production", "credential_log_mode", "alert_min_risk"):
        value = getattr(args, field_name)
        if value is not None:
            updates[field_name] = value
    if updates:
        config = replace(config, **updates)
    config.validate()
    return config


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        config = resolve_config(args)
    except ValueError as exc:
        parser.error(str(exc))

    logger = JsonEventLogger(
        queue_size=config.log_queue_size,
        field_limit=config.log_field_limit,
        credential_mode=config.credential_log_mode,
        asynchronous=True,
        log_hashing=config.log_hashing,
    )
    try:
        server = SSHHoneypot(config, logger)
    except ValueError as exc:
        logger.emit("startup_failed", component="config", error=type(exc).__name__, error_type=type(exc).__name__, message=str(exc))
        logger.close()
        parser.error(str(exc))

    shutdown_once = False

    def request_shutdown(signum: int, frame: object) -> None:
        nonlocal shutdown_once
        if shutdown_once:
            return
        shutdown_once = True
        logger.emit("shutdown_requested", signal=signum)
        server.stop()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)

    exit_code = 0
    try:
        server.serve_forever()
    except OSError as exc:
        exit_code = 1
        logger.emit(
            "startup_failed",
            component="ssh_listener",
            error=type(exc).__name__,
            error_type=type(exc).__name__,
            message=str(exc)[:512],
            host=config.host,
            port=config.port,
        )
    finally:
        server.stop()
        logger.flush(2.0)
        logger.close(2.0)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
