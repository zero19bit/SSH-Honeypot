"""Validated runtime configuration loaded only from CLI values or environment.

No configuration file is opened by the application. Secrets can be injected
as environment values and are never included in repr/log output.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Mapping


def _boolean(value: str, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


def _integer(values: Mapping[str, str], name: str, default: int) -> int:
    raw = values.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _float(values: Mapping[str, str], name: str, default: float) -> float:
    raw = values.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc


@dataclass(frozen=True, slots=True)
class HoneypotConfig:
    """Runtime and abuse-control settings for the inbound SSH listener."""

    host: str = "0.0.0.0"
    port: int = 2222
    hostname: str = "server01"
    kernel: str = "5.15.0-122-generic"
    ssh_banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    welcome_release: str = "Ubuntu 22.04.5 LTS"
    production: bool = False

    # SSH lifecycle.
    max_connections: int = 64
    max_connections_per_ip: int = 4
    listen_backlog: int = 128
    banner_timeout: float = 12.0
    auth_timeout: float = 20.0
    channel_timeout: float = 20.0
    request_timeout: float = 10.0
    channel_io_timeout: float = 30.0
    idle_timeout: float = 90.0
    max_session_seconds: float = 900.0
    shutdown_grace_seconds: float = 10.0

    # Connection-rate token buckets, expressed per minute.
    global_connection_rate: float = 120.0
    global_connection_burst: int = 30
    per_ip_connection_rate: float = 12.0
    per_ip_connection_burst: int = 4
    rate_bucket_ttl_seconds: float = 900.0

    # Terminal/session bounds.
    max_line_length: int = 4096
    receive_size: int = 2048
    command_delay_min: float = 0.1
    command_delay_max: float = 1.0
    max_commands_per_session: int = 500
    max_chain_commands: int = 32
    history_limit: int = 200
    max_session_history: int = 500
    max_score: int = 1000
    intelligence_enabled: bool = True
    log_hashing: bool = True
    ioc_enabled: bool = True
    max_command_output_bytes: int = 65536
    max_packages_per_session: int = 256

    # Per-session in-memory filesystem bounds.
    vfs_max_nodes: int = 2048
    vfs_max_total_bytes: int = 2 * 1024 * 1024
    vfs_max_file_bytes: int = 128 * 1024
    vfs_max_path_length: int = 512
    vfs_max_name_length: int = 255
    vfs_max_query_results: int = 512

    # Logging and credentials.
    log_queue_size: int = 10000
    log_field_limit: int = 4096
    credential_log_mode: str = "sha256"  # plain (development only) | sha256 | redact
    alert_min_risk: int = 65

    # Stable key is base64-encoded PEM. It is intentionally hidden from repr.
    host_key_b64: str | None = field(default=None, repr=False)
    ephemeral_host_key_bits: int = 3072

    @classmethod
    def from_env(cls, values: Mapping[str, str] | None = None) -> "HoneypotConfig":
        env = os.environ if values is None else values
        defaults = cls()
        production_raw = env.get("HONEYPOT_PRODUCTION")
        production = defaults.production if production_raw is None else _boolean(production_raw, "HONEYPOT_PRODUCTION")
        config = cls(
            host=env.get("HONEYPOT_HOST", defaults.host),
            port=_integer(env, "HONEYPOT_PORT", defaults.port),
            hostname=env.get("HONEYPOT_HOSTNAME", defaults.hostname),
            production=production,
            max_connections=_integer(env, "HONEYPOT_MAX_CONNECTIONS", defaults.max_connections),
            max_connections_per_ip=_integer(env, "HONEYPOT_MAX_CONNECTIONS_PER_IP", defaults.max_connections_per_ip),
            listen_backlog=_integer(env, "HONEYPOT_LISTEN_BACKLOG", defaults.listen_backlog),
            banner_timeout=_float(env, "HONEYPOT_BANNER_TIMEOUT", defaults.banner_timeout),
            auth_timeout=_float(env, "HONEYPOT_AUTH_TIMEOUT", defaults.auth_timeout),
            channel_timeout=_float(env, "HONEYPOT_CHANNEL_TIMEOUT", defaults.channel_timeout),
            request_timeout=_float(env, "HONEYPOT_REQUEST_TIMEOUT", defaults.request_timeout),
            channel_io_timeout=_float(env, "HONEYPOT_CHANNEL_IO_TIMEOUT", defaults.channel_io_timeout),
            idle_timeout=_float(env, "HONEYPOT_IDLE_TIMEOUT", defaults.idle_timeout),
            max_session_seconds=_float(env, "HONEYPOT_MAX_SESSION_SECONDS", defaults.max_session_seconds),
            shutdown_grace_seconds=_float(
                env, "HONEYPOT_SHUTDOWN_GRACE_SECONDS", defaults.shutdown_grace_seconds
            ),
            global_connection_rate=_float(env, "HONEYPOT_GLOBAL_RATE_PER_MINUTE", defaults.global_connection_rate),
            global_connection_burst=_integer(env, "HONEYPOT_GLOBAL_RATE_BURST", defaults.global_connection_burst),
            per_ip_connection_rate=_float(env, "HONEYPOT_IP_RATE_PER_MINUTE", defaults.per_ip_connection_rate),
            per_ip_connection_burst=_integer(env, "HONEYPOT_IP_RATE_BURST", defaults.per_ip_connection_burst),
            rate_bucket_ttl_seconds=_float(
                env, "HONEYPOT_RATE_BUCKET_TTL_SECONDS", defaults.rate_bucket_ttl_seconds
            ),
            max_line_length=_integer(env, "HONEYPOT_MAX_LINE_LENGTH", defaults.max_line_length),
            receive_size=_integer(env, "HONEYPOT_RECEIVE_SIZE", defaults.receive_size),
            command_delay_min=_float(env, "HONEYPOT_COMMAND_DELAY_MIN", defaults.command_delay_min),
            command_delay_max=_float(env, "HONEYPOT_COMMAND_DELAY_MAX", defaults.command_delay_max),
            max_commands_per_session=_integer(env, "HONEYPOT_MAX_COMMANDS", defaults.max_commands_per_session),
            max_chain_commands=_integer(env, "HONEYPOT_MAX_CHAIN_COMMANDS", defaults.max_chain_commands),
            history_limit=_integer(env, "HONEYPOT_HISTORY_LIMIT", defaults.history_limit),
            max_session_history=_integer(env, "HONEYPOT_MAX_SESSION_HISTORY", defaults.max_session_history),
            max_score=_integer(env, "HONEYPOT_MAX_SCORE", defaults.max_score),
            intelligence_enabled=_boolean(env.get("HONEYPOT_INTELLIGENCE_ENABLED", "true"), "HONEYPOT_INTELLIGENCE_ENABLED"),
            log_hashing=_boolean(env.get("HONEYPOT_LOG_HASHING", "true"), "HONEYPOT_LOG_HASHING"),
            ioc_enabled=_boolean(env.get("HONEYPOT_IOC_ENABLED", "true"), "HONEYPOT_IOC_ENABLED"),
            max_command_output_bytes=_integer(env, "HONEYPOT_MAX_OUTPUT_BYTES", defaults.max_command_output_bytes),
            max_packages_per_session=_integer(
                env, "HONEYPOT_MAX_PACKAGES", defaults.max_packages_per_session
            ),
            vfs_max_nodes=_integer(env, "HONEYPOT_VFS_MAX_NODES", defaults.vfs_max_nodes),
            vfs_max_total_bytes=_integer(env, "HONEYPOT_VFS_MAX_TOTAL_BYTES", defaults.vfs_max_total_bytes),
            vfs_max_file_bytes=_integer(env, "HONEYPOT_VFS_MAX_FILE_BYTES", defaults.vfs_max_file_bytes),
            vfs_max_path_length=_integer(
                env, "HONEYPOT_VFS_MAX_PATH_LENGTH", defaults.vfs_max_path_length
            ),
            vfs_max_name_length=_integer(
                env, "HONEYPOT_VFS_MAX_NAME_LENGTH", defaults.vfs_max_name_length
            ),
            vfs_max_query_results=_integer(
                env, "HONEYPOT_VFS_MAX_QUERY_RESULTS", defaults.vfs_max_query_results
            ),
            log_queue_size=_integer(env, "HONEYPOT_LOG_QUEUE_SIZE", defaults.log_queue_size),
            log_field_limit=_integer(env, "HONEYPOT_LOG_FIELD_LIMIT", defaults.log_field_limit),
            credential_log_mode=env.get("HONEYPOT_CREDENTIAL_LOG_MODE", defaults.credential_log_mode),
            alert_min_risk=_integer(env, "HONEYPOT_ALERT_MIN_RISK", defaults.alert_min_risk),
            host_key_b64=env.get("HONEYPOT_HOST_KEY_B64") or None,
            ephemeral_host_key_bits=_integer(
                env, "HONEYPOT_EPHEMERAL_HOST_KEY_BITS", defaults.ephemeral_host_key_bits
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not 0 < self.port < 65536:
            raise ValueError("port must be between 1 and 65535")
        if self.production and self.port < 1024:
            raise ValueError("production listener must use a non-privileged internal port (>=1024)")
        if self.production and not self.host_key_b64:
            raise ValueError("HONEYPOT_HOST_KEY_B64 is required in production mode")
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,61}[A-Za-z0-9])?", self.hostname):
            raise ValueError("hostname must be a safe DNS-style name with 1 to 63 characters")
        if not 1 <= self.max_connections <= 4096:
            raise ValueError("max_connections must be between 1 and 4096")
        if not 1 <= self.max_connections_per_ip <= self.max_connections:
            raise ValueError("max_connections_per_ip must be between 1 and max_connections")
        if not 1 <= self.listen_backlog <= 4096:
            raise ValueError("listen_backlog must be between 1 and 4096")
        for name, value in (
            ("banner_timeout", self.banner_timeout),
            ("auth_timeout", self.auth_timeout),
            ("channel_timeout", self.channel_timeout),
            ("request_timeout", self.request_timeout),
            ("channel_io_timeout", self.channel_io_timeout),
            ("idle_timeout", self.idle_timeout),
            ("max_session_seconds", self.max_session_seconds),
            ("shutdown_grace_seconds", self.shutdown_grace_seconds),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if self.command_delay_min < 0 or self.command_delay_max < self.command_delay_min:
            raise ValueError("command delay range is invalid")
        if self.command_delay_max > 10:
            raise ValueError("command_delay_max cannot exceed 10 seconds")
        if self.global_connection_rate <= 0 or self.per_ip_connection_rate <= 0:
            raise ValueError("connection rates must be positive")
        if self.global_connection_burst < 1 or self.per_ip_connection_burst < 1:
            raise ValueError("connection bursts must be positive")
        if self.rate_bucket_ttl_seconds <= 0:
            raise ValueError("rate_bucket_ttl_seconds must be positive")
        if not 128 <= self.max_line_length <= 65536:
            raise ValueError("max_line_length must be between 128 and 65536")
        if not 64 <= self.receive_size <= 65536:
            raise ValueError("receive_size must be between 64 and 65536")
        if self.max_commands_per_session < 1 or self.history_limit < 1:
            raise ValueError("session command/history limits must be positive")
        if not 1 <= self.max_session_history <= 500:
            raise ValueError("max_session_history must be between 1 and 500")
        if not 90 <= self.max_score <= 1000:
            raise ValueError("max_score must be between 90 and 1000")
        if not 1 <= self.max_chain_commands <= 256:
            raise ValueError("max_chain_commands must be between 1 and 256")
        if not 1 <= self.max_packages_per_session <= 65536:
            raise ValueError("max_packages_per_session must be between 1 and 65536")
        if self.max_command_output_bytes < 1024:
            raise ValueError("max_command_output_bytes must be at least 1024")
        if self.vfs_max_nodes < 128:
            raise ValueError("vfs_max_nodes must be at least 128")
        if self.vfs_max_file_bytes < 1024 or self.vfs_max_total_bytes < self.vfs_max_file_bytes:
            raise ValueError("VFS byte limits are invalid")
        if self.vfs_max_path_length < 128 or self.vfs_max_name_length < 32:
            raise ValueError("VFS path limits are too small")
        if not 1 <= self.vfs_max_query_results <= self.vfs_max_nodes:
            raise ValueError("vfs_max_query_results must be between 1 and vfs_max_nodes")
        if self.log_queue_size < 100:
            raise ValueError("log_queue_size must be at least 100")
        if not 256 <= self.log_field_limit <= 65536:
            raise ValueError("log_field_limit must be between 256 and 65536")
        if self.credential_log_mode not in {"plain", "sha256", "redact"}:
            raise ValueError("credential_log_mode must be plain, sha256, or redact")
        if self.production and self.credential_log_mode == "plain":
            raise ValueError("credential_log_mode=plain is not allowed in production mode")
        if not 1 <= self.alert_min_risk <= self.max_score:
            raise ValueError("alert_min_risk must be between 1 and max_score")
        if not 2048 <= self.ephemeral_host_key_bits <= 8192:
            raise ValueError("ephemeral_host_key_bits must be between 2048 and 8192")

    def public_summary(self) -> dict[str, object]:
        """Return log-safe settings without secret material."""
        return {
            "production": self.production,
            "max_connections": self.max_connections,
            "max_connections_per_ip": self.max_connections_per_ip,
            "max_session_seconds": self.max_session_seconds,
            "vfs_max_nodes": self.vfs_max_nodes,
            "vfs_max_total_bytes": self.vfs_max_total_bytes,
            "credential_log_mode": self.credential_log_mode,
            "alert_min_risk": self.alert_min_risk,
            "intelligence_enabled": self.intelligence_enabled,
            "ioc_enabled": self.ioc_enabled,
            "log_hashing": self.log_hashing,
            "max_session_history": self.max_session_history,
            "max_score": self.max_score,
            "stable_host_key": bool(self.host_key_b64),
        }
