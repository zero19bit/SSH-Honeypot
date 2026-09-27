"""Hardened inbound Paramiko SSH server for the simulated environment."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import logging
import socket
import threading
import time
from typing import Any

import paramiko

from .config import HoneypotConfig
from .filesystem import VirtualFSLimits, VirtualFileSystem
from .intelligence.analyzer import Analyzer
from .logger import JsonEventLogger
from .rate_limit import ConnectionGate
from .session import SessionState
from .shell import FakeShell, run_exec_request


DISABLED_ALGORITHMS: dict[str, list[str]] = {
    "kex": [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group-exchange-sha1",
    ],
    "ciphers": [
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "blowfish-cbc",
        "cast128-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
    ],
    "macs": ["hmac-md5", "hmac-md5-96", "hmac-sha1-96"],
    "keys": ["ssh-dss"],
    "pubkeys": ["ssh-dss"],
}


def _host_key_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _load_host_key(config: HoneypotConfig) -> tuple[paramiko.PKey, bool]:
    if not config.host_key_b64:
        return paramiko.RSAKey.generate(config.ephemeral_host_key_bits), False
    try:
        pem = base64.b64decode(config.host_key_b64, validate=True).decode("ascii")
        return paramiko.RSAKey.from_private_key(io.StringIO(pem)), True
    except (binascii.Error, UnicodeDecodeError, ValueError, paramiko.SSHException) as exc:
        raise ValueError("HONEYPOT_HOST_KEY_B64 is not a valid base64 RSA private key") from exc


class HoneypotServerInterface(paramiko.ServerInterface):
    """Allow password auth/session channels and explicitly reject tunneling."""

    def __init__(
        self,
        session: SessionState,
        logger: JsonEventLogger,
        max_exec_bytes: int,
    ) -> None:
        self.session = session
        self.logger = logger
        self.max_exec_bytes = max_exec_bytes
        self.request_event = threading.Event()
        self.exec_command: bytes | None = None
        self.pty_requested = False

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        self.session.username = username[:256]
        self.logger.authentication(self.session, password)
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        self.session.username = username[:256]
        self.logger.emit(
            "authentication",
            self.session,
            method="publickey",
            key_type=key.get_name(),
            key_fingerprint=_host_key_fingerprint(key),
            result="rejected",
        )
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        self.pty_requested = True
        self.session.terminal_type = term.decode("ascii", errors="replace")[:128]
        self.session.terminal_width = max(1, min(width, 1000))
        self.session.terminal_height = max(1, min(height, 1000))
        return True

    def check_channel_window_change_request(
        self,
        channel: paramiko.Channel,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
    ) -> bool:
        self.session.terminal_width = max(1, min(width, 1000))
        self.session.terminal_height = max(1, min(height, 1000))
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.request_event.set()
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.exec_command = bytes(command[: self.max_exec_bytes])
        self.request_event.set()
        return True

    def check_channel_subsystem_request(self, channel: paramiko.Channel, name: str) -> bool:
        return False

    def check_channel_env_request(self, channel: paramiko.Channel, name: bytes, value: bytes) -> bool:
        return False

    def check_channel_forward_agent_request(self, channel: paramiko.Channel) -> bool:
        return False

    def check_channel_x11_request(self, *args: Any, **kwargs: Any) -> bool:
        return False

    def check_channel_direct_tcpip_request(
        self,
        chanid: int,
        origin: tuple[str, int],
        destination: tuple[str, int],
    ) -> int:
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_port_forward_request(self, address: str, port: int) -> bool:
        return False

    def check_global_request(self, kind: str, msg: paramiko.Message) -> bool:
        return False


class SSHHoneypot:
    """Threaded listener with bounded resources and isolated session state."""

    def __init__(self, config: HoneypotConfig, logger: JsonEventLogger | None = None) -> None:
        config.validate()
        if config.production and logger is not None and logger._credential_mode == "plain":
            raise ValueError("plain credential logging is not allowed in production mode")
        self.config = config
        self.logger = logger or JsonEventLogger(
            queue_size=config.log_queue_size,
            field_limit=config.log_field_limit,
            credential_mode=config.credential_log_mode,
            asynchronous=True,
        )
        self._stopping = threading.Event()
        self._host_key, self._stable_host_key = _load_host_key(config)
        self._host_key_fingerprint = _host_key_fingerprint(self._host_key)
        self._gate = ConnectionGate(
            max_total=config.max_connections,
            max_per_ip=config.max_connections_per_ip,
            global_rate_per_minute=config.global_connection_rate,
            global_burst=config.global_connection_burst,
            per_ip_rate_per_minute=config.per_ip_connection_rate,
            per_ip_burst=config.per_ip_connection_burst,
            bucket_ttl_seconds=config.rate_bucket_ttl_seconds,
        )
        self._listener: socket.socket | None = None
        self._listener_lock = threading.Lock()
        self._clients: set[socket.socket] = set()
        self._clients_lock = threading.Lock()
        self._threads: set[threading.Thread] = set()
        self._threads_lock = threading.Lock()
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    def _new_session(self, address: tuple[Any, ...]) -> SessionState:
        limits = VirtualFSLimits(
            max_nodes=self.config.vfs_max_nodes,
            max_total_bytes=self.config.vfs_max_total_bytes,
            max_file_bytes=self.config.vfs_max_file_bytes,
            max_path_length=self.config.vfs_max_path_length,
            max_name_length=self.config.vfs_max_name_length,
            max_query_results=self.config.vfs_max_query_results,
        )
        filesystem = VirtualFileSystem(limits=limits)
        # Keep the configurable fake identity internally consistent. This is
        # a write to the in-memory VFS only; no host file is opened.
        filesystem.write_file("/", "/etc/hostname", self.config.hostname + "\n")
        return SessionState(
            client_ip=str(address[0]),
            client_port=int(address[1]),
            hostname=self.config.hostname,
            filesystem=filesystem,
            history_limit=self.config.history_limit,
            max_session_history=self.config.max_session_history,
            intelligence=Analyzer(enabled=self.config.intelligence_enabled, ioc_enabled=self.config.ioc_enabled, max_score=self.config.max_score),
            max_commands=self.config.max_commands_per_session,
            max_chain_commands=self.config.max_chain_commands,
            max_packages=self.config.max_packages_per_session,
        )

    def _handle_client(self, client: socket.socket, address: tuple[Any, ...]) -> None:
        session = self._new_session(address)
        transport: paramiko.Transport | None = None
        disconnect_reason = "unknown"
        self.logger.emit("connection_open", session)
        try:
            client.settimeout(self.config.banner_timeout)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            transport = paramiko.Transport(
                client,
                disabled_algorithms=DISABLED_ALGORITHMS,
                strict_kex=True,
            )
            transport.local_version = self.config.ssh_banner
            transport.banner_timeout = self.config.banner_timeout
            transport.auth_timeout = self.config.auth_timeout
            transport.add_server_key(self._host_key)
            interface = HoneypotServerInterface(
                session,
                self.logger,
                max_exec_bytes=self.config.max_line_length,
            )
            transport.start_server(server=interface)
            session.client_version = transport.remote_version or "unknown"
            self.logger.emit("ssh_negotiated", session)

            channel = transport.accept(self.config.channel_timeout)
            if channel is None:
                disconnect_reason = "no_channel"
                return
            channel.settimeout(self.config.channel_io_timeout)
            if not interface.request_event.wait(self.config.request_timeout):
                disconnect_reason = "no_shell_or_exec_request"
                return

            if interface.exec_command is not None:
                disconnect_reason = run_exec_request(
                    channel,
                    session,
                    interface.exec_command,
                    self.config,
                    self.logger,
                )
            else:
                self.logger.emit("shell_open", session, pty=interface.pty_requested)
                shell = FakeShell(
                    channel,
                    session,
                    self.config,
                    self.logger,
                    interface.pty_requested,
                )
                disconnect_reason = shell.run()
        except (paramiko.SSHException, EOFError, ConnectionError, socket.error) as exc:
            disconnect_reason = f"transport_error:{type(exc).__name__}"
            self.logger.emit(
                "transport_error",
                session,
                component="ssh_transport",
                error=type(exc).__name__,
                error_type=type(exc).__name__,
                message=str(exc)[:512],
            )
        except Exception as exc:  # A malformed session must never stop the listener.
            disconnect_reason = f"internal_error:{type(exc).__name__}"
            self.logger.emit(
                "internal_error",
                session,
                component="ssh_session",
                error=type(exc).__name__,
                error_type=type(exc).__name__,
                message=str(exc)[:512],
            )
        finally:
            try:
                if transport is not None:
                    transport.close()
                else:
                    client.close()
            except Exception:
                pass
            self.logger.disconnect(session, disconnect_reason)

    def _client_worker(self, client: socket.socket, address: tuple[Any, ...]) -> None:
        ip = str(address[0])
        try:
            self._handle_client(client, address)
        finally:
            # Also covers failure while constructing the session, before the
            # handler's own socket cleanup has been installed.
            try:
                client.close()
            except OSError:
                pass
            with self._clients_lock:
                self._clients.discard(client)
            self._gate.release(ip)
            current = threading.current_thread()
            with self._threads_lock:
                self._threads.discard(current)

    def _socket_family(self) -> socket.AddressFamily:
        return socket.AF_INET6 if ":" in self.config.host else socket.AF_INET

    def serve_forever(self) -> None:
        listener = socket.socket(self._socket_family(), socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.config.host, self.config.port))
            listener.listen(self.config.listen_backlog)
            listener.settimeout(1.0)
        except Exception:
            listener.close()
            raise
        with self._listener_lock:
            self._listener = listener
        self.logger.emit(
            "listener_started",
            host=self.config.host,
            port=self.config.port,
            ssh_banner=self.config.ssh_banner,
            host_key_fingerprint=self._host_key_fingerprint,
            **self.config.public_summary(),
        )
        next_metrics = time.monotonic() + 60.0
        try:
            while not self._stopping.is_set():
                try:
                    client, address = listener.accept()
                except socket.timeout:
                    if time.monotonic() >= next_metrics:
                        self.logger.emit(
                            "runtime_metrics",
                            **self._gate.snapshot(),
                            dropped_log_records=self.logger.dropped_records,
                            log_write_errors=self.logger.write_errors,
                        )
                        next_metrics = time.monotonic() + 60.0
                    continue
                except OSError as exc:
                    if self._stopping.is_set():
                        break
                    self.logger.emit(
                        "accept_error",
                        component="ssh_listener",
                        error=type(exc).__name__,
                        error_type=type(exc).__name__,
                        message=str(exc)[:512],
                    )
                    time.sleep(0.25)
                    continue

                ip, source_port = str(address[0]), int(address[1])
                allowed, reason = self._gate.try_acquire(ip)
                if not allowed:
                    self.logger.emit(
                        "connection_rejected",
                        ip=ip,
                        source_port=source_port,
                        reason=reason,
                    )
                    client.close()
                    continue

                with self._clients_lock:
                    self._clients.add(client)
                thread = threading.Thread(
                    target=self._client_worker,
                    args=(client, address),
                    name=f"ssh-session-{ip}-{source_port}",
                    daemon=True,
                )
                with self._threads_lock:
                    self._threads.add(thread)
                try:
                    thread.start()
                except Exception:
                    with self._threads_lock:
                        self._threads.discard(thread)
                    with self._clients_lock:
                        self._clients.discard(client)
                    self._gate.release(ip)
                    client.close()
                    raise
        finally:
            self.stop()
            self._join_workers()
            self.logger.emit(
                "listener_stopped",
                host=self.config.host,
                port=self.config.port,
                **self._gate.snapshot(),
            )

    def _join_workers(self) -> None:
        deadline = time.monotonic() + self.config.shutdown_grace_seconds
        while True:
            with self._threads_lock:
                threads = list(self._threads)
            if not threads or time.monotonic() >= deadline:
                return
            for thread in threads:
                remaining = max(0.0, deadline - time.monotonic())
                thread.join(min(0.2, remaining))

    def stop(self) -> None:
        self._stopping.set()
        with self._listener_lock:
            listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        with self._clients_lock:
            clients = list(self._clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass
