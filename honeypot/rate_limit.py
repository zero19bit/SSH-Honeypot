"""Thread-safe connection admission control with token buckets."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float
    last_seen: float


class ConnectionGate:
    """Bound active sessions and connection rates globally and per source IP."""

    def __init__(
        self,
        *,
        max_total: int,
        max_per_ip: int,
        global_rate_per_minute: float,
        global_burst: int,
        per_ip_rate_per_minute: float,
        per_ip_burst: int,
        bucket_ttl_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_total = max_total
        self.max_per_ip = max_per_ip
        self.global_rate = global_rate_per_minute / 60.0
        self.global_burst = float(global_burst)
        self.per_ip_rate = per_ip_rate_per_minute / 60.0
        self.per_ip_burst = float(per_ip_burst)
        self.bucket_ttl_seconds = bucket_ttl_seconds
        self._clock = clock
        now = clock()
        self._global = _Bucket(self.global_burst, now, now)
        self._per_ip: dict[str, _Bucket] = {}
        self._active_by_ip: dict[str, int] = {}
        self._active_total = 0
        self._lock = threading.Lock()
        self._decisions = 0

    @staticmethod
    def _refill(bucket: _Bucket, now: float, rate: float, burst: float) -> None:
        elapsed = max(0.0, now - bucket.updated)
        bucket.tokens = min(burst, bucket.tokens + elapsed * rate)
        bucket.updated = now
        bucket.last_seen = now

    def try_acquire(self, ip: str) -> tuple[bool, str]:
        now = self._clock()
        with self._lock:
            self._decisions += 1
            self._refill(self._global, now, self.global_rate, self.global_burst)
            bucket = self._per_ip.get(ip)
            if bucket is None:
                bucket = _Bucket(self.per_ip_burst, now, now)
                self._per_ip[ip] = bucket
            self._refill(bucket, now, self.per_ip_rate, self.per_ip_burst)

            if self._active_total >= self.max_total:
                return False, "global_connection_limit"
            if self._active_by_ip.get(ip, 0) >= self.max_per_ip:
                return False, "per_ip_connection_limit"
            if self._global.tokens < 1.0:
                return False, "global_rate_limit"
            if bucket.tokens < 1.0:
                return False, "per_ip_rate_limit"

            self._global.tokens -= 1.0
            bucket.tokens -= 1.0
            self._active_total += 1
            self._active_by_ip[ip] = self._active_by_ip.get(ip, 0) + 1
            if self._decisions % 256 == 0:
                self._cleanup(now)
            return True, "accepted"

    def release(self, ip: str) -> None:
        with self._lock:
            count = self._active_by_ip.get(ip, 0)
            if count <= 1:
                self._active_by_ip.pop(ip, None)
            else:
                self._active_by_ip[ip] = count - 1
            self._active_total = max(0, self._active_total - 1)

    def _cleanup(self, now: float) -> None:
        expired = [
            ip
            for ip, bucket in self._per_ip.items()
            if ip not in self._active_by_ip and now - bucket.last_seen > self.bucket_ttl_seconds
        ]
        for ip in expired:
            del self._per_ip[ip]

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "active_connections": self._active_total,
                "active_source_ips": len(self._active_by_ip),
                "tracked_source_ips": len(self._per_ip),
            }

