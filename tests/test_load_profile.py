from concurrent.futures import ThreadPoolExecutor

from honeypot.commands import CommandSimulator
from honeypot.rate_limit import ConnectionGate
from honeypot.session import SessionState


def test_parallel_sessions_keep_virtual_state_isolated() -> None:
    def exercise(index: int) -> tuple[str, bool, int]:
        session = SessionState(f"192.0.2.{index + 1}", 40000 + index, username="root")
        simulator = CommandSimulator(session)
        path = f"/tmp/session-{index}"
        result = simulator.execute(f"touch {path}")
        return path, session.filesystem.exists(path), result.exit_status

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(exercise, range(64)))
    assert all(exists and status == 0 for _, exists, status in results)
    assert len({path for path, _, _ in results}) == 64


def test_connection_gate_is_thread_safe_under_burst() -> None:
    gate = ConnectionGate(
        max_total=20,
        max_per_ip=2,
        global_rate_per_minute=60000,
        global_burst=20,
        per_ip_rate_per_minute=60000,
        per_ip_burst=2,
        bucket_ttl_seconds=60,
    )

    def attempt(index: int) -> tuple[str, bool]:
        ip = f"198.51.100.{index % 10}"
        accepted, _ = gate.try_acquire(ip)
        return ip, accepted

    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(attempt, range(100)))
    accepted = [item for item in results if item[1]]
    assert len(accepted) <= 20
    assert all(sum(1 for candidate, ok in accepted if candidate == ip and ok) <= 2 for ip, _ in accepted)
