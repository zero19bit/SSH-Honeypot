"""Container health probe: test that the configured SSH listener accepts TCP."""

from __future__ import annotations

import os
import socket


def main() -> int:
    try:
        port = int(os.environ.get("HONEYPOT_PORT", "2222"))
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            return 0
    except (OSError, ValueError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
