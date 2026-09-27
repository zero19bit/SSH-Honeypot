"""Generate a stable RSA host key as one base64 environment value."""

from __future__ import annotations

import base64
import io
import sys

import paramiko


def generate_host_key_b64(bits: int = 3072) -> str:
    if not 2048 <= bits <= 8192:
        raise ValueError("bits must be between 2048 and 8192")
    key = paramiko.RSAKey.generate(bits)
    buffer = io.StringIO()
    key.write_private_key(buffer)
    return base64.b64encode(buffer.getvalue().encode("ascii")).decode("ascii")


def main() -> None:
    bits = 3072
    if len(sys.argv) > 1:
        bits = int(sys.argv[1])
    sys.stdout.write(generate_host_key_b64(bits) + "\n")


if __name__ == "__main__":
    main()

