"""Report missing development tools before pytest imports test modules."""

from importlib.metadata import PackageNotFoundError, version

import pytest


def pytest_sessionstart(session: pytest.Session) -> None:
    """Run once from the root conftest before pytest starts collection."""
    required = ("pytest", "paramiko", "pip-audit")
    missing = []
    for distribution in required:
        try:
            version(distribution)
        except PackageNotFoundError:
            missing.append(distribution)

    if missing:
        raise pytest.UsageError(
            "Missing development dependencies: " + ", ".join(missing) + ".\n"
            "From the project root, install them and retry:\n"
            "  python3 -m venv .venv\n"
            "  source .venv/bin/activate\n"
            "  pip install -r requirements-dev.txt\n"
            "  pytest -q"
        )
