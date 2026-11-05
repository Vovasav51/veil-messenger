#!/usr/bin/env python3
"""Build a single-file, dependency-free executable: ``dist/veil-relay.pyz``.

The output lands in the repository root ``dist/`` (the documented artifact path),
not next to this script.

Usage:
    python3 server/build_zipapp.py [--output PATH]

The archive embeds the ``veil_relay`` package and a ``__main__.py`` shim, so it
runs on any Linux with Python 3.11+ and needs nothing installed:

    python3 dist/veil-relay.pyz --host 127.0.0.1 --port 8787 --db /path/relay.sqlite3
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
REPO_ROOT = SERVER_DIR.parent
DEFAULT_OUTPUT = REPO_ROOT / "dist" / "veil-relay.pyz"
MIN_PYTHON = (3, 11)

ENTRY_POINT = """#!/usr/bin/env python3
import sys

from veil_relay.cli import main

if __name__ == "__main__":
    sys.exit(main())
"""


def build(output: Path = DEFAULT_OUTPUT) -> Path:
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="veil-zipapp-") as tmp:
        stage = Path(tmp) / "app"
        stage.mkdir()
        shutil.copytree(
            SERVER_DIR / "veil_relay",
            stage / "veil_relay",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        (stage / "__main__.py").write_text(ENTRY_POINT, encoding="utf-8")
        if output.exists():
            output.unlink()
        zipapp.create_archive(
            stage,
            target=output,
            interpreter="/usr/bin/env python3",
            compressed=True,
        )

    output.chmod(0o755)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"target archive (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args(argv)

    if sys.version_info < MIN_PYTHON:
        print(
            f"build_zipapp: Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required",
            file=sys.stderr,
        )
        return 1

    target = build(args.output)
    size = target.stat().st_size
    print(f"built {target} ({size} bytes)")
    print(f"run: python3 {target} --host 127.0.0.1 --port 8787 --db /path/relay.sqlite3")
    return 0


if __name__ == "__main__":
    sys.exit(main())
