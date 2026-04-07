#!/usr/bin/env python3
"""Root launcher for the nested CTF Buddy app."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


PROJECT_MAIN = Path(__file__).resolve().parent / "CTF_buddy" / "main.py"


if __name__ == "__main__":
    if not PROJECT_MAIN.exists():
        raise SystemExit(f"Could not find project entrypoint at {PROJECT_MAIN}")

    sys.path.insert(0, str(PROJECT_MAIN.parent))
    runpy.run_path(str(PROJECT_MAIN), run_name="__main__")
