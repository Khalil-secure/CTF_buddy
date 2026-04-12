#!/usr/bin/env python3
"""Root entry point — delegates to CTF_buddy/main.py."""

import sys
from pathlib import Path

_root = Path(__file__).resolve().parent
_pkg = _root / "CTF_buddy"

# CTF_buddy/main.py uses bare imports (e.g. `from agent import run`)
# so the package directory must be first on the path.
for _p in [str(_pkg), str(_root)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from CTF_buddy.main import main  # noqa: E402

if __name__ == "__main__":
    main()
