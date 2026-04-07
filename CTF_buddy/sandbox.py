"""
Execution sandbox — enforces allowed/forbidden operation boundaries.
All subprocess calls from tools must go through safe_run().
"""

import subprocess
from pathlib import Path

ALLOWED_COMMANDS = {
    "tshark", "hashcat", "dig", "john", "python3", "python",
    "scapy", "tcpdump",
}

FORBIDDEN_PATTERNS = [
    "rm -rf", "dd if=", "; rm", "| rm",
    "curl ", "wget ", "nc ", "netcat",
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    ">/dev/", "mkfs", "chmod 777",
]

ALLOWED_WRITE_DIRS = ["/tmp", "/tmp/ctf_buddy"]


def safe_run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess only if the binary is in the allowlist."""
    binary = Path(str(cmd[0])).name
    if binary not in ALLOWED_COMMANDS:
        raise PermissionError(
            f"[SANDBOX] Command '{binary}' is not allowed.\n"
            f"Allowed: {', '.join(sorted(ALLOWED_COMMANDS))}"
        )

    cmd_str = " ".join(str(c) for c in cmd)
    for pattern in FORBIDDEN_PATTERNS:
        if pattern in cmd_str:
            raise PermissionError(
                f"[SANDBOX] Forbidden pattern detected in command: '{pattern}'"
            )

    return subprocess.run(cmd, **kwargs)


def validate_path(path: str, must_exist: bool = True) -> Path:
    """Validate a file path is accessible and safe."""
    p = Path(path).resolve()
    if must_exist and not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not p.is_file() and must_exist:
        raise ValueError(f"Not a file: {path}")
    return p
