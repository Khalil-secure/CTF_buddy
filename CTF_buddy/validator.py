"""
Flag validator — detects CTF flag patterns in tool output.
Covers Root-Me, HackTheBox, CTFtime, and generic formats.
"""

import re

FLAG_PATTERNS = [
    r"CTF\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"ROOTME\{[^}]+\}",
    r"THM\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    # Generic: looks like a flag word near braces
    r"\b\w+\{[A-Za-z0-9_\-!@#$%^&*()+=.<>?/\\|~` ]+\}",
]

# Secondary: raw hashes / passwords that ARE the flag
HASH_PATTERNS = [
    r"\b[a-f0-9]{32}\b",   # MD5
    r"\b[a-f0-9]{40}\b",   # SHA1
    r"\b[a-f0-9]{64}\b",   # SHA256
]


TOOL_RESULT_KEYS = ["key", "password", "decoded", "secret"]

def find_flag(text: str) -> str | None:
    """Return the first flag-like string found in text, or None."""
    # Check standard flag patterns
    for pattern in FLAG_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return match.group()

    # Check for tool result keys with non-null values (e.g. ospf key, cracked password)
    try:
        import json
        data = json.loads(text)
        for key in TOOL_RESULT_KEYS:
            if data.get(key):
                return str(data[key])
    except Exception:
        pass

    # Check for "FLAG: <value>" explicitly stated by Claude
    match = re.search(r"FLAG:\s*[`*]*([^\n`*]+)[`*]*", text)
    if match:
        return match.group(1).strip()

    return None


def find_hash(text: str) -> str | None:
    """Return the first hash-like string found in text, or None."""
    for pattern in HASH_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return match.group()
    return None


def is_flag(text: str) -> bool:
    return find_flag(text) is not None


def highlight(text: str) -> str:
    """Wrap flag patterns in [FLAG: ...] markers for display."""
    flag = find_flag(text)
    if flag:
        return text.replace(flag, f"\n\n🚩 FLAG FOUND: {flag}\n\n")
    return text
