"""
Crypto / encoding tools for CTF challenges.
Covers: hash cracking (hashcat), base64, URL-decode, caesar cipher.
"""

import base64
import hashlib
import hmac
import json
import tempfile
import urllib.parse
from pathlib import Path
from string import ascii_lowercase, ascii_uppercase

from sandbox import safe_run

TMP = Path(tempfile.gettempdir())

DEFAULT_WORDLIST = str(Path(__file__).parent.parent / "wordlists" / "rockyou.txt")

# hashcat mode reference
HASH_MODES = {
    "md5":        0,
    "sha1":       100,
    "sha256":     1400,
    "sha512":     1700,
    "ntlm":       1000,
    "cisco_md5":  500,
    "cisco_sha1": 5800,
    "bcrypt":     3200,
    "wpa2":       22000,
    "krb5pa_18":  19900,
}


# ─────────────────────────────────────────────────────────────
# TOOL 5: Generic hash cracker
# Root-Me: CISCO, NTLM, MD5, etc.
# ─────────────────────────────────────────────────────────────

def hash_crack(hash_value: str, mode: int | str, wordlist: str = DEFAULT_WORDLIST) -> dict:
    """
    Crack a hash using hashcat.
    mode can be an integer (hashcat mode) or a string key from HASH_MODES.
    """
    result = {"password": None, "hash": hash_value, "mode": mode, "error": None}
    try:
        if isinstance(mode, str):
            if mode.lower() not in HASH_MODES:
                result["error"] = f"Unknown mode '{mode}'. Known: {list(HASH_MODES.keys())}"
                return result
            mode = HASH_MODES[mode.lower()]

        hash_file = str(TMP / "ctf_buddy_hash.txt")
        Path(hash_file).write_text(hash_value.strip())

        # Check potfile first
        show = safe_run([
            "hashcat", "-m", str(mode), hash_file, wordlist, "--force", "--show",
        ], capture_output=True, text=True)

        if show.stdout.strip():
            result["password"] = show.stdout.strip().split(":")[-1]
            return result

        # Actually crack
        safe_run([
            "hashcat", "-m", str(mode), hash_file, wordlist, "--force",
        ], capture_output=True)

        show2 = safe_run([
            "hashcat", "-m", str(mode), hash_file, wordlist, "--force", "--show",
        ], capture_output=True, text=True)

        if show2.stdout.strip():
            result["password"] = show2.stdout.strip().split(":")[-1]
        else:
            result["error"] = "Wordlist exhausted — hash not cracked"

    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────
# TOOL 6: Credential decoder (base64, URL-encoded)
# Root-Me: HTTP Basic Auth, Twitter auth, OAuth
# ─────────────────────────────────────────────────────────────

def decode_credentials(encoded: str) -> dict:
    """
    Decode base64 / URL-encoded credential strings.
    Tries URL-decode → base64 → split on ':' for user:password.
    """
    result = {"decoded": None, "username": None, "password": None, "steps": [], "error": None}
    try:
        s = encoded.strip()

        # Step 1: strip common prefixes
        for prefix in ("Basic ", "Bearer ", "basic ", "bearer "):
            if s.startswith(prefix):
                s = s[len(prefix):]
                result["steps"].append(f"Stripped prefix: '{prefix.strip()}'")
                break

        # Step 2: URL-decode (handle double-encoding)
        url1 = urllib.parse.unquote(s)
        if url1 != s:
            s = url1
            result["steps"].append("URL-decoded (single)")
        url2 = urllib.parse.unquote(s)
        if url2 != s:
            s = url2
            result["steps"].append("URL-decoded (double)")

        # Step 3: base64 decode (pad as needed)
        padded = s + "=" * ((4 - len(s) % 4) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
        result["decoded"] = decoded
        result["steps"].append(f"Base64 decoded → '{decoded}'")

        if ":" in decoded:
            result["username"], result["password"] = decoded.split(":", 1)

    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────
# TOOL 7: Base64 decode (raw)
# ─────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────
# TOOL: Pure-Python NTLMv2 cracker (no hashcat required)
# ─────────────────────────────────────────────────────────────

def ntlmv2_crack(ntlmv2_hash: str, wordlist: str = DEFAULT_WORDLIST) -> dict:
    """
    Crack an NTLMv2 hash using a pure-Python dictionary attack.
    No hashcat required.

    NTLMv2 format (hashcat mode 5600):
      username::domain:ServerChallenge:NTProofStr:blob

    Algorithm:
      NT = MD4(UTF-16-LE(password))
      ResponseKeyNT = HMAC-MD5(NT, UTF-16-LE(upper(username) + domain))
      NTProofStr = HMAC-MD5(ResponseKeyNT, ServerChallenge_bytes + Blob_bytes)
    """
    result = {"password": None, "hash": ntlmv2_hash, "error": None}
    try:
        # Parse the hash
        parts = ntlmv2_hash.strip().split(":")
        if len(parts) < 6:
            result["error"] = f"Invalid NTLMv2 format — expected 6 colon-separated parts, got {len(parts)}"
            return result

        # username::domain:ServerChallenge:NTProofStr:blob
        username   = parts[0]
        domain     = parts[2]
        challenge  = bytes.fromhex(parts[3])
        ntproofstr = bytes.fromhex(parts[4])
        blob       = bytes.fromhex(parts[5])

        def _md4(data: bytes) -> bytes:
            """MD4 via hashlib (Python 3.6+ includes it via OpenSSL)."""
            h = hashlib.new("md4")
            h.update(data)
            return h.digest()

        def _hmac_md5(key: bytes, msg: bytes) -> bytes:
            return hmac.new(key, msg, hashlib.md5).digest()

        target_user = (username.upper() + domain).encode("utf-16-le")

        with open(wordlist, "rb") as f:
            for line in f:
                pw = line.rstrip(b"\n\r")
                try:
                    nt_hash        = _md4(pw.decode("latin-1").encode("utf-16-le"))
                    response_key   = _hmac_md5(nt_hash, target_user)
                    computed_proof = _hmac_md5(response_key, challenge + blob)
                    if computed_proof == ntproofstr:
                        result["password"] = pw.decode("latin-1")
                        return result
                except Exception:
                    continue

        result["error"] = "Wordlist exhausted — password not found"

    except Exception as e:
        result["error"] = str(e)
    return result


def base64_decode(encoded: str) -> dict:
    """Decode a raw base64 string."""
    result = {"decoded": None, "error": None}
    try:
        padded = encoded.strip() + "=" * ((4 - len(encoded.strip()) % 4) % 4)
        result["decoded"] = base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────
# TOOL 8: Caesar / ROT-N brute force
# ─────────────────────────────────────────────────────────────

def caesar_crack(ciphertext: str, shift: int | None = None) -> dict:
    """
    Brute-force all 26 ROT shifts of a caesar cipher.
    If shift is given, return only that rotation.
    """
    result = {"results": [], "best_guess": None, "error": None}
    try:
        common_words = {"the", "flag", "ctf", "password", "secret", "key", "and", "for", "are"}

        def rotate(text: str, n: int) -> str:
            out = []
            for ch in text:
                if ch in ascii_lowercase:
                    out.append(ascii_lowercase[(ascii_lowercase.index(ch) + n) % 26])
                elif ch in ascii_uppercase:
                    out.append(ascii_uppercase[(ascii_uppercase.index(ch) + n) % 26])
                else:
                    out.append(ch)
            return "".join(out)

        shifts_to_try = [shift] if shift is not None else range(26)
        best_score = -1

        for n in shifts_to_try:
            rotated = rotate(ciphertext, n)
            words = set(rotated.lower().split())
            score = len(words & common_words)
            entry = {"shift": n, "text": rotated, "score": score}
            result["results"].append(entry)

            if score > best_score:
                best_score = score
                result["best_guess"] = entry

        result["results"].sort(key=lambda x: x["score"], reverse=True)

    except Exception as e:
        result["error"] = str(e)
    return result
