from strands import tool


@tool
def encoding_identify(data: str) -> dict:
    """
    Analyse a string and identify what encoding it likely is, without decoding it yet.
    Call this first — it tells you which specific decoder to use next.

    Args:
        data: The string to analyse

    Returns:
        Most likely encoding, confidence, visual clues, and which tool to call next
    """
    import re

    h = data.strip()
    length = len(h)
    clues = []
    candidates = []

    # Base64 clues
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    b64_urlsafe_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
    if set(h) <= b64_chars and length % 4 == 0:
        candidates.append({"encoding": "base64", "confidence": "high", "tool": "decode_base64"})
        clues.append("only base64 chars, correct padding length")
    elif set(h) <= b64_urlsafe_chars and "-" in h or "_" in h:
        candidates.append({"encoding": "base64_urlsafe", "confidence": "high", "tool": "decode_base64"})
        clues.append("contains - or _ which are URL-safe base64 chars")

    # Hex clues
    clean_hex = h.replace(" ", "").replace("0x", "").replace("\\x", "").replace(":", "")
    if all(c in "0123456789abcdefABCDEF" for c in clean_hex) and len(clean_hex) % 2 == 0:
        candidates.append({"encoding": "hex", "confidence": "high", "tool": "decode_hex"})
        clues.append("only hex chars, even length")

    # Binary clues
    groups = h.split()
    if all(len(g) == 8 and set(g) <= {"0", "1"} for g in groups):
        candidates.append({"encoding": "binary", "confidence": "high", "tool": "decode_binary"})
        clues.append("space-separated 8-bit groups")

    # URL encoded clues
    if "%" in h and re.search(r"%[0-9A-Fa-f]{2}", h):
        candidates.append({"encoding": "url", "confidence": "high", "tool": "decode_url"})
        clues.append("contains %XX percent-encoded sequences")

    # ROT13 — looks like English but letters are shifted
    alpha_ratio = sum(1 for c in h if c.isalpha()) / max(length, 1)
    if alpha_ratio > 0.7 and not h.isascii() is False:
        candidates.append({"encoding": "rot13", "confidence": "medium", "tool": "decode_rot"})
        clues.append("mostly alphabetic — could be ROT13 or Caesar shift")

    # Hash clues
    is_hex_only = all(c in "0123456789abcdefABCDEF" for c in h)
    if is_hex_only and length in (32, 40, 56, 64, 96, 128):
        candidates.append({"encoding": "hash", "confidence": "high", "tool": "hash_identify"})
        clues.append(f"hex string of length {length} matches a known hash size")

    if not candidates:
        candidates.append({"encoding": "unknown", "confidence": "low", "tool": "none — inspect manually"})
        clues.append("no pattern matched — may be a custom or chained encoding")

    return {
        "input_preview": h[:80] + ("..." if length > 80 else ""),
        "length": length,
        "clues": clues,
        "candidates": candidates,
        "top_recommendation": candidates[0],
    }


@tool
def decode_base64(data: str) -> dict:
    """
    Decode a Base64 or Base64 URL-safe string.
    Handles missing padding automatically.

    Args:
        data: Base64-encoded string (standard or URL-safe)

    Returns:
        Decoded text, or hex representation if the result is binary
    """
    import base64

    result = {"input": data, "decoded_text": None, "decoded_hex": None, "error": None}
    try:
        clean = data.strip().replace(" ", "")
        # Normalise URL-safe to standard
        clean = clean.replace("-", "+").replace("_", "/")
        clean += "=" * (-len(clean) % 4)
        raw = base64.b64decode(clean)
        result["decoded_hex"] = raw.hex()
        result["decoded_text"] = raw.decode("utf-8")
    except UnicodeDecodeError:
        result["decoded_text"] = "(binary data — see decoded_hex)"
    except Exception as e:
        result["error"] = str(e)
    return result


@tool
def decode_hex(data: str) -> dict:
    """
    Decode a hex-encoded string to text or bytes.
    Handles 0x prefix, \\x escapes, colon-separated, and plain hex.

    Args:
        data: Hex string in any common format

    Returns:
        Decoded text and raw hex bytes
    """
    result = {"input": data, "decoded_text": None, "decoded_hex": None, "error": None}
    try:
        clean = data.strip().replace(" ", "").replace("0x", "").replace("\\x", "").replace(":", "")
        raw = bytes.fromhex(clean)
        result["decoded_hex"] = raw.hex()
        result["decoded_text"] = raw.decode("utf-8")
    except UnicodeDecodeError:
        result["decoded_text"] = "(binary data — see decoded_hex)"
    except Exception as e:
        result["error"] = str(e)
    return result


@tool
def decode_rot(data: str, shift: int = 13) -> dict:
    """
    Decode a ROT/Caesar cipher. Defaults to ROT13.
    If shift=0, brute forces all 25 shifts and returns all results.

    Args:
        data: The encoded text
        shift: Number of positions to shift (1-25). Use 0 to brute force all shifts.

    Returns:
        Decoded text for the given shift, or all 25 shifts if shift=0
    """
    def caesar(text, n):
        out = ""
        for c in text:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                out += chr((ord(c) - base + n) % 26 + base)
            else:
                out += c
        return out

    if shift == 0:
        return {
            "input": data,
            "all_shifts": {f"shift_{i}": caesar(data, i) for i in range(1, 26)}
        }

    return {
        "input": data,
        "shift": shift,
        "decoded": caesar(data, shift),
    }


@tool
def decode_binary(data: str) -> dict:
    """
    Decode binary (space-separated 8-bit groups) to text.

    Args:
        data: Binary string like '01101000 01100101 01101100 01101100 01101111'

    Returns:
        Decoded text
    """
    result = {"input": data, "decoded_text": None, "error": None}
    try:
        groups = data.strip().split()
        result["decoded_text"] = "".join(chr(int(g, 2)) for g in groups)
    except Exception as e:
        result["error"] = str(e)
    return result


@tool
def decode_url(data: str) -> dict:
    """
    URL-decode a percent-encoded string.

    Args:
        data: URL-encoded string like 'hello%20world'

    Returns:
        Decoded text
    """
    import urllib.parse
    result = {"input": data, "decoded_text": None, "error": None}
    try:
        result["decoded_text"] = urllib.parse.unquote(data)
    except Exception as e:
        result["error"] = str(e)
    return result


@tool
def hash_identify(hash_string: str) -> dict:
    """
    Identify the type of a hash and get the hashcat mode for cracking.
    Call this before attempting to crack any hash.

    Args:
        hash_string: The hash to identify

    Returns:
        Possible hash types with hashcat modes and suggested next steps
    """
    h = hash_string.strip()
    length = len(h)
    is_hex = all(c in "0123456789abcdefABCDEF" for c in h)

    candidates = []

    if is_hex:
        if length == 32:
            candidates += [{"type": "MD5", "hashcat_mode": 0}, {"type": "NTLM", "hashcat_mode": 1000}]
        elif length == 40:
            candidates.append({"type": "SHA1", "hashcat_mode": 100})
        elif length == 56:
            candidates.append({"type": "SHA224", "hashcat_mode": 1300})
        elif length == 64:
            candidates.append({"type": "SHA256", "hashcat_mode": 1400})
        elif length == 96:
            candidates.append({"type": "SHA384", "hashcat_mode": 10800})
        elif length == 128:
            candidates.append({"type": "SHA512", "hashcat_mode": 1700})

    if h.startswith("$2b$") or h.startswith("$2a$"):
        candidates.append({"type": "bcrypt", "hashcat_mode": 3200})
    if h.startswith("$6$"):
        candidates.append({"type": "SHA512crypt", "hashcat_mode": 1800})
    if h.startswith("$5$"):
        candidates.append({"type": "SHA256crypt", "hashcat_mode": 7400})
    if h.startswith("$1$"):
        candidates.append({"type": "MD5crypt", "hashcat_mode": 500})
    if "::" in h and len(h.split(":")) >= 5:
        candidates.append({"type": "NTLMv2", "hashcat_mode": 5600})
    if h.startswith("$krb5pa$"):
        candidates.append({"type": "Kerberos pre-auth", "hashcat_mode": 19900})

    return {
        "hash": h,
        "length": length,
        "candidates": candidates if candidates else [{"type": "unknown — inspect manually", "hashcat_mode": None}],
        "next_step": "run hashcat with the matching mode and rockyou.txt",
    }
