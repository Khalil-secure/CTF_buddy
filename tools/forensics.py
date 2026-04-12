from strands import tool


@tool
def file_inspect(file_path: str) -> dict:
    """
    General inspection of any file. Always call this first on a forensics challenge.
    Identifies file type by magic bytes, extracts strings, checks for hidden data.

    Args:
        file_path: Path to the file to inspect

    Returns:
        File type, magic bytes, entropy, strings preview, and recommended next steps
    """
    import os
    import math
    import struct

    MAGIC_SIGNATURES = {
        b"\xff\xd8\xff": "JPEG image",
        b"\x89PNG\r\n\x1a\n": "PNG image",
        b"GIF87a": "GIF image",
        b"GIF89a": "GIF image",
        b"BM": "BMP image",
        b"PK\x03\x04": "ZIP archive",
        b"PK\x05\x06": "ZIP archive (empty)",
        b"\x1f\x8b": "GZIP archive",
        b"Rar!": "RAR archive",
        b"\x7fELF": "ELF binary",
        b"MZ": "Windows PE/EXE",
        b"%PDF": "PDF document",
        b"\xff\xfe": "UTF-16 LE text",
        b"\xfe\xff": "UTF-16 BE text",
        b"RIFF": "RIFF container (WAV/AVI)",
        b"\x00\x00\x01\xba": "MPEG video",
        b"OggS": "OGG audio",
        b"ID3": "MP3 audio",
        b"SQLite format 3": "SQLite database",
        b"-----BEGIN": "PEM encoded (certificate/key)",
    }

    result = {
        "file": file_path,
        "size_bytes": None,
        "detected_type": "unknown",
        "magic_bytes_hex": None,
        "entropy": None,
        "strings_preview": [],
        "suspicious_strings": [],
        "recommended_next_steps": [],
        "error": None,
    }

    try:
        if not os.path.exists(file_path):
            result["error"] = f"file not found: {file_path}"
            return result

        size = os.path.getsize(file_path)
        result["size_bytes"] = size

        with open(file_path, "rb") as f:
            raw = f.read()

        # Magic bytes
        result["magic_bytes_hex"] = raw[:16].hex()
        for magic, name in MAGIC_SIGNATURES.items():
            if raw.startswith(magic):
                result["detected_type"] = name
                break

        # Entropy (high entropy = compressed/encrypted)
        if raw:
            freq = [0] * 256
            for b in raw:
                freq[b] += 1
            entropy = -sum((f / size) * math.log2(f / size) for f in freq if f > 0)
            result["entropy"] = round(entropy, 3)
            if entropy > 7.5:
                result["recommended_next_steps"].append("high entropy (>7.5) — file may be encrypted or compressed")

        # Extract printable strings (min 4 chars)
        strings = []
        current = []
        for b in raw:
            c = chr(b)
            if c.isprintable() and c not in "\r\n":
                current.append(c)
            else:
                if len(current) >= 4:
                    strings.append("".join(current))
                current = []
        if current and len(current) >= 4:
            strings.append("".join(current))

        result["strings_preview"] = strings[:20]

        # Flag / suspicious patterns
        suspicious_keywords = ["flag{", "ctf{", "password", "passwd", "secret",
                               "key", "token", "admin", "root", "FLAG"]
        for s in strings:
            for kw in suspicious_keywords:
                if kw.lower() in s.lower():
                    result["suspicious_strings"].append(s)
                    break

        # Next steps based on type
        t = result["detected_type"]
        if "image" in t.lower():
            result["recommended_next_steps"].append("image file — try file_check_stego() for hidden data")
        if "ZIP" in t or "RAR" in t or "GZIP" in t:
            result["recommended_next_steps"].append("archive — try extracting contents, may be password protected")
        if "ELF" in t or "PE/EXE" in t:
            result["recommended_next_steps"].append("binary — try file_extract_strings() then reverse engineering")
        if "PDF" in t:
            result["recommended_next_steps"].append("PDF — check for hidden layers, metadata, or embedded files")
        if result["suspicious_strings"]:
            result["recommended_next_steps"].append("suspicious strings found — check suspicious_strings field")

    except Exception as e:
        result["error"] = str(e)

    return result


@tool
def file_extract_strings(file_path: str, min_length: int = 6) -> dict:
    """
    Extract all printable strings from a file.
    Use after file_inspect() on binary/ELF/PE files to find hardcoded secrets or flags.

    Args:
        file_path: Path to the file
        min_length: Minimum string length to return (default 6)

    Returns:
        All printable strings, grouped by length and flagged if suspicious
    """
    import os
    import re

    result = {
        "file": file_path,
        "total_strings": 0,
        "strings": [],
        "flag_candidates": [],
        "error": None,
    }

    try:
        with open(file_path, "rb") as f:
            raw = f.read()

        # ASCII strings
        ascii_strings = re.findall(rb"[ -~]{" + str(min_length).encode() + rb",}", raw)
        # Unicode strings (UTF-16 LE)
        unicode_strings = re.findall(rb"(?:[ -~]\x00){" + str(min_length).encode() + rb",}", raw)

        all_strings = []
        for s in ascii_strings:
            all_strings.append(s.decode("ascii", errors="replace"))
        for s in unicode_strings:
            try:
                all_strings.append(s.decode("utf-16-le").strip())
            except Exception:
                pass

        result["total_strings"] = len(all_strings)
        result["strings"] = all_strings[:100]  # cap at 100

        # Flag patterns
        flag_pattern = re.compile(r"[A-Za-z0-9_]+\{[^}]+\}", re.IGNORECASE)
        for s in all_strings:
            if flag_pattern.search(s):
                result["flag_candidates"].append(s)

    except Exception as e:
        result["error"] = str(e)

    return result


@tool
def file_check_stego(file_path: str) -> dict:
    """
    Check an image file for common steganography techniques.
    Use after file_inspect() identifies an image.

    Checks: LSB patterns, appended data after EOF, EXIF metadata, unusual file size.

    Args:
        file_path: Path to the image file (PNG, JPEG, BMP, etc.)

    Returns:
        Findings for each stego technique checked and recommended tools
    """
    import os
    import struct

    result = {
        "file": file_path,
        "file_size": None,
        "checks": {},
        "recommended_tools": [],
        "error": None,
    }

    try:
        with open(file_path, "rb") as f:
            raw = f.read()

        result["file_size"] = len(raw)

        # Check for appended data after EOF markers
        if raw[:2] == b"\xff\xd8":  # JPEG
            eof_pos = raw.rfind(b"\xff\xd9")
            if eof_pos != -1 and eof_pos < len(raw) - 2:
                appended = raw[eof_pos + 2:]
                result["checks"]["data_after_eof"] = {
                    "found": True,
                    "bytes_appended": len(appended),
                    "preview_hex": appended[:32].hex(),
                    "preview_text": appended[:64].decode("utf-8", errors="replace"),
                }
            else:
                result["checks"]["data_after_eof"] = {"found": False}

        elif raw[:8] == b"\x89PNG\r\n\x1a\n":  # PNG
            iend_pos = raw.rfind(b"IEND")
            if iend_pos != -1:
                after_iend = iend_pos + 8  # IEND chunk is 12 bytes total
                if after_iend < len(raw):
                    appended = raw[after_iend:]
                    result["checks"]["data_after_eof"] = {
                        "found": True,
                        "bytes_appended": len(appended),
                        "preview_hex": appended[:32].hex(),
                        "preview_text": appended[:64].decode("utf-8", errors="replace"),
                    }
                else:
                    result["checks"]["data_after_eof"] = {"found": False}

        # Check EXIF metadata (JPEG)
        if raw[:2] == b"\xff\xd8" and b"Exif" in raw[:2000]:
            exif_pos = raw.find(b"Exif")
            exif_chunk = raw[exif_pos:exif_pos + 512]
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in exif_chunk)
            result["checks"]["exif_metadata"] = {
                "found": True,
                "preview": printable[:200],
            }
            result["recommended_tools"].append("exiftool for full metadata extraction")
        else:
            result["checks"]["exif_metadata"] = {"found": False}

        # Check LSB (look for unusual byte distribution in low bits)
        if len(raw) > 100:
            sample = raw[:min(10000, len(raw))]
            lsb_ones = sum(b & 1 for b in sample)
            lsb_ratio = lsb_ones / len(sample)
            result["checks"]["lsb_analysis"] = {
                "lsb_ones_ratio": round(lsb_ratio, 3),
                "note": "ratio near 0.5 is normal; far from 0.5 may indicate LSB steganography",
                "suspicious": abs(lsb_ratio - 0.5) > 0.1,
            }
            if result["checks"]["lsb_analysis"]["suspicious"]:
                result["recommended_tools"].append("steghide, zsteg, or stegsolve for LSB extraction")

        # Check for embedded ZIP/archive
        for magic, name in [(b"PK\x03\x04", "ZIP"), (b"\x1f\x8b", "GZIP"), (b"Rar!", "RAR")]:
            pos = raw.find(magic, 100)  # skip file header
            if pos != -1:
                result["checks"][f"embedded_{name.lower()}"] = {
                    "found": True,
                    "offset": pos,
                    "note": f"{name} archive signature found inside image at offset {pos}",
                }
                result["recommended_tools"].append(f"binwalk to extract embedded {name}")

        if not result["recommended_tools"]:
            result["recommended_tools"] = ["steghide (try empty passphrase)", "stegsolve", "binwalk"]

    except Exception as e:
        result["error"] = str(e)

    return result


@tool
def file_extract_metadata(file_path: str) -> dict:
    """
    Extract metadata from a file (images, PDFs, Office docs).
    Useful for finding author names, creation dates, software versions, GPS coordinates.

    Args:
        file_path: Path to the file

    Returns:
        All metadata fields found
    """
    result = {"file": file_path, "metadata": {}, "error": None}

    try:
        from PIL import Image
        from PIL.ExifTags import TAGS

        img = Image.open(file_path)
        result["metadata"]["format"] = img.format
        result["metadata"]["mode"] = img.mode
        result["metadata"]["size"] = img.size

        exif_data = img._getexif() if hasattr(img, "_getexif") and img._getexif() else {}
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                result["metadata"][str(tag)] = str(value)

    except ImportError:
        result["error"] = "Pillow not installed — run: pip install Pillow"
    except Exception:
        # Fallback: read raw bytes and extract printable metadata-like strings
        try:
            with open(file_path, "rb") as f:
                raw = f.read(4096)
            import re
            strings = re.findall(rb"[ -~]{6,}", raw)
            result["metadata"]["raw_strings"] = [s.decode("ascii", errors="replace") for s in strings[:30]]
        except Exception as e:
            result["error"] = str(e)

    return result
