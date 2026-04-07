"""
Tool registry — Claude tool schemas + dispatcher.
Add new tools here: define the schema, map the function.
"""

import json

from .network import (
    pcap_inspect,
    pcap_sniff_credentials,
    kerberos_crack,
    dns_zone_transfer,
    ospf_crack,
    ntlm_extract,
)
from .crypto import hash_crack, decode_credentials, base64_decode, caesar_crack, ntlmv2_crack, HASH_MODES

# ─── Claude tool schemas ───────────────────────────────────────────────────────

TOOL_SCHEMAS = [
    {
        "name": "pcap_inspect",
        "description": (
            "Universal pcap analyser — your FIRST call on any network capture challenge. "
            "Detects all known auth protocols in one pass: NTLM/NTLMv2, OSPF/MD5, "
            "FTP cleartext, Telnet streams, HTTP Basic Auth, Kerberos. "
            "Returns structured findings and recommended next steps. "
            "No external tools required — pure scapy. "
            "After calling this, use the appropriate cracking/decoding tool based on what was found."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pcap_path": {
                    "type": "string",
                    "description": "Absolute path to the pcap/pcapng file",
                },
            },
            "required": ["pcap_path"],
        },
    },
    {
        "name": "pcap_sniff",
        "description": (
            "Extract cleartext credentials from a pcap/pcapng file. "
            "Handles FTP USER/PASS, Telnet TCP streams, HTTP Basic Auth, and OAuth tokens. "
            "Use for challenges involving FTP auth, Telnet auth, Twitter auth, HTTP captures."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pcap_path": {
                    "type": "string",
                    "description": "Absolute or relative path to the pcap/pcapng file",
                },
            },
            "required": ["pcap_path"],
        },
    },
    {
        "name": "kerberos_crack",
        "description": (
            "Extract Kerberos pre-authentication hash (etype 18, AES-256) from a pcap file "
            "and crack it with hashcat mode 19900. "
            "Use for challenges involving Kerberos authentication captures."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pcap_path": {
                    "type": "string",
                    "description": "Path to pcap/pcapng file containing Kerberos traffic",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file (default: wordlists/rockyou.txt)",
                },
            },
            "required": ["pcap_path"],
        },
    },
    {
        "name": "dns_enum",
        "description": (
            "Perform a DNS AXFR zone transfer against a nameserver. "
            "Extracts all records and flags TXT records that may contain the flag. "
            "Use for DNS zone transfer challenges."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The domain to transfer (e.g. 'ch11.challenge01.root-me.org')",
                },
                "server": {
                    "type": "string",
                    "description": "The nameserver IP or hostname to query",
                },
                "port": {
                    "type": "integer",
                    "description": "DNS port (default 53; challenges often use non-standard ports)",
                },
            },
            "required": ["domain", "server"],
        },
    },
    {
        "name": "ospf_crack",
        "description": (
            "Crack OSPF MD5 authentication key from a pcap using a dictionary attack. "
            "Computes md5(first_48_bytes + password) and compares to the observed 16-byte hash. "
            "Use for OSPF authentication challenges."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pcap_path": {
                    "type": "string",
                    "description": "Path to pcap/pcapng file with OSPF traffic",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist (default: wordlists/rockyou.txt)",
                },
            },
            "required": ["pcap_path"],
        },
    },
    {
        "name": "ntlm_extract",
        "description": (
            "Extract NTLMv2 hash from a pcap file using scapy (no tshark required). "
            "Parses NTLMSSP Type 2 (server challenge) and Type 3 (authenticate) messages "
            "and formats the result as a hashcat-ready NTLMv2 string (mode 5600). "
            "Use for NTLM authentication challenges."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pcap_path": {
                    "type": "string",
                    "description": "Path to pcap/pcapng file containing NTLM traffic",
                },
            },
            "required": ["pcap_path"],
        },
    },
    {
        "name": "ntlmv2_crack",
        "description": (
            "Crack an NTLMv2 hash using a pure-Python dictionary attack — no hashcat required. "
            "Input format (hashcat mode 5600): username::domain:ServerChallenge:NTProofStr:blob. "
            "Algorithm: NT=MD4(UTF-16-LE(password)), ResponseKeyNT=HMAC-MD5(NT, UTF-16-LE(upper(user)+domain)), "
            "NTProofStr=HMAC-MD5(ResponseKeyNT, challenge+blob). "
            "Use after pcap_inspect detects NTLM and provides the NTLMv2 hash."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ntlmv2_hash": {
                    "type": "string",
                    "description": "NTLMv2 hash in hashcat mode 5600 format: username::domain:ServerChallenge:NTProofStr:blob",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist (default: wordlists/rockyou.txt)",
                },
            },
            "required": ["ntlmv2_hash"],
        },
    },
    {
        "name": "hash_crack",
        "description": (
            "Crack a password hash using hashcat with a wordlist. "
            f"Supported mode names: {list(HASH_MODES.keys())}. "
            "You can also pass an integer hashcat mode directly."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hash_value": {
                    "type": "string",
                    "description": "The hash to crack (raw hash or hashcat format)",
                },
                "mode": {
                    "type": ["string", "integer"],
                    "description": (
                        "Hashcat mode as integer (e.g. 0 for MD5) or "
                        f"named string from: {list(HASH_MODES.keys())}"
                    ),
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist (default: wordlists/rockyou.txt)",
                },
            },
            "required": ["hash_value", "mode"],
        },
    },
    {
        "name": "decode",
        "description": (
            "Decode base64 and/or URL-encoded credential strings. "
            "Strips 'Basic'/'Bearer' prefixes, URL-decodes (handles double-encoding), "
            "then base64-decodes, and splits on ':' for user:password. "
            "Use for HTTP Basic Auth, Twitter OAuth, and similar encoding challenges."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "encoded": {
                    "type": "string",
                    "description": "The encoded credential string to decode",
                },
            },
            "required": ["encoded"],
        },
    },
    {
        "name": "base64_decode",
        "description": "Decode a raw base64 string to plaintext.",
        "input_schema": {
            "type": "object",
            "properties": {
                "encoded": {"type": "string", "description": "Base64-encoded string"},
            },
            "required": ["encoded"],
        },
    },
    {
        "name": "caesar_crack",
        "description": (
            "Brute-force all 26 ROT shifts of a caesar/ROT cipher. "
            "Returns all rotations sorted by English word score, with the best guess. "
            "Optionally pass a specific shift (e.g. 13 for ROT13)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ciphertext": {
                    "type": "string",
                    "description": "The ciphertext to decrypt",
                },
                "shift": {
                    "type": "integer",
                    "description": "Specific shift to apply (0-25). Omit to try all 26.",
                },
            },
            "required": ["ciphertext"],
        },
    },
]

# ─── Dispatcher ───────────────────────────────────────────────────────────────

_FUNCTIONS = {
    "pcap_inspect":  pcap_inspect,
    "pcap_sniff":    pcap_sniff_credentials,
    "kerberos_crack": kerberos_crack,
    "ntlm_extract":  ntlm_extract,
    "dns_enum":      dns_zone_transfer,
    "ospf_crack":    ospf_crack,
    "ntlmv2_crack":  ntlmv2_crack,
    "hash_crack":    hash_crack,
    "decode":        decode_credentials,
    "base64_decode": base64_decode,
    "caesar_crack":  caesar_crack,
}


def dispatch(tool_name: str, tool_input: dict) -> str:
    """Execute a tool by name and return JSON-encoded result."""
    if tool_name not in _FUNCTIONS:
        return json.dumps({"error": f"Unknown tool: '{tool_name}'. Available: {list(_FUNCTIONS)}"})
    try:
        result = _FUNCTIONS[tool_name](**tool_input)
        return json.dumps(result, indent=2, ensure_ascii=False)
    except TypeError as e:
        return json.dumps({"error": f"Bad arguments for '{tool_name}': {e}"})
    except Exception as e:
        return json.dumps({"error": str(e)})
