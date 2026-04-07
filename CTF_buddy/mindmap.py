"""
Mind Map — challenge classifier.
Matches the challenge description to known challenge types and
returns ranked suggestions with tools + approach hints.
"""

CHALLENGE_MINDMAP = {
    "cleartext_protocol": {
        "keywords": ["telnet", "ftp", "authentication", "capture", "cleartext", "credentials", "sniff"],
        "tools": ["pcap_sniff"],
        "approach": "Extract cleartext credentials from pcap — follow the TCP stream",
        "hints": [
            "FTP: look for USER / PASS commands",
            "Telnet: keystrokes appear in the TCP stream",
            "HTTP Basic Auth: Authorization header is base64(user:pass)",
            "Twitter: OAuth token may be URL-encoded in the stream",
        ],
    },
    "ntlm": {
        "keywords": ["ntlm", "ntlmv2", "ntlmssp", "smb", "windows auth", "challenge response", "net-ntlmv2"],
        "tools": ["ntlm_extract", "hash_crack"],
        "approach": "Extract NTLMv2 hash from pcap with ntlm_extract, then crack with hash_crack mode 5600",
        "hints": [
            "ntlm_extract reads NTLMSSP messages directly from pcap (no tshark needed)",
            "hashcat mode 5600 = NTLMv2 (Net-NTLMv2)",
            "format: username::domain:ServerChallenge:NTProofStr:blob",
        ],
    },
    "hash_cracking": {
        "keywords": ["password", "hash", "md5", "sha1", "sha256", "crack", "cisco", "shadow"],
        "tools": ["hash_crack"],
        "approach": "Dictionary attack with rockyou.txt via hashcat",
        "hints": [
            "MD5 → hashcat mode 0",
            "NTLM → hashcat mode 1000",
            "Cisco IOS MD5 → hashcat mode 500",
            "SHA1 → hashcat mode 100",
        ],
    },
    "kerberos": {
        "keywords": ["kerberos", "ticket", "tgt", "as-req", "krb5", "pre-auth", "kinit", "realm"],
        "tools": ["kerberos_crack"],
        "approach": "Extract Kerberos pre-auth hash from pcap, crack with hashcat mode 19900",
        "hints": [
            "Look for AS-REQ packets with etype 18 (AES-256)",
            "hashcat mode 19900 = $krb5pa$18$ (Kerberos 5 AS-REQ Pre-Auth AES256-CTS-HMAC-SHA1-96)",
            "Username and realm are in the CNameString / realm fields",
        ],
    },
    "dns": {
        "keywords": ["dns", "zone transfer", "axfr", "domain", "nameserver", "txt record", "subdomain"],
        "tools": ["dns_enum"],
        "approach": "Perform DNS zone transfer with dig axfr",
        "hints": [
            "TXT records often contain the flag directly",
            "Try AXFR on every nameserver",
            "Check for unusual subdomains in the zone",
        ],
    },
    "ospf": {
        "keywords": ["ospf", "routing", "md5", "message-digest", "router", "ospf2", "hello packet"],
        "tools": ["ospf_crack"],
        "approach": "Dictionary attack against OSPF MD5 authentication key",
        "hints": [
            "OSPF MD5: md5(first 48 bytes of packet + password)",
            "The key is usually a short word — rockyou.txt covers it",
            "Scapy reads pcap; extract OSPF layer bytes",
        ],
    },
    "encoding": {
        "keywords": ["twitter", "basic auth", "http", "base64", "encoded", "authorization", "bearer", "oauth"],
        "tools": ["decode", "pcap_sniff"],
        "approach": "Decode base64/URL-encoded credentials from captured HTTP headers",
        "hints": [
            "HTTP Basic Auth: Authorization: Basic base64(user:pass)",
            "Twitter OAuth: may be double-URL-encoded",
            "Try base64 decode first, then URL decode",
        ],
    },
    "caesar_cipher": {
        "keywords": ["caesar", "rot13", "rot", "substitution", "cipher", "shift", "vigenere"],
        "tools": ["caesar_crack"],
        "approach": "Brute-force all 26 ROT shifts and look for readable English",
        "hints": [
            "ROT13 is shift 13 — extremely common",
            "Look for common English words: 'the', 'flag', 'password'",
            "Try online solvers if brute-force fails (Vigenere needs a key)",
        ],
    },
}


def classify(description: str) -> list[dict]:
    """
    Score each challenge type by keyword hits.
    Returns list sorted by score descending.
    """
    desc = description.lower()
    results = []

    for ctype, info in CHALLENGE_MINDMAP.items():
        hits = [kw for kw in info["keywords"] if kw in desc]
        if hits:
            results.append({
                "type": ctype,
                "score": len(hits),
                "matched_keywords": hits,
                "tools": info["tools"],
                "approach": info["approach"],
                "hints": info["hints"],
            })

    return sorted(results, key=lambda x: x["score"], reverse=True)


def format_for_prompt(classifications: list[dict]) -> str:
    """Format classification results as a system prompt section."""
    if not classifications:
        return "No challenge type matched. Explore all available tools."

    lines = ["## Challenge Classification\n"]
    for c in classifications[:3]:  # top 3
        lines.append(f"### {c['type'].replace('_', ' ').title()} (score: {c['score']})")
        lines.append(f"- **Matched keywords**: {', '.join(c['matched_keywords'])}")
        lines.append(f"- **Approach**: {c['approach']}")
        lines.append(f"- **Suggested tools**: {', '.join(c['tools'])}")
        lines.append("- **Hints**:")
        for hint in c["hints"]:
            lines.append(f"  - {hint}")
        lines.append("")

    return "\n".join(lines)
