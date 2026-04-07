"""
Network analysis tools for CTF challenges.
Covers: universal pcap inspector, Kerberos, DNS zone transfer, OSPF MD5 cracking.
"""

import base64
import json
import struct
import tempfile
import urllib.parse
from hashlib import md5
from pathlib import Path

from sandbox import safe_run, validate_path

TMP = Path(tempfile.gettempdir())

DEFAULT_WORDLIST = str(Path(__file__).parent.parent / "wordlists" / "rockyou.txt")

NTLMSSP_MAGIC = b"NTLMSSP\x00"


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 0 — Universal pcap inspector (Claude's first call on any pcap challenge)
# Detects: NTLM, OSPF/MD5, FTP, Telnet, HTTP Basic Auth, Kerberos
# Returns structured findings + recommended next steps — Claude decides what to do
# ─────────────────────────────────────────────────────────────────────────────

def pcap_inspect(pcap_path: str) -> dict:
    """
    Analyse a pcap/pcapng file and return a structured report of everything found.

    Detects protocols by inspecting raw payloads (no external tools required).
    Claude reads this report and decides which cracking/decoding step to take next.
    """
    result = {
        "file": pcap_path,
        "packet_count": 0,
        "protocols_detected": [],
        "findings": {},
        "recommended_next_steps": [],
        "error": None,
    }

    try:
        validate_path(pcap_path)
        from scapy.all import rdpcap, IP, TCP, UDP, Raw

        pkts = rdpcap(pcap_path)
        result["packet_count"] = len(pkts)

        # ── Accumulators ──────────────────────────────────────────────────
        ntlm_challenges, ntlm_auths = [], []
        ospf_md5_pkts = []
        ftp_lines, telnet_streams = [], []
        http_auth_headers = []
        krb_fields = []

        for pkt in pkts:
            ip_proto = pkt[IP].proto if pkt.haslayer(IP) else None

            # ── OSPF (IP proto 89) ────────────────────────────────────────
            if ip_proto == 89:
                raw = bytes(pkt[IP].payload)
                if len(raw) >= 64 and int.from_bytes(raw[14:16], "big") == 2:
                    ospf_md5_pkts.append((raw[:48], raw[48:64]))

            # Search full raw bytes — NTLMSSP can be buried inside SMB, HTTP, etc.
            raw_payload = bytes(pkt)

            # ── NTLMSSP (any transport: SMB, HTTP, etc.) ──────────────────
            off = raw_payload.find(NTLMSSP_MAGIC)
            if off != -1:
                msg = raw_payload[off:]
                if len(msg) >= 12:
                    msg_type = int.from_bytes(msg[8:12], "little")
                    if msg_type == 2 and len(msg) >= 32:
                        ntlm_challenges.append(msg[24:32].hex())
                    elif msg_type == 3 and len(msg) >= 72:
                        try:
                            def _field(d, o):
                                l = int.from_bytes(d[o:o+2], "little")
                                p = int.from_bytes(d[o+4:o+8], "little")
                                return d[p:p+l]
                            domain   = _field(msg, 28).decode("utf-16-le", errors="replace")
                            username = _field(msg, 36).decode("utf-16-le", errors="replace")
                            nt_resp  = _field(msg, 20)
                            if len(nt_resp) >= 16:
                                ntlm_auths.append((username, domain,
                                                   nt_resp[:16].hex(), nt_resp[16:].hex()))
                        except Exception:
                            pass

            # ── FTP (port 21) ─────────────────────────────────────────────
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 21 or pkt[TCP].sport == 21):
                if pkt.haslayer(Raw):
                    try:
                        line = bytes(pkt[Raw].load).decode("utf-8", errors="replace").strip()
                        if any(line.startswith(k) for k in ("USER ", "PASS ", "230 ", "331 ")):
                            ftp_lines.append(line)
                    except Exception:
                        pass

            # ── Telnet (port 23) ──────────────────────────────────────────
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 23 or pkt[TCP].sport == 23):
                if pkt.haslayer(Raw):
                    chunk = bytes(pkt[Raw].load)
                    if not chunk.startswith(b"\xff"):
                        try:
                            telnet_streams.append(chunk.decode("utf-8", errors="replace"))
                        except Exception:
                            pass

            # ── HTTP Basic Auth ───────────────────────────────────────────
            if b"Authorization:" in raw_payload:
                try:
                    for line in raw_payload.split(b"\r\n"):
                        if line.lower().startswith(b"authorization:"):
                            http_auth_headers.append(line.decode("utf-8", errors="replace"))
                except Exception:
                    pass
            # Also: WWW-Authenticate with NTLM base64 payload
            if raw_payload and b"WWW-Authenticate: NTLM " in raw_payload:
                try:
                    for line in raw_payload.split(b"\r\n"):
                        if b"WWW-Authenticate: NTLM " in line or b"Authorization: NTLM " in line:
                            token_b64 = line.split(b" ", 2)[-1].strip()
                            token = base64.b64decode(token_b64 + b"==")
                            off2 = token.find(NTLMSSP_MAGIC)
                            if off2 != -1:
                                inner = token[off2:]
                                msg_type = int.from_bytes(inner[8:12], "little")
                                if msg_type == 2 and len(inner) >= 32:
                                    ntlm_challenges.append(inner[24:32].hex())
                                elif msg_type == 3 and len(inner) >= 72:
                                    try:
                                        def _field2(d, o):
                                            l = int.from_bytes(d[o:o+2], "little")
                                            p = int.from_bytes(d[o+4:o+8], "little")
                                            return d[p:p+l]
                                        domain   = _field2(inner, 28).decode("utf-16-le", errors="replace")
                                        username = _field2(inner, 36).decode("utf-16-le", errors="replace")
                                        nt_resp  = _field2(inner, 20)
                                        if len(nt_resp) >= 16:
                                            ntlm_auths.append((username, domain,
                                                               nt_resp[:16].hex(), nt_resp[16:].hex()))
                                    except Exception:
                                        pass
                except Exception:
                    pass

            # ── Kerberos (port 88) ────────────────────────────────────────
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 88 or pkt[TCP].sport == 88):
                krb_fields.append("kerberos_traffic_present")

        # ── Build findings ────────────────────────────────────────────────

        # NTLM
        if ntlm_challenges or ntlm_auths:
            result["protocols_detected"].append("NTLM")
            ntlm_info = {"found": True, "ntlmv2_hash": None}
            if ntlm_challenges and ntlm_auths:
                username, domain, ntproofstr, blob = ntlm_auths[0]
                challenge = ntlm_challenges[0]
                ntlmv2 = f"{username}::{domain}:{challenge}:{ntproofstr}:{blob}"
                ntlm_info.update({
                    "username": username, "domain": domain,
                    "server_challenge": challenge,
                    "ntlmv2_hash": ntlmv2,
                    "hashcat_mode": 5600,
                })
                result["recommended_next_steps"].append(
                    f"crack ntlmv2 hash with hash_crack(mode=5600, wordlist=rockyou.txt)"
                )
            elif ntlm_challenges:
                ntlm_info["server_challenge"] = ntlm_challenges[0]
                ntlm_info["note"] = "Type 2 found but no Type 3 auth — capture may be incomplete"
            result["findings"]["ntlm"] = ntlm_info

        # OSPF
        if ospf_md5_pkts:
            result["protocols_detected"].append("OSPF/MD5")
            result["findings"]["ospf"] = {
                "found": True,
                "md5_auth_packets": len(ospf_md5_pkts),
                "crack_ready": True,
                "hashcat_note": "use ospf_crack() — pure-python MD5 attack",
            }
            result["recommended_next_steps"].append(
                "crack ospf key with ospf_crack(pcap_path=..., wordlist=rockyou.txt)"
            )

        # FTP
        if ftp_lines:
            result["protocols_detected"].append("FTP")
            creds = {}
            for line in ftp_lines:
                if line.startswith("USER "):
                    creds["username"] = line[5:].strip()
                elif line.startswith("PASS "):
                    creds["password"] = line[5:].strip()
            result["findings"]["ftp"] = {"found": True, "cleartext": creds, "raw_lines": ftp_lines}
            if creds:
                result["recommended_next_steps"].append("ftp credentials extracted — flag may be the password")

        # Telnet
        if telnet_streams:
            result["protocols_detected"].append("Telnet")
            combined = "".join(telnet_streams)
            result["findings"]["telnet"] = {
                "found": True,
                "stream_sample": combined[:500],
            }
            result["recommended_next_steps"].append("inspect telnet stream for typed credentials")

        # HTTP Basic Auth
        if http_auth_headers:
            result["protocols_detected"].append("HTTP-Auth")
            decoded_creds = []
            for header in http_auth_headers:
                parts = header.strip().split(" ", 2)
                if len(parts) >= 2:
                    token = parts[-1].strip()
                    try:
                        token = urllib.parse.unquote(token)
                        decoded = base64.b64decode(token + "==").decode("utf-8", errors="replace")
                        decoded_creds.append(decoded)
                    except Exception:
                        decoded_creds.append(f"(raw) {token}")
            result["findings"]["http_auth"] = {
                "found": True,
                "raw_headers": http_auth_headers,
                "decoded": decoded_creds,
            }
            if decoded_creds:
                result["recommended_next_steps"].append(
                    "http basic auth decoded — check 'decoded' field for user:pass"
                )

        # Kerberos
        if krb_fields:
            result["protocols_detected"].append("Kerberos")
            result["findings"]["kerberos"] = {
                "found": True,
                "note": "Kerberos traffic on port 88 detected — use kerberos_crack() for pre-auth hash",
            }
            result["recommended_next_steps"].append(
                "extract and crack kerberos pre-auth hash with kerberos_crack()"
            )

        if not result["protocols_detected"]:
            result["recommended_next_steps"].append(
                "no known auth protocols detected — inspect raw packets or try pcap_sniff()"
            )

    except ImportError:
        result["error"] = "scapy not installed — pip install scapy"
    except Exception as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────
# TOOL 1: Cleartext credential sniffer (FTP / Telnet / HTTP)
# Root-Me: FTP authentication, TELNET authentication, Twitter auth
# ─────────────────────────────────────────────────────────────

def pcap_sniff_credentials(pcap_path: str) -> dict:
    """Extract cleartext credentials from a pcap/pcapng file."""
    result = {"credentials": [], "ftp": None, "telnet": None, "http_auth": None, "error": None}
    try:
        validate_path(pcap_path)

        # FTP USER/PASS commands
        ftp = safe_run([
            "tshark", "-r", pcap_path,
            "-Y", "ftp",
            "-T", "fields",
            "-e", "ftp.request.command",
            "-e", "ftp.request.arg",
        ], capture_output=True, text=True)
        result["ftp"] = ftp.stdout.strip() or None

        # Telnet TCP stream (stream 0)
        telnet = safe_run([
            "tshark", "-r", pcap_path,
            "-z", "follow,tcp,ascii,0", "-q",
        ], capture_output=True, text=True)
        result["telnet"] = telnet.stdout.strip() or None

        # HTTP Basic Auth header
        http = safe_run([
            "tshark", "-r", pcap_path,
            "-Y", "http",
            "-T", "fields",
            "-e", "http.authorization",
        ], capture_output=True, text=True)
        raw_auth = http.stdout.strip()
        result["http_auth"] = raw_auth or None

        # Auto-decode base64 Basic Auth if present
        if raw_auth:
            import base64, urllib.parse
            for token in raw_auth.splitlines():
                token = token.strip()
                if token.lower().startswith("basic "):
                    token = token[6:]
                try:
                    decoded = base64.b64decode(token + "==").decode("utf-8", errors="replace")
                    if ":" in decoded:
                        user, pw = decoded.split(":", 1)
                        result["credentials"].append({"user": user, "password": pw, "source": "http_basic"})
                except Exception:
                    pass

    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────
# TOOL 2: Kerberos pre-auth hash extractor + cracker
# Root-Me: Kerberos Authentication
# ─────────────────────────────────────────────────────────────

def kerberos_crack(pcap_path: str, wordlist: str = DEFAULT_WORDLIST) -> dict:
    """Extract Kerberos AS-REQ pre-auth hash from pcap and crack it."""
    result = {"hash": None, "password": None, "error": None}
    try:
        validate_path(pcap_path)

        user_cmd = safe_run([
            "tshark", "-r", pcap_path,
            "-Y", "kerberos",
            "-T", "fields",
            "-e", "kerberos.CNameString",
            "-e", "kerberos.realm",
            "-e", "kerberos.etype",
            "-e", "kerberos.cipher",
        ], capture_output=True, text=True)

        username, realm, cipher = None, None, None
        for line in user_cmd.stdout.strip().splitlines():
            fields = line.split("\t")
            if len(fields) < 4:
                continue
            if fields[0]:
                username = fields[0]
            if fields[1]:
                realm = fields[1]
            if fields[2] == "18" and fields[3]:
                # Pick shortest cipher (pre-auth packet, not ticket body)
                if cipher is None or len(fields[3]) < len(cipher):
                    cipher = fields[3]

        if not all([username, realm, cipher]):
            result["error"] = (
                "Could not extract Kerberos fields — "
                f"username={username}, realm={realm}, cipher={'<found>' if cipher else None}"
            )
            return result

        hash_str = f"$krb5pa$18${username}${realm}${cipher}"
        result["hash"] = hash_str

        hash_file = str(TMP / "ctf_buddy_krb.txt")
        Path(hash_file).write_text(hash_str)

        # Try --show first (already cracked in potfile)
        show = safe_run([
            "hashcat", "-m", "19900", hash_file, wordlist, "--force", "--show",
        ], capture_output=True, text=True)

        if show.stdout.strip():
            result["password"] = show.stdout.strip().split(":")[-1]
        else:
            # Run crack
            safe_run([
                "hashcat", "-m", "19900", hash_file, wordlist, "--force",
            ], capture_output=True)
            show2 = safe_run([
                "hashcat", "-m", "19900", hash_file, wordlist, "--force", "--show",
            ], capture_output=True, text=True)
            if show2.stdout.strip():
                result["password"] = show2.stdout.strip().split(":")[-1]
            else:
                result["error"] = "Wordlist exhausted — password not found"

    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────
# TOOL 3: DNS Zone Transfer
# Root-Me: DNS zone transfer
# ─────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────
# TOOL: NTLMv2 hash extractor (scapy-based, no tshark required)
# Root-Me: NTLM Authentication
# ─────────────────────────────────────────────────────────────

NTLMSSP_MAGIC = b"NTLMSSP\x00"

def ntlm_extract(pcap_path: str) -> dict:
    """
    Extract NTLMv2 hash from a pcap for cracking with hashcat mode 5600.

    Parses raw TCP payloads for NTLMSSP messages:
      - Type 1 (Negotiate): identifies client
      - Type 2 (Challenge): server challenge (8 bytes)
      - Type 3 (Authenticate): username, domain, NT response

    Returns hashcat-ready NTLMv2 string:
      username::domain:ServerChallenge:NTProofStr:blob
    """
    result = {
        "ntlmv2_hash": None,
        "username": None,
        "domain": None,
        "server_challenge": None,
        "hashcat_mode": 5600,
        "error": None,
    }
    try:
        validate_path(pcap_path)
        from scapy.all import rdpcap, TCP, Raw

        pkts = rdpcap(pcap_path)

        challenges = []   # (server_challenge_hex,)
        auth_msgs  = []   # (username, domain, ntproofstr, blob)

        for pkt in pkts:
            if not pkt.haslayer(Raw):
                continue
            payload = bytes(pkt[Raw].load)

            # Scan payload for NTLMSSP magic (may appear at offset > 0)
            offset = payload.find(NTLMSSP_MAGIC)
            if offset == -1:
                continue
            msg = payload[offset:]
            if len(msg) < 12:
                continue

            msg_type = int.from_bytes(msg[8:12], "little")

            # Type 2 — NTLMSSP_CHALLENGE: bytes 24-31 = server challenge
            if msg_type == 2 and len(msg) >= 32:
                challenge_hex = msg[24:32].hex()
                challenges.append(challenge_hex)

            # Type 3 — NTLMSSP_AUTH: extract username, domain, NT response
            elif msg_type == 3 and len(msg) >= 72:
                try:
                    def read_field(data, off):
                        length = int.from_bytes(data[off:off+2], "little")
                        ptr    = int.from_bytes(data[off+4:off+8], "little")
                        return data[ptr:ptr+length]

                    domain_raw   = read_field(msg, 28)
                    username_raw = read_field(msg, 36)
                    nt_resp_raw  = read_field(msg, 20)

                    domain   = domain_raw.decode("utf-16-le", errors="replace")
                    username = username_raw.decode("utf-16-le", errors="replace")

                    if len(nt_resp_raw) >= 16:
                        ntproofstr = nt_resp_raw[:16].hex()
                        blob       = nt_resp_raw[16:].hex()
                        auth_msgs.append((username, domain, ntproofstr, blob))
                except Exception:
                    pass

        if not challenges:
            result["error"] = "No NTLMSSP Type 2 (Challenge) messages found in pcap"
            return result
        if not auth_msgs:
            result["error"] = "No NTLMSSP Type 3 (Authenticate) messages found in pcap"
            return result

        server_challenge = challenges[0]
        username, domain, ntproofstr, blob = auth_msgs[0]

        result["username"]         = username
        result["domain"]           = domain
        result["server_challenge"] = server_challenge

        # hashcat NTLMv2 format: user::domain:challenge:ntproofstr:blob
        ntlmv2 = f"{username}::{domain}:{server_challenge}:{ntproofstr}:{blob}"
        result["ntlmv2_hash"] = ntlmv2

    except Exception as e:
        result["error"] = str(e)
    return result


def dns_zone_transfer(domain: str, server: str, port: int = 53) -> dict:
    """Attempt a DNS AXFR zone transfer and extract TXT/flag records."""
    result = {"records": [], "txt_records": [], "secret": None, "raw": None, "error": None}
    try:
        cmd = safe_run([
            "dig", f"@{server}", "-p", str(port), "axfr", domain,
        ], capture_output=True, text=True, timeout=15)

        result["raw"] = cmd.stdout
        if "Transfer failed" in cmd.stdout or "communications error" in cmd.stdout:
            result["error"] = "Zone transfer refused or failed"
            return result

        for line in cmd.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            result["records"].append(line)
            if "TXT" in line:
                result["txt_records"].append(line)
                if any(kw in line.lower() for kw in ["secret", "key", "flag", "pass", "ctf"]):
                    result["secret"] = line

    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────
# TOOL 4: OSPF MD5 dictionary attack
# Root-Me: OSPF Authentication
# ─────────────────────────────────────────────────────────────

def ospf_crack(pcap_path: str, wordlist: str = DEFAULT_WORDLIST) -> dict:
    """
    Crack OSPF MD5 authentication key from a pcap.

    OSPF MD5 auth (RFC 2328):
      - IP protocol 89
      - Auth type 2 = cryptographic (MD5)
      - 16-byte MD5 digest appended after byte 48 of the OSPF header
      - digest = MD5(first_48_ospf_bytes + key)

    Strategy: extract raw IP payload for proto=89 packets,
    verify auth_type == 2, then brute-force the key.
    """
    result = {"key": None, "packets_checked": 0, "ospf_found": 0, "error": None}
    try:
        validate_path(pcap_path)

        from scapy.all import rdpcap, IP, raw as scapy_raw  # noqa

        pkts = rdpcap(pcap_path)

        # Try scapy_ospf first (adds OSPF layer recognition)
        try:
            import sys, os
            ospf_dir = str(Path(__file__).parent.parent.parent / "OSPF_bruteforce")
            if ospf_dir not in sys.path:
                sys.path.insert(0, ospf_dir)
            from scapy_ospf import OSPF_Hdr  # noqa
        except ImportError:
            OSPF_Hdr = None  # fall back to raw IP parsing

        ospf_pkts = []

        for pkt in pkts:
            ospf_raw = None

            # Method 1: scapy_ospf loaded — walk layers
            if OSPF_Hdr is not None:
                layer = pkt
                while layer and hasattr(layer, "payload"):
                    if layer.__class__.__name__.startswith("OSPF"):
                        ospf_raw = scapy_raw(layer)
                        break
                    layer = layer.payload

            # Method 2: raw IP proto 89 (OSPF)
            if ospf_raw is None and pkt.haslayer(IP):
                if pkt[IP].proto == 89:
                    # IP payload = OSPF packet
                    ospf_raw = bytes(pkt[IP].payload)

            if ospf_raw is None:
                continue

            result["ospf_found"] += 1

            # OSPF MD5 auth: auth_type at bytes 14-15, must be 0x0002
            if len(ospf_raw) < 64:
                continue
            auth_type = int.from_bytes(ospf_raw[14:16], "big")
            if auth_type != 2:
                continue  # not MD5 auth

            # bytes 0-47: data to hash; bytes 48-63: 16-byte MD5 digest
            data_block = ospf_raw[:48]
            observed   = ospf_raw[48:64]
            ospf_pkts.append((data_block, observed))

        result["packets_checked"] = len(ospf_pkts)

        if result["ospf_found"] == 0:
            result["error"] = "No OSPF packets (IP proto 89) found in pcap"
            return result

        if len(ospf_pkts) == 0:
            result["error"] = (
                f"Found {result['ospf_found']} OSPF packets but none use MD5 auth (auth_type=2)"
            )
            return result

        # Dictionary attack
        with open(wordlist, "rb") as f:
            for line in f:
                password = line.rstrip(b"\n\r")
                for data, observed in ospf_pkts:
                    if md5(data + password).digest() == observed:
                        result["key"] = password.decode("latin-1")
                        return result

        result["error"] = f"Wordlist exhausted after checking {result['packets_checked']} packet(s) — key not found"

    except ImportError as e:
        result["error"] = f"scapy not installed: {e} — run: pip install scapy"
    except Exception as e:
        result["error"] = str(e)
    return result
