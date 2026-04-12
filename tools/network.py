from strands import tool


@tool
def pcap_inspect(pcap_path: str) -> dict:
    """
    General inspection of a pcap/pcapng file.
    Always call this first on any network challenge — it gives a full overview
    of what protocols and credentials are present, then you can drill deeper.

    Args:
        pcap_path: Path to the .pcap or .pcapng file

    Returns:
        Summary report with packet count, protocols detected, findings, and recommended next steps
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
        from scapy.all import rdpcap, IP, TCP, UDP, Raw
        import base64
        import urllib.parse
        import struct

        NTLMSSP_MAGIC = b"NTLMSSP\x00"

        pkts = rdpcap(pcap_path)
        result["packet_count"] = len(pkts)

        ntlm_sessions, _last_challenge = [], None
        ospf_md5_pkts = []
        ftp_lines = []
        telnet_streams = []
        http_auth_headers = []
        krb_traffic = False
        dns_queries = []

        for pkt in pkts:
            raw_bytes = bytes(pkt)
            ip_proto = pkt[IP].proto if pkt.haslayer(IP) else None

            # OSPF (proto 89)
            if ip_proto == 89:
                raw = bytes(pkt[IP].payload)
                if len(raw) >= 64 and int.from_bytes(raw[14:16], "big") == 2:
                    ospf_md5_pkts.append(raw)

            # NTLMSSP (any transport)
            off = raw_bytes.find(NTLMSSP_MAGIC)
            if off != -1:
                msg = raw_bytes[off:]
                if len(msg) >= 12:
                    msg_type = int.from_bytes(msg[8:12], "little")
                    if msg_type == 2 and len(msg) >= 32:
                        _last_challenge = msg[24:32].hex()
                    elif msg_type == 3 and len(msg) >= 72:
                        try:
                            def _f(d, o):
                                l = int.from_bytes(d[o:o+2], "little")
                                p = int.from_bytes(d[o+4:o+8], "little")
                                return d[p:p+l]
                            domain   = _f(msg, 28).decode("utf-16-le", errors="replace")
                            username = _f(msg, 36).decode("utf-16-le", errors="replace")
                            nt_resp  = _f(msg, 20)
                            if len(nt_resp) >= 16 and _last_challenge:
                                ntlm_sessions.append((_last_challenge, username, domain,
                                                      nt_resp[:16].hex(), nt_resp[16:].hex()))
                        except Exception:
                            pass

            # FTP
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 21 or pkt[TCP].sport == 21):
                if pkt.haslayer(Raw):
                    line = bytes(pkt[Raw].load).decode("utf-8", errors="replace").strip()
                    if any(line.startswith(k) for k in ("USER ", "PASS ", "230 ", "331 ")):
                        ftp_lines.append(line)

            # Telnet
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 23 or pkt[TCP].sport == 23):
                if pkt.haslayer(Raw):
                    chunk = bytes(pkt[Raw].load)
                    if not chunk.startswith(b"\xff"):
                        telnet_streams.append(chunk.decode("utf-8", errors="replace"))

            # HTTP Basic Auth
            if b"Authorization:" in raw_bytes:
                for line in raw_bytes.split(b"\r\n"):
                    if line.lower().startswith(b"authorization:"):
                        http_auth_headers.append(line.decode("utf-8", errors="replace"))

            # Kerberos
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 88 or pkt[TCP].sport == 88):
                krb_traffic = True

            # DNS
            if pkt.haslayer(UDP) and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53):
                if b"query" in raw_bytes or pkt[UDP].dport == 53:
                    dns_queries.append("dns_traffic_present")

        # Build findings
        if ntlm_sessions:
            result["protocols_detected"].append("NTLM")
            c, u, d, p, b = ntlm_sessions[0]
            result["findings"]["ntlm"] = {
                "username": u, "domain": d,
                "ntlmv2_hash": f"{u}::{d}:{c}:{p}:{b}",
                "hashcat_mode": 5600,
            }
            result["recommended_next_steps"].append("crack NTLMv2 hash with pcap_crack_ntlm()")

        if ospf_md5_pkts:
            result["protocols_detected"].append("OSPF/MD5")
            result["findings"]["ospf"] = {"packets_found": len(ospf_md5_pkts)}
            result["recommended_next_steps"].append("crack OSPF MD5 key with pcap_crack_ospf()")

        if ftp_lines:
            result["protocols_detected"].append("FTP")
            creds = {}
            for line in ftp_lines:
                if line.startswith("USER "):
                    creds["username"] = line[5:].strip()
                elif line.startswith("PASS "):
                    creds["password"] = line[5:].strip()
            result["findings"]["ftp"] = {"cleartext_creds": creds, "lines": ftp_lines}
            result["recommended_next_steps"].append("FTP credentials found in plaintext — check findings.ftp")

        if telnet_streams:
            result["protocols_detected"].append("Telnet")
            result["findings"]["telnet"] = {"stream_sample": "".join(telnet_streams)[:300]}
            result["recommended_next_steps"].append("inspect telnet stream for credentials")

        if http_auth_headers:
            result["protocols_detected"].append("HTTP-Auth")
            decoded = []
            for h in http_auth_headers:
                token = h.strip().split(" ", 2)[-1].strip()
                try:
                    decoded.append(base64.b64decode(token + "==").decode("utf-8", errors="replace"))
                except Exception:
                    decoded.append(token)
            result["findings"]["http_auth"] = {"decoded": decoded}
            result["recommended_next_steps"].append("HTTP Basic Auth decoded — check findings.http_auth")

        if krb_traffic:
            result["protocols_detected"].append("Kerberos")
            result["findings"]["kerberos"] = {"note": "Kerberos traffic on port 88 detected"}
            result["recommended_next_steps"].append("extract Kerberos hash with pcap_crack_kerberos()")

        if dns_queries:
            result["protocols_detected"].append("DNS")

        if not result["protocols_detected"]:
            result["recommended_next_steps"].append("no known protocols detected — try inspecting raw packets manually")

    except ImportError:
        result["error"] = "scapy not installed — run: pip install scapy"
    except Exception as e:
        result["error"] = str(e)

    return result


@tool
def pcap_get_stream(pcap_path: str, protocol: str, stream_index: int = 0) -> dict:
    """
    Drill into a specific protocol stream from a pcap file.
    Use after pcap_inspect() identifies something interesting.

    Args:
        pcap_path: Path to the .pcap or .pcapng file
        protocol: One of 'tcp', 'udp', 'http', 'ftp', 'telnet'
        stream_index: Which stream to extract (default 0 = first)

    Returns:
        Raw stream content for the selected protocol/index
    """
    result = {"protocol": protocol, "stream_index": stream_index, "content": None, "error": None}

    try:
        from scapy.all import rdpcap, TCP, UDP, Raw

        pkts = rdpcap(pcap_path)
        streams = {}

        for pkt in pkts:
            if protocol in ("tcp", "http", "ftp", "telnet") and pkt.haslayer(TCP):
                key = (pkt[TCP].sport, pkt[TCP].dport)
                if pkt.haslayer(Raw):
                    streams.setdefault(key, []).append(bytes(pkt[Raw].load))
            elif protocol == "udp" and pkt.haslayer(UDP):
                key = (pkt[UDP].sport, pkt[UDP].dport)
                if pkt.haslayer(Raw):
                    streams.setdefault(key, []).append(bytes(pkt[UDP].load))

        if not streams:
            result["error"] = f"no {protocol} streams found"
            return result

        keys = list(streams.keys())
        if stream_index >= len(keys):
            result["error"] = f"stream_index {stream_index} out of range — {len(keys)} streams available"
            return result

        chosen_key = keys[stream_index]
        combined = b"".join(streams[chosen_key])
        result["content"] = combined.decode("utf-8", errors="replace")
        result["stream_key"] = {"sport": chosen_key[0], "dport": chosen_key[1]}
        result["total_streams_available"] = len(keys)

    except ImportError:
        result["error"] = "scapy not installed — run: pip install scapy"
    except Exception as e:
        result["error"] = str(e)

    return result
