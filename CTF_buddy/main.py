#!/usr/bin/env python3
"""
CTF Buddy — CLI entry point.

Usage examples:
  python main.py "FTP authentication challenge" --file capture.pcap
  python main.py "OSPF MD5 cracking" --file ospf.pcapng --wordlist rockyou.txt
  python main.py "DNS zone transfer on port 54011" --domain ch11.challenge01.root-me.org --server challenge01.root-me.org --port 54011
  python main.py --demo ospf
"""

import argparse
import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Force UTF-8 output on Windows so Claude's responses print cleanly
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

load_dotenv(Path(__file__).parent / ".env")

# Add project root to path so imports work from anywhere
sys.path.insert(0, str(Path(__file__).parent))

from agent import run
from tools.network import pcap_inspect, dns_zone_transfer, ospf_crack, kerberos_crack
from tools.crypto import ntlmv2_crack
from validator import find_flag


DEMOS = {
    "ospf": {
        "description": "OSPF MD5 authentication — crack the routing protocol password from a pcap",
        "files": ["../OSPF_bruteforce/ospf_authentication_hash.pcapng"],
        "wordlist": "../OSPF_bruteforce/rockyou.txt",
    },
    "ftp": {
        "description": "FTP authentication — extract cleartext FTP credentials from a network capture",
        "files": [],
    },
    "dns": {
        "description": (
            "DNS zone transfer — perform AXFR on challenge01.root-me.org "
            "domain ch11.challenge01.root-me.org port 54011"
        ),
        "files": [],
        "extra": {"domain": "ch11.challenge01.root-me.org", "server": "challenge01.root-me.org", "port": 54011},
    },
}


def build_description(args) -> str:
    """Construct a challenge description from CLI arguments."""
    parts = [args.description]
    if hasattr(args, "domain") and args.domain:
        parts.append(f"Domain: {args.domain}, Server: {args.server}, Port: {args.port or 53}")
    return "\n".join(parts)


def run_local_analysis(
    challenge_description: str,
    challenge_files: list[str] | None = None,
    wordlist: str | None = None,
    domain: str | None = None,
    server: str | None = None,
    port: int | None = None,
    verbose: bool = True,
) -> dict:
    """Run local analysis using built-in tools without the Anthropic API."""
    if wordlist is None:
        default_wordlist = Path(__file__).parent / "wordlists" / "rockyou.txt"
        wordlist = str(default_wordlist) if default_wordlist.exists() else None

    if challenge_files is None:
        challenge_files = []

    if verbose:
        print("\n" + "=" * 60)
        print("[CTF BUDDY] Local analysis mode")
        print("=" * 60)
        print(f"Description: {challenge_description}")
        if challenge_files:
            for path in challenge_files:
                print(f"- File: {path}")
        if domain and server:
            print(f"- DNS domain: {domain} server: {server} port: {port or 53}")

    found_flag = None
    analysis = []

    def inspect_file(path: str):
        nonlocal found_flag
        if verbose:
            print(f"\n[local] Inspecting pcap: {path}")
        try:
            summary = pcap_inspect(path)
        except Exception as exc:
            summary = {"error": str(exc)}

        if verbose:
            print(json.dumps(summary, indent=2, ensure_ascii=False))

        flag = find_flag(json.dumps(summary, ensure_ascii=False))
        if flag:
            found_flag = flag

        analysis.append({"file": path, "summary": summary})
        return summary

    def try_ntlm(summary: dict, path: str):
        nonlocal found_flag
        ntlm = summary.get("findings", {}).get("ntlm")
        if not ntlm or not ntlm.get("ntlmv2_hash"):
            return
        if verbose:
            print("\n[local] NTLMv2 hash found — attempting pure-Python NTLMv2 crack...")
        ntlm_result = ntlmv2_crack(ntlm["ntlmv2_hash"], wordlist=wordlist) if wordlist else ntlmv2_crack(ntlm["ntlmv2_hash"])
        print(json.dumps(ntlm_result, indent=2, ensure_ascii=False))
        flag = find_flag(json.dumps(ntlm_result, ensure_ascii=False))
        if flag:
            found_flag = flag

    def try_ospf(summary: dict, path: str):
        nonlocal found_flag
        if not summary.get("findings", {}).get("ospf"):
            return
        if verbose:
            print("\n[local] OSPF MD5 traffic detected — attempting dictionary crack...")
        ospf_result = ospf_crack(path, wordlist=wordlist) if wordlist else ospf_crack(path)
        print(json.dumps(ospf_result, indent=2, ensure_ascii=False))
        flag = find_flag(json.dumps(ospf_result, ensure_ascii=False))
        if flag:
            found_flag = flag

    def try_kerberos(summary: dict, path: str):
        nonlocal found_flag
        if not summary.get("findings", {}).get("kerberos"):
            return
        if verbose:
            print("\n[local] Kerberos traffic detected — attempting pre-auth crack...")
        krb_result = kerberos_crack(path, wordlist=wordlist) if wordlist else kerberos_crack(path)
        print(json.dumps(krb_result, indent=2, ensure_ascii=False))
        flag = find_flag(json.dumps(krb_result, ensure_ascii=False))
        if flag:
            found_flag = flag

    for path in challenge_files:
        summary = inspect_file(path)
        try_ntlm(summary, path)
        try_ospf(summary, path)
        try_kerberos(summary, path)

    if domain and server:
        if verbose:
            print("\n[local] Running DNS zone transfer analysis...")
        dns_result = dns_zone_transfer(domain, server, port=port or 53)
        print(json.dumps(dns_result, indent=2, ensure_ascii=False))
        flag = find_flag(json.dumps(dns_result, ensure_ascii=False))
        if flag:
            found_flag = flag
        analysis.append({"dns": dns_result})

    if verbose:
        print("\n" + "=" * 60)
        if found_flag:
            print(f"[OK] Found secret/flag: {found_flag}")
        else:
            print("[!!] No flag-like secret found in local analysis.")
        print("=" * 60 + "\n")

    return {"flag": found_flag, "solved": bool(found_flag), "analysis": analysis}


def main():
    parser = argparse.ArgumentParser(
        description="CTF Buddy — AI-powered CTF solver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py "FTP auth challenge" --file capture.pcap
  python main.py "Kerberos challenge" --file krb.pcapng
  python main.py "DNS zone transfer" --domain ch11.challenge01.root-me.org --server challenge01.root-me.org --port 54011
  python main.py "OSPF MD5 crack" --file ospf.pcapng
  python main.py --demo ospf
        """,
    )

    parser.add_argument(
        "description",
        nargs="?",
        default=None,
        help="Challenge description (what the challenge is about)",
    )
    parser.add_argument(
        "--file", "-f",
        action="append",
        dest="files",
        metavar="PATH",
        help="Challenge file(s) — pcap, hash file, etc. (can repeat)",
    )
    parser.add_argument(
        "--wordlist", "-w",
        default=None,
        help="Custom wordlist path (default: wordlists/rockyou.txt)",
    )
    parser.add_argument(
        "--domain",
        default=None,
        help="Domain for DNS challenges",
    )
    parser.add_argument(
        "--server",
        default=None,
        help="DNS server for zone transfer",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="DNS port (default 53)",
    )
    parser.add_argument(
        "--turns",
        type=int,
        default=20,
        help="Max agentic loop turns (default 20)",
    )
    parser.add_argument(
        "--demo",
        choices=list(DEMOS.keys()),
        help=f"Run a demo challenge: {list(DEMOS.keys())}",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run local analysis only without calling Anthropic/Claude",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress streaming output, only print the final flag",
    )

    args = parser.parse_args()

    # ── API key check ───────────────────────────────────────────────────────
    if not args.local and not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY environment variable not set.")
        print("  export ANTHROPIC_API_KEY=sk-ant-...")
        print("Or run with --local to analyze captured traffic using local tools only.")
        sys.exit(1)

    # ── Demo mode ───────────────────────────────────────────────────────────
    if args.demo:
        demo = DEMOS[args.demo]
        description = demo["description"]
        files = [f for f in demo.get("files", []) if Path(f).exists()]
        if not files and demo.get("files"):
            print(f"Demo files not found. Place them at: {demo['files']}")

        if args.local:
            result = run_local_analysis(
                challenge_description=description,
                challenge_files=files or None,
                wordlist=args.wordlist,
                domain=demo.get("extra", {}).get("domain"),
                server=demo.get("extra", {}).get("server"),
                port=demo.get("extra", {}).get("port"),
                verbose=not args.quiet,
            )
        else:
            result = run(
                challenge_description=description,
                challenge_files=files or None,
                max_turns=args.turns,
                verbose=not args.quiet,
            )
        if args.quiet:
            print(result.get("flag") or "No flag found")
        return

    # ── Normal mode ─────────────────────────────────────────────────────────
    if not args.description:
        parser.print_help()
        sys.exit(1)

    # Build enriched description
    description_parts = [args.description]
    if args.domain:
        description_parts.append(
            f"\nDNS details — Domain: {args.domain}, "
            f"Server: {args.server or 'unknown'}, "
            f"Port: {args.port or 53}"
        )

    description = "\n".join(description_parts)
    files = args.files or []

    if args.local:
        result = run_local_analysis(
            challenge_description=description,
            challenge_files=files or None,
            wordlist=args.wordlist,
            domain=args.domain,
            server=args.server,
            port=args.port,
            verbose=not args.quiet,
        )
    else:
        result = run(
            challenge_description=description,
            challenge_files=files or None,
            wordlist=args.wordlist,
            max_turns=args.turns,
            verbose=not args.quiet,
        )

    if args.quiet:
        print(result.get("flag") or "No flag found")
    else:
        if result["solved"]:
            print(f"\n[OK] Flag: {result['flag']}")
        else:
            print("\n[!!] Could not find flag - check the output above for clues")


if __name__ == "__main__":
    main()
