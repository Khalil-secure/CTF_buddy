# CTF Buddy

English | [Français](README.fr.md)

> AI-powered CTF helper for network challenges today, with a path toward a broader CTF assistant over time.

CTF Buddy is currently focused on network and authentication-style challenges:
- packet captures
- protocol inspection
- credential extraction
- auth hash cracking
- DNS transfer-style tasks

Right now, the project is intentionally narrow. The goal is to make the network workflow solid first, then expand toward a more general-purpose CTF assistant for crypto, web, reversing, and mixed challenge chains in future versions.

![CTF Buddy](/image.png)

Drop a `.pcapng` file, describe the challenge, and let the agent figure out the rest.

---

## How it works

```
You: "network auth challenge"  +  capture.pcapng
         │
         ▼
   [ Mind Map ]  ──── classifies challenge type from description
         │
         ▼
   [ Claude Opus 4.6 ]  ──── adaptive thinking + tool-use loop
         │
    ┌────┴──────────────────────────────────────────┐
    ▼                                               ▼
pcap_inspect()                              hash_crack()
 detect all protocols                        hashcat wrapper
 in one pass:                                modes: NTLMv2 · MD5
  · NTLM/NTLMv2                              · SHA1 · Kerberos
  · OSPF/MD5                                 · Cisco · NTLM
  · FTP cleartext
  · Telnet streams               ospf_crack()
  · HTTP Basic Auth               pure-python MD5
  · Kerberos                      dictionary attack

    ▼                                               ▼
    └──────────── findings + next steps ────────────┘
                          │
                          ▼
                   [ Validator ]
                  flag pattern detection
                  CTF{} · HTB{} · NTLMv2 key
                  cracked password · TXT record
                          │
                          ▼
                    FLAG: <value>
```

Claude reads `pcap_inspect()` output and decides which tool to call next — no hardcoded routing.

---

## Supported challenge types

| Category | Protocol | Technique |
|---|---|---|
| Network capture | FTP | Cleartext USER/PASS extraction |
| Network capture | Telnet | TCP stream reconstruction |
| Network capture | HTTP Basic Auth | Base64 decode of Authorization header |
| Network capture | NTLM / NTLMv2 | Hash extraction + hashcat mode 5600 |
| Network capture | Kerberos | Pre-auth hash + hashcat mode 19900 |
| Network capture | OSPF / MD5 | Dictionary attack on routing auth key |
| DNS | Zone Transfer | AXFR against nameserver, TXT flag extraction |
| Crypto | Any hash | hashcat with configurable mode |
| Crypto | Caesar / ROT | Brute-force all 26 shifts |
| Crypto | Base64 / URL | Multi-layer decode |

Tested on [Root-Me](https://www.root-me.org/) network challenges.

## Current scope

At the moment, CTF Buddy is built for network-centric challenges only.

That means the main supported flow is:
- inspect a capture
- detect the protocol or authentication mechanism
- extract useful material
- crack or decode it
- validate the result as a likely flag, password, or secret

It is not yet a full multi-category CTF framework. Some crypto helpers already exist, but the project should still be understood as a network-first assistant rather than a universal solver.

## Future direction

The long-term goal is to grow CTF Buddy into a more general CTF copilot.

Planned expansion areas include:
- broader crypto workflows
- web challenge helpers
- steganography support
- richer challenge routing across categories
- mixed-tool workflows where one challenge moves across network, crypto, and web steps

For now, the README, prompts, and tool design should be read with one main assumption:

`CTF Buddy is for network challenges first.`

---

## Installation

```bash
git clone https://github.com/<your-handle>/ctf-buddy
cd ctf-buddy

pip install -r requirements.txt
```

**External tools** (optional — only needed for tshark-based features):
- [Wireshark / tshark](https://www.wireshark.org/) — packet inspection
- [hashcat](https://hashcat.net/) — GPU-accelerated hash cracking

**Wordlist** — drop `rockyou.txt` in `wordlists/`:
```bash
# Linux
cp /usr/share/wordlists/rockyou.txt wordlists/

# or download
curl -L https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt \
     -o wordlists/rockyou.txt
```

**API key** — copy `.env.example` to `.env` and fill in your key:
```bash
cp .env.example .env
# then edit .env and set ANTHROPIC_API_KEY=sk-ant-...
```

---

## Usage

```bash
# Any network capture — Claude figures out the protocol
python main.py "network authentication challenge" \
  --file capture.pcapng \
  --wordlist wordlists/rockyou.txt

# NTLM
python main.py "windows authentication capture" \
  --file ntlm_auth.pcapng \
  --wordlist wordlists/rockyou.txt

# OSPF routing protocol MD5 auth
python main.py "ospf authentication" \
  --file ospf.pcapng \
  --wordlist wordlists/rockyou.txt

# Kerberos pre-auth
python main.py "kerberos capture" \
  --file kerberos.pcapng

# DNS zone transfer
python main.py "dns zone transfer challenge" \
  --domain ch11.challenge01.root-me.org \
  --server challenge01.root-me.org \
  --port 54011

# Quick result only (no streaming)
python main.py "ospf challenge" --file ospf.pcapng --quiet
```

### Windows side terminal

If you want CTF Buddy open in a separate helper terminal while you work the challenge:

```powershell
.\launch_ctf_buddy.ps1
```

Or double-click:

```text
launch_ctf_buddy.cmd
```

For direct command-style use from the repo root:

```powershell
.\ctf_buddy.ps1 "network authentication challenge" --file .\capture.pcapng --local
```

---

## Example output

```
============================================================
[CTF BUDDY] Starting analysis
============================================================
[mind-map] matched: ntlm (score 3)

[turn 1] Calling Claude...

[thinking...]
I'll start with pcap_inspect to identify what's in this capture...

[TOOL] pcap_inspect
  Input: { "pcap_path": "/home/user/ntlm_auth.pcapng" }
  Result: {
    "protocols_detected": ["NTLM"],
    "findings": {
      "ntlm": {
        "ntlmv2_hash": "Administrator::WORKGROUP:abc123:...",
        "hashcat_mode": 5600
      }
    },
    "recommended_next_steps": ["crack ntlmv2 hash with hash_crack(mode=5600)"]
  }

[TOOL] hash_crack
  Input: { "hash_value": "Administrator::...", "mode": 5600 }
  Result: { "password": "Tigre" }

[FLAG] FLAG IN TOOL RESULT: Tigre

============================================================
[OK] SOLVED in 2 turns — Flag: Tigre
============================================================
```

---

## Architecture

```
CTF_buddy/                     ← repo root
├── main.py                    single entry point
├── requirements.txt           pip dependencies
├── .env.example               API key template
│
├── CTF_buddy/                 ← Python package
│   ├── main.py                CLI argument parsing + local analysis mode
│   ├── agent.py               Claude Opus 4.6 agentic loop (streaming + adaptive thinking)
│   ├── mindmap.py             Keyword-based challenge classifier → primes Claude's context
│   ├── sandbox.py             Subprocess safety layer (command allowlist + forbidden patterns)
│   ├── validator.py           Flag pattern detection (CTF{}, HTB{}, cracked keys, hashes)
│   │
│   ├── tools/
│   │   ├── registry.py        Tool schemas (Claude API format) + dispatcher
│   │   ├── network.py         pcap_inspect · kerberos_crack · dns_enum · ospf_crack · ntlm_extract
│   │   └── crypto.py          hash_crack · decode · base64_decode · caesar_crack
│   │
│   ├── wordlists/             place rockyou.txt here
│   └── challenges/            drop your .pcapng files here
│       └── rootme_network/
│
└── tests/                     unittest suite
```

### Key design decisions

**`pcap_inspect` as the universal entry point** — instead of making Claude guess the protocol from the filename, one tool does a full scan and returns structured findings. Claude reads the report and decides which cracking tool to call. This cuts wasted turns from ~8 to ~2 on new challenge types.

**Claude as the decision layer** — the agent isn't scripted. It reads tool output, reasons with adaptive thinking, and picks the next action. If a tool fails it tries an alternative. The same agent solved OSPF and NTLM challenges without any challenge-specific code paths.

**Safety sandbox** — all subprocess calls go through `sandbox.safe_run()` which enforces a binary allowlist (`tshark`, `hashcat`, `dig`, `john`) and blocks forbidden shell patterns. The agent cannot execute arbitrary commands.

---

## Contributing

Contributions welcome — especially new tool modules for challenge types not yet covered.

### Adding a new tool

1. **Implement** the function in `tools/network.py` or `tools/crypto.py`
2. **Register** the Claude schema in `tools/registry.py` (add to `TOOL_SCHEMAS` and `_FUNCTIONS`)
3. **Add detection** to `pcap_inspect()` if it's a pcap-based protocol
4. **Add keywords** to `mindmap.py` so the classifier primes Claude's context

### Ideas for new tools

- [ ] WPA/WPA2 handshake cracker (hashcat mode 22000)
- [ ] SSH private key cracker (hashcat mode 22921)  
- [ ] VoIP / SIP credential extractor
- [ ] SSL/TLS session key decryption (with key log file)
- [ ] PCAP diff / timeline view
- [ ] Web challenge tools (JWT decode, SQL injection payloads)
- [ ] Steganography detection

### Challenge types wanted

Testing on a wider range of Root-Me, HackTheBox, and CTFtime challenges. If you solve a challenge with CTF Buddy, open a PR adding the challenge file + expected flag to `challenges/`.

---

## Requirements

```
anthropic>=0.40.0
scapy>=2.5.0
python-dotenv>=1.0.0
```

Python 3.10+

---

## License

MIT
