# Root-Me Network Challenges

Place challenge files (.pcap, .pcapng, .cap) in this directory.

## Usage

```bash
# From CTF_buddy root:
python main.py "FTP authentication challenge" --file challenges/rootme_network/ftp_auth.pcap
python main.py "Kerberos challenge" --file challenges/rootme_network/kerberos.pcapng
python main.py "OSPF MD5 cracking" --file challenges/rootme_network/ospf.pcapng
python main.py "DNS zone transfer on port 54011" \
    --domain ch11.challenge01.root-me.org \
    --server challenge01.root-me.org \
    --port 54011
```

## Wordlists

Symlink or copy rockyou.txt to `wordlists/rockyou.txt`:

```bash
ln -s /path/to/rockyou.txt ../wordlists/rockyou.txt
# or on Windows:
mklink ..\wordlists\rockyou.txt C:\path\to\rockyou.txt
```
