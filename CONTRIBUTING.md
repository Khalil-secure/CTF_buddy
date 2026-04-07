# Contributing to CTF Buddy

Thanks for contributing.

CTF Buddy is currently focused on network-first CTF workflows. Contributions are most useful when they improve:
- packet capture analysis
- authentication protocol extraction
- decoding and cracking helpers connected to network challenges
- docs, tests, and usability around that workflow

## Getting started

1. Clone the repository.
2. Create a virtual environment.
3. Install dependencies from `CTF_buddy/requirements.txt`.
4. Run the CLI from the repo root with `python main.py --help`.

Example setup:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r CTF_buddy/requirements.txt
python main.py --help
```

## Development guidelines

- Keep the project network-first for now.
- Prefer small, focused pull requests.
- Do not commit secrets, API keys, large wordlists, or solved challenge captures.
- Add or update tests when changing parsing, decoding, validation, or classification logic.
- Prefer extending existing tool flows before adding many new top-level concepts.

## Adding a new capability

If you add a new challenge helper:

1. Implement the behavior in `CTF_buddy/tools/network.py` or `CTF_buddy/tools/crypto.py`.
2. Register the tool in `CTF_buddy/tools/registry.py`.
3. Update `pcap_inspect()` if the feature is network-capture driven.
4. Update `CTF_buddy/mindmap.py` so the classifier can hint the right workflow.
5. Add a test or fixture-based check when practical.
6. Update the README if the supported scope changes.

## Pull requests

Good pull requests usually include:
- a short summary of the problem
- the approach taken
- any limits or tradeoffs
- test coverage or manual verification notes

If your change touches external tools like `hashcat`, `tshark`, or `dig`, mention what you tested locally and what still needs verification.

## Scope note

Ideas for future general CTF support are welcome, but please align implementation with the current project direction:

`CTF Buddy is a network challenge assistant first, and a broader CTF copilot later.`
