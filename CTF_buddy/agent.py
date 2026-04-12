import sys
import io
import os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from dotenv import load_dotenv
load_dotenv()

from strands import Agent
from tools.network import pcap_inspect, pcap_get_stream
from tools.crypto import (
    encoding_identify, decode_base64, decode_hex,
    decode_rot, decode_binary, decode_url, hash_identify
)
from tools.web import web_inspect, web_get_paths, web_fuzz_param, web_inspect_cookie, web_solve_image_captcha, web_fetch_challenge, web_solve_sequence
from tools.forensics import file_inspect, file_extract_strings, file_check_stego, file_extract_metadata
from tools.workspace import write_and_run, read_workspace, submit_answer


def _build_model():
    """
    Auto-detect backend from .env:
    - ANTHROPIC_API_KEY set  → Anthropic API (claude-sonnet-4-6)
    - AWS_ACCESS_KEY_ID set  → AWS Bedrock (default, us-west-2)
    Returns None to let Strands fall back to its default (Bedrock from env).
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        from strands.models import AnthropicModel
        print("[backend] Anthropic API")
        return AnthropicModel(
            model_id="claude-sonnet-4-6",
            api_key=os.environ["ANTHROPIC_API_KEY"],
        )
    print("[backend] AWS Bedrock")
    return None  # Strands picks up AWS credentials from environment automatically


_model = _build_model()

agent = Agent(
    model=_model,
    system_prompt="""You are CTF Buddy, an expert AI assistant for Capture The Flag competitions.

APPROACH — two layers, pick the right one:

LAYER 1 — Direct tools (use for most challenges):
  Use *_inspect / encoding_identify tools first to get the full picture,
  then call targeted tools based on what the general scan found.

LAYER 2 — Workspace (use when tools get close but not all the way):
  1. Call web_fetch_challenge(url) to read the page
  2. Write custom Python code with write_and_run(code) — you can import any tool:
       from tools.crypto import decode_base64, decode_hex
       from tools.network import pcap_inspect
       from tools.web import web_inspect
       from tools.forensics import file_inspect
  3. Use read_workspace() to review or iterate on your code
  4. Use submit_answer(url, answer) to submit the final result

Use Layer 1 for simple/known challenge types.
Use Layer 2 when the challenge needs custom logic or an unknown format.
Always explain your reasoning before writing code.

NETWORK TOOLS:
- pcap_inspect(pcap_path): Full overview of any pcap — call first on network challenges
- pcap_get_stream(pcap_path, protocol, stream_index): Drill into a specific stream

CRYPTO TOOLS:
- encoding_identify(data): Identify encoding type — call first on any suspicious string
- decode_base64(data): Decode Base64 / Base64 URL-safe
- decode_hex(data): Decode hex (handles 0x, \\x, colon formats)
- decode_rot(data, shift): ROT13 / Caesar. shift=0 brute forces all 25
- decode_binary(data): Decode space-separated binary (01001000 ...)
- decode_url(data): URL-decode percent-encoded strings
- hash_identify(hash_string): Identify hash type and get hashcat mode

WEB TOOLS:
- web_inspect(url): Full overview of a web target — call first on web challenges
- web_get_paths(url): Discover hidden directories and files
- web_fuzz_param(url, param, payload_type): Test a parameter for SQLi / XSS / LFI
- web_inspect_cookie(cookie_value): Analyse a cookie (JWT, Flask session, base64, etc.)
- web_solve_image_captcha(url, form_field): Fetch page, OCR the captcha image locally, submit answer
- web_fetch_challenge(url): Fetch any challenge page — returns clean text + raw HTML so you can read and understand it before deciding how to solve it
- web_solve_sequence(url, u0, target_n, formula_expr, submit_url_template, recurrence_type): Solve any math recurrence and submit. Always call web_fetch_challenge first to read the page, then pass what you find here. formula_expr is a Python expression using 'u' (current value) and 'n' (index). Works for linear, geometric, fibonacci-like, modular.

FORENSICS TOOLS:
- file_inspect(file_path): General overview of any file — call first on forensics challenges
- file_extract_strings(file_path, min_length): Extract all printable strings from a binary
- file_check_stego(file_path): Check image for steganography (LSB, appended data, embedded archives)
- file_extract_metadata(file_path): Extract EXIF and metadata from images/docs

WORKSPACE TOOLS (Layer 2 — for hard/custom challenges):
- web_fetch_challenge(url): Fetch any challenge page — returns clean text + raw HTML
- write_and_run(code): Write Python code to workspace.py and run it. Import tools as utilities inside.
- read_workspace(): Read the current workspace.py code
- submit_answer(url, answer, method, field): Submit an answer via GET or POST
""",
    tools=[
        # Network
        pcap_inspect, pcap_get_stream,
        # Crypto
        encoding_identify, decode_base64, decode_hex,
        decode_rot, decode_binary, decode_url, hash_identify,
        # Web
        web_inspect, web_get_paths, web_fuzz_param, web_inspect_cookie,
        web_solve_image_captcha, web_fetch_challenge, web_solve_sequence,
        # Forensics
        file_inspect, file_extract_strings, file_check_stego, file_extract_metadata,
        # Workspace (Layer 2)
        web_fetch_challenge, write_and_run, read_workspace, submit_answer,
    ],
)

if __name__ == "__main__":
    print("CTF Buddy 2.0")
    print("=" * 40)
    print("Type 'exit' to quit\n")

    while True:
        user_input = input("You: ").strip()
        if user_input.lower() in ("exit", "quit"):
            break
        if not user_input:
            continue
        print()
        agent(user_input)
        print()
