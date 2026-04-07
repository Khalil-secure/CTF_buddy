"""
CTF Buddy — Claude Opus 4.6 agentic loop.
Receives challenge description + file paths, runs tools autonomously,
streams reasoning, and reports the flag when found.
"""

import os
import sys
import json
from pathlib import Path

import anthropic

from mindmap import classify, format_for_prompt
from validator import find_flag, highlight
from tools import TOOL_SCHEMAS, dispatch

MODEL = "claude-opus-4-6"

SYSTEM_PROMPT = """\
You are CTF Buddy, an expert CTF (Capture The Flag) solver specializing in network forensics.

## Your mission
Analyse the challenge, choose the right tools, execute them, reason about the output, and find the flag.

## Available tools
You have access to specialized tools for:
- pcap analysis (FTP, Telnet, HTTP credentials, Kerberos, OSPF, NTLM)
- DNS zone transfers
- Hash cracking: `ntlmv2_crack` (pure-Python, no hashcat), `hash_crack` (hashcat)
- Credential decoding (base64, URL-encoding)
- Caesar / ROT cipher brute force

## Strategy
1. For any pcap/network challenge — call `pcap_inspect` first. It detects all protocols
   in one pass and tells you exactly what to do next.
2. Read the findings and follow the recommended_next_steps.
3. Use the targeted tool based on what was found:
   - NTLM/NTLMv2 hash → `ntlmv2_crack` (preferred, no external tools needed)
   - OSPF MD5 → `ospf_crack`
   - DNS challenge → `dns_enum`
   - Other hashes → `hash_crack` (requires hashcat)
4. Report the flag clearly: FLAG: <value>

Never guess which protocol a pcap contains — let `pcap_inspect` tell you.

## Rules
- Only work with the provided challenge files — do not scan external targets
- If a tool fails, try a different approach or tool
- Be methodical: explain your reasoning before each tool call
- When you find the flag, state it clearly: FLAG: <value>

{mind_map_section}
"""


def run(
    challenge_description: str,
    challenge_files: list[str] | None = None,
    wordlist: str | None = None,
    max_turns: int = 20,
    verbose: bool = True,
) -> dict:
    """
    Run the CTF Buddy agent on a challenge.

    Args:
        challenge_description: Text description of the challenge.
        challenge_files: List of file paths (pcap, wordlist, etc.).
        max_turns: Maximum agentic loop iterations.
        verbose: Stream Claude's reasoning to stdout.

    Returns:
        dict with keys: flag, turns, conversation_summary
    """
    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    # ── Classify challenge ──────────────────────────────────────────────────
    classifications = classify(challenge_description)
    mind_map_section = format_for_prompt(classifications)

    system = SYSTEM_PROMPT.format(mind_map_section=mind_map_section)

    # ── Build initial user message ──────────────────────────────────────────
    file_info = ""
    if challenge_files:
        for path in challenge_files:
            p = Path(path).resolve()          # always give Claude absolute paths
            if p.exists():
                size = p.stat().st_size
                file_info += f"\n- `{p.name}` ({size:,} bytes) — use exact path: `{p}`"
            else:
                file_info += f"\n- `{path}` (WARNING: file not found at {p})"

    wordlist_info = ""
    if wordlist:
        wl = Path(wordlist)
        wordlist_info = f"\n\n## Wordlist\n- Use this exact path for all cracking tools: `{wl.resolve()}`"

    user_message = f"""## Challenge
{challenge_description}

## Challenge files{file_info if file_info else chr(10) + "- No files provided"}{wordlist_info}

Please solve this challenge. Start by reasoning about what type of challenge it is, then use the available tools.
Use the exact file paths provided above — do not guess alternative paths.
"""

    if verbose:
        print("\n" + "=" * 60)
        print("[CTF BUDDY] Starting analysis")
        print("=" * 60)
        if classifications:
            print(f"[mind-map] matched: {classifications[0]['type']} (score {classifications[0]['score']})")
        print()

    # ── Agentic loop ────────────────────────────────────────────────────────
    messages = [{"role": "user", "content": user_message}]
    found_flag = None
    turns = 0

    while turns < max_turns:
        turns += 1

        if verbose:
            print(f"[turn {turns}] Calling Claude...", end=" ", flush=True)

        # Stream the response
        with client.messages.stream(
            model=MODEL,
            max_tokens=8192,
            thinking={"type": "adaptive"},
            system=system,
            tools=TOOL_SCHEMAS,
            messages=messages,
        ) as stream:
            response_text = ""
            tool_calls = []

            if verbose:
                print()  # newline after "Calling Claude..."

            for event in stream:
                # Stream text to terminal
                if event.type == "content_block_delta":
                    if event.delta.type == "text_delta":
                        if verbose:
                            print(event.delta.text, end="", flush=True)
                        response_text += event.delta.text
                    elif event.delta.type == "thinking_delta":
                        pass  # thinking is internal; skip streaming it

                elif event.type == "content_block_start":
                    if event.content_block.type == "tool_use":
                        tool_calls.append({
                            "id": event.content_block.id,
                            "name": event.content_block.name,
                            "input_chunks": [],
                        })
                    elif event.content_block.type == "thinking" and verbose:
                        print("\n[thinking...]", flush=True)

                elif event.type == "content_block_delta":
                    if event.delta.type == "input_json_delta" and tool_calls:
                        tool_calls[-1]["input_chunks"].append(event.delta.partial_json)

            final_msg = stream.get_final_message()

        if verbose:
            print()  # newline after response

        # ── Append assistant turn ───────────────────────────────────────────
        messages.append({"role": "assistant", "content": final_msg.content})

        # ── Check for flag in text ──────────────────────────────────────────
        flag = find_flag(response_text)
        if flag and not found_flag:
            found_flag = flag
            if verbose:
                print(f"\n[FLAG] FLAG DETECTED: {flag}\n")

        # ── Handle tool calls ───────────────────────────────────────────────
        if final_msg.stop_reason == "end_turn":
            break

        if final_msg.stop_reason == "tool_use":
            tool_results = []

            for block in final_msg.content:
                if block.type != "tool_use":
                    continue

                tool_name = block.name
                tool_input = block.input

                if verbose:
                    print(f"\n[TOOL] Tool: {tool_name}")
                    print(f"   Input: {json.dumps(tool_input, indent=2)}")

                raw_result = dispatch(tool_name, tool_input)

                if verbose:
                    result_preview = raw_result[:500] + ("..." if len(raw_result) > 500 else "")
                    print(f"   Result: {result_preview}")

                # Check result for flag
                flag_in_result = find_flag(raw_result)
                if flag_in_result and not found_flag:
                    found_flag = flag_in_result
                    if verbose:
                        print(f"\n[FLAG] FLAG IN TOOL RESULT: {flag_in_result}\n")

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": raw_result,
                })

            messages.append({"role": "user", "content": tool_results})
            continue

        # pause_turn or unexpected — continue
        if final_msg.stop_reason == "pause_turn":
            messages.append({"role": "assistant", "content": final_msg.content})
            continue

        break  # unexpected stop reason

    if verbose:
        print("\n" + "=" * 60)
        if found_flag:
            print(f"[OK] SOLVED in {turns} turns — Flag: {found_flag}")
        else:
            print(f"[!!]  No flag found after {turns} turns")
        print("=" * 60 + "\n")

    return {
        "flag": found_flag,
        "turns": turns,
        "solved": found_flag is not None,
    }
