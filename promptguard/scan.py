"""Heuristic prompt-injection pre-filter (the cheap, deterministic triage layer).

This is NOT a blocklist that rejects input. It is a *scorer* that runs over
UNTRUSTED content (tool outputs entering the model's context) and emits a risk
score plus the evidence behind it. Low scores pass silently; medium/high scores
are escalated to the LLM-as-judge step (the prompt-guard skill) for a semantic
verdict. Combining a fast filter with model judgment is what avoids both the
regex arms-race and the cost of judging every byte.

Design choices that differ from a naive blocklist:
  * Scores instead of rejects -- evidence accrues, no single magic word decides.
  * Runs after normalization -- evasion via unicode/base64/leet is folded first.
  * Targets instructions aimed at an *assistant*, not generic keywords, so it
    does not fire on legitimate prose that merely mentions "instructions".

Python 3.6.8 compatible.
"""
from __future__ import print_function, unicode_literals

import json
import re
import sys

from . import normalize as _norm

# Each signal: (id, weight, compiled regex, human description).
# Weights are tuned so that any single strong signal lands in MEDIUM and two
# corroborating signals reach HIGH. They are applied to normalized text.
_SIGNALS = [
    ("instruction_override", 40,
     re.compile(
         r"\b(ignore|disregard|forget|override|bypass|dismiss|abandon|discard|"
         r"revoke|supersede|annul|negate|nullify|cancel|suspend|erase|void|"
         r"invalidate|overrule|countermand|rescind|retract|withdraw)\b"
         r"[^\n]{0,40}"
         r"\b(previous|prior|above|earlier|all|any|the|your|existing|current|"
         r"former|past|original|initial|foregoing|aforementioned)\b"
         r"[^\n]{0,20}"
         r"\b(instruction|instructions|prompt|prompts|context|rule|rules|"
         r"direction|directions|directive|directives|mandate|mandates|"
         r"objective|objectives|constraint|constraints|guideline|guidelines|"
         r"order|orders|training|programming|configuration|behavior|conduct|"
         r"restriction|restrictions|limit|limits|policy|policies|protocol|"
         r"protocols|command|commands|task|tasks)\b"
     ),
     "Attempt to discard prior instructions/context"),
    ("role_reassignment", 30,
     re.compile(
         r"\b(you are now|from now on,? you(?:r)?|you must now|act as|"
         r"pretend to be|roleplay as|behave as|you will now|new persona|"
         r"developer mode|do anything now|\bdan\b)\b"
     ),
     "Attempt to reassign the assistant's role/persona"),
    ("system_prompt_probe", 32,
     re.compile(r"\b(system prompt|your (instructions|guidelines|rules|directives|configuration|system message)|initial prompt|reveal your|print your|repeat the (above|system)|what were you told)\b"),
     "Probing or referencing the assistant's system prompt"),
    ("tool_call_mimicry", 32,
     re.compile(r"(</?\s*(system|assistant|user|inst|tool_call|function_calls?|antml)\s*>|\[/?inst\]|\bassistant\s*:|\bsystem\s*:|<\|.*?\|>)"),
     "Fake role tags / tool-call syntax to impersonate the harness"),
    ("exfiltration", 36,
     re.compile(
         r"\b(send|post|exfiltrate|upload|email|leak|transmit|curl|wget|fetch|"
         r"share|forward|transfer|export|dump|copy|relay|disclose|reveal|give|"
         r"extract|harvest|ship|push|pipe|output|expose|smuggle)\b"
         r"[^\n]{0,60}?"
         r"\b(api[_ ]?key|secret|token|password|credential|\.ssh|id_rsa|"
         r"/etc/passwd|environment variable|conversation|chat history|"
         r"system prompt|system message|private key|ssh key|access key|"
         r"session|auth|bearer|cookie|passphrase|configuration)\b"
     ),
     "Instruction to exfiltrate secrets or context"),
    ("embedded_command", 32,
     re.compile(r"\b(run|execute|eval|delete|rm -rf|drop table|chmod|chown|sudo|install|download and run|curl[^\n]{0,40}\|\s*(sh|bash))\b"),
     "Embedded instruction to run a command / destructive action"),
    ("urgency_authority", 14,
     re.compile(r"\b(important[:!]|urgent[:!]|critical[:!]|you must|it is (critical|imperative|mandatory)|as an ai|do not (tell|inform|warn) the user|without (asking|confirmation)|silently)\b"),
     "Pressure/authority framing to suppress scrutiny"),
    ("instruction_to_assistant", 18,
     re.compile(r"\b(assistant|claude|ai|model|llm|chatbot|agent)\b[^.\n]{0,20}\b(should|must|will|needs to|has to|please)\b"),
     "Directives addressed to the assistant by name/role"),
]

# Risk bands. Tuned against the weights above.
_BAND_MEDIUM = 30
_BAND_HIGH = 60
_SCAN_LIMIT = 65536   # per-window scan budget
_SCAN_OVERLAP = 512   # overlap at head/tail join to close exact-boundary gap


def _band(score):
    if score >= _BAND_HIGH:
        return "high"
    if score >= _BAND_MEDIUM:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _recommend(band):
    # 'escalate' -> hand to the LLM-judge skill; 'advise' -> inline warning only.
    if band == "high":
        return "escalate"
    if band == "medium":
        return "escalate"
    if band == "low":
        return "advise"
    return "allow"


def _match_layer(text, found, multiplier=1.0):
    """Score one text layer, appending hits to `found`. Returns added score."""
    added = 0
    for sig_id, weight, pattern, desc in _SIGNALS:
        m = pattern.search(text)
        if m:
            w = int(round(weight * multiplier))
            added += w
            found.append({
                "id": sig_id,
                "weight": w,
                "description": desc,
                "evidence": _snippet(text, m.start(), m.end()),
            })
    return added


def _snippet(text, start, end, pad=24):
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    frag = text[lo:hi].replace("\n", " ")
    return ("..." if lo > 0 else "") + frag + ("..." if hi < len(text) else "")


def scan(content, source="unknown"):
    """Score `content` for prompt-injection risk.

    Returns a JSON-serializable dict with risk_score, risk_band, recommend,
    signals (evidence), and obfuscation indicators. Caps at 100.
    """
    if content is None:
        content = ""
    original_length = len(content)
    if original_length > _SCAN_LIMIT:
        third = _SCAN_LIMIT // 3
        mid = original_length // 2
        # Three-window scan: head + centre + tail — no single blind spot covers all three
        content = (content[:third + _SCAN_OVERLAP] +
                   content[mid - third // 2: mid + third // 2] +
                   content[-(third + _SCAN_OVERLAP):])
    norm = _norm.normalize(content)
    found = []
    score = 0

    # Primary layer: normalized + homoglyph-folded text.
    score += _match_layer(norm["lowered"], found)
    # Leet-folded layer catches "ign0re" etc. Only run when leet folding actually
    # changed something — otherwise lowered == leet and every signal fires twice.
    # Multiplier 0.75 ensures a single strong leet signal (e.g. instruction_override
    # weight 40) reaches the MEDIUM threshold (40*0.75=30) on its own.
    if norm["leet"] != norm["lowered"]:
        score += _match_layer(norm["leet"], found, multiplier=0.75)

    # Decoded base64 reveals are high-signal: hidden instructions are rarely benign.
    for token, decoded in norm["decoded_layers"]:
        dnorm = _norm.normalize(decoded)
        layer_score = _match_layer(dnorm["lowered"], found, multiplier=1.0)
        # Apply leet layer to decoded content too — catches double-encoded payloads.
        if dnorm["leet"] != dnorm["lowered"]:
            layer_score += _match_layer(dnorm["leet"], found, multiplier=0.6)
        if layer_score:
            score += layer_score + 20  # bonus: it was deliberately hidden
            found.append({
                "id": "encoded_payload",
                "weight": 20,
                "description": "Injection text concealed in a base64 blob",
                "evidence": (token[:24] + "... -> " + decoded[:60]),
            })

    # Obfuscation indicators add a little on their own (intent signal).
    if norm["invisible_count"] >= 3:
        score += 12
        found.append({
            "id": "invisible_chars",
            "weight": 12,
            "description": "Zero-width/invisible characters used to break up text",
            "evidence": "%d invisible characters stripped" % norm["invisible_count"],
        })
    if norm["homoglyph_count"] >= 3:
        score += 12
        found.append({
            "id": "homoglyphs",
            "weight": 12,
            "description": "Look-alike Unicode characters substituted for ASCII",
            "evidence": "%d homoglyphs folded" % norm["homoglyph_count"],
        })

    score = min(100, score)
    band = _band(score)
    return {
        "source": source,
        "risk_score": score,
        "risk_band": band,
        "recommend": _recommend(band),
        "signals": found,
        "obfuscation": {
            "invisible_chars": norm["invisible_count"],
            "homoglyphs": norm["homoglyph_count"],
            "base64_reveals": len(norm["decoded_layers"]),
        },
        "content_length": original_length,
    }


def _main(argv):
    import argparse
    p = argparse.ArgumentParser(description="Scan untrusted text for prompt-injection risk.")
    p.add_argument("file", nargs="?", help="File to scan; reads stdin if omitted.")
    p.add_argument("--source", default="cli", help="Label for the content's origin.")
    p.add_argument("--pretty", action="store_true", help="Indent JSON output.")
    args = p.parse_args(argv)

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    else:
        content = sys.stdin.read()

    result = scan(content, source=args.source)
    print(json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False))
    # Exit code encodes the band for shell/hook use: 0 none/low, 1 medium, 2 high.
    return {"none": 0, "low": 0, "medium": 1, "high": 2}[result["risk_band"]]


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
