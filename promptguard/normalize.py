"""Text normalization for prompt-injection detection.

The point of normalization is to defeat *evasion*: attackers hide instructions
behind zero-width characters, homoglyphs, leetspeak, and base64 so a naive
substring/regex scan misses them. We canonicalize text BEFORE scoring so the
detector sees what the model effectively sees, not the obfuscated surface form.

Python 3.6.8 compatible (no f-strings with '=', no dataclasses, no walrus).
"""
from __future__ import print_function, unicode_literals

import base64
import binascii
import re
import unicodedata

# Zero-width / invisible characters used to break up trigger words.
_INVISIBLE = [
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "⁠",  # word joiner
    "﻿",  # BOM / zero-width no-break space
    "­",  # soft hyphen
    "͏",  # combining grapheme joiner
]
_INVISIBLE_RE = re.compile("[" + "".join(_INVISIBLE) + "]")

# Common homoglyphs -> ASCII. Cyrillic/Greek look-alikes are the usual vectors.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "Ѕ": "S", "І": "I", "Ј": "J", "Х": "X", "Ο": "O",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ρ": "P", "Τ": "T", "Χ": "X",
    "ɣ": "y", "ɩ": "i",
}

# Leetspeak folding, applied only for matching (not shown back to the user).
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}

_B64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_PRINTABLE_RE = re.compile(r"[\x09\x0a\x0d\x20-\x7e]")


def strip_invisible(text):
    """Remove zero-width / invisible formatting characters."""
    return _INVISIBLE_RE.sub("", text)


def fold_homoglyphs(text):
    """Map look-alike Unicode letters to their ASCII equivalents."""
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def fold_leet(text):
    """Fold common leetspeak substitutions for matching purposes."""
    return "".join(_LEET.get(ch, ch) for ch in text)


def decode_base64_layers(text, max_tokens=20):
    """Find base64-looking tokens and return any that decode to printable text.

    Returns a list of (token, decoded) pairs. We only surface decodes that are
    mostly printable ASCII -- random binary is not an injection payload we can
    read, and treating it as one creates noise.
    """
    out = []
    for match in list(_B64_TOKEN_RE.finditer(text))[:max_tokens]:
        token = match.group(0)
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            continue
        printable = len(_PRINTABLE_RE.findall(decoded))
        if decoded and printable / float(len(decoded)) >= 0.85:
            out.append((token, decoded))
    return out


def normalize(text):
    """Canonicalize text for scoring.

    Returns a dict:
      lowered          - NFKC + invisible-stripped + homoglyph-folded, lowercased
      leet             - lowered with leetspeak folded (for trigger matching)
      decoded_layers   - list of (token, decoded) base64 reveals
      invisible_count  - how many invisible chars were stripped (obfuscation signal)
      homoglyph_count  - how many homoglyphs were folded (obfuscation signal)
    """
    if text is None:
        text = ""
    nfkc = unicodedata.normalize("NFKC", text)
    invisible_count = len(_INVISIBLE_RE.findall(nfkc))
    no_invis = strip_invisible(nfkc)
    folded = fold_homoglyphs(no_invis)
    homoglyph_count = sum(1 for a, b in zip(no_invis, folded) if a != b)
    lowered = folded.lower()
    return {
        "lowered": lowered,
        "leet": fold_leet(lowered),
        "decoded_layers": decode_base64_layers(text),
        "invisible_count": invisible_count,
        "homoglyph_count": homoglyph_count,
    }
