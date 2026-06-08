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
import html
import re
import unicodedata
import urllib.parse

# Zero-width / invisible characters used to break up trigger words.
_INVISIBLE = [
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "⁠",  # word joiner
    "﻿",  # BOM / zero-width no-break space
    "­",  # soft hyphen
    "͏",  # combining grapheme joiner
    # Bidi override / isolate chars — known LLM text-direction attack vector
    "‪", "‫", "‬", "‭", "‮",  # LTR/RTL embedding and override
    "⁦", "⁧", "⁨", "⁩",             # bidi isolates
]
# Tag characters (U+E0000–U+E007F) are appended as a range in the pattern.
_INVISIBLE_RE = re.compile(
    "[" + "".join(_INVISIBLE) + "\U000e0000-\U000e007f]"
)

# Common homoglyphs -> ASCII. Cyrillic/Greek look-alikes are the usual vectors.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "Ѕ": "S", "І": "I", "Ј": "J", "Х": "X", "Ο": "O",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ρ": "P", "Τ": "T", "Χ": "X",
    "ɣ": "y", "ɩ": "i",
    # Greek lowercase homoglyphs missing from the baseline
    "ι": "i", "ο": "o", "λ": "l", "μ": "m", "ρ": "r",
    "σ": "s", "ς": "s", "τ": "t", "υ": "y", "φ": "f",
    "ω": "o",
    # P1: remaining Greek lowercase homoglyphs
    "κ": "k", "η": "n", "χ": "x", "γ": "y",
    # QA: additional Greek homoglyphs with clear ASCII visual similarity
    "α": "a", "ε": "e", "ν": "v", "β": "b", "δ": "d",
    # Greek uppercase gaps
    "Ι": "I", "Υ": "Y", "Ζ": "Z",
}

# Leetspeak folding, applied only for matching (not shown back to the user).
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}

_MAX_DECODE_ITERATIONS = 5

# Matches both standard (+/) and URL-safe (-_) base64 tokens of 16+ chars.
_B64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_PRINTABLE_RE = re.compile(r"[\x09\x0a\x0d\x20-\x7e]")


def decode_html_entities(text):
    """Decode HTML character references: &#105; → i, &#x69; → i, &lt; → <."""
    try:
        return html.unescape(text)
    except Exception:
        return text


def decode_url_encoding(text):
    """Decode URL percent-encoding: %69%67%6e%6f%72%65 → ignore."""
    try:
        return urllib.parse.unquote(text)
    except Exception:
        return text


def strip_invisible(text):
    """Remove zero-width / invisible formatting characters."""
    return _INVISIBLE_RE.sub("", text)


def fold_homoglyphs(text):
    """Map look-alike Unicode letters to their ASCII equivalents."""
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def fold_leet(text):
    """Fold common leetspeak substitutions for matching purposes."""
    return "".join(_LEET.get(ch, ch) for ch in text)


def strip_combining(text):
    """Remove Unicode Nonspacing Mark (Mn) characters used to break trigger words."""
    return "".join(ch for ch in text if unicodedata.category(ch) != "Mn")


def _decode_encodings(text):
    """Iteratively decode URL percent-encoding and HTML entities until stable.

    Handles multi-layer evasion like %2569gnore (double URL) and
    %26%23105%3Bgnore (URL-encoded HTML entity).
    """
    prev = None
    iterations = 0
    while prev != text and iterations < _MAX_DECODE_ITERATIONS:
        prev = text
        try:
            text = urllib.parse.unquote(text)
        except Exception:
            pass
        try:
            text = html.unescape(text)
        except Exception:
            pass
        iterations += 1
    return text


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
            # Fall back to URL-safe alphabet (- and _ instead of + and /)
            try:
                raw = base64.urlsafe_b64decode(padded)
            except (binascii.Error, ValueError):
                continue
        try:
            decoded = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            continue
        if decoded:
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
    # Iterative decode: handles double-URL-encoding and URL-encoded HTML entities.
    nfkc = _decode_encodings(nfkc)
    # Re-normalize: decoding can introduce full-width or composed chars
    # (e.g. &#65353; → ｉ) that NFKC must fold to ASCII equivalents.
    nfkc = unicodedata.normalize("NFKC", nfkc)
    # Strip combining marks (e.g. U+0336 stroke overlay used to break \b matching).
    nfkc = strip_combining(nfkc)
    # P0: NFKC may have produced precomposed accented Latin chars (e.g. ï U+00EF from i+U+0308).
    # Those are category Ll (not Mn), so strip_combining above missed them.
    # NFD decomposes them back into base-letter + combining-mark; strip_combining then removes the mark.
    nfkc = unicodedata.normalize("NFD", nfkc)
    nfkc = strip_combining(nfkc)
    invisible_count = len(_INVISIBLE_RE.findall(nfkc))
    no_invis = strip_invisible(nfkc)
    folded = fold_homoglyphs(no_invis)
    homoglyph_count = sum(1 for a, b in zip(no_invis, folded) if a != b)
    lowered = folded.lower()
    return {
        "lowered": lowered,
        "leet": fold_leet(lowered),
        "decoded_layers": decode_base64_layers(folded),
        "invisible_count": invisible_count,
        "homoglyph_count": homoglyph_count,
    }
