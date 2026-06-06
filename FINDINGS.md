# Security Review Findings — prompt-guard

Reviewed: 2026-06-05  
**All findings closed: 2026-06-05 (PR #1)**  
Scope: full codebase (`promptguard/`, `hooks/`, `install.sh`, `tests/`)  
Method: 7-angle heuristic + per-finding verification

---

## Summary Table

| # | File | Severity | Category | Status |
|---|------|----------|----------|--------|
| 1 | `promptguard/scan.py` | HIGH | Correctness — scoring | ✅ Fixed |
| 2 | `hooks/posttooluse_guard.py` | HIGH | Bypass — extraction | ✅ Fixed |
| 3 | `promptguard/scan.py` | HIGH | Bypass — detection gap | ✅ Fixed |
| 4 | `promptguard/normalize.py` | HIGH | Bypass — normalization | ✅ Fixed |
| 5 | `install.sh` | MEDIUM | Config — incomplete install | ✅ Fixed |
| 6 | `promptguard/normalize.py` | MEDIUM | Bypass — invisible chars | ✅ Fixed |
| 7 | `promptguard/normalize.py` | MEDIUM | Bypass — ratio evasion | ✅ Fixed |
| 8 | `promptguard/scan.py` | LOW | Efficiency — no size cap | ✅ Fixed |

All 8 findings were resolved in PR #1 (merged 2026-06-05).  
An additional 11 bypass techniques were found and closed in PR #2 (merged 2026-06-06) — see commit history for details.

---

## Finding 1 — Leet Layer Double-Scores Plain-Text Injections ✅ Fixed

**Fix applied:** Skip leet layer when `norm["leet"] == norm["lowered"]` (no leet chars present).  
**Verified:** Single-signal "Ignore all previous instructions" → score 40, MEDIUM. No duplicate signal IDs.

---

## Finding 2 — `_extract_text` Doesn't Recurse Into Nested List Values ✅ Fixed

**Fix applied:** Replaced 7-key whitelist with scan of all dict values; `_extract_text(val)` replaces `json.dumps(val)`.  
**Verified:** `{"content": [{"type": "text", "text": "Ignore all previous instructions"}]}` → score 40, MEDIUM.

---

## Finding 3 — Leet Layer Skipped for Base64-Decoded Content ✅ Fixed

**Fix applied:** Added `_match_layer(dnorm["leet"], ...)` in base64 decode loop when leet ≠ lowered.  
**Verified:** base64(leet("ignore all previous instructions")) → detected.

---

## Finding 4 — `decode_base64_layers` Runs on Original Text ✅ Fixed

**Fix applied:** `decode_base64_layers` now receives `folded` (homoglyph-folded) text instead of raw `text`.  
**Verified:** Base64 token with Cyrillic 'а' inside → decoded and scanned after folding.

---

## Finding 5 — `install.sh` Matcher Omits `Fetch` and `mcp__fetch` ✅ Fixed

**Fix applied:** Matcher updated to `"WebFetch|Bash|Read|Grep|Glob|Fetch|mcp__fetch"`.

---

## Finding 6 — Bidi Override and Unicode Tag Characters Not Stripped ✅ Fixed

**Fix applied:** Added U+202A–202E (bidi overrides), U+2066–2069 (bidi isolates), and U+E0000–E007F (tag chars) to `_INVISIBLE_RE`.  
**Verified:** U+202E (RIGHT-TO-LEFT OVERRIDE) wrapping "ignore all previous instructions" → score 40, MEDIUM.

---

## Finding 7 — Printable Ratio Evasion via Unicode Padding ✅ Fixed

**Fix applied:** Removed printable-ratio threshold entirely. UTF-8 strict decoding is the quality bar.

---

## Finding 8 — No Size Limit in `scan()` ✅ Fixed

**Fix applied:** Three-window scan (head + centre + tail) for inputs exceeding `_SCAN_LIMIT = 65536`. `_SCAN_OVERLAP = 512` closes exact-boundary gap.
