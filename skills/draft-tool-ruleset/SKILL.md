---
name: draft-tool-ruleset
description: "Use this skill when asked to generate a risk ruleset for a shell command or tool. Produces a JSON document conforming to tool_risk_ruleset_schema.json that maps the tool's flags, arguments, and usage patterns to intrinsic risk categories. Triggers: any request to generate, create, or draft a risk ruleset for a named shell tool. Do NOT use for assessing a specific command invocation at runtime — this skill generates the offline ruleset, not a per-invocation assessment."
compatibility: "Any agent with access to this skill directory. No script execution required."
license: See LICENSE in the project root.
---

# Drafting a Tool Risk Ruleset

## What This Skill Produces

A JSON document conforming to `tool_risk_ruleset_schema.json` that maps a shell tool's flags, argument patterns, and usage combinations to intrinsic risk categories. This is an **offline artifact** — generated once per tool per platform, reviewed by a human, and committed under `rulesets/{platform}/`.

## Resources

| File | Purpose |
|---|---|
| `tool_risk_ruleset_schema.json` | JSON schema — structure, types, enums, and required fields |
| `tool_risk_ruleset_prompt.md` | Generation rules and worked example (`sed`, linux) |

The schema is enforced by the protocol at generation time. Read the prompt for the judgment rules the schema cannot enforce.

---

## How to Generate a Ruleset

### Step 1 — Identify the platform

- `linux` — GNU implementation
- `macos` — BSD implementation; may differ significantly from GNU
- `windows` — cmd.exe or PowerShell
- `posix` — valid for both linux and macos with no platform-specific caveats

When flag semantics differ meaningfully across platforms, generate separate rulesets. `platform_notes` should describe what differs and whether a sibling ruleset is needed.

### Step 2 — Apply your knowledge of the tool

For each flag or combination, ask:
- Does this change what the tool reads, writes, deletes, or executes?
- Does this make the operation irreversible?
- Does this invoke another binary or spawn a subshell?
- Does this escalate privilege or modify environment?

Every flag or combination that meaningfully changes the risk profile needs its own rule. Combinations that together produce a risk not present in either flag alone need a dedicated rule — use `flags_all` within a pattern to require multiple flags to be co-present. `all_match: true` on the rule is different: it requires ALL patterns in the rule to fire simultaneously. This is rarely correct — use it only when the rule genuinely needs two independent patterns to both match at the same time. When a rule has multiple patterns each encoding a flag combination via `flags_all`, leave `all_match` at its default (false) so any one pattern fires the rule.

### Step 3 — Populate both `pattern` and `match`

These serve different phases:

| Field | Phase | Used by |
|---|---|---|
| `pattern` | Offline | Semgrep CLI during verification |
| `match` | Runtime | Crystal shard evaluator |

`pattern` uses Semgrep syntax — `...` as wildcard, not regex. `grep -r ...` not `(grep)(.*\s)?(-r)`.

`match` field semantics:

| Field | Meaning |
|---|---|
| `flags_any` | Fires if any of these flags are present |
| `flags_all` | Fires only if ALL of these flags are present |
| `args_any` | Fires if any of these values appear in arguments |
| `args_none` | Fires only if NONE of these values appear |
| `raw_pattern` | Regex on raw string — use only when flag/arg matching is insufficient |

All values in `flags_any`, `flags_all`, `args_any`, and `args_none` are matched as **exact strings — not regex**. For regex matching against the raw command string, use `raw_pattern`.

**Flag-value pair trap:** `-d recurse` cannot be matched with `flags_any: ["-d"]` alone — that fires on `-d skip` too. Use `flags_any: ["-d"]` + `args_any: ["recurse"]` with `all_match: true`.

Use `raw_pattern` sparingly — only for subshell detection, line-continuation sequences, or patterns genuinely not expressible via flag/arg fields.

### Step 4 — Calibrate severity honestly

| Severity | When |
|---|---|
| `ERROR` | Destructive, irreversible, or arbitrary code execution |
| `WARNING` | Concrete, direct threat vector beyond output verbosity |
| `INFO` | Changes output format without expanding access scope |

A WARNING requires a concrete threat vector — not just "more information is revealed." Flags that change output format or verbosity without expanding file access are INFO.

### Step 5 — Set reversible accurately

| Value | When |
|---|---|
| `yes` | Files are not modified |
| `no` | Effect cannot be undone without a backup |
| `depends` | Outcome genuinely varies based on argument content |

Read-only operations are `"yes"` even if output reveals sensitive content. `"depends"` is for cases where whether a write occurs depends on argument values — not for read operations where the content revealed varies.

### Step 6 — Handle special cases

**Multiplexers** (busybox, toybox): ruleset covers dispatch behavior only; each subcommand needs its own ruleset.

**GNU long options**: populate `option_abbreviations` with commonly-used abbreviations to canonical forms.

**Uncertain flags**: add to `unknown_flags`. Do not invent behaviors.

### Step 7 — Write the default rule

Covers the tool when invoked with no risky flags. Lowest-risk baseline state of the tool. No patterns — only `risk_tags`, `reversible`, `severity`.

---

### Step 8 — Self-review before output

Before producing the final JSON, verify:

- [ ] **`likely_consequences` direct-cause test**: for each tag, does this rule's matched command directly cause this outcome — or does it only make a harmful outcome easier for a subsequent action? If a separate actor, decision, or tool is required, remove the tag and add a caveat to `notes` instead.
- [ ] **Severity consistency within groups**: find rules that share the same base operation with different output modifiers (e.g. recursive search + count vs. recursive search + filename-only). Are severity levels consistent across the group? If not, is the difference justified and recorded in `notes`?
- [ ] **`reversible: "depends"` check**: does a write actually occur conditionally, or is this read-only with variable output content? If the latter, change to `"yes"`.
- [ ] **Exact strings in `match` fields**: do any values in `flags_any`, `flags_all`, `args_any`, or `args_none` contain regex syntax? If so, move the regex to `raw_pattern` and replace the match field value with the exact string a parser would produce.

---

## Repository Placement

```
rulesets/
  posix/      ← valid for linux and macos without caveats
  linux/      ← GNU-specific
  macos/      ← BSD-specific
  windows/
```

When in doubt between `posix` and platform-specific, generate platform-specific. A `posix` ruleset that silently misrepresents BSD behaviour is worse than two honest platform-specific rulesets.

---

## What This Skill Does Not Cover

- Runtime assessment of a specific command invocation
- Constraint evaluation (sandbox boundary, allowed-tools list) — runtime concerns only
- Verification against community rulesets — post-generation human review step
