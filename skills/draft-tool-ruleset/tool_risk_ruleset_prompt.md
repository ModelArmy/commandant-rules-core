---
name: draft-tool-ruleset
description: "Use this skill when asked to generate a risk ruleset for a shell command or tool. Produces a JSON document conforming to tool_risk_ruleset_schema.json that maps the tool's flags, arguments, and usage patterns to intrinsic risk categories. Triggers: any request to generate, create, or draft a risk ruleset for a named shell tool. Do NOT use for assessing a specific command invocation at runtime — this skill generates the offline ruleset, not a per-invocation assessment."
compatibility: "Any agent with access to this skill directory. No script execution required."
license: See LICENSE in the project root.
---

# Generating a Tool Risk Ruleset

## What This Skill Produces

A JSON document conforming to `tool_risk_ruleset_schema.json` that maps a shell tool's flags, argument patterns, and usage combinations to intrinsic risk categories. This document is an **offline artifact** — generated once per tool per platform, reviewed by a human, and committed to the repository under `rulesets/{platform}/`.

## Resources

All resources are in the same directory as this skill:

| File                            | Purpose                                                                |
|---------------------------------|------------------------------------------------------------------------|
| `tool_risk_ruleset_schema.json` | The JSON schema the output must conform to                             |
| `tool_risk_ruleset_prompt.md`   | System prompt, user prompt template, and worked example (`sed`, linux) |

Read both files before generating any output.

---

## How to Generate a Ruleset

### Step 1 — Read the schema

Read `tool_risk_ruleset_schema.json`. Every field in your output must conform to it. Pay particular attention to:

- `platform` — required; determines which folder the ruleset is committed to
- `risk_tags` enum — use only these values, exactly as spelled
- `likely_consequences` enum — use only where consequences are concrete and direct
- `pattern_type` enum — flag, argument, flag-argument-combination, subshell, pipe
- `reversible` enum — yes, no, depends; `depends` always requires `reversible_note`
- `all_match` — false means any pattern triggers the rule (OR); true means all must match (AND)
- `match` — every pattern item requires both a `pattern` string (for Semgrep offline verification) and a `match` object (for runtime evaluation by the shard). Both are mandatory.

### Step 2 — Read the prompt

Read `tool_risk_ruleset_prompt.md`. The system prompt defines the rules. The worked `sed` (linux) example shows the expected level of detail — including populated `match` objects on every pattern.

### Step 3 — Identify the platform

Establish the target platform before writing any rules:

- `linux` — GNU implementation
- `macos` — BSD implementation; may differ significantly from GNU
- `windows` — cmd.exe or PowerShell; `/flag` syntax, different compound syntax
- `posix` — valid for both linux and macos with no platform-specific caveats

If the tool has meaningfully different flag semantics across platforms (e.g. GNU `sed -i` vs BSD `sed -i`), generate separate rulesets per platform rather than trying to cover both in one document. Use `platform_notes` to describe differences that would require a sibling ruleset.

### Step 4 — Apply your knowledge of the tool

You do not need external input beyond the tool name and platform. Apply your training knowledge of the tool's flags, argument patterns, and dangerous combinations for the specified platform.

For each flag or combination ask:
- Does this change what the tool reads, writes, deletes, or executes?
- Does this make the operation irreversible?
- Does this cause the tool to invoke another binary or spawn a subshell?
- Does this escalate privilege or modify environment?

### Step 5 — Populate both `pattern` and `match` for every pattern item

`pattern` and `match` serve different phases and must both be present:

| Field     | Phase   | Used by                                           |
|-----------|---------|---------------------------------------------------|
| `pattern` | Offline | Semgrep CLI during community ruleset verification |
| `match`   | Runtime | Crystal shard evaluator — no external process     |

The `match` object fields:

| Field         | Meaning                                                                       |
|---------------|-------------------------------------------------------------------------------|
| `flags_any`   | Fires if any of these flags are present                                       |
| `flags_all`   | Fires only if ALL of these flags are present                                  |
| `args_any`    | Fires if any of these values appear in arguments                              |
| `args_none`   | Fires only if NONE of these values appear in arguments                        |
| `raw_pattern` | Regex on raw command string — use only when flag/arg matching is insufficient |

Use `raw_pattern` sparingly — only for patterns that cannot be expressed via flag/arg fields (subshell detection, line-continuation sequences).

### Step 6 — Handle special cases

**Multiplexer tools** (busybox, toybox): set `is_multiplexer: true`. Ruleset covers dispatch behavior only.

**GNU long options**: populate `option_abbreviations` with commonly-used abbreviations to canonical forms.

**Uncertain flags**: add to `unknown_flags`. Do not invent behaviors.

### Step 7 — Write the default rule

`default_rule` covers the tool when invoked with no risky flags. It is the fallback when no specific rule matches and has no patterns — only `risk_tags`, `reversible`, and `severity`.

### Step 8 — Set confidence honestly

| Value    | When                                                            |
|----------|-----------------------------------------------------------------|
| `high`   | Detailed knowledge of this tool and its flags on this platform  |
| `medium` | Know the tool well but uncertain about some flags or edge cases |
| `low`    | Tool is unfamiliar or knowledge is limited                      |

For well-known tools (`cat`, `ls`, `find`, `grep`, `sed`, `awk`, `curl`, `git`), `high` is expected. Lower confidence on these tools signals the output warrants extra scrutiny.

---

## Output Requirements

- Valid JSON only — no preamble, no explanation, no markdown fences
- Must validate against `tool_risk_ruleset_schema.json`
- `platform` must be set
- Every rule must have at least one pattern with a concrete `example`
- Every pattern must have both `pattern` (Semgrep) and `match` (runtime) populated
- `reversible: "depends"` always accompanied by `reversible_note`
- `all_match: true` only when a combination of patterns is required — not when any single pattern is sufficient
- `raw_pattern` in `match` only when flag/arg matching is genuinely insufficient

---

## Repository Placement

Committed rulesets live at:

```
rulesets/
  linux/
    find.json
    sed.json
    grep.json
    ...
  macos/
    sed.json     ← separate from linux/sed.json; -i semantics differ
    ...
  windows/
    ...
```

A `posix` ruleset may be placed at `rulesets/posix/` if it is genuinely valid for both linux and macos. When in doubt, generate platform-specific rulesets.

---

## What This Skill Does Not Cover

- **Runtime assessment** — evaluating a specific command invocation against a committed ruleset
- **Constraint evaluation** — sandbox boundary checks, allowed-tools list; these are runtime concerns and must not appear in the ruleset
- **Verification** — cross-checking against Semgrep community rulesets or explainshell; this is a post-generation human review step

---

## Quick Reference: Risk Categories

| Category               | Meaning                                                |
|------------------------|--------------------------------------------------------|
| `reads-files`          | Accesses file content from the filesystem              |
| `writes-files`         | Modifies or creates files                              |
| `deletes-files`        | Removes files or directories                           |
| `recursive`            | Operates on directory trees                            |
| `irreversible`         | No undo path without a backup                          |
| `executes-code`        | Invokes another binary, script, or shell command       |
| `network-egress`       | Makes outbound network connections                     |
| `elevated-privilege`   | Requires or escalates privileges                       |
| `modifies-environment` | Alters shell state, environment variables, or PATH     |
| `subshell`             | Spawns a subshell via `$()`, backticks, pipes to shell |

## Quick Reference: Consequence Categories

| Consequence                    | When to use                                    |
|--------------------------------|------------------------------------------------|
| `data-loss`                    | Files permanently destroyed                    |
| `data-corruption`              | Files modified in a damaging or unintended way |
| `privacy-breach`               | Private or sensitive content exposed           |
| `computer-security-compromise` | System security posture weakened               |
| `unsafe-code-execution`        | Arbitrary or unvalidated code run              |
| `financial-loss`               | Actions with financial cost                    |
| `legal-violation`              | Actions that may violate laws or regulations   |
| `harmful-decision`             | Broader harmful consequences                   |

Only include where risk is concrete and direct. Do not speculate.
