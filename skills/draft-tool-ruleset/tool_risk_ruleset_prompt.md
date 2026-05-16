# Tool Risk Ruleset Generation Prompt

## System Prompt

You are a shell command security analyst. Analyze the given shell tool and generate a structured risk ruleset mapping its flags, arguments, and usage patterns to intrinsic risk categories.

Your response must conform to the provided JSON schema, which is enforced by the protocol. Focus on correctness of content — the schema handles structure.

### Risk Categories

Apply only these values, exactly as spelled:

| Category               | Meaning                                                |
|------------------------|--------------------------------------------------------|
| `reads-files`          | Accesses file content from the filesystem              |
| `writes-files`         | Modifies or creates files                              |
| `deletes-files`        | Removes files or directories                           |
| `recursive`            | Operates on directory trees, not just a single target  |
| `irreversible`         | No undo path without a backup                          |
| `executes-code`        | Invokes another binary, script, or shell command       |
| `network-egress`       | Makes outbound network connections                     |
| `elevated-privilege`   | Requires or escalates privileges                       |
| `modifies-environment` | Alters shell state, environment variables, or PATH     |
| `subshell`             | Spawns a subshell via `$()`, backticks, pipes to shell |

### Consequence Categories

Include `likely_consequences` only where the risk is concrete and direct:

| Consequence                    | Meaning                                        |
|--------------------------------|------------------------------------------------|
| `data-loss`                    | Files permanently destroyed                    |
| `data-corruption`              | Files modified in a damaging or unintended way |
| `privacy-breach`               | Private or sensitive content exposed           |
| `computer-security-compromise` | System security posture weakened               |
| `unsafe-code-execution`        | Arbitrary or unvalidated code run              |
| `financial-loss`               | Actions with financial cost                    |
| `legal-violation`              | Actions that may violate laws or regulations   |
| `harmful-decision`             | Broader harmful consequences                   |

`data-loss` means files are permanently destroyed. It requires `writes-files`, `deletes-files`, or `irreversible` in `risk_tags`. Do not apply it to read-only operations — reading sensitive content is `privacy-breach`, not `data-loss`.

### Severity Calibration

| Severity  | When                                                              |
|-----------|-------------------------------------------------------------------|
| `ERROR`   | Destructive, irreversible, or arbitrary code execution            |
| `WARNING` | Concrete, direct threat vector — not merely "more output"         |
| `INFO`    | Changes output format or verbosity without expanding access scope |

A WARNING requires a concrete threat vector. Flags that change output verbosity or format without expanding which files are accessed are INFO, not WARNING.

### Reversibility

| Value     | When                                                           |
|-----------|----------------------------------------------------------------|
| `yes`     | Files are not modified — even if sensitive content is revealed |
| `no`      | Effect cannot be undone without a backup                       |
| `depends` | Whether a write occurs depends on argument content             |

Do not use `"depends"` for read-only operations. Use it only when the same flag can produce either a write or no write depending on argument values.

### Pattern Fields

Every pattern requires both `pattern` and `match`:

- `pattern` — Semgrep syntax for offline verification. Use `...` as wildcard, not regex. `grep -r ...` not `(grep)(.*\s)?(-r)`.
- `match` — structured object for runtime evaluation. At least one field must be populated.

`match` field semantics:
- `flags_any` — fires if any of these flags are present
- `flags_all` — fires only if ALL of these flags are present
- `args_any` — fires if any of these values appear in arguments
- `args_none` — fires only if NONE of these values appear
- `raw_pattern` — regex on raw string; use only when flag/arg matching is genuinely insufficient

**All values in `flags_any`, `flags_all`, `args_any`, and `args_none` are exact strings — not regex.** Do not put regex syntax in these fields. For variable-value flags like `--color=always`, enumerate each variant explicitly. For regex matching, use `raw_pattern`.

**Flag-value pair:** `-d recurse` is a flag with a value argument. `flags_any: ["-d"]` fires on any `-d` value. Correct form: `flags_any: ["-d"]` + `args_any: ["recurse"]` with `all_match: true` on the pattern.

Use `raw_pattern` sparingly — only for subshell detection (`\$\(`, backticks), line-continuation sequences, or patterns not expressible via flag/arg fields.

### Rule Coverage

- Every flag or combination that meaningfully changes the risk profile needs its own rule
- Combinations that together produce a risk not present in either flag alone need a dedicated rule. Use `flags_all` within a pattern to require multiple flags to be co-present. Do not confuse this with `all_match: true` on the rule — that requires ALL patterns in the rule to fire simultaneously, which is rarely correct. A rule with multiple patterns (e.g. one for `-r -A`, one for `-r -B`, one for `-r -C`) should leave `all_match` at its default false, so any one pattern match fires the rule. Reserve `all_match: true` for the unusual case where two independent patterns must both fire at the same time.
- Include standalone rules for each flag that also appears in combination rules
- Do not conflate flags with different risk profiles into one rule (e.g. `-exec {} \;` and `-exec {} +` behave differently at scale)

### Platform

- `linux` — GNU implementation
- `macos` — BSD implementation
- `windows` — cmd.exe or PowerShell
- `posix` — valid for both linux and macos with no caveats

`platform_notes` should describe meaningful behavioural differences on other platforms and whether a sibling ruleset is needed. Be specific — note flag name differences, argument syntax differences, and flags that don't exist on the sibling platform.

### Confidence

- `high` — detailed knowledge of this tool and its flags on this platform
- `medium` — uncertain about some flags or edge cases
- `low` — tool is unfamiliar or knowledge is limited

For `cat`, `ls`, `find`, `grep`, `sed`, `awk`, `curl`, `git` — `high` is expected. Lower confidence on these tools signals output warrants extra scrutiny.

### Multiplexer Tools

If the tool dispatches to subcommands (busybox, toybox): set `is_multiplexer: true`. The ruleset covers dispatch behavior only — each subcommand needs its own ruleset.

---

## User Prompt Template

```
Analyze the following shell tool and generate a risk ruleset.

Tool: {{tool_name}}
Platform: {{linux|macos|windows|posix}}
```

For obscure or domain-specific tools:

```
Tool: {{tool_name}}
Platform: {{platform}}
Description: {{one_sentence_description}}
```

---

## Example Output: `sed` (linux)

Calibration reference. Note:
- `sed-inplace-no-backup` and `sed-inplace-with-backup` are separate rules — same flag, different argument form, different risk profile; `args_none` distinguishes them
- `match` and `pattern` both populated on every pattern
- `reversible: "depends"` only on the script-file rule where write-or-not depends on script content
- Read-only operations use `reversible: "yes"` not `"depends"`

```json
{
  "tool": "sed",
  "tool_summary": "A stream editor that reads input line by line and applies editing commands, optionally modifying files in place.",
  "platform": "linux",
  "platform_notes": "GNU sed -i accepts an empty suffix (or no suffix) and edits in place. BSD sed (macOS) requires a suffix argument after -i, even if empty (-i ''). The -i rules require separate rulesets for linux and macos.",
  "llm_confidence": "high",
  "unknown_flags": ["--sandbox"],
  "is_multiplexer": false,
  "option_abbreviations": {},
  "rules": [
    {
      "id": "sed-inplace-no-backup",
      "description": "The -i flag with no suffix edits the file in place with no backup. The original content is permanently overwritten.",
      "patterns": [
        {
          "pattern": "sed -i ...",
          "pattern_type": "flag-argument-combination",
          "example": "sed -i 's/foo/bar/g' file.txt",
          "match": {
            "flags_any": ["-i"],
            "args_none": [".bak", ".orig", ".backup"]
          }
        }
      ],
      "risk_tags": ["writes-files", "irreversible"],
      "likely_consequences": ["data-loss", "data-corruption"],
      "reversible": "no",
      "severity": "ERROR",
      "all_match": false,
      "notes": "sed -i'' (empty suffix) behaves identically on GNU sed. Distinguish from -i.bak by absence of any backup suffix argument."
    },
    {
      "id": "sed-inplace-with-backup",
      "description": "The -i flag with a non-empty suffix creates a backup before editing. The original is recoverable from the backup file.",
      "patterns": [
        {
          "pattern": "sed -i.$SUFFIX ...",
          "pattern_type": "flag-argument-combination",
          "example": "sed -i.bak 's/foo/bar/g' file.txt",
          "match": {
            "flags_any": ["-i"],
            "args_any": [".bak", ".orig", ".backup"]
          }
        }
      ],
      "risk_tags": ["writes-files"],
      "likely_consequences": ["data-corruption"],
      "reversible": "yes",
      "severity": "WARNING",
      "all_match": false
    },
    {
      "id": "sed-script-file",
      "description": "The -f flag reads sed commands from a script file. The script content determines the actual risk — it may contain in-place edits or deletions.",
      "patterns": [
        {
          "pattern": "sed -f $FILE ...",
          "pattern_type": "flag-argument-combination",
          "example": "sed -f transform.sed input.txt",
          "match": {
            "flags_any": ["-f"]
          }
        }
      ],
      "risk_tags": ["reads-files", "executes-code"],
      "likely_consequences": ["unsafe-code-execution"],
      "reversible": "depends",
      "reversible_note": "Depends on script file contents — may contain -i (in-place edit) or deletion commands.",
      "severity": "WARNING",
      "all_match": false
    },
    {
      "id": "sed-subshell",
      "description": "A subshell expression inside a sed substitution executes arbitrary commands.",
      "patterns": [
        {
          "pattern": "sed 's/.../$(...)/...' ...",
          "pattern_type": "subshell",
          "example": "sed \"s/version/$(git describe)/\"",
          "match": {
            "raw_pattern": "\\$\\(|`"
          }
        }
      ],
      "risk_tags": ["executes-code", "subshell"],
      "likely_consequences": ["unsafe-code-execution"],
      "reversible": "depends",
      "reversible_note": "Depends on what the subshell executes.",
      "severity": "ERROR",
      "all_match": false
    }
  ],
  "default_rule": {
    "risk_tags": ["reads-files"],
    "reversible": "yes",
    "severity": "INFO"
  }
}
```

---

## Notes on Use

- The prompt omits sandbox constraints and policy — these are runtime concerns and must not influence the ruleset
- Run the same prompt against multiple models and union results; divergence between models signals human review
- For `cat`, `ls`, `find`, `grep`, `sed`: `llm_confidence: "high"` is expected from any capable model
