# Ruleset Review Guide

This document is used by both human reviewers and LLMs. The checklist and reference material in Sections 2–6 apply equally to both. Where guidance differs by audience it is labelled **[human]** or **[LLM]**; everything else is shared.

**[LLM] — Starting a review session:** Upload this document, the ruleset JSON(s) to be reviewed, and `tool_risk_ruleset_schema.json` from `commandant-rules-core/skills/draft-tool-ruleset/`. Then produce your review as an **annotated list of findings**, one finding per issue, each with: the rule `id` (or `"top-level"` for file-level issues), the field in question, a description of the problem, and a concrete recommended fix. At the end, produce a corrected version of any rule that had findings.

**[human] — Starting a review session:** Upload the same files. Work through the checklist in Section 2 and record findings as inline comments or a separate notes file.

---

## 1. Project Context

`commandant` is a shell command risk assessment library and protocol server for AI agent tool calling. Rulesets map shell tool flags and argument patterns to intrinsic risk categories. They are generated offline by LLMs using the `draft-tool-ruleset` skill, reviewed by a human, and committed to `modelarmy/commandant-rules-core`.

The goal of review is to produce a commit-ready ruleset — correct, complete, calibrated, and schema-compliant.

---

## 2. Review Checklist

### 2.1. Schema Compliance

Required field presence and type correctness are enforced by the protocol at generation time — the model cannot produce output that violates `required` or enum constraints. No need to check field presence manually.

**[LLM]** Skip the field-presence check and go directly to the content checks below.

**Do check:**
- [ ] `id` follows `{tool}-{risk-summary}` convention, lowercase hyphenated
- [ ] `description` explains *why* the flag is risky, not just *what* it does
- [ ] `platform` value matches the intended target platform
- [ ] `platform_notes` content is accurate and specific — not generic
- [ ] `mitre_attack` is present on every rule (enforced by schema, but verify content): each listed technique must be one the matched command *directly* performs — not one it merely enables for a subsequent action. Empty array `[]` is correct when no technique applies.

### 2.2. Pattern Field Format

The `pattern` field must use **Semgrep pattern syntax**, not regex:
- ✅ `grep -r ...` — Semgrep-style; `...` is the wildcard
- ❌ `(grep)(.*\\s)?(-r)(\\s.*)?` — this is regex; belongs in `match.raw_pattern` if needed at all

If the model used regex in the `pattern` field, rewrite as Semgrep-style or flag for correction.

### 2.3. Match Object Correctness

Each pattern must have a `match` object. Verify:

- `flags_any` — fires if **any** of these flags are present
- `flags_all` — fires only if **all** of these flags are present
- `args_any` — fires if **any** of these values appear in arguments
- `args_none` — fires only if **none** of these values appear in arguments
- `raw_pattern` — regex on raw string; use only when flag/arg matching is insufficient

**Flag-value pair trap:** flags like `-d recurse` (where the value is a separate token) cannot be matched with `flags_any: ["-d"]` alone — that fires on `-d skip` too. Use `flags_any: ["-d"]` + `args_any: ["recurse"]` with `all_match: true`, or `raw_pattern`.

**`match` must be non-empty** (`minProperties: 1`). A `match: {}` object is invalid — at least one of `flags_any`, `flags_all`, `args_any`, `args_none`, or `raw_pattern` must be present. The protocol enforces this but check that the populated field is semantically correct, not just present.

**`all_match` on the rule vs. within `match`:** `rule.all_match: true` means ALL patterns in the rule must fire (AND logic across patterns). The `match` object's `flags_all` means ALL of those flags must be present. These are independent.

### 2.4. Severity Calibration

| Severity  | When                                                              |
|-----------|-------------------------------------------------------------------|
| `ERROR`   | Destructive, irreversible, or arbitrary code execution            |
| `WARNING` | Meaningful risk requiring attention — concrete threat vector      |
| `INFO`    | Changes output format or verbosity without expanding access scope |

**Common miscalibrations to check:**
- Context flags (`-A`, `-B`, `-C`, `-n`) — INFO unless combined with recursive search
- `-v` (invert match) — INFO standalone; WARNING only when combined with `-r`
- `-l`, `-L` (list files) — INFO; file listing is reconnaissance but not high risk alone
- `-f` (pattern file) — WARNING standalone is borderline; ERROR only combined with `-r`

A WARNING requires a **concrete, direct threat vector** beyond "more information is revealed." If the description only says "expands output" or "reveals more content," it should be INFO.

### 2.5. Reversible Field Accuracy

| Value     | When                                                                  |
|-----------|-----------------------------------------------------------------------|
| `yes`     | Files are not modified; outcome is the same regardless of arguments   |
| `no`      | Effect cannot be undone without a backup                              |
| `depends` | Outcome varies based on argument content — requires `reversible_note` |

**Common error:** `reversible: "depends"` applied to read-only operations. If files are not modified, `reversible` should be `"yes"` even if the output reveals sensitive content. `"depends"` is for cases like `sed -f script.sed` where the script content determines whether writes occur.

### 2.6. Combination Rule Coverage

Check that high-risk flag combinations have dedicated rules with `all_match: true`:

- Is there a rule for the two most dangerous flags combined (e.g. `-r` + `-o` for grep, `-exec` + `-delete` for find)?
- Does each combination rule use `flags_all` or `all_match: true` correctly?
- Are there standalone rules for each flag that also appear in combination rules?

### 2.7. Missing Rules

For the five primary coding assistant tools, check for these commonly missed rules:

**grep:**
- `grep-recursive-extract` — `-r` + `-o` (only-matching): targeted extraction across tree; should be ERROR
- `grep-recursive-dereference` — `-r` + `--dereference`: filesystem-wide scope
- `grep-recursive-pattern-file` — `-r` + `-f`: external patterns across tree; should be ERROR

**find:**
- `find-exec-batch` — `-exec {} +` vs `-exec {} \;` distinction (batching changes scale)
- `find-delete-depth` — `-delete` + `-depth`: depth-first deletion of directory trees
- `find-pipeline-exec` — `-print0` / `-X`: pipeline enablers that chain into execution

**sed:**
- `sed-inplace-no-backup` vs `sed-inplace-with-backup` — these must be separate rules; `args_none` distinguishes them
- `sed-script-file` — `-f script.sed`: script content determines risk

**cat:**
- `cat-stdin` — `-` argument: reads from stdin, potential injection vector

**ls:**
- Minimal risk overall; check for `-R` recursive and `-L` symlink-follow

### 2.8. Default Rule

The `default_rule` must reflect the tool's **baseline behavior with no risky flags**. It should be the lowest-risk state of the tool. Verify it is not duplicated inside the `rules` array.

### 2.9. MITRE ATT&CK Mapping

`mitre_attack` is required on every rule; an empty array `[]` signals no applicable technique. The schema enforces presence and format (`T####` or `T####.###`) but not content accuracy — that requires human review.

**Check each non-empty entry:**
- Does the matched command *directly* perform this technique, or does it only make the technique easier for a subsequent actor or decision? If the latter, the technique does not belong here — move any caveat to `notes`.
- Is the sub-technique used where one exists? Prefer `T1059.004` (Unix Shell) over the parent `T1059` when the behaviour maps specifically to shell execution.

**Common mappings to verify:**

| Pattern                                          | Expected technique(s)                        |
|--------------------------------------------------|----------------------------------------------|
| Recursive file deletion                          | T1485 Data Destruction                       |
| Shell execution via exec flag (`-exec`, `xargs`) | T1059.004 Unix Shell                         |
| Subshell / inline code (`$()`, backticks)        | T1059.004 Unix Shell                         |
| Script file execution (`-f script`)              | T1059.004 Unix Shell                         |
| In-place file modification, no backup            | T1565.001 Stored Data Manipulation + T1485   |
| In-place file modification, with backup          | T1565.001 Stored Data Manipulation           |
| Outbound network connection                      | T1105 Ingress Tool Transfer                  |
| Pipeline exfiltration                            | T1048 Exfiltration Over Alternative Protocol |
| Privilege escalation                             | T1548 Abuse Elevation Control Mechanism      |
| Environment modification                         | T1574 Hijack Execution Flow                  |
| Recursive directory traversal                    | T1083 File and Directory Discovery           |
| Sensitive file content reading                   | T1005 Data from Local System                 |

**Existing rulesets (pre-mitre_attack):** All committed rulesets in `commandant-rules-core` predate the `mitre_attack` field and will need a backfill pass before the first release. This is non-blocking for new rulesets; flag existing ones for a dedicated backfill session.


---

## 3. Committed Ruleset Status

**[human]** Reference for tracking what has been reviewed and committed.

**[LLM]** Skip this section — it describes the corpus state, not the ruleset under review.

All five primary coding assistant tools plus several extended tools are committed to `commandant-rules-core`. Rulesets listed here do **not** yet have `mitre_attack` — a backfill pass is needed before first release (see Section 2.9).

### 3.1. Primary coding assistant tools

| Tool   | Platform(s)      | Status                                                              |
|--------|------------------|---------------------------------------------------------------------|
| `grep` | `posix`          | ✅ Committed — 19 rules including `grep-recursive-extract`           |
| `find` | `posix`          | ✅ Committed — 11 rules including `-exec {} +` / `{} \;` distinction |
| `cat`  | `posix`          | ✅ Committed — 4 rules including `cat-stdin` injection vector        |
| `ls`   | `posix`          | ✅ Committed — 8 rules                                               |
| `sed`  | `linux`, `macos` | ✅ Committed — 19 rules (linux); macos variant also committed        |

### 3.2. Extended tools

| Tool                                 | Platform  | Status      |
|--------------------------------------|-----------|-------------|
| `git`                                | `posix`   | ✅ Committed |
| `jq`                                 | `posix`   | ✅ Committed |
| `xargs`                              | `posix`   | ✅ Committed |
| `convert` / `magick`                 | `posix`   | ✅ Committed |
| `pandoc`                             | `posix`   | ✅ Committed |
| `pdfseparate`                        | `posix`   | ✅ Committed |
| `dir`, `findstr`, `type`, `forfiles` | `windows` | ✅ Committed |

### 3.3. Pending for all committed rulesets

- [ ] `mitre_attack` backfill — all committed rulesets predate the field; needs a dedicated pass (Section 2.9)

---

## 4. Multi-Model Union Approach

When merging rulesets generated by multiple models:

1. Start with the most schema-compliant version as the base
2. Add rules present in other versions but missing from the base
3. For overlapping rules, take the version with better `match` object precision and calibrated severity
4. Verify the union against the checklist above
5. Add any manually-identified missing rules from Section 7

---

## 5. Risk Tag Reference

| Tag                    | Meaning                                                |
|------------------------|--------------------------------------------------------|
| `reads-files`          | Accesses file content                                  |
| `writes-files`         | Modifies or creates files                              |
| `deletes-files`        | Removes files or directories                           |
| `recursive`            | Operates on directory trees                            |
| `irreversible`         | No undo path without a backup                          |
| `executes-code`        | Invokes another binary or shell command                |
| `network-egress`       | Makes outbound network connections                     |
| `elevated-privilege`   | Requires or escalates privileges                       |
| `modifies-environment` | Alters shell state or environment variables            |
| `subshell`             | Spawns a subshell via `$()`, backticks, pipes to shell |

## 6. Consequence Category Reference

| Consequence                    | When                                         |
|--------------------------------|----------------------------------------------|
| `data-loss`                    | Files permanently destroyed                  |
| `data-corruption`              | Files modified in damaging or unintended way |
| `privacy-breach`               | Private or sensitive content exposed         |
| `computer-security-compromise` | System security posture weakened             |
| `unsafe-code-execution`        | Arbitrary or unvalidated code run            |
| `financial-loss`               | Actions with financial cost                  |
| `legal-violation`              | Actions that may violate laws or regulations |
| `harmful-decision`             | Broader harmful consequences                 |

Only include `likely_consequences` where the risk is concrete and direct.

---

*Schema reference: `commandant-rules-core/skills/draft_tool_ruleset/tool_risk_ruleset_schema.json`*
*Last updated: June 2026*
