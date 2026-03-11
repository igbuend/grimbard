---
name: skill-reviewer
description: Reviews skills against vendor-aware best practices, emphasizing portability, progressive disclosure, determinism, and local-model fitness. Use when auditing or updating skill files or directories before baselining or publication.
disable-model-invocation: true
aliases:
  - review-skill
  - audit-skill
  - baseline-skill
---

# Skill Reviewer

Reviews skills against a vendor-aware baseline normalized for local, smaller models.

**Target:** `$ARGUMENTS` (skill file or directory)

## When to Use

Use when:

- auditing an existing skill before rework or publication
- reviewing a new skill draft
- baselining a whole skill directory before broader tuning
- checking whether a skill is too vendor-specific or too large-model-oriented
- deciding whether instructions should stay in prose or move into scripts/references

## Review Priorities

Rank findings in this order:

1. Local-model fitness
2. Portability
3. Determinism
4. Context efficiency
5. Vendor alignment

## What to Read

1. Read the target `SKILL.md`.
2. If the target is a directory, locate every `SKILL.md` under it and review each one independently before summarizing cross-cutting issues.
3. Always read:
   - `references/review-rubric.md`
   - `references/local-first-normalization.md`
4. Read `references/vendor-guidance.md` when:
   - the skill is clearly tuned to one vendor runtime
   - you need to judge whether vendor-specific advice is portable
   - you need to explain why a recommendation is down-ranked for local or smaller models
5. Read bundled references in the target skill only when needed to judge progressive disclosure, variant organization, or duplicated content.

## Core Review Questions

Check the skill against these questions:

- Does the metadata clearly say when to use the skill, not just what it is?
- Is the main `SKILL.md` concise enough to justify its token cost?
- Does the skill use progressive disclosure instead of packing every detail into one file?
- Should any fragile or repeated procedure be moved into a script?
- Are outputs, tool results, or review expectations expressed as clear contracts?
- Does the skill assume a frontier model where a local or smaller model needs more structure?
- Are variants split by language, framework, or domain when needed?
- Does the skill provide fallback behavior when tools, files, or assumptions are missing?
- Does it include verification or success criteria when work is procedural?
- Does it contain vendor-specific advice that should be marked as optional or narrowed?

## Review Rules

- Prefer portable guidance shared across vendors over product-specific tricks.
- Down-rank advice that assumes very large context windows or strong implicit inference.
- Flag vendor-specific recommendations when they do not transfer cleanly to local or smaller models.
- Treat missing progressive disclosure, missing contracts, and script-worthy prose as important issues.
- Prioritize behavioral and structural issues over generic writing polish.
- Do not praise trivialities.
- Provide diffs only for high-confidence changes that are easy to apply.

## Findings to Emit

Use these labels when applicable:

- `vendor_overfit`
- `frontier_model_assumption`
- `context_budget_risk`
- `missing_progressive_disclosure`
- `should_be_script`
- `missing_output_contract`
- `variant_bloat`
- `local_runtime_gap`

## Review Process

1. Identify the review target shape: single file, single skill directory, or multi-skill directory.
2. Read the core rubric and local-first normalization references.
3. Read the target skill and note its type: knowledge skill, workflow skill, search skill, reviewer skill, or tool-integration skill.
4. Evaluate metadata, scope, progressive disclosure, determinism, contracts, portability, and verification behavior.
5. Load vendor guidance only if a vendor-specific judgment is needed.
6. Record the highest-severity issues first, with locations.
7. Score the skill using the output format below.
8. Suggest structural edits or diffs only where they materially improve the baseline.

## Output Format

````markdown
## Skill Review: [skill-name]

### Summary
[1-2 sentences]

### Portable Strengths
- [High-value strength]

### Critical Issues
- [label] [Issue] - Location: [section/line]

### Local-Model Risks
- [Issue] - Impact: [why this hurts smaller/local models]

### Vendor-Overfit Risks
- [Issue] - Vendor: [name] - Why it may not transfer

### Baseline Recommendations
- [Actionable recommendation]

### Scores
- Portability: [1-5] - [brief reason]
- Context Efficiency: [1-5] - [brief reason]
- Determinism: [1-5] - [brief reason]
- Local-Model Fitness: [1-5] - [brief reason]
- Vendor Alignment: [1-5] - [brief reason]

### Overall Assessment
[Pass | Pass with Recommendations | Needs Revision]

### Suggested Diff
```diff
[Only include when high-confidence and useful]
```
````

## Notes

- Prefer review comments that help establish a reusable baseline across many skills.
- If the target skill is already highly portable and local-model-friendly, say so explicitly.
- If the target is a directory, finish with a short cross-skill summary after the per-skill reviews.

