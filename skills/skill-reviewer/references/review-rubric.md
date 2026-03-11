# Review Rubric

Use this rubric for every skill review.

## 1. Metadata and Trigger Quality

Check:

- `name` is specific and stable
- `description` says when to use the skill
- aliases help discovery without being noisy
- `disable-model-invocation: true` is present when the skill is primarily a workflow or review process

Flag when:

- metadata is vague
- trigger conditions are too broad
- the skill name suggests a much wider scope than the body supports

## 2. Progressive Disclosure

Check:

- `SKILL.md` keeps only core workflow and selection guidance
- detailed variants live in `references/`
- deterministic or repeated logic lives in `scripts/`
- assets are separated from documentation

Flag when:

- one file contains all variants, examples, and edge cases
- large reference material is duplicated in the main file
- the skill lacks guidance on when to read bundled references

## 3. Context Efficiency

Check:

- concise headings and bullets
- examples only when they reduce ambiguity
- minimal repetition
- no filler docs inside the skill package

Flag when:

- prose repeats known model capabilities
- the same rule is restated multiple times
- examples are too numerous for likely runtime use

## 4. Determinism and Tooling

Check:

- fragile or repeated procedures are moved into scripts
- tool usage guidance is explicit
- tool outputs have clear purpose and small schemas
- the skill says when to verify results

Flag when:

- the skill asks the model to do mechanical work repeatedly in prose
- tool calls are vague or too broad
- there is no clear verification step for procedural tasks

## 5. Output Contracts

Check:

- expected outputs are named and structured
- required fields are explicit when the skill expects analysis results
- enumerations or labels are stable where needed

Flag when:

- outputs are freeform but later steps assume structure
- the skill expects evidence but does not ask for it explicitly
- field names or categories are inconsistent

## 6. Variant Organization

Check:

- language, framework, or domain variants are split cleanly
- selection logic is short and obvious
- shared rules stay shared, variant rules stay isolated

Flag when:

- many variants are mixed together in one body
- framework-specific details appear without selection rules
- examples from unrelated stacks clutter the main path

## 7. Verification and Fallbacks

Check:

- clear success criteria
- fallback behavior when files, tools, or context are missing
- user confirmation for destructive actions where relevant

Flag when:

- the skill assumes ideal environment state
- failures have no fallback
- success is subjective or undefined

## 8. Portability

Check:

- advice is portable across runtimes unless explicitly marked otherwise
- vendor-specific guidance is scoped and labeled
- the skill avoids hard dependence on one hosted environment unless that is the goal

Flag when:

- product-specific behavior is treated as universal
- the skill depends on hosted capabilities not available in local settings
- the skill assumes tools or APIs not bundled or not standard
