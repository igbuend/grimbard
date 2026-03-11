# Vendor Guidance Overlay

Use this file only when you need vendor-specific judgment. Start with the portable rubric first.

## OpenAI / Codex

Strongest published skill-writing guidance in this project context.

Emphasize:

- concise `SKILL.md`
- progressive disclosure
- strong metadata
- `references/` for large detail
- `scripts/` for deterministic work
- domain or framework split when variants are large

Be careful:

- do not copy the exact structure blindly when the target runtime differs
- normalize recommendations for smaller local models if the skill is too broad

## Anthropic

Public guidance strongly supports:

- explicit task framing
- clear structure
- examples when ambiguity matters
- tool-use clarity

Be careful:

- Claude-oriented advice can encourage assuming a stronger baseline reasoner than a local 9B model

## Google

Public guidance strongly supports:

- clean system-instruction style behavior rules
- separation of instructions from context
- output-format clarity

Be careful:

- system-level guidance is useful, but not a complete skill-authoring standard by itself

## Qwen

Public guidance strongly supports:

- explicit task framing
- clear formatting constraints
- examples when useful
- structured outputs

Be careful:

- keep prompts tighter than frontier-vendor examples may imply
- prefer language/framework-specific annexes over broad all-in-one skills

## DeepSeek

Public guidance strongly supports:

- concise structured prompting
- explicit output requirements
- reducing ambiguity

Be careful:

- down-rank guidance that assumes the model can stabilize large freeform tasks without schemas

## Mistral

Public guidance is thinner and less prescriptive for skill-writing.

Use it mainly as:

- support for structured outputs
- a reminder not to overstate confidence in vendor-specific best practices when they are not well documented

## Reviewer Rule

When a recommendation is mostly vendor-specific:

1. say which vendor it comes from
2. explain whether it is portable
3. explain whether it fits local and smaller-model constraints
4. downgrade it if it conflicts with the local-first normalization rules

