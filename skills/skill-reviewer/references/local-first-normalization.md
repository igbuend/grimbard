# Local-First Normalization

Use this note to normalize vendor advice for this project.

## Default Rules

When vendor guidance conflicts, prefer:

1. local-model reliability over frontier-model convenience
2. explicit schemas over implied behavior
3. scripts for deterministic or fragile work
4. variant splitting over one giant skill
5. portable guidance over product-specific tricks
6. concise core files plus references over monolithic instructions

## Small-Model Checks

Treat these as high priority:

- hidden assumptions that require strong implicit reasoning
- too many examples in the main file
- large mixed-scope skills
- unclear handoff between tools and reasoning
- missing output schemas
- missing fallback behavior

## Findings to Raise

Raise `frontier_model_assumption` when a skill assumes:

- large context can absorb long background sections
- the model will infer framework details without guidance
- freeform outputs will stay stable enough for downstream use
- tool usage can remain vague without harming reliability

Raise `local_runtime_gap` when a skill assumes:

- hosted APIs or cloud-only integrations
- unrestricted network access
- compute-heavy flows without bounded alternatives
- cross-file reasoning with no narrowing step

Raise `context_budget_risk` when:

- the main file is bloated
- multiple variants are mixed together
- the skill duplicates detailed references in `SKILL.md`

Raise `should_be_script` when:

- the same mechanical steps appear repeatedly
- correctness depends on exact transformations
- the model is asked to produce structured intermediate artifacts that a script can generate deterministically

## Scoring Guidance

### Portability

- `5`: Portable across vendors and local runtimes with minimal assumptions
- `3`: Usable with some vendor or runtime caveats
- `1`: Heavily coupled to one runtime or product

### Context Efficiency

- `5`: Compact core file, strong progressive disclosure, no obvious waste
- `3`: Acceptable but has material trimming opportunities
- `1`: Bloated and likely to degrade runtime performance

### Determinism

- `5`: Fragile work moved into scripts or explicit contracts
- `3`: Some important flows remain prose-heavy
- `1`: Core behavior depends on brittle freeform execution

### Local-Model Fitness

- `5`: Explicit, narrow, structured, and robust for smaller models
- `3`: Generally usable but still assumes some stronger model behavior
- `1`: Written mainly for frontier hosted models
