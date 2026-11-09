# Mandatory Context Pin (`AGENTS.md` -> `@RULES.md`)

@RULES.md

- **Single Source of Truth**: All universal and project-specific hard rules for `opaque-relay-runner` are unified exclusively in [`RULES.md`](RULES.md) (`[ZONE-1: UNIVERSAL_ENGINEERING_RULES]` + `[ZONE-2: PROJECT_SPECIFIC_RULES]`).
- **Mandatory Context Pinning**: You MUST load and keep the entire contents of `RULES.md` pinned in your active context before analyzing, planning, or modifying anything in this repository.
- **Zero Rule Duplication (`[UNI-RULE-13]`)**: NEVER duplicate, scatter, or append concrete rules into `AGENTS.md`, `.cursorrules`, `CLAUDE.md`, or any other file. Whenever adding or updating any project hard rule, write it ONLY inside `[ZONE-2: PROJECT_SPECIFIC_RULES]` of `RULES.md`.
