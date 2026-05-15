# Orchestra — Documentation ↔ Code Synchronization Prompt

> **Purpose:** Reusable prompt to align all documentation with the current state of the codebase. Give this to an AI agent whenever code changes have outpaced the docs.

---

## Your Task

The Orchestra codebase has evolved faster than its documentation. Your job is to **bring every documentation file into exact agreement with the current code** — no more, no less.

**You ARE allowed to edit documentation files.** You are **NOT** allowed to modify any source code, build scripts, or configuration files — only `.md` files under `docs/`, the root `README.md`, `ROADMAP.md`, `CHANGELOG.md`, and any `*/README.md` files.

---

## Phase 1 — Read the Code (Source of Truth)

The **source code is always the source of truth.** Documentation must describe what the code actually does, not what it was intended to do.

Read the following to establish current reality:

### 1A. Workspace Structure
- `Cargo.toml` (workspace root) — workspace members, dependency overrides
- Every `*/Cargo.toml` — feature flags, dependencies, build targets
- Every `*/build.rs` — compile-time code generation and env vars

### 1B. Agent Source Files
Read **every** file in `agent/src/`. For each file, note:
- What `#[cfg(...)]` gates exist (feature flags, OS, architecture)
- What public functions/types exist and their actual signatures
- What the implementation actually does (not what comments claim)
- Any `todo!()`, `unimplemented!()`, stub returns, or placeholder logic
- Any modules referenced in `mod.rs` that don't exist, or files that exist but aren't referenced

### 1C. Supporting Crates
Read the `src/` directory of **every** workspace crate:
- `nt_syscall/`, `hollowing/`, `module_loader/`, `common/`, `builder/`,
  `console/`, `launcher/`, `optimizer/`, `payload-packager/`,
  `shellcode_packager/`, `pe_resolve/`, `string_crypt/`, `code_transform/`,
  `code_transform_macro/`, `junk_macro/`, `orchestra-pe-hardener/`,
  `orchestra-server/`, `orchestra-side-load-gen/`, `redirector/`,
  `keygen/`, `uefi-persistence/`, `dev-server/`

For each crate, note:
- Public API surface (pub fn, pub struct, pub enum)
- Feature flags and conditional compilation
- Actual behavior vs. documented behavior

### 1D. Configuration & Scripts
- `agent/src/` config structs — what fields exist, defaults, validation
- `scripts/*` — what build/deploy scripts actually do
- `justfile` — available recipes

---

## Phase 2 — Read the Documentation (Claims to Verify)

Read **every** documentation file:

| File | What it covers |
|------|---------------|
| `README.md` | Project overview, quickstart, feature summary |
| `ROADMAP.md` | Completed vs. planned features, known limitations |
| `CHANGELOG.md` | Version history, recent changes |
| `docs/ARCHITECTURE.md` | Internal design, module initialization, state machines, pipelines |
| `docs/FEATURES.md` | Feature flag reference, platform support, maturity labels |
| `docs/DESIGN.md` | High-level design philosophy |
| `docs/EVASION.md` | Evasion subsystem documentation |
| `docs/INJECTION_ENGINE.md` | Injection engine specification |
| `docs/POST_EXPLOITATION.md` | Post-exploitation module documentation |
| `docs/SECURITY_AUDIT.md` | Security considerations |
| `docs/SLEEP_OBFUSCATION.md` | Sleep obfuscation pipeline |
| `docs/P2P_MESH.md` | Peer-to-peer mesh protocol |
| `docs/FORENSICS.md` | Forensic cleanup pipeline |
| `docs/CONFIGURATION.md` | Configuration schema reference |
| `docs/CONTROL_CENTER.md` | Control center documentation |
| `docs/C_SERVER.md` | C server documentation |
| `docs/C2_PANEL_STARTUP.md` | C2 panel startup guide |
| `docs/CONTRIBUTING.md` | Contribution guidelines |
| `docs/LAUNCHER.md` | Launcher documentation |
| `docs/LOCAL_TESTING_GUIDE.md` | Local testing instructions |
| `docs/MALLEABLE_PROFILES.md` | Malleable profile documentation |
| `docs/OPERATOR_MANUAL.md` | Operator manual |
| `docs/QUICKSTART.md` | Quickstart guide |
| `docs/REDIRECTOR_GUIDE.md` | Redirector setup guide |
| `docs/SECURITY.md` | Security policy |
| `docs/INTEGRATION_TEST_WALKTHROUGH.md` | Integration test walkthrough |
| `docs/USER_GUIDE.md` | User guide |
| `builder/README.md` | Builder crate documentation |
| `console/README.md` | Console crate documentation |
| `zai-provider-extension/README.md` | VS Code extension documentation |

---

## Phase 3 — Identify Discrepancies

For **each documentation file**, compare its claims against the actual code. Flag every discrepancy you find. Classify each as one of:

### Discrepancy Types

| Type | Description | Example |
|------|-------------|---------|
| **STALE** | Doc describes old behavior; code has changed since | Doc says "3 AMSI modes" but code now has 4 |
| **MISSING** | Code has new functionality not mentioned in docs | New feature flag added to `Cargo.toml` but not in `FEATURES.md` |
| **GHOST** | Doc describes something that no longer exists in code | Doc mentions `old_module.rs` but the file was deleted |
| **WRONG** | Doc makes a factually incorrect claim about current code | Doc says "Linux only" but code also has macOS support |
| **VAGUE** | Doc is imprecise and could be clarified with actual code details | Doc says "encrypts memory" but doesn't specify the algorithm |
| **STRUCTURAL** | Doc references files/modules/paths that have been renamed or moved | Doc says `agent/src/syscalls.rs` but it's now `nt_syscall/src/syscalls.rs` |

### Key Areas to Check

For each area below, verify doc ↔ code agreement:

1. **Feature flags** — Does `docs/FEATURES.md` list every feature in `agent/Cargo.toml`? Does it miss any? Does it describe features that no longer exist? Are platform attributions correct? Are maturity labels current?

2. **Module initialization order** — Does `docs/ARCHITECTURE.md`'s initialization sequence match the actual `main.rs` / `lib.rs` startup code?

3. **Command dispatch table** — Does `docs/ARCHITECTURE.md`'s command list match what `handlers.rs` actually dispatches? Are there new commands? Removed commands? Changed signatures?

4. **Dependency graph** — Does `docs/ARCHITECTURE.md`'s module dependency graph match actual `use` statements and `mod` declarations?

5. **Pipeline flows** — Do all ASCII-art pipelines (evasion, unhooking, forensic cleanup, etc.) match the actual code flow? Are there new steps? Removed steps? Reordered steps?

6. **Data structures** — Do documented structs/enums match actual definitions? Field names, types, visibility?

7. **Configuration fields** — Does `docs/CONFIGURATION.md` document every config field that the code actually parses? Are defaults correct? Are required/optional markers accurate?

8. **Cargo dependencies** — Do docs mention dependencies that have been removed or added? Are version numbers current?

9. **Platform support** — Do `#[cfg(target_os)]` gates in code match what docs claim about platform support?

10. **Public API surface** — Do docs accurately describe the public API of each crate? Missing functions? Extra functions? Changed signatures?

11. **ROADMAP accuracy** — Are items marked ✅ truly complete in code? Are "known limitations" still accurate? Are short/medium/long-term items still relevant?

12. **Script and CLI commands** — Do docs reference scripts/commands that exist? Are script behaviors accurately described?

---

## Phase 4 — Fix the Documentation

For each discrepancy found, **edit the documentation file** to match the code. Follow these rules:

### Editing Rules

1. **Code wins.** When code and docs disagree, update the docs to match the code. Never the reverse.

2. **Preserve doc structure.** Keep the existing document organization, heading hierarchy, and formatting style. Only change the content that is wrong.

3. **Be precise.** Replace vague claims with specifics drawn from the code. If the code uses XChaCha20-Poly1305, the docs should say that — not just "encryption."

4. **Don't over-document.** If the code has a private internal function that isn't referenced in docs, don't add it. Only update docs where they already make claims or where public-facing features are missing.

5. **Mark new additions.** If you add a new section describing functionality that was previously undocumented, prefix the heading with `🆕` so the reviewer can spot what's new. For example: `### 🆕 Widget Loader`

6. **Don't invent content.** If you find a ghost (doc references deleted code), remove the reference. Do not replace it with speculation about what should exist.

7. **Update cross-references.** If you change a module name or path in one doc, search all other docs for references to the old name and update them too.

8. **Keep ASCII art valid.** If you modify an ASCII diagram, verify alignment and box-drawing characters render correctly.

9. **Preserve intentional forward-looking statements.** If `ROADMAP.md` says "Planned: X" and X isn't in the code yet, that's fine — it's a plan, not a claim. Leave it alone unless the plan has actually been completed (then mark it ✅).

10. **Update the CHANGELOG.** If you discover completed features that aren't in `CHANGELOG.md`, add entries under a `## [Unreleased]` heading at the top. Use the existing changelog format.

---

## Phase 5 — Final Verification

After making all edits, perform a final sweep:

1. **Grep for stale paths.** Search all `.md` files for references to files or modules that don't exist. Fix or remove them.

2. **Grep for stale feature names.** Search all `.md` files for feature flag names that don't appear in `agent/Cargo.toml`. Fix or remove them.

3. **Check internal links.** Verify that any `[link](path)` markdown links in docs point to files that actually exist.

4. **Check code blocks.** Verify that any Rust code blocks in documentation compile mentally — correct syntax, valid types, existing function names.

5. **Consistency check.** If `ARCHITECTURE.md` says a module does X, verify `FEATURES.md` and any other doc that mentions it says the same X.

---

## Output

After completing all phases, provide a summary in this format:

```markdown
# Documentation Sync Report

## Files Modified
- `docs/ARCHITECTURE.md` — (N changes): brief description of what was updated
- `docs/FEATURES.md` — (N changes): ...
- ...

## Discrepancies Found & Fixed
| # | Type | File | Section | What was wrong | What was corrected to |
|---|------|------|---------|---------------|----------------------|
| 1 | STALE | docs/ARCHITECTURE.md | Evasion Pipeline | Listed 3 AMSI modes | Updated to 4 modes per amsi_defense.rs |
| 2 | MISSING | docs/FEATURES.md | Feature Flags | Missing `new-feature` flag | Added entry with details from Cargo.toml |
| ... |

## Discrepancies Found But NOT Fixed
(If any discrepancies require human judgment — e.g., architectural decisions — list them here with a recommendation)

## Stale References Removed
(List any references to deleted files/modules/features that were cleaned up)

## New Sections Added
(List any 🆕 sections added to cover previously undocumented functionality)
```

---

## Important Reminders

- **You may only edit `.md` files.** Do not touch `.rs`, `.toml`, `.sh`, `.bat`, `.js`, `.json`, `.lock`, or any other non-documentation file.
- **Read the actual code first.** Do not trust the existing documentation to be accurate — that's the whole point of this task.
- **One file at a time.** Read a doc, compare to code, fix it, move to the next. Don't batch-assume.
- **Be conservative with additions.** Only add new documentation sections for features that are clearly implemented and functional in code. Don't document plans or aspirations.
- **Run this prompt repeatedly.** After major code changes, re-run this prompt. Each run will catch what drifted since the last sync.