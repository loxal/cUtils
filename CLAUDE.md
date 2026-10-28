<!-- SPDX-FileCopyrightText: Copyright 2026 Alexander Orlov <info@lifub.com> -->

# CLAUDE.md — cUtils

## Overview

Collection of Rust CLI utilities for cloud AI media generation and format conversion.

## Sub-Projects

| Directory | Purpose |
|-----------|---------|
| `hurl-to-har-to-hurl-converter/` | Convert between HURL and HAR file formats |
| `bitwarden-dedup/` | Deduplicate a Bitwarden JSON export (strict match, URI merge, TOTP/FIDO2 preserved) |
| `generate-speech/` | Google Cloud TTS long-form audio synthesis (SSML/Markdown → M4A/MP3) |
| `generate-image/` | Google Cloud Imagen via Vertex AI (prompt → PNG) |
| `generate-audio/` | Google Cloud Lyria music generation (prompt → WAV) |
| `generate-video/` | Google Cloud Veo video generation |
| `transcribe-audio/` | Audio transcription utilities |

## Build & Test

Each sub-project is an independent Cargo crate:

```bash
cd hurl-to-har-to-hurl-converter
cargo build
cargo test
```

Every crate must also pass `cargo fmt --check` and
`cargo clippy --locked --all-targets -- -D warnings` (bitwarden-dedup: add
`--all-features`, as its `just check` recipe does).

## Conventions

- Rust edition 2024, stable channel
- Minimum Rust 1.88: several crates use let chains and `slice::as_chunks`
- Each tool is a standalone binary crate with its own `Cargo.toml`
- Google Cloud credentials via Application Default Credentials (`gcloud auth application-default login`)

## Finish with reconciled Git state

Synced copy of the global agent instructions' "Finish with reconciled Git
state" (Lifub `agent/prompts/agent-instructions.md`); update every copy in the
same change set.

Before concluding a task, apply the gist of Lifub's
`agent/public.skills/finalize-finish-address-open-topics-issues.skill.md`
unless that is beyond reasonable: finish the worthwhile open topics the task
left, and leave its Git state reconciled. In every repository the task
touched, inventory the registered worktrees, local branches, stashes and
uncommitted changes. Integrate each completed, authorized unit against the
current upstream, commit and push it under that repository's rules, and prove
its hosted CI where the repository requires it. Remove a clean worktree or a
merged branch once its head is on the upstream and its useful evidence is
preserved, with `git worktree remove` and `git branch -d`, never their forcing
variants. Give every other remnant an owner and a disposition instead of
forcing it: another session's active work, an unknown owner, a stash, a
missing authorization or an uncertain operation stays intact and is reported
with its exact prerequisite. It is beyond reasonable to take over or delete
foreign work, to pop, drop, reset or force-push merely to empty the
inventory, to retry an uncertain operation, to pre-empt a decision that
belongs to the operator, or to spend effort out of proportion to the task.
Under `/Users/alex/my/src/fastly`, corporate working hours and each
repository's branch and pull-request route govern every commit and push;
outside the window, report the prepared change as pending.
