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
