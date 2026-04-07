# CLAUDE.md — cUtils

## Overview

Collection of Rust CLI utilities for cloud AI media generation and format conversion.

## Sub-Projects

| Directory | Purpose |
|-----------|---------|
| `hurl-to-har-to-hurl-converter/` | Convert between HURL and HAR file formats |
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

## Conventions

- Rust edition 2024, stable channel
- Each tool is a standalone binary crate with its own `Cargo.toml`
- Google Cloud credentials via Application Default Credentials (`gcloud auth application-default login`)
