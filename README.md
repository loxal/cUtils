# cUtils
* coreUtils
* consoleUtils
* cloudUtils
* cyberUtils
* cryptUtils
* cyberUtils

## [generate-speech](generate-speech/)

Rust CLI for Google Cloud Text-to-Speech long-form audio synthesis. Takes SSML or Markdown input, calls the Google TTS API, and outputs tagged M4A or MP3 files.

## [generate-image](generate-image/)

Rust CLI for Google Cloud Imagen image generation via Vertex AI. Reads a text prompt, calls the Imagen API, and saves PNG images.

## [generate-audio](generate-audio/)

Rust CLI for Google Cloud Lyria music generation via Vertex AI. Reads a prompt file, calls the Lyria API, and saves WAV audio clips.

## [generate-video](generate-video/)

Rust CLI for Google Cloud Veo video generation via Vertex AI. Supports text-to-video, image-to-video, and video extension modes with long-running operation polling.

## [transcribe-audio](transcribe-audio/)

Rust CLI for audio-to-SSML transcription using whisper.cpp. Recursively processes audio files in a folder with optional speaker diarization via HuggingFace API.

## [hurl-to-har-to-hurl-converter](hurl-to-har-to-hurl-converter/)

Bidirectional converter between HURL and HAR formats.
