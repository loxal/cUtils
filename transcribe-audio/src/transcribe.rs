use std::path::Path;
use std::process::Command;
use whisper_rs::{FullParams, SamplingStrategy, WhisperContext, WhisperContextParameters};

pub struct Segment {
    pub start: f64,
    pub end: f64,
    pub text: String,
}

pub struct TranscriptionResult {
    pub language: String,
    pub segments: Vec<Segment>,
}

pub fn load_model(model_path: &Path) -> Result<WhisperContext, Box<dyn std::error::Error>> {
    if !model_path.exists() {
        return Err(format!(
            "Model file not found: {}\n\
             Download from: https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-large-v3.bin",
            model_path.display()
        )
        .into());
    }

    let ctx = WhisperContext::new_with_params(
        model_path.to_str().unwrap(),
        WhisperContextParameters::default(),
    )?;

    Ok(ctx)
}

fn load_audio_pcm(audio_path: &str) -> Result<Vec<f32>, Box<dyn std::error::Error>> {
    let output = Command::new("ffmpeg")
        .args([
            "-i",
            audio_path,
            "-f",
            "f32le",
            "-acodec",
            "pcm_f32le",
            "-ar",
            "16000",
            "-ac",
            "1",
            "-v",
            "quiet",
            "-",
        ])
        .output()?;

    if !output.status.success() {
        return Err(
            format!("ffmpeg failed: {}", String::from_utf8_lossy(&output.stderr)).into(),
        );
    }

    let samples: Vec<f32> = output
        .stdout
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();

    Ok(samples)
}

pub fn transcribe(
    ctx: &WhisperContext,
    audio_path: &str,
    language: Option<&str>,
) -> Result<TranscriptionResult, Box<dyn std::error::Error>> {
    let pcm_data = load_audio_pcm(audio_path)?;

    let mut state = ctx.create_state()?;
    let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });

    if let Some(lang) = language {
        params.set_language(Some(lang));
    }
    params.set_print_progress(false);
    params.set_print_realtime(false);
    params.set_print_timestamps(false);

    state.full(params, &pcm_data)?;

    let num_segments = state.full_n_segments()?;
    let mut segments = Vec::new();

    for i in 0..num_segments {
        let text = state.full_get_segment_text(i)?;
        let start = state.full_get_segment_t0(i)? as f64 / 100.0;
        let end = state.full_get_segment_t1(i)? as f64 / 100.0;

        if !text.trim().is_empty() {
            segments.push(Segment {
                start,
                end,
                text: text.trim().to_string(),
            });
        }
    }

    let detected_lang = language.unwrap_or("en").to_string();

    Ok(TranscriptionResult {
        language: detected_lang,
        segments,
    })
}
