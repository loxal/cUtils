use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

pub struct SpeakerSegment {
    pub start: f64,
    pub end: f64,
    pub speaker: String,
}

#[derive(Deserialize)]
struct ApiSegment {
    label: String,
    start: f64,
    end: f64,
}

fn mime_type_for_audio(path: &str) -> &'static str {
    match std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .as_deref()
    {
        Some("wav") => "audio/wav",
        Some("mp3" | "mpga" | "mpeg") => "audio/mpeg",
        Some("m4a" | "aac") => "audio/mp4",
        Some("ogg" | "opus") => "audio/ogg",
        Some("flac") => "audio/flac",
        Some("webm") => "audio/webm",
        Some("wma") => "audio/x-ms-wma",
        Some("mp4") => "audio/mp4",
        _ => "application/octet-stream",
    }
}

pub async fn diarize(
    audio_path: &str,
    hf_token: &str,
) -> Result<Vec<SpeakerSegment>, Box<dyn std::error::Error>> {
    let audio_bytes = std::fs::read(audio_path)?;
    let content_type = mime_type_for_audio(audio_path);

    let client = Client::new();
    let response = client
        .post("https://api-inference.huggingface.co/models/pyannote/speaker-diarization-3.1")
        .header("Authorization", format!("Bearer {hf_token}"))
        .header("Content-Type", content_type)
        .body(audio_bytes)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Diarization API error {status}: {body}").into());
    }

    let api_segments: Vec<ApiSegment> = response.json().await?;

    Ok(api_segments
        .into_iter()
        .map(|seg| SpeakerSegment {
            start: seg.start,
            end: seg.end,
            speaker: seg.label,
        })
        .collect())
}

pub fn find_speaker_for_segment(
    start: f64,
    end: f64,
    speaker_segments: &[SpeakerSegment],
) -> Option<String> {
    let mut best_overlap = 0.0f64;
    let mut best_speaker = None;

    for seg in speaker_segments {
        let overlap_start = start.max(seg.start);
        let overlap_end = end.min(seg.end);
        let overlap = (overlap_end - overlap_start).max(0.0);

        if overlap > best_overlap {
            best_overlap = overlap;
            best_speaker = Some(seg.speaker.clone());
        }
    }

    best_speaker
}

pub fn build_speaker_labels(speaker_segments: &[SpeakerSegment]) -> HashMap<String, String> {
    let mut raw_ids: Vec<String> = speaker_segments.iter().map(|s| s.speaker.clone()).collect();
    raw_ids.sort();
    raw_ids.dedup();

    let mut labels = HashMap::new();
    for (i, raw_id) in raw_ids.iter().enumerate() {
        let letter = if i < 26 {
            char::from(b'A' + i as u8).to_string()
        } else {
            (i + 1).to_string()
        };
        labels.insert(raw_id.clone(), format!("Speaker {letter}"));
    }
    labels
}
