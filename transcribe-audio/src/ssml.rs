use crate::diarization::{self, SpeakerSegment};
use crate::transcribe::TranscriptionResult;
use std::collections::HashMap;

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn voices_for_language(lang: &str) -> Vec<String> {
    let voice_names = ["Fenrir", "Aoede", "Orus", "Puck", "Charon", "Kore"];
    let locale = match lang {
        "de" => "de-DE",
        "en" => "en-US",
        "es" => "es-ES",
        "fr" => "fr-FR",
        "ru" => "ru-RU",
        other => {
            let upper = other.to_uppercase();
            return voice_names
                .iter()
                .map(|name| format!("{other}-{upper}-Chirp3-HD-{name}"))
                .collect();
        }
    };
    voice_names
        .iter()
        .map(|name| format!("{locale}-Chirp3-HD-{name}"))
        .collect()
}

pub fn build_ssml(
    result: &TranscriptionResult,
    speaker_segments: &[SpeakerSegment],
    title: &str,
) -> String {
    let speaker_labels = if !speaker_segments.is_empty() {
        diarization::build_speaker_labels(speaker_segments)
    } else {
        HashMap::new()
    };

    let voice_pool = voices_for_language(&result.language);

    let mut speaker_voice_map = HashMap::new();
    for (i, label) in speaker_labels.values().enumerate() {
        speaker_voice_map.insert(label.clone(), voice_pool[i % voice_pool.len()].clone());
    }

    let mut lines = Vec::new();
    lines.push(r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_string());
    lines.push(r#"<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis""#.to_string());
    lines.push(r#"       xmlns:dc="http://purl.org/dc/elements/1.1/""#.to_string());
    lines.push(format!(r#"       xml:lang="{}">"#, result.language));
    lines.push(format!("  <dc:title>{}</dc:title>", escape_xml(title)));
    lines.push(String::new());

    if !speaker_voice_map.is_empty() {
        for (label, voice) in &speaker_voice_map {
            lines.push(format!("  <!-- {label}: {voice} -->"));
        }
        lines.push(String::new());
    }

    let mut current_speaker: Option<String> = None;
    let mut voice_open = false;
    let mut prev_end = 0.0f64;

    for segment in &result.segments {
        if segment.text.is_empty() {
            continue;
        }

        let raw_speaker =
            diarization::find_speaker_for_segment(segment.start, segment.end, speaker_segments);
        let speaker = raw_speaker
            .as_ref()
            .and_then(|raw| speaker_labels.get(raw))
            .cloned();

        let gap = segment.start - prev_end;
        if prev_end > 0.0 && gap > 0.5 {
            let pause_ms = ((gap * 1000.0) as u32).min(5000);
            let indent = if voice_open { "    " } else { "  " };
            lines.push(format!(r#"{indent}<break time="{pause_ms}ms"/>"#));
        }

        if !speaker_labels.is_empty() && speaker != current_speaker {
            if voice_open {
                lines.push("  </voice>".to_string());
                lines.push(String::new());
            }
            let voice_name = speaker
                .as_ref()
                .and_then(|s| speaker_voice_map.get(s))
                .unwrap_or(&voice_pool[0]);
            if let Some(ref spk) = speaker {
                lines.push(format!("  <!-- {spk} -->"));
            }
            lines.push(format!(r#"  <voice name="{voice_name}">"#));
            current_speaker = speaker;
            voice_open = true;
        }

        let indent = if voice_open { "    " } else { "  " };
        lines.push(format!("{indent}{}", escape_xml(&segment.text)));
        prev_end = segment.end;
    }

    if voice_open {
        lines.push("  </voice>".to_string());
    }
    lines.push("</speak>".to_string());

    lines.join("\n")
}
