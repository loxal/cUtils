mod markdown;
mod metadata;
mod ssml;
mod tts;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};

use chrono::Utc;
use clap::Parser;
use sha2::{Digest, Sha256};

const PROJECT_ID: &str = "instant-droplet-485818-i0";
const LOCATION: &str = "us-central1";
const GCS_BUCKET: &str = "video-1312312uuio323";

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "de")]
    lang: String,

    #[arg(long)]
    author: Option<String>,

    #[arg(long)]
    override_voice: Option<String>,

    #[arg(long)]
    strip_pitch: bool,

    #[arg(long)]
    strip_emphasis: bool,

    #[arg(long)]
    mp3: bool,
}

struct LangConfig {
    voice: &'static str,
    language_code: &'static str,
}

fn lang_config(lang: &str) -> Option<LangConfig> {
    match lang {
        "de" => Some(LangConfig {
            voice: "de-DE-Chirp3-HD-Fenrir",
            language_code: "de-DE",
        }),
        "en" => Some(LangConfig {
            voice: "en-US-Chirp3-HD-Fenrir",
            language_code: "en-US",
        }),
        "ru" => Some(LangConfig {
            voice: "ru-RU-Chirp3-HD-Fenrir",
            language_code: "ru-RU",
        }),
        _ => None,
    }
}

fn find_ssml_file(prompts_dir: &Path) -> Option<PathBuf> {
    let ssml_file = prompts_dir.join("speech.ssml");
    if ssml_file.exists() {
        if let Ok(content) = fs::read_to_string(&ssml_file) {
            if !content.trim().is_empty() {
                return Some(ssml_file);
            }
        }
    }
    let mut candidates: Vec<PathBuf> = fs::read_dir(prompts_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("speech-") && n.ends_with(".ssml"))
        })
        .collect();
    candidates.sort();
    candidates.reverse();
    for c in candidates {
        if let Ok(content) = fs::read_to_string(&c) {
            if !content.trim().is_empty() {
                return Some(c);
            }
        }
    }
    None
}

enum SynthesisInput {
    Ssml(String),
    Text(String),
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let cfg = lang_config(&args.lang).unwrap_or_else(|| {
        eprintln!("Unsupported language: {}", args.lang);
        process::exit(1);
    });

    let mut voice_name = cfg.voice.to_string();
    let language_code = cfg.language_code;

    if let Some(ref v) = args.override_voice {
        voice_name.clone_from(v);
        println!("Voice overridden to: {voice_name}");
    }

    let speech_dir = Path::new("speech");
    fs::create_dir_all(speech_dir).expect("Failed to create speech directory");

    let home = std::env::var("HOME").expect("HOME not set");
    let prompts_dir = PathBuf::from(home).join("my/src/loxal/lox/al/prompts");
    let md_file = prompts_dir.join("speech.md");

    let resolved_ssml = find_ssml_file(&prompts_dir);

    let mut file_prefix = String::from("speech");
    let mut dc_metadata = HashMap::new();

    let (input, input_hash) = if let Some(ssml_path) = resolved_ssml {
        let ssml_content = fs::read_to_string(&ssml_path)
            .expect("Failed to read SSML file")
            .trim()
            .to_string();
        let mut google_ssml = ssml::sanitize_for_google(&ssml_content);
        if args.strip_pitch {
            google_ssml = ssml::strip_pitch_from_prosody(&google_ssml);
            println!("Pitch attributes stripped from prosody tags");
        }
        if args.strip_emphasis {
            google_ssml = ssml::strip_emphasis_tags(&google_ssml);
            println!("Emphasis tags stripped");
        }
        dc_metadata = ssml::extract_dc_metadata(&ssml_content);
        if let Some(title) = dc_metadata.get("title") {
            file_prefix = regex::Regex::new(r"[^\w\s-]")
                .unwrap()
                .replace_all(title, "")
                .trim()
                .replace(' ', "-");
        }
        println!("Using SSML input: {}", ssml_path.display());
        (SynthesisInput::Ssml(google_ssml), ssml_content)
    } else if md_file.exists() {
        let md_content = fs::read_to_string(&md_file)
            .expect("Failed to read markdown file")
            .trim()
            .to_string();
        if md_content.is_empty() {
            eprintln!(
                "No input found. Provide speech.ssml, a timestamped speech-*.ssml in {}, or {}",
                prompts_dir.display(),
                md_file.display()
            );
            process::exit(1);
        }
        let prompt = markdown::to_plain_text(&md_content);
        if prompt.is_empty() {
            eprintln!("Prompt file produced no text: {}", md_file.display());
            process::exit(1);
        }
        println!("Using markdown input: {}", md_file.display());
        let hash_input = prompt.clone();
        (SynthesisInput::Text(prompt), hash_input)
    } else {
        eprintln!(
            "No input found. Provide speech.ssml, a timestamped speech-*.ssml in {}, or {}",
            prompts_dir.display(),
            md_file.display()
        );
        process::exit(1);
    };

    let theme: String = Sha256::digest(input_hash.as_bytes())
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");

    let gcs_filename = format!("{file_prefix}_{voice_name}_{theme}-{timestamp}.wav");
    let output_gcs_uri = format!("gs://{GCS_BUCKET}/speech/{gcs_filename}");

    let (text, ssml_str) = match &input {
        SynthesisInput::Text(t) => (Some(t.as_str()), None),
        SynthesisInput::Ssml(s) => (None, Some(s.as_str())),
    };

    println!("Generating speech ({} chars)...", input_hash.len());

    let operation_name = tts::synthesize_long_audio(
        PROJECT_ID,
        LOCATION,
        text,
        ssml_str,
        &voice_name,
        language_code,
        &output_gcs_uri,
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("Synthesis request failed: {e}");
        process::exit(1);
    });

    println!("Waiting for long audio synthesis to complete...");
    tts::poll_operation(&operation_name, PROJECT_ID)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Synthesis failed: {e}");
            process::exit(1);
        });

    let local_wav = speech_dir.join(&gcs_filename);
    let status = Command::new("gcloud")
        .args(["storage", "cp", &output_gcs_uri, &local_wav.to_string_lossy()])
        .status()
        .expect("Failed to run gcloud");
    if !status.success() {
        eprintln!("gcloud storage cp failed");
        process::exit(1);
    }

    let rm_status = Command::new("gcloud")
        .args(["storage", "rm", &output_gcs_uri])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if rm_status.is_err() || !rm_status.unwrap().success() {
        eprintln!("Warning: failed to clean up {output_gcs_uri}");
    }

    if let Some(ref author) = args.author {
        dc_metadata.insert("creator".to_string(), author.clone());
    }

    let local_out =
        metadata::convert_and_tag(&local_wav, args.mp3, &dc_metadata).unwrap_or_else(|e| {
            eprintln!("ffmpeg conversion failed: {e}");
            process::exit(1);
        });

    fs::remove_file(&local_wav).ok();
    println!("Saved {}", local_out.display());
}
