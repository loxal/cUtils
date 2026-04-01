mod lyria;

use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use chrono::Utc;
use clap::Parser;
use sha2::{Digest, Sha256};

const PROJECT_ID: &str = "instant-droplet-485818-i0";
const LOCATION: &str = "us-central1";
const MODEL: &str = "lyria-002";

#[derive(Parser)]
struct Args {
    #[arg(long)]
    prompt_file: String,

    #[arg(long, default_value_t = 1)]
    sample_count: u32,

    #[arg(long, default_value = "vocals, singing, voice")]
    negative_prompt: String,
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").expect("HOME not set");
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(path)
    }
}

fn parse_prompt_file(path: &Path) -> String {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Failed to read prompt file {}: {e}", path.display());
        process::exit(1);
    });

    if let Some((_meta_section, prompt)) = raw.split_once("---") {
        prompt.trim().to_string()
    } else {
        raw.trim().to_string()
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let prompt_file = expand_home(&args.prompt_file);
    let prompt = parse_prompt_file(&prompt_file);

    if prompt.is_empty() {
        eprintln!("Prompt is empty: {}", prompt_file.display());
        process::exit(1);
    }

    let audio_dir = Path::new("audio");
    fs::create_dir_all(audio_dir).expect("Failed to create audio directory");

    let theme: String = Sha256::digest(prompt.as_bytes())
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();

    println!("Generating audio...");
    let clips = lyria::generate_audio(
        PROJECT_ID,
        LOCATION,
        MODEL,
        &prompt,
        &args.negative_prompt,
        args.sample_count,
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("Audio generation failed: {e}");
        process::exit(1);
    });

    if clips.is_empty() {
        eprintln!("No audio was generated.");
        process::exit(1);
    }

    println!("Generated {} audio clip(s).", clips.len());
    for (i, clip) in clips.iter().enumerate() {
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let filename = audio_dir.join(format!("audio-series-{theme}-{timestamp}-{i}.wav"));
        fs::write(&filename, clip).unwrap_or_else(|e| {
            eprintln!("Failed to write {}: {e}", filename.display());
            process::exit(1);
        });
        println!("Saved {}", filename.display());
    }
}
