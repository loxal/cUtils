mod diarization;
mod ssml;
mod transcribe;

use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

const AUDIO_EXTENSIONS: &[&str] = &[
    "m4a", "aac", "mp3", "wav", "flac", "ogg", "wma", "opus", "webm", "mp4", "mpeg", "mpga",
];

const MODEL_URL: &str =
    "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-large-v3.bin";

#[derive(Parser)]
#[command(about = "Audio-to-SSML transcription using whisper.cpp")]
struct Args {
    #[arg(long)]
    audio_folder: Option<String>,

    #[arg(long)]
    lang: Option<String>,

    #[arg(long)]
    hugging_face_api_key: Option<String>,

    #[arg(long, default_value = "~/Downloads/whisper_models/ggml-large-v3.bin")]
    model_path: String,
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").expect("HOME not set");
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(path)
    }
}

fn find_audio_files(folder: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = WalkDir::new(folder)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| {
                    let lower = ext.to_lowercase();
                    AUDIO_EXTENSIONS.contains(&lower.as_str())
                })
        })
        .map(|e| e.into_path())
        .collect();
    files.sort();
    files.dedup();
    files
}

fn check_ffmpeg() {
    if process::Command::new("ffmpeg")
        .arg("-version")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("ERROR: ffmpeg not found!");
        eprintln!("Install on macOS:  brew install ffmpeg");
        process::exit(1);
    }
    println!("ffmpeg found");
}

async fn download_model(model_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Downloading Whisper large-v3 model (~3GB)...");
    println!("(This is a one-time download)");
    if let Some(parent) = model_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let client = reqwest::Client::new();
    let mut response = client.get(MODEL_URL).send().await?;

    if !response.status().is_success() {
        return Err(format!("Failed to download model: {}", response.status()).into());
    }

    let total_size = response.content_length().unwrap_or(0);
    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::with_template("Downloading [{bar:40}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("=> "),
    );

    let mut file = fs::File::create(model_path)?;
    while let Some(chunk) = response.chunk().await? {
        std::io::Write::write_all(&mut file, &chunk)?;
        pb.inc(chunk.len() as u64);
    }

    pb.finish_with_message("Download complete");
    println!("Model saved to {}", model_path.display());
    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("{}", "=".repeat(60));
    println!("   AUDIO TO SSML TRANSCRIPTION");
    println!("   Using whisper.cpp (large-v3)");
    println!("{}", "=".repeat(60));

    check_ffmpeg();

    if let Some(ref key) = args.hugging_face_api_key {
        unsafe { std::env::set_var("HF_TOKEN", key) };
    }

    let model_path = expand_home(&args.model_path);
    if !model_path.exists() {
        if let Err(e) = download_model(&model_path).await {
            eprintln!("Failed to download model: {e}");
            process::exit(1);
        }
    }

    println!("\nLoading Whisper large-v3 model...");
    let ctx = transcribe::load_model(&model_path).unwrap_or_else(|e| {
        eprintln!("Failed to load model: {e}");
        process::exit(1);
    });
    println!("Model loaded successfully!\n");

    let folder = args
        .audio_folder
        .map(|f| expand_home(&f))
        .unwrap_or_else(|| {
            eprintln!("No audio folder specified. Use --audio-folder <path>");
            process::exit(1);
        });

    if !folder.is_dir() {
        eprintln!("Not a valid directory: {}", folder.display());
        process::exit(1);
    }

    println!("Processing folder: {}", folder.display());

    let audio_files = find_audio_files(&folder);
    if audio_files.is_empty() {
        println!("No audio files found in {}", folder.display());
        return;
    }

    println!("\nFound {} audio file(s) to process:", audio_files.len());
    for f in audio_files.iter().take(10) {
        println!("  - {}", f.file_name().unwrap_or_default().to_string_lossy());
    }
    if audio_files.len() > 10 {
        println!("  ... and {} more", audio_files.len() - 10);
    }

    let hf_token = std::env::var("HF_TOKEN").ok();
    if hf_token.is_some() {
        println!("\nSpeaker diarization enabled (via HuggingFace API)");
    }

    let pb = ProgressBar::new(audio_files.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("Transcribing [{bar:40}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("=> "),
    );

    let mut successful = 0u32;
    let mut failed = 0u32;

    for audio_path in &audio_files {
        let ssml_path = audio_path.with_extension("ssml");

        if ssml_path.exists() {
            pb.println(format!(
                "  Skipping (already exists): {}",
                ssml_path.file_name().unwrap_or_default().to_string_lossy()
            ));
            pb.inc(1);
            continue;
        }

        pb.println(format!(
            "  Processing: {}",
            audio_path.file_name().unwrap_or_default().to_string_lossy()
        ));

        let audio_str = audio_path.to_string_lossy().to_string();

        let speaker_segments = if let Some(ref token) = hf_token {
            match diarization::diarize(&audio_str, token).await {
                Ok(segs) => segs,
                Err(e) => {
                    pb.println(format!("  Diarization failed: {e}"));
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        match transcribe::transcribe(&ctx, &audio_str, args.lang.as_deref()) {
            Ok(result) => {
                let title = audio_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("audio");
                let ssml_content = ssml::build_ssml(&result, &speaker_segments, title);

                let temp_path = ssml_path.with_extension("ssml.tmp");
                if let Err(e) = fs::write(&temp_path, &ssml_content) {
                    pb.println(format!("  Failed to write: {e}"));
                    failed += 1;
                } else if let Err(e) = fs::rename(&temp_path, &ssml_path) {
                    pb.println(format!("  Failed to rename: {e}"));
                    failed += 1;
                } else {
                    pb.println(format!(
                        "  Created: {}",
                        ssml_path.file_name().unwrap_or_default().to_string_lossy()
                    ));
                    successful += 1;
                }
            }
            Err(e) => {
                pb.println(format!(
                    "  Failed: {} - {e}",
                    audio_path.file_name().unwrap_or_default().to_string_lossy()
                ));
                failed += 1;
            }
        }

        pb.inc(1);
    }

    pb.finish();
    println!("\n{}", "=".repeat(50));
    println!("COMPLETE: {successful} transcribed, {failed} failed");
    println!("{}", "=".repeat(50));
}
