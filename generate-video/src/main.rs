mod veo;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use chrono::Utc;
use clap::Parser;
use regex::Regex;
use sha2::{Digest, Sha256};

const PROJECT_ID: &str = "instant-droplet-485818-i0";
const LOCATION: &str = "us-central1";

#[derive(Parser)]
struct Args {
    #[arg(long)]
    prompt_file: String,

    #[arg(long, default_value = "text", value_parser = ["text", "jpg", "png", "video"])]
    input: String,

    #[arg(long, default_value = "720p", value_parser = ["720p", "1080p"])]
    resolution: String,

    #[arg(long, default_value = "veo-3.1-generate-001")]
    model: String,

    #[arg(long)]
    no_audio: bool,

    #[arg(long)]
    gcs_bucket: Option<String>,
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

fn extract_negative_prompt(prompt: &str) -> (String, Option<String>) {
    let re = Regex::new(r"(?m)^negative_prompt:\s*(.+)$").unwrap();
    if let Some(caps) = re.captures(prompt) {
        let negative = caps[1].trim().to_string();
        let m = re.find(prompt).unwrap();
        let cleaned = format!("{}{}", &prompt[..m.start()], &prompt[m.end()..]);
        (cleaned.trim().to_string(), Some(negative))
    } else {
        (prompt.to_string(), None)
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let prompt_file = expand_home(&args.prompt_file);
    let raw_prompt = parse_prompt_file(&prompt_file);

    if raw_prompt.is_empty() {
        eprintln!("Prompt is empty: {}", prompt_file.display());
        process::exit(1);
    }

    let (prompt, negative_prompt) = extract_negative_prompt(&raw_prompt);
    if let Some(ref neg) = negative_prompt {
        println!("Negative prompt: {neg}");
    }

    let video_dir = Path::new("video");
    fs::create_dir_all(video_dir).expect("Failed to create video directory");

    let theme: String = Sha256::digest(prompt.as_bytes())
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();

    let input_mode = match args.input.as_str() {
        "video" => {
            let prefix = format!("video-series-{theme}-");
            let mut candidates: Vec<PathBuf> = fs::read_dir(video_dir)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to read video directory: {e}");
                    process::exit(1);
                })
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".mp4"))
                })
                .collect();
            candidates.sort();
            let latest = candidates.last().cloned().unwrap_or_else(|| {
                eprintln!("No previous video found for extension. Run with --input text first.");
                process::exit(1);
            });
            println!("Extending from video: {}", latest.display());
            veo::InputMode::Video {
                path: latest.to_string_lossy().to_string(),
            }
        }
        ext @ ("jpg" | "png") => {
            let mime_type = if ext == "jpg" {
                "image/jpeg"
            } else {
                "image/png"
            };
            let mut candidates: Vec<PathBuf> = fs::read_dir(video_dir)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to read video directory: {e}");
                    process::exit(1);
                })
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e == ext)
                })
                .collect();
            candidates.sort();
            let latest = candidates.last().cloned().unwrap_or_else(|| {
                eprintln!("No .{ext} files found in video/ folder.");
                process::exit(1);
            });
            println!("Generating video from image: {}", latest.display());
            veo::InputMode::Image {
                path: latest.to_string_lossy().to_string(),
                mime_type: mime_type.to_string(),
            }
        }
        _ => {
            println!("Generating from text prompt only.");
            veo::InputMode::Text
        }
    };

    let final_prompt = if args.input == "video" {
        format!(
            "Continue this video the best possible way for the initial prompt: {}",
            prompt.trim()
        )
    } else {
        prompt.clone()
    };

    let videos = veo::generate_video(
        PROJECT_ID,
        LOCATION,
        &args.model,
        &final_prompt,
        &input_mode,
        !args.no_audio,
        negative_prompt.as_deref(),
        &args.resolution,
        args.gcs_bucket.as_deref(),
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("Video generation failed: {e}");
        process::exit(1);
    });

    if videos.is_empty() {
        eprintln!("No videos were generated.");
        process::exit(1);
    }

    println!("Generated {} video(s).", videos.len());
    for (i, video) in videos.iter().enumerate() {
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let filename = video_dir.join(format!("video-series-{theme}-{timestamp}-{i}.mp4"));

        if let Some(bytes) = &video.bytes {
            fs::write(&filename, bytes).unwrap_or_else(|e| {
                eprintln!("Failed to write {}: {e}", filename.display());
                process::exit(1);
            });
            println!("Saved {}", filename.display());
        } else if let Some(uri) = &video.uri {
            let status = Command::new("gcloud")
                .args(["storage", "cp", uri, &filename.to_string_lossy()])
                .status()
                .expect("Failed to run gcloud");
            if !status.success() {
                eprintln!("gcloud storage cp failed for video {i}");
                process::exit(1);
            }
            println!("Saved {} (from {uri})", filename.display());
        } else {
            println!("Video {i}: no video bytes or URI available");
        }
    }
}
