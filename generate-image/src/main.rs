mod imagen;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use chrono::Utc;
use clap::Parser;
use sha2::{Digest, Sha256};

const PROJECT_ID: &str = "instant-droplet-485818-i0";
const LOCATION: &str = "us-central1";

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "~/my/src/loxal/lifub/agent/prompts/avatar.md")]
    prompt_file: String,

    #[arg(long, default_value_t = 4)]
    number_of_images: u32,

    #[arg(long, default_value = "1:1")]
    aspect_ratio: String,

    #[arg(long, default_value = "imagen-4.0-ultra-generate-001")]
    model: String,

    #[arg(long, default_value = "blurry, low quality, distorted")]
    negative_prompt: String,

    #[arg(long)]
    no_watermark: bool,
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").expect("HOME not set");
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(path)
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let prompt_file = expand_home(&args.prompt_file);
    let prompt = fs::read_to_string(&prompt_file)
        .unwrap_or_else(|e| {
            eprintln!("Failed to read prompt file {}: {e}", prompt_file.display());
            process::exit(1);
        })
        .trim()
        .to_string();

    if prompt.is_empty() {
        eprintln!("Prompt file is empty: {}", prompt_file.display());
        process::exit(1);
    }

    let image_dir = Path::new("image");
    fs::create_dir_all(image_dir).expect("Failed to create image directory");

    let theme: String = Sha256::digest(prompt.as_bytes())
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();

    println!("Generating image(s)...");
    let images = imagen::generate_images(
        PROJECT_ID,
        LOCATION,
        &args.model,
        &prompt,
        args.number_of_images,
        &args.aspect_ratio,
        &args.negative_prompt,
        !args.no_watermark,
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("Image generation failed: {e}");
        process::exit(1);
    });

    if images.is_empty() {
        eprintln!("No images were generated.");
        process::exit(1);
    }

    println!("Generated {} image(s).", images.len());
    for (i, image) in images.iter().enumerate() {
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let filename = image_dir.join(format!("image-series-{theme}-{timestamp}-{i}.png"));

        if let Some(bytes) = &image.bytes {
            fs::write(&filename, bytes).unwrap_or_else(|e| {
                eprintln!("Failed to write {}: {e}", filename.display());
                process::exit(1);
            });
            println!("Saved {}", filename.display());
        } else if let Some(gcs_uri) = &image.gcs_uri {
            let status = Command::new("gcloud")
                .args(["storage", "cp", gcs_uri, &filename.to_string_lossy()])
                .status()
                .expect("Failed to run gcloud");
            if !status.success() {
                eprintln!("gcloud storage cp failed for image {i}");
                process::exit(1);
            }
            println!("Saved {} (from {gcs_uri})", filename.display());
        } else {
            println!("Image {i}: no image bytes or URI available");
        }
    }
}
