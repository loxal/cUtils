use base64::Engine;
use gcp_auth::TokenProvider;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize)]
struct PredictRequest {
    instances: Vec<serde_json::Value>,
    parameters: Parameters,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Parameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    aspect_ratio: Option<String>,
    sample_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_seconds: Option<u32>,
    person_generation: String,
    generate_audio: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    negative_prompt: Option<String>,
    resolution: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_uri: Option<String>,
}

#[derive(Deserialize)]
struct Operation {
    name: String,
    #[serde(default)]
    done: bool,
    error: Option<OperationError>,
    response: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct OperationError {
    code: i32,
    message: String,
}

pub struct GeneratedVideo {
    pub bytes: Option<Vec<u8>>,
    pub uri: Option<String>,
}

pub enum InputMode {
    Text,
    Image { path: String, mime_type: String },
    Video { path: String },
}

async fn get_token() -> Result<String, Box<dyn std::error::Error>> {
    // Use ConfigDefaultCredentials directly — gcp_auth::provider() misparses
    // authorized_user credentials as service account when GOOGLE_APPLICATION_CREDENTIALS is set
    let provider = gcp_auth::ConfigDefaultCredentials::new().await?;
    let scopes = &["https://www.googleapis.com/auth/cloud-platform"];
    let token = provider.token(scopes).await?;
    Ok(token.as_str().to_string())
}

pub async fn generate_video(
    project_id: &str,
    location: &str,
    model: &str,
    prompt: &str,
    input_mode: &InputMode,
    generate_audio: bool,
    negative_prompt: Option<&str>,
    resolution: &str,
    gcs_bucket: Option<&str>,
) -> Result<Vec<GeneratedVideo>, Box<dyn std::error::Error>> {
    let url = format!(
        "https://{location}-aiplatform.googleapis.com/v1beta1/projects/{project_id}/locations/{location}/publishers/google/models/{model}:predictLongRunning"
    );

    let mut instance = serde_json::json!({"prompt": prompt});

    let (aspect_ratio, duration_seconds, storage_uri) = match input_mode {
        InputMode::Text => (Some("16:9".to_string()), Some(8u32), None),
        InputMode::Image { path, mime_type } => {
            let image_bytes = std::fs::read(path)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&image_bytes);
            instance["image"] = serde_json::json!({
                "bytesBase64Encoded": b64,
                "mimeType": mime_type,
            });
            (Some("16:9".to_string()), Some(8u32), None)
        }
        InputMode::Video { path } => {
            let video_bytes = std::fs::read(path)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&video_bytes);
            instance["video"] = serde_json::json!({
                "bytesBase64Encoded": b64,
                "mimeType": "video/mp4",
            });
            (
                None,
                None,
                gcs_bucket.map(|b| format!("{b}/video-staging/")),
            )
        }
    };

    let request = PredictRequest {
        instances: vec![instance],
        parameters: Parameters {
            aspect_ratio,
            sample_count: 1,
            duration_seconds,
            person_generation: "allow_all".to_string(),
            generate_audio,
            negative_prompt: negative_prompt.map(String::from),
            resolution: resolution.to_string(),
            storage_uri,
        },
    };

    let token = get_token().await?;
    let client = Client::new();
    let response = client.post(&url).bearer_auth(&token).json(&request).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("API error {status}: {body}").into());
    }

    let operation: Operation = response.json().await?;
    println!("Waiting for video generation to complete...");
    poll_operation(location, &operation.name).await
}

async fn poll_operation(
    location: &str,
    operation_name: &str,
) -> Result<Vec<GeneratedVideo>, Box<dyn std::error::Error>> {
    // Publisher model operations use UUID IDs and must be polled at the full
    // operation name under v1beta1 (not the v1 numeric-ID operations endpoint).
    let url = format!(
        "https://{location}-aiplatform.googleapis.com/v1beta1/{operation_name}"
    );
    let client = Client::new();
    let timeout = Duration::from_secs(600);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err("Operation timed out after 600 seconds".into());
        }

        tokio::time::sleep(Duration::from_secs(10)).await;

        let token = get_token().await?;
        let response = client.get(&url).bearer_auth(&token).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Poll error {status}: {body}").into());
        }

        let operation: Operation = response.json().await?;

        if !operation.done {
            println!("Video has not been generated yet. Check again in 10 seconds...");
            continue;
        }

        if let Some(err) = operation.error {
            return Err(
                format!("Video generation failed (code {}): {}", err.code, err.message).into(),
            );
        }

        return parse_response(operation.response);
    }
}

fn parse_response(
    response: Option<serde_json::Value>,
) -> Result<Vec<GeneratedVideo>, Box<dyn std::error::Error>> {
    let response = response.ok_or("No response in completed operation")?;
    let mut videos = Vec::new();

    // Try predictions format (standard Vertex AI)
    if let Some(predictions) = response.get("predictions").and_then(|p| p.as_array()) {
        for pred in predictions {
            let bytes = pred
                .get("bytesBase64Encoded")
                .and_then(|b| b.as_str())
                .map(|b64| base64::engine::general_purpose::STANDARD.decode(b64))
                .transpose()?;
            let uri = pred
                .get("gcsUri")
                .or_else(|| pred.get("uri"))
                .and_then(|u| u.as_str())
                .map(String::from);
            videos.push(GeneratedVideo { bytes, uri });
        }
    }

    // Try generatedSamples format (genai-style)
    if videos.is_empty() {
        let samples = response
            .get("generateVideoResponse")
            .and_then(|r| r.get("generatedSamples"))
            .or_else(|| response.get("generatedSamples"))
            .and_then(|s| s.as_array());
        if let Some(samples) = samples {
            for sample in samples {
                if let Some(video) = sample.get("video") {
                    let bytes = video
                        .get("bytesBase64Encoded")
                        .and_then(|b| b.as_str())
                        .map(|b64| base64::engine::general_purpose::STANDARD.decode(b64))
                        .transpose()?;
                    let uri = video
                        .get("uri")
                        .and_then(|u| u.as_str())
                        .map(String::from);
                    videos.push(GeneratedVideo { bytes, uri });
                }
            }
        }
    }

    Ok(videos)
}
