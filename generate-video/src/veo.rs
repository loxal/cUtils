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

fn normalize_storage_uri(storage_uri: &str) -> String {
    if storage_uri.ends_with('/') {
        storage_uri.to_string()
    } else {
        format!("{storage_uri}/")
    }
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

    let storage_uri = gcs_bucket.map(normalize_storage_uri);

    let (aspect_ratio, duration_seconds) = match input_mode {
        InputMode::Text => (Some("16:9".to_string()), Some(8u32)),
        InputMode::Image { path, mime_type } => {
            let image_bytes = std::fs::read(path)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&image_bytes);
            instance["image"] = serde_json::json!({
                "bytesBase64Encoded": b64,
                "mimeType": mime_type,
            });
            (Some("16:9".to_string()), Some(8u32))
        }
        InputMode::Video { path } => {
            let video_bytes = std::fs::read(path)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&video_bytes);
            instance["video"] = serde_json::json!({
                "bytesBase64Encoded": b64,
                "mimeType": "video/mp4",
            });
            (None, None)
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
    // Publisher model LROs use UUID IDs in a separate namespace.
    // They must be polled via the model's fetchPredictOperation endpoint,
    // not the standard operations.get resource.
    let model_resource = operation_name
        .rsplit_once("/operations/")
        .map(|(base, _)| base)
        .unwrap_or(operation_name);
    let url = format!(
        "https://{location}-aiplatform.googleapis.com/v1beta1/{model_resource}:fetchPredictOperation"
    );
    let poll_body = serde_json::json!({"operationName": operation_name});

    let client = Client::new();
    let timeout = Duration::from_secs(600);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err("Operation timed out after 600 seconds".into());
        }

        tokio::time::sleep(Duration::from_secs(10)).await;

        let token = get_token().await?;
        let response = client
            .post(&url)
            .bearer_auth(&token)
            .json(&poll_body)
            .send()
            .await?;

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

fn extract_video(obj: &serde_json::Value) -> Option<GeneratedVideo> {
    let bytes = obj
        .get("bytesBase64Encoded")
        .and_then(|b| b.as_str())
        .map(|b64| base64::engine::general_purpose::STANDARD.decode(b64))
        .transpose()
        .ok()?;
    let uri = obj
        .get("gcsUri")
        .or_else(|| obj.get("uri"))
        .and_then(|u| u.as_str())
        .map(String::from);
    if bytes.is_some() || uri.is_some() {
        Some(GeneratedVideo { bytes, uri })
    } else {
        None
    }
}

fn parse_response(
    response: Option<serde_json::Value>,
) -> Result<Vec<GeneratedVideo>, Box<dyn std::error::Error>> {
    let response = response.ok_or("No response in completed operation")?;
    let mut videos = Vec::new();

    // The response may contain video data under several possible keys depending
    // on the API version. Try them all.
    let candidate_arrays: &[&[&str]] = &[
        // REST fetchPredictOperation response
        &["videos"],
        // google-genai SDK / Vertex AI GenerateVideoResponse
        &["generatedVideos"],
        // Nested under a typed wrapper
        &["generateVideoResponse", "videos"],
        &["generateVideoResponse", "generatedVideos"],
        // Older predict-style
        &["predictions"],
        &["generatedSamples"],
        &["generateVideoResponse", "generatedSamples"],
    ];

    for path in candidate_arrays {
        let mut node = Some(&response);
        for key in *path {
            node = node.and_then(|n| n.get(*key));
        }
        if let Some(arr) = node.and_then(|n| n.as_array()) {
            for item in arr {
                // Videos may be directly in the item or nested under "video"
                if let Some(v) = item.get("video").and_then(extract_video) {
                    videos.push(v);
                } else if let Some(v) = extract_video(item) {
                    videos.push(v);
                }
            }
            if !videos.is_empty() {
                return Ok(videos);
            }
        }
    }

    if videos.is_empty() {
        eprintln!(
            "Warning: could not locate videos in response: {}",
            serde_json::to_string_pretty(&response).unwrap_or_default()
        );
    }

    Ok(videos)
}

#[cfg(test)]
mod tests {
    use super::{normalize_storage_uri, parse_response};

    #[test]
    fn parses_rest_videos_response_shape() {
        let response = serde_json::json!({
            "videos": [
                {
                    "gcsUri": "gs://bucket/output/sample_0.mp4",
                    "mimeType": "video/mp4"
                }
            ]
        });

        let videos = parse_response(Some(response)).expect("expected parsed videos");
        assert_eq!(videos.len(), 1);
        assert_eq!(
            videos[0].uri.as_deref(),
            Some("gs://bucket/output/sample_0.mp4")
        );
        assert!(videos[0].bytes.is_none());
    }

    #[test]
    fn normalizes_storage_uri_with_trailing_slash() {
        assert_eq!(
            normalize_storage_uri("gs://bucket/prefix"),
            "gs://bucket/prefix/"
        );
        assert_eq!(
            normalize_storage_uri("gs://bucket/prefix/"),
            "gs://bucket/prefix/"
        );
    }
}
