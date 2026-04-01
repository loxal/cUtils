use gcp_auth::TokenProvider;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SynthesizeLongAudioRequest<'a> {
    parent: String,
    input: SynthesisInput<'a>,
    audio_config: AudioConfig,
    voice: VoiceSelectionParams<'a>,
    output_gcs_uri: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SynthesisInput<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssml: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AudioConfig {
    audio_encoding: &'static str,
    speaking_rate: f64,
    sample_rate_hertz: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VoiceSelectionParams<'a> {
    name: &'a str,
    language_code: &'a str,
}

#[derive(Deserialize)]
struct Operation {
    name: String,
    #[serde(default)]
    done: bool,
    error: Option<OperationError>,
}

#[derive(Deserialize)]
struct OperationError {
    code: i32,
    message: String,
}

async fn get_token() -> Result<String, Box<dyn std::error::Error>> {
    // Use ConfigDefaultCredentials directly — gcp_auth::provider() misparses
    // authorized_user credentials as service account when GOOGLE_APPLICATION_CREDENTIALS is set
    let provider = gcp_auth::ConfigDefaultCredentials::new().await?;
    let scopes = &["https://www.googleapis.com/auth/cloud-platform"];
    let token = provider.token(scopes).await?;
    Ok(token.as_str().to_string())
}

pub async fn synthesize_long_audio(
    project_id: &str,
    location: &str,
    text: Option<&str>,
    ssml: Option<&str>,
    voice_name: &str,
    language_code: &str,
    output_gcs_uri: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!(
        "https://texttospeech.googleapis.com/v1/projects/{project_id}/locations/{location}:synthesizeLongAudio"
    );

    let request = SynthesizeLongAudioRequest {
        parent: format!("projects/{project_id}/locations/{location}"),
        input: SynthesisInput { text, ssml },
        audio_config: AudioConfig {
            audio_encoding: "LINEAR16",
            speaking_rate: 1.0,
            sample_rate_hertz: 48000,
        },
        voice: VoiceSelectionParams {
            name: voice_name,
            language_code,
        },
        output_gcs_uri,
    };

    let token = get_token().await?;
    let client = Client::new();
    let response = client
        .post(&url)
        .bearer_auth(&token)
        .header("x-goog-user-project", project_id)
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("API error {status}: {body}").into());
    }

    let operation: Operation = response.json().await?;
    Ok(operation.name)
}

pub async fn poll_operation(
    operation_name: &str,
    project_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("https://texttospeech.googleapis.com/v1/{operation_name}");
    let client = Client::new();
    let timeout = Duration::from_secs(600);
    let start = std::time::Instant::now();
    let mut interval = Duration::from_secs(2);

    loop {
        if start.elapsed() > timeout {
            return Err("Operation timed out after 600 seconds".into());
        }

        tokio::time::sleep(interval).await;
        interval = Duration::from_secs(5);

        let token = get_token().await?;
        let response = client
            .get(&url)
            .bearer_auth(&token)
            .header("x-goog-user-project", project_id)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Poll error {status}: {body}").into());
        }

        let operation: Operation = response.json().await?;
        if operation.done {
            if let Some(err) = operation.error {
                return Err(
                    format!("Synthesis failed (code {}): {}", err.code, err.message).into(),
                );
            }
            return Ok(());
        }
    }
}
