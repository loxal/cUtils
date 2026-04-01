use base64::Engine;
use gcp_auth::TokenProvider;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct PredictRequest {
    instances: Vec<Instance>,
    parameters: serde_json::Value,
}

#[derive(Serialize)]
struct Instance {
    prompt: String,
    negative_prompt: String,
    sample_count: u32,
}

#[derive(Deserialize)]
struct PredictResponse {
    predictions: Option<Vec<Prediction>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Prediction {
    bytes_base64_encoded: Option<String>,
}

async fn get_token() -> Result<String, Box<dyn std::error::Error>> {
    // Use ConfigDefaultCredentials directly — gcp_auth::provider() misparses
    // authorized_user credentials as service account when GOOGLE_APPLICATION_CREDENTIALS is set
    let provider = gcp_auth::ConfigDefaultCredentials::new().await?;
    let scopes = &["https://www.googleapis.com/auth/cloud-platform"];
    let token = provider.token(scopes).await?;
    Ok(token.as_str().to_string())
}

pub async fn generate_audio(
    project_id: &str,
    location: &str,
    model: &str,
    prompt: &str,
    negative_prompt: &str,
    sample_count: u32,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let url = format!(
        "https://{location}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{location}/publishers/google/models/{model}:predict"
    );

    let request = PredictRequest {
        instances: vec![Instance {
            prompt: prompt.to_string(),
            negative_prompt: negative_prompt.to_string(),
            sample_count,
        }],
        parameters: serde_json::json!({}),
    };

    let token = get_token().await?;
    let client = Client::new();
    let response = client.post(&url).bearer_auth(&token).json(&request).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("API error {status}: {body}").into());
    }

    let predict_response: PredictResponse = response.json().await?;
    let predictions = predict_response.predictions.unwrap_or_default();

    let mut clips = Vec::new();
    for pred in predictions {
        if let Some(b64) = pred.bytes_base64_encoded {
            let bytes = base64::engine::general_purpose::STANDARD.decode(&b64)?;
            clips.push(bytes);
        }
    }

    Ok(clips)
}
