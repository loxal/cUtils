use base64::Engine;
use gcp_auth::TokenProvider;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PredictRequest {
    instances: Vec<Instance>,
    parameters: Parameters,
}

#[derive(Serialize)]
struct Instance {
    prompt: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Parameters {
    sample_count: u32,
    aspect_ratio: String,
    negative_prompt: String,
    person_generation: String,
    add_watermark: bool,
    output_options: OutputOptions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputOptions {
    mime_type: String,
}

#[derive(Deserialize)]
struct PredictResponse {
    predictions: Option<Vec<Prediction>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Prediction {
    bytes_base64_encoded: Option<String>,
    gcs_uri: Option<String>,
}

async fn get_token() -> Result<String, Box<dyn std::error::Error>> {
    // Use ConfigDefaultCredentials directly — gcp_auth::provider() misparses
    // authorized_user credentials as service account when GOOGLE_APPLICATION_CREDENTIALS is set
    let provider = gcp_auth::ConfigDefaultCredentials::new().await?;
    let scopes = &["https://www.googleapis.com/auth/cloud-platform"];
    let token = provider.token(scopes).await?;
    Ok(token.as_str().to_string())
}

pub struct GeneratedImage {
    pub bytes: Option<Vec<u8>>,
    pub gcs_uri: Option<String>,
}

pub async fn generate_images(
    project_id: &str,
    location: &str,
    model: &str,
    prompt: &str,
    sample_count: u32,
    aspect_ratio: &str,
    negative_prompt: &str,
    add_watermark: bool,
) -> Result<Vec<GeneratedImage>, Box<dyn std::error::Error>> {
    let url = format!(
        "https://{location}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{location}/publishers/google/models/{model}:predict"
    );

    let request = PredictRequest {
        instances: vec![Instance {
            prompt: prompt.to_string(),
        }],
        parameters: Parameters {
            sample_count,
            aspect_ratio: aspect_ratio.to_string(),
            negative_prompt: negative_prompt.to_string(),
            person_generation: "allow_all".to_string(),
            add_watermark,
            output_options: OutputOptions {
                mime_type: "image/png".to_string(),
            },
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

    let predict_response: PredictResponse = response.json().await?;
    let predictions = predict_response.predictions.unwrap_or_default();

    let mut images = Vec::new();
    for pred in predictions {
        let bytes = pred
            .bytes_base64_encoded
            .as_ref()
            .map(|b64| base64::engine::general_purpose::STANDARD.decode(b64))
            .transpose()?;
        images.push(GeneratedImage {
            bytes,
            gcs_uri: pred.gcs_uri,
        });
    }

    Ok(images)
}
