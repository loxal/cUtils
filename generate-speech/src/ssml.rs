use regex::Regex;
use std::collections::HashMap;

pub fn sanitize_for_google(ssml: &str) -> String {
    let mut s = ssml.to_string();
    s = Regex::new(r"<\?xml[^?]*\?>")
        .unwrap()
        .replace_all(&s, "")
        .to_string();
    s = Regex::new(r"<!DOCTYPE[^>]*>")
        .unwrap()
        .replace_all(&s, "")
        .to_string();
    s = Regex::new(r"(?s)<metadata[^>]*>.*?</metadata>")
        .unwrap()
        .replace_all(&s, "")
        .to_string();
    s = Regex::new(r"<voice[^>]*>")
        .unwrap()
        .replace_all(&s, "")
        .to_string();
    s = s.replace("</voice>", "");
    let lang_attr = Regex::new(r#"xml:lang="([^"]*)""#)
        .unwrap()
        .captures(&s)
        .map(|c| format!(r#" xml:lang="{}""#, &c[1]))
        .unwrap_or_default();
    s = Regex::new(r"<speak[^>]*>")
        .unwrap()
        .replace(&s, format!("<speak{lang_attr}>"))
        .to_string();
    s.trim().to_string()
}

pub fn strip_pitch_from_prosody(ssml: &str) -> String {
    Regex::new(r#"(<prosody[^>]*)\s+pitch="[^"]*""#)
        .unwrap()
        .replace_all(ssml, "$1")
        .to_string()
}

pub fn strip_emphasis_tags(ssml: &str) -> String {
    Regex::new(r"(?s)<emphasis[^>]*>(.*?)</emphasis>")
        .unwrap()
        .replace_all(ssml, "$1")
        .to_string()
}

pub fn extract_dc_metadata(ssml: &str) -> HashMap<String, String> {
    let fields = [
        "title",
        "creator",
        "subject",
        "description",
        "publisher",
        "contributor",
        "date",
        "type",
        "format",
        "identifier",
        "source",
        "language",
        "relation",
        "coverage",
        "rights",
    ];
    let mut metadata = HashMap::new();
    for field in fields {
        let pattern = format!(r"(?s)<dc:{field}>(.*?)</dc:{field}>");
        if let Some(caps) = Regex::new(&pattern).unwrap().captures(ssml) {
            metadata.insert(field.to_string(), caps[1].trim().to_string());
        }
    }
    metadata
}
