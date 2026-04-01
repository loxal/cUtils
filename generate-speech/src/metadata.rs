use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const DC_TO_TAG: &[(&str, &str)] = &[
    ("title", "title"),
    ("creator", "artist"),
    ("subject", "genre"),
    ("description", "comment"),
    ("publisher", "publisher"),
    ("contributor", "album_artist"),
    ("date", "date"),
    ("language", "language"),
    ("rights", "copyright"),
    ("source", "url"),
];

pub fn convert_and_tag(
    wav_path: &Path,
    mp3: bool,
    dc_metadata: &HashMap<String, String>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let output = if mp3 {
        wav_path.with_extension("mp3")
    } else {
        wav_path.with_extension("m4a")
    };

    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-y", "-i"]);
    cmd.arg(wav_path);

    if mp3 {
        cmd.args(["-codec:a", "libmp3lame", "-q:a", "0", "-ar", "48000"]);
    } else {
        cmd.args(["-codec:a", "aac", "-b:a", "256k", "-ar", "48000"]);
    }

    for &(dc_field, tag) in DC_TO_TAG {
        if let Some(value) = dc_metadata.get(dc_field) {
            cmd.args(["-metadata", &format!("{tag}={value}")]);
        }
    }

    cmd.arg(&output);

    let result = cmd.output()?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(format!("ffmpeg failed: {stderr}").into());
    }

    Ok(output)
}
