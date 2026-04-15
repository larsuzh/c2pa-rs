use anyhow::{bail, Result};

pub fn mime_from_path(path: &str) -> Result<&'static str> {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => Ok("image/jpeg"),
        "png" => Ok("image/png"),
        "gif" => Ok("image/gif"),
        "tiff" | "tif" => Ok("image/tiff"),
        "webp" => Ok("image/webp"),
        "svg" => Ok("image/svg+xml"),
        "mp4" => Ok("video/mp4"),
        "mp3" => Ok("audio/mpeg"),
        "wav" => Ok("audio/wav"),
        other => bail!("unsupported file extension: {other}"),
    }
}
