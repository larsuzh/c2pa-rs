// Redact an assertion from an existing signed image and write the result to disk.
//
// Usage:
//   cargo run --example redact_assertion -p c2pa -- <input_image> <output_image> <assertion_label>
//
// Example (redact the thumbnail):
//   cargo run --example redact_assertion -p c2pa -- \
//     sdk/examples/assets/chairlift_signed.jpg \
//     /tmp/chairlift_redacted.jpg \
//     c2pa.thumbnail.claim

use std::io::Cursor;

use anyhow::{bail, Result};
use c2pa::{
    crypto::raw_signature::SigningAlg, settings::Settings, Builder, BuilderIntent, CallbackSigner,
    Context, Reader,
};
use serde_json::json;

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        bail!("Usage: redact_assertion <input_image> <output_image> <assertion_label>");
    }
    let input_path = &args[1];
    let output_path = &args[2];
    let assertion_label = &args[3];

    let format = mime_from_path(input_path)?;

    // Step 1: read the existing manifest to get the active manifest label.
    // We need it to build the full JUMBF URI for the assertion we want to redact.
    let image_bytes = std::fs::read(input_path)?;
    let mut source = Cursor::new(image_bytes.clone());

    // let settings = Settings::new()
    //     .with_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    // let context = Context::new().with_settings(settings)?.into_shared();

    let parent = Reader::from_stream(format, &mut source)?;
    let parent_manifest_label = parent
        .active_label()
        .ok_or_else(|| anyhow::anyhow!("No active manifest found in input image"))?;

    // Step 2: build the full JUMBF URI for the assertion.
    // Format: "self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{assertion_label}"
    let redacted_uri = format!(
        "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
        parent_manifest_label, assertion_label
    );
    println!("Redacting: {redacted_uri}");

    // Step 3: build a new claim that redacts the assertion.
    let ed_signer =
        |_ctx: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);

    let new_context = Context::new()
        .with_settings(
            Settings::new()
                .with_toml(include_str!("../tests/fixtures/test_settings.toml"))?,
        )?
        .with_signer(signer)
        .into_shared();

    let mut builder = Builder::from_shared_context(&new_context)
        .with_definition(
            json!({
                "title": output_path,
                "format": format,
                "claim_generator_info": [{"name": "redact_assertion_example", "version": "0.1.0"}],
                // The c2pa.redacted action is required alongside a redaction
                "assertions": [{
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [{
                            "action": "c2pa.redacted",
                            "parameters": {
                                "redacted": redacted_uri
                            }
                        }]
                    }
                }],
                // List the full JUMBF URI of every assertion to redact
                "redactions": [redacted_uri]
            })
            .to_string(),
        )?;

    builder.set_intent(BuilderIntent::Edit);

    // Step 4: sign with the original image as source (it becomes the parent ingredient).
    source.set_position(0);
    let mut dest = Cursor::new(Vec::new());
    builder.save_to_stream(format, &mut source, &mut dest)?;

    std::fs::write(output_path, dest.get_ref())?;
    println!("Written to {output_path}");

    // Step 5: verify and show the result.
    dest.set_position(0);
    let reader = Reader::from_stream(format, &mut dest)?;
    println!("\n--- validation status ---");
    for status in reader.validation_status().unwrap_or_default() {
        println!("  {} — {}", status.code(), status.url().unwrap_or_default());
    }
    println!("\n--- manifest store ---");
    println!("{reader}");

    Ok(())
}

fn mime_from_path(path: &str) -> Result<&'static str> {
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
        other => bail!("unsupported file extension: {other}"),
    }
}
