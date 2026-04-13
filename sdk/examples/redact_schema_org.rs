// Redact a non-thumbnail assertion (defaults to stds.schema-org.CreativeWork) from
// a signed image to verify that the thumbnail-resolution error is not triggered.
//
// Usage:
//   cargo run --example redact_schema_org -p c2pa -- <input_image> <output_image> [assertion_label]
//
// Example:
//   cargo run --example redact_schema_org -p c2pa -- \
//     sdk/examples/assets/car-es-1sm.jpg \
//     /tmp/car_redacted.jpg

use std::io::Cursor;

use anyhow::{bail, Result};
use c2pa::{
    crypto::raw_signature::SigningAlg, settings::Settings, Builder, BuilderIntent, CallbackSigner,
    Context, Reader,
};
use serde_json::json;

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

const DEFAULT_LABEL: &str = "stds.schema-org.CreativeWork";

fn main() -> Result<()> {
    // Simple logging so ERROR lines are visible
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error")).init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        bail!("Usage: redact_schema_org <input_image> <output_image> [assertion_label]");
    }
    let input_path = &args[1];
    let output_path = &args[2];
    let assertion_label = args.get(3).map(String::as_str).unwrap_or(DEFAULT_LABEL);

    let format = mime_from_path(input_path)?;
    println!("Assertion to redact : {assertion_label}");

    // Step 1: read the existing manifest to get the active manifest label.
    let image_bytes = std::fs::read(input_path)?;
    let mut source = Cursor::new(image_bytes.clone());

    let settings = Settings::new()
        .with_toml(include_str!("../tests/fixtures/test_settings.toml"))?;
    let _context = Context::new().with_settings(settings)?.into_shared();

    let parent = Reader::from_stream(format, &mut source)?;
    let parent_manifest_label = parent
        .active_label()
        .ok_or_else(|| anyhow::anyhow!("No active manifest found in input image"))?;

    println!("Parent manifest     : {parent_manifest_label}");

    // Step 2: build the full JUMBF URI for the assertion.
    let redacted_uri = format!(
        "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
        parent_manifest_label, assertion_label
    );
    println!("Redacting URI       : {redacted_uri}");

    // Step 3: confirm the assertion actually exists in the manifest.
    {
        let parent_manifest = parent
            .active_manifest()
            .ok_or_else(|| anyhow::anyhow!("No active manifest"))?;
        let found = parent_manifest
            .assertions()
            .iter()
            .any(|a| a.label().contains(assertion_label));
        if !found {
            bail!(
                "Assertion '{assertion_label}' not found in the active manifest.\n\
                 Available labels: {:?}",
                parent_manifest
                    .assertions()
                    .iter()
                    .map(|a| a.label())
                    .collect::<Vec<_>>()
            );
        }
        println!("Assertion found     : yes");
    }

    // Step 4: build a new claim that redacts the assertion.
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

    let mut builder = Builder::from_shared_context(&new_context).with_definition(
        json!({
            "title": output_path,
            "format": format,
            "claim_generator_info": [{"name": "redact_schema_org_example", "version": "0.1.0"}],
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
            "redactions": [redacted_uri]
        })
        .to_string(),
    )?;

    builder.set_intent(BuilderIntent::Edit);

    // Step 5: sign with the original image as source.
    source.set_position(0);
    let mut dest = Cursor::new(Vec::new());
    builder.save_to_stream(format, &mut source, &mut dest)?;

    std::fs::write(output_path, dest.get_ref())?;
    println!("\nWritten to          : {output_path}");

    // Step 6: read back and report validation status.
    dest.set_position(0);
    let reader = Reader::from_stream(format, &mut dest)?;

    println!("\n--- validation status ---");
    match reader.validation_status() {
        Some(statuses) if !statuses.is_empty() => {
            for s in statuses {
                println!("  {} — {}", s.code(), s.url().unwrap_or_default());
            }
        }
        _ => println!("  (none)"),
    }

    println!("\n--- assertions in redacted manifest ---");
    if let Some(m) = reader.active_manifest() {
        for a in m.assertions() {
            println!("  {}", a.label());
        }
        println!(
            "\nThumbnail present   : {}",
            m.thumbnail().is_some()
        );
    }

    println!("\n--- full manifest store ---");
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
