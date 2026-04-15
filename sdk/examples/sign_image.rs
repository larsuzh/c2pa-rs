// Sign an unsigned image and write the result to disk.
//
// Usage:
//   cargo run --example sign_image -p c2pa -- <input_image> <output_image>
//
// Example:
//   cargo run --example sign_image -p c2pa -- sdk/examples/assets/photo.jpg sdk/examples/assets/photo_signed.jpg

use std::io::Cursor;

use anyhow::{bail, Result};
use c2pa::{crypto::raw_signature::SigningAlg, settings::Settings, Builder, CallbackSigner, Context};
use serde_json::json;

mod common;
use common::mime_from_path;

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        bail!("Usage: sign_image <input_image> <output_image>");
    }
    let input_path = &args[1];
    let output_path = &args[2];

    let format = mime_from_path(input_path)?;

    let image_bytes = std::fs::read(input_path)?;
    let mut source = Cursor::new(image_bytes);

    let settings = Settings::new()
        .with_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let ed_signer =
        |_ctx: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);

    let context = Context::new()
        .with_settings(settings)?
        .with_signer(signer)
        .into_shared();

    let manifest_def = json!({
        "title": output_path,
        "format": format,
        "claim_generator_info": [{"name": "sign_image_example", "version": "0.1.0"}],
        "assertions": [{
            "label": "c2pa.actions",
            "data": {
                "actions": [{"action": "c2pa.created"}]
            }
        }]
    })
    .to_string();

    let mut builder =
        Builder::from_shared_context(&context).with_definition(manifest_def)?;

    let mut dest = Cursor::new(Vec::new());
    builder.save_to_stream(format, &mut source, &mut dest)?;

    std::fs::write(output_path, dest.get_ref())?;
    println!("signed image written to {output_path}");

    Ok(())
}

