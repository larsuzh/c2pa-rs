// Sign a child image and record another image as its parent ingredient.
// Works whether the parent image already has a C2PA manifest or not.
//
// Usage:
//   cargo run --example add_parent -p c2pa -- <parent_image> <child_image> <output_image>
//
// Example:
//   cargo run --example add_parent -p c2pa -- sdk/examples/assets/original.jpg sdk/examples/assets/edited.jpg sdk/examples/assets/edited_signed.jpg

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
    if args.len() != 4 {
        bail!("Usage: add_parent <parent_image> <child_image> <output_image>");
    }
    let parent_path = &args[1];
    let child_path = &args[2];
    let output_path = &args[3];

    let parent_format = mime_from_path(parent_path)?;
    let child_format = mime_from_path(child_path)?;

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
        "format": child_format,
        "claim_generator_info": [{"name": "add_parent_example", "version": "0.1.0"}],
        "assertions": [{
            "label": "c2pa.actions",
            "data": {
                "actions": [{
                    "action": "c2pa.opened",
                    "parameters": {
                        "ingredientIds": ["parent_ingredient"]
                    }
                }]
            }
        }]
    })
    .to_string();

    let mut builder =
        Builder::from_shared_context(&context).with_definition(manifest_def)?;

    // Add the parent — works whether it has an existing manifest or not.
    // The parent bytes are hashed at this point and bound into the child manifest.
    let parent_bytes = std::fs::read(parent_path)?;
    let mut parent_source = Cursor::new(parent_bytes);
    builder.add_ingredient_from_stream(
        json!({
            "title": parent_path,
            "relationship": "parentOf",
            "label": "parent_ingredient"
        })
        .to_string(),
        parent_format,
        &mut parent_source,
    )?;

    let child_bytes = std::fs::read(child_path)?;
    let mut child_source = Cursor::new(child_bytes);
    let mut dest = Cursor::new(Vec::new());
    builder.save_to_stream(child_format, &mut child_source, &mut dest)?;

    std::fs::write(output_path, dest.get_ref())?;
    println!("signed child image written to {output_path}");
    println!("parent {parent_path} recorded as parentOf ingredient");

    Ok(())
}

