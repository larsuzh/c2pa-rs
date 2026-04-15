// Sign a child image with a parent ingredient, then overwrite that ingredient's
// thumbnail with an arbitrary image chosen at the command line. Demonstrates
// that the ingredient thumbnail in the derived manifest is signed by the
// derived manifest's signer, not the parent's — so any producer can substitute
// it without invalidating the derived claim.
//
// Usage:
//   cargo run --example spoof_ingredient_thumbnail -p c2pa -- \
//       <parent_image> <child_image> <spoof_thumbnail> <output_image>
//
// Example:
//   cargo run --example spoof_ingredient_thumbnail -p c2pa -- \
//       sdk/examples/assets/cloudscape.jpg \
//       sdk/examples/assets/chairlift_cropped.jpg \
//       sdk/examples/assets/chairlift.jpg \
//       sdk/examples/assets/spoofed.jpg

use std::io::{Cursor};

use anyhow::{bail, Result};
use c2pa::{
    crypto::raw_signature::SigningAlg, settings::Settings, Builder, CallbackSigner, Context,
};
use serde_json::json;

mod common;
use common::mime_from_path;

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        bail!(
            "Usage: spoof_ingredient_thumbnail <parent_image> <child_image> \
             <spoof_thumbnail> <output_image>"
        );
    }
    let parent_path = &args[1];
    let child_path = &args[2];
    let spoof_thumb_path = &args[3];
    let output_path = &args[4];

    let parent_format = mime_from_path(parent_path)?;
    let child_format = mime_from_path(child_path)?;
    let spoof_thumb_format = mime_from_path(spoof_thumb_path)?;

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
        "claim_generator_info": [{"name": "spoof_ingredient_thumbnail_example", "version": "0.1.0"}],
        "assertions": [{
            "label": "c2pa.actions",
            "data": {
                "actions": [{
                        "action": "c2pa.cropped"
                }]
            }
        }]
    })
        .to_string();

    let mut builder =
        Builder::from_shared_context(&context).with_definition(manifest_def)?;

    // Add the parent — the SDK will populate a thumbnail for the ingredient
    // based on the parent image (or its embedded claim thumbnail, if valid).
    let parent_bytes = std::fs::read(parent_path)?;
    let mut parent_source = Cursor::new(parent_bytes);
    let parent_ingredient = builder.add_ingredient_from_stream(
        json!({
            "title": parent_path,
            "relationship": "parentOf",
            "label": "parent_ingredient"
        })
            .to_string(),
        parent_format,
        &mut parent_source,
    )?;

    // Overwrite the thumbnail that the SDK just populated. The replacement
    // becomes the c2pa.thumbnail.ingredient assertion in our manifest and
    // gets signed by our cert. The parent's original c2pa.thumbnail.claim
    // (if any) is untouched inside the parent manifest.
    let spoof_bytes = std::fs::read(spoof_thumb_path)?;
    parent_ingredient.set_thumbnail(spoof_thumb_format, spoof_bytes)?;

    let child_bytes = std::fs::read(child_path)?;
    let mut child_source = Cursor::new(child_bytes);
    let mut dest = Cursor::new(Vec::new());
    builder.save_to_stream(child_format, &mut child_source, &mut dest)?;

    std::fs::write(output_path, dest.get_ref())?;
    println!("signed child image written to {output_path}");
    println!("parent {parent_path} recorded as parentOf ingredient");
    println!("ingredient thumbnail replaced with {spoof_thumb_path}");

    // dest.rewind()?;
    // let reader = Reader::from_shared_context(&context).with_stream(child_format, &mut dest)?;
    // println!("\n--- c2pa validation ---");
    // println!("{}", reader.json());
    // println!("validation_state: {:?}", reader.validation_state());
    Ok(())
}

