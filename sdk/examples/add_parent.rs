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
        .with_toml(include_str!("../tests/fixtures/test_settings.toml"))?
        .with_value("verify.verify_after_reading", false)?
        .with_value("verify.verify_after_sign", false)?;

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
    let mut parent_bytes = std::fs::read(parent_path)?;

    // VERIFICATION HOOK: mutate the parent's embedded manifest before adding it.
    // If the SDK's parent-validation is sound, the resulting child should surface
    // a validation failure on the parent ingredient (signature or assertion-hash
    // mismatch). If validation passes silently, the implementation is NOT
    // trustworthy.
    tamper_parent_manifest(&mut parent_bytes)?;

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

/// Flip a single byte inside the parent's embedded C2PA manifest payload.
///
/// Strategy: search the file bytes for a known assertion label, then mutate
/// a byte well past the label (likely inside that assertion's payload). This
/// preserves all JUMBF box lengths and JPEG segment lengths — only the
/// signed content changes — so the SDK will parse the manifest normally and
/// the tamper has to be caught by the cryptographic verification path
/// (signature check or assertion-box hash check), which is exactly what we
/// want to exercise.
///
/// Returns Err if no known assertion label is found (e.g. the parent has no
/// embedded manifest), so the test fails loudly rather than silently
/// producing an unaltered run.
fn tamper_parent_manifest(bytes: &mut [u8]) -> Result<()> {
    // Try a few common assertion labels in priority order. The first one we
    // find in the parent's byte stream is the one we mutate near.
    const CANDIDATES: &[&[u8]] = &[
        b"stds.schema-org.CreativeWork",
    ];

    let (label, label_pos) = CANDIDATES
        .iter()
        .find_map(|needle| {
            bytes
                .windows(needle.len())
                .position(|w| w == *needle)
                .map(|p| (*needle, p))
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no known C2PA assertion label found in parent — \
                 does the parent actually contain an embedded manifest?"
            )
        })?;

    // Skip past the label and a small amount of CBOR/JUMBF framing so we
    // land in the assertion payload rather than in the label string itself.
    let target = label_pos + label.len() + 32;
    if target >= bytes.len() {
        bail!(
            "parent file too short to apply tamper offset \
             (label at {label_pos}, want byte {target}, len {})",
            bytes.len()
        );
    }

    let original = bytes[target];
    bytes[target] ^= 0x01;

    println!(
        "TAMPER: located {:?} at offset {label_pos}; flipped byte at {target}: \
         0x{:02x} -> 0x{:02x}",
        std::str::from_utf8(label).unwrap_or("<non-utf8>"),
        original,
        bytes[target]
    );
    println!(
        "        if validation is sound, the resulting child manifest should \
         flag the parent ingredient as invalid."
    );

    Ok(())
}

