// Pixel-tamper detection check (the honest counterpart to
// `pixel_tamper_exclusion`).
//
// This script takes an *already C2PA-signed* JPEG, overwrites a window of its
// entropy-coded scan data (the compressed pixel bitstream), and then runs the
// validator to confirm that the tampering is detected.
//
// Unlike `pixel_tamper_exclusion`, nothing is signed here: we never touch the
// manifest, never declare any DataHash exclusions, and never re-hash.  The
// input is assumed to have been signed normally, so its DataHash covers the
// pixel bytes we corrupt.  The expected result is therefore an INVALID
// validation state with an `assertion.dataHash.mismatch` failure.
//
// Usage:
//   cargo run --release -p c2pa --example pixel_tamper_detect -- \
//       <input_signed.jpg> <output_tampered.jpg>
//
// Exit code is 0 if the verifier correctly flagged the tampering, non-zero if
// the tampered file somehow still validated (which would indicate a problem).

use std::io::Cursor;

use anyhow::{anyhow, bail, Result};
use c2pa::{Reader, ValidationState};

mod common;
use common::mime_from_path;

// Skip this many bytes past the start of the entropy-coded scan data before
// the tamper window begins.  Keeps the first few MCUs intact so the JPEG still
// decodes (with visible corruption further down) instead of failing to parse.
const ENTROPY_GAP: usize = 128;

// Size of the pixel-bitstream window we overwrite.
const TAMPER_LEN: usize = 4096;

// Pattern written into the tamper window.  0x00 is safe for JPEG entropy
// streams (no 0xFF bytes -> no risk of synthesising a fake marker).
const TAMPER_BYTE: u8 = 0x00;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        bail!("Usage: pixel_tamper_detect <input_signed.jpg> <output_tampered.jpg>");
    }
    let input_path = &args[1];
    let tampered_path = &args[2];

    let format = mime_from_path(input_path)?;
    if format != "image/jpeg" {
        bail!("only image/jpeg is supported by this check");
    }

    let signed_bytes = std::fs::read(input_path)?;
    let entropy_start = find_entropy_data_start(&signed_bytes)?;
    println!(
        "Input signed JPEG: {} bytes, entropy-coded scan data starts at offset {}",
        signed_bytes.len(),
        entropy_start
    );

    // -- First confirm the input actually validates before we touch it, so a
    //    failure afterwards can be attributed to our tampering and not to a
    //    pre-existing problem with the file.
    let baseline = validate("Input (untampered)", &signed_bytes)?;
    if baseline != ValidationState::Valid {
        bail!(
            "input does not validate as-is (state = {baseline:?}); \
             provide a normally-signed JPEG"
        );
    }

    // -- Tamper a window of the entropy-coded pixel bytes.
    let tamper_start = entropy_start + ENTROPY_GAP;
    let tamper_end = tamper_start + TAMPER_LEN;
    if tamper_end >= signed_bytes.len() - 2 {
        bail!("signed JPEG too small for a {TAMPER_LEN}-byte tamper window");
    }

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

    // -- Validate the tampered file.  We expect this to be detected.
    let state = validate("Tampered (pixel bytes overwritten)", &tampered)?;

    println!("\n=== Result ===");
    if state == ValidationState::Valid {
        println!(
            "  UNEXPECTED: the tampered file still validated as Valid. \
             The verifier did NOT detect the pixel tampering."
        );
        std::process::exit(1);
    } else {
        println!(
            "  OK: the verifier detected the tampering (state = {state:?}). \
             The DataHash over the pixel bytes no longer matches."
        );
    }
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

/// Validate a JPEG byte buffer, print a summary, and return the state.
fn validate(label: &str, bytes: &[u8]) -> Result<ValidationState> {
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
            let datahash_match = am
                .success()
                .iter()
                .any(|s| s.code() == c2pa::validation_status::ASSERTION_DATAHASH_MATCH);
            println!("  ASSERTION_DATAHASH_MATCH present in success codes: {datahash_match}");
        }
    }
    Ok(state)
}
