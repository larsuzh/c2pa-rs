// Verify that bytes inside a DataHash exclusion really are unprotected.
//
// Hard-coded for one specific finding from `analyze_exclusion_content`:
//
//   === sdk/examples/assets/L1000055.JPG ===
//     exclusion #2: bytes [27572..27586) (14 bytes)
//       -> APP1/XMP metadata
//          XMP content: xmp:Rating="0"
//
// The Leica signer left these 14 bytes of XMP outside the hash, so we
// should be able to flip the rating from 0 to 5 without invalidating the
// C2PA signature.  Same byte length, same offset, no length recomputation
// needed -- a true byte-for-byte swap.
//
// Steps:
//   1. Read the source file, dump the 14 bytes at [27572..27586).
//   2. Validate the source through `c2pa::Reader` and print its state.
//   3. Build a tampered copy with `xmp:Rating="5"` at the same offset,
//      write it to disk, and dump the new 14 bytes.
//   4. Validate the tampered copy and print its state.
//   5. Diff the two states side-by-side.
//
// Usage:
//   cargo run --release -p c2pa --example tamper_excluded_rating --features file_io
//
// (no arguments -- everything is hard-coded for L1000055.JPG)

use std::{fs, io::Cursor, path::PathBuf};

use anyhow::{bail, Result};
use c2pa::Reader;

const SOURCE: &str = "sdk/examples/assets/L1000055.JPG";
const TAMPERED: &str = "sdk/examples/assets/L1000055_rating_tampered.jpg";
const OFFSET: usize = 27572;
const LEN: usize = 14;
const EXPECTED: &[u8] = b"xmp:Rating=\"0\"";
const REPLACEMENT: &[u8] = b"xmp:Rating=\"5\"";

fn main() -> Result<()> {
    // ---- 1. Read source, sanity-check the target window ----
    let source_path = PathBuf::from(SOURCE);
    let original = fs::read(&source_path)?;
    if original.len() < OFFSET + LEN {
        bail!("source is shorter than {} bytes", OFFSET + LEN);
    }
    let original_window = &original[OFFSET..OFFSET + LEN];
    println!("== source: {} ==", source_path.display());
    println!(
        "  bytes [{}..{}) ({} bytes) before tampering:",
        OFFSET,
        OFFSET + LEN,
        LEN
    );
    println!("    raw  = {:02X?}", original_window);
    println!(
        "    text = {:?}",
        String::from_utf8_lossy(original_window)
    );
    if original_window != EXPECTED {
        bail!(
            "source window does not match the expected `xmp:Rating=\"0\"` -- \
             did the asset change?  Got {:?}",
            String::from_utf8_lossy(original_window)
        );
    }
    if REPLACEMENT.len() != LEN {
        bail!(
            "replacement is {} bytes but exclusion is {} bytes -- must match exactly",
            REPLACEMENT.len(),
            LEN
        );
    }

    // ---- 2. Validate the source ----
    let source_state = validate(&original)?;
    println!("\n  c2pa validation_state = {source_state}");

    // ---- 3. Build and write the tampered copy ----
    let mut tampered = original.clone();
    tampered[OFFSET..OFFSET + LEN].copy_from_slice(REPLACEMENT);
    fs::write(TAMPERED, &tampered)?;

    let tampered_window = &tampered[OFFSET..OFFSET + LEN];
    println!("\n== tampered: {TAMPERED} ==");
    println!(
        "  bytes [{}..{}) ({} bytes) after tampering:",
        OFFSET,
        OFFSET + LEN,
        LEN
    );
    println!("    raw  = {:02X?}", tampered_window);
    println!(
        "    text = {:?}",
        String::from_utf8_lossy(tampered_window)
    );

    // ---- 4. Validate the tampered copy ----
    let tampered_state = validate(&tampered)?;
    println!("\n  c2pa validation_state = {tampered_state}");

    // ---- 5. Side-by-side comparison ----
    println!("\n== summary ==");
    println!(
        "  source   : window={:?}  validation_state={}",
        String::from_utf8_lossy(original_window),
        source_state
    );
    println!(
        "  tampered : window={:?}  validation_state={}",
        String::from_utf8_lossy(tampered_window),
        tampered_state
    );
    if source_state == tampered_state {
        println!(
            "\n  -> validation state is unchanged after rewriting bytes inside the \
             DataHash exclusion: the 14-byte XMP slice really is outside the hash."
        );
    } else {
        println!(
            "\n  -> validation state CHANGED after tampering -- the bytes were not \
             actually outside the hash."
        );
    }

    Ok(())
}

fn validate(bytes: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(bytes);
    let reader = Reader::from_stream("image/jpeg", &mut cursor)?;
    Ok(format!("{:?}", reader.validation_state()))
}
