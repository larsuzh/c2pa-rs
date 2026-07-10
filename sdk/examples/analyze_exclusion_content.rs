// Walk every JPEG under `sdk/examples/assets`, inspect each `c2pa.hash.data`
// assertion, and report -- for every exclusion range -- *what bytes the
// signer chose to leave out of the data hash*.
//
// For each exclusion we:
//   * walk the JPEG marker structure to figure out which segments the byte
//     range overlaps;
//   * for C2PA JUMBF (APP11), just announce it -- we don't print the
//     manifest itself;
//   * for textual metadata (EXIF/XMP/JFIF/COM/Adobe APP14) we print
//     human-readable content (XMP verbatim, EXIF/binary as ASCII runs);
//   * for entropy-coded scan data we flag it as pixel bitstream and report
//     how much of the segment is uncovered.
//
// Usage:
//   cargo run --release -p c2pa --example analyze_exclusion_content
//   cargo run --release -p c2pa --example analyze_exclusion_content -- <dir>

use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Result};
use c2pa::Reader;
use serde_json::Value;

mod common;
use common::mime_from_path;

const DEFAULT_DIR: &str = "sdk/examples/assets";

// Maximum bytes of payload we'll scan for printable strings.
const MAX_SCAN: usize = 4096;
// Minimum length of a printable run we'll print.
const MIN_RUN: usize = 4;
// Cap on how many printable runs to show per exclusion (avoid wall-of-text).
const MAX_RUNS: usize = 24;
// Cap on raw XMP text dump.
const MAX_XMP: usize = 2000;

#[derive(Debug)]
struct JpegSegment {
    start: usize,         // inclusive, position of first byte of marker (or entropy data)
    end: usize,           // exclusive
    payload_start: usize, // first byte past marker + length field; == start for SOI/EOI/RSTn/entropy
    kind: SegmentKind,
}

#[derive(Debug, Clone)]
enum SegmentKind {
    Soi,
    Eoi,
    Standalone(u8),    // RSTn / TEM
    Sof(u8),           // marker low byte
    Dht,
    Dqt,
    Dri,
    SosHeader,         // FFDA + length + scan params
    EntropyData,       // bytes after SOS header, up to next non-restart marker
    Com(String),
    AppJfif,
    AppExif,
    AppXmp,
    AppIcc,
    AppMpf,
    AppJumbfC2pa,
    AppJumbfOther,
    AppPhotoshop,
    AppAdobe,
    AppOther { n: u8, id: String },
    Other(u8),
}

impl SegmentKind {
    fn short(&self) -> String {
        match self {
            SegmentKind::Soi => "SOI".into(),
            SegmentKind::Eoi => "EOI".into(),
            SegmentKind::Standalone(m) => format!("standalone marker 0x{m:02X}"),
            SegmentKind::Sof(m) => format!("SOF (0x{m:02X}, frame header)"),
            SegmentKind::Dht => "DHT (Huffman tables)".into(),
            SegmentKind::Dqt => "DQT (quantization tables)".into(),
            SegmentKind::Dri => "DRI (restart interval)".into(),
            SegmentKind::SosHeader => "SOS header".into(),
            SegmentKind::EntropyData => "entropy-coded scan data (JPEG pixel bitstream)".into(),
            SegmentKind::Com(_) => "COM (JPEG comment)".into(),
            SegmentKind::AppJfif => "APP0/JFIF metadata".into(),
            SegmentKind::AppExif => "APP1/EXIF metadata".into(),
            SegmentKind::AppXmp => "APP1/XMP metadata".into(),
            SegmentKind::AppIcc => "APP2/ICC color profile".into(),
            SegmentKind::AppMpf => "APP2/MPF (multi-picture)".into(),
            SegmentKind::AppJumbfC2pa => "APP11/JUMBF (C2PA manifest)".into(),
            SegmentKind::AppJumbfOther => "APP11/JUMBF (non-C2PA)".into(),
            SegmentKind::AppPhotoshop => "APP13/Photoshop (IPTC/IIM)".into(),
            SegmentKind::AppAdobe => "APP14/Adobe (color transform)".into(),
            SegmentKind::AppOther { n, id } => format!("APP{n} ({id:?})"),
            SegmentKind::Other(m) => format!("unknown marker 0x{m:02X}"),
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let dir = if args.len() >= 2 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from(DEFAULT_DIR)
    };
    if !dir.is_dir() {
        bail!("not a directory: {}", dir.display());
    }

    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    entries.sort();

    let mut total = 0usize;
    let mut signed = 0usize;
    let mut with_excl = 0usize;

    for path in entries {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let mime = match mime_from_path(name) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if mime != "image/jpeg" {
            // Keep this script JPEG-only.  Other containers carry exclusions
            // differently (BoxHash for PNG, BmffHash for MP4) and don't fit
            // the byte-range-into-JPEG-segments model below.
            continue;
        }
        total += 1;
        match analyze(&path) {
            Ok(true) => {
                signed += 1;
                with_excl += 1;
            }
            Ok(false) => {}
            Err(e) => {
                println!("\n=== {} ===", path.display());
                println!("  error: {e:#}");
            }
        }
    }

    println!(
        "\n----\nScanned {total} JPEG file(s); {signed} carried a c2pa.hash.data assertion \
         with at least one exclusion ({with_excl} reported)."
    );
    Ok(())
}

/// Returns Ok(true) if the file had a DataHash assertion with one or more
/// exclusions (whether or not we could describe their contents).
fn analyze(path: &Path) -> Result<bool> {
    let bytes = fs::read(path)?;

    // Read the manifest; some assets in the directory are unsigned, which is
    // fine -- we just skip them.
    let mut cursor = Cursor::new(&bytes);
    let reader = match Reader::from_stream("image/jpeg", &mut cursor) {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };
    let _ = reader.active_manifest(); // ensure manifest exists

    // The DataHash binding assertion is not exposed on the public `Manifest`
    // struct (it lives in the claim's assertion_store, not the
    // user-assertion list).  Pull it out via `detailed_json`, which
    // serializes every entry of the assertion_store including
    // `c2pa.hash.data` with its exclusions.
    let detailed: serde_json::Value =
        serde_json::from_str(&reader.detailed_json_checked()?)?;
    let exclusions = match extract_exclusions(&detailed) {
        Some(e) if !e.is_empty() => e,
        _ => return Ok(false),
    };

    println!("\n=== {} ===", path.display());
    println!("  file size: {} bytes", bytes.len());

    let segments = match parse_jpeg_segments(&bytes) {
        Ok(s) => s,
        Err(e) => {
            println!("  could not parse JPEG segments: {e:#}");
            return Ok(true);
        }
    };

    for (i, (s, l)) in exclusions.iter().enumerate() {
        let start = *s as usize;
        let len = *l as usize;
        let end = start.saturating_add(len);
        println!(
            "\n  exclusion #{}: bytes [{start}..{end}) ({len} bytes)",
            i + 1
        );

        let overlaps = segments_overlapping(&segments, start, end);
        if overlaps.is_empty() {
            println!("    (no JPEG segment overlaps this range -- out-of-bounds or trailer)");
            continue;
        }

        // Collapse a contiguous run of APP11/JUMBF chunks (the C2PA manifest is
        // typically split across many of them) into a single line.  Anything
        // else prints one line per overlapping segment.
        let mut i = 0;
        while i < overlaps.len() {
            let (seg, ov_start, ov_end) = overlaps[i];
            if is_jumbf(&seg.kind) {
                let run_start_byte = ov_start;
                let mut run_end_byte = ov_end;
                let mut count = 1;
                let mut any_c2pa = matches!(seg.kind, SegmentKind::AppJumbfC2pa);
                while i + 1 < overlaps.len() && is_jumbf(&overlaps[i + 1].0.kind) {
                    i += 1;
                    let (s, _os, oe) = overlaps[i];
                    run_end_byte = oe;
                    count += 1;
                    if matches!(s.kind, SegmentKind::AppJumbfC2pa) {
                        any_c2pa = true;
                    }
                }
                let label = if any_c2pa {
                    "APP11/JUMBF (C2PA manifest)"
                } else {
                    "APP11/JUMBF"
                };
                let total_len = run_end_byte - run_start_byte;
                println!(
                    "    -> {label} -- {count} segment(s), {total_len} bytes [{run_start_byte}..{run_end_byte})"
                );
                i += 1;
                continue;
            }
            let ov_len = ov_end - ov_start;
            let seg_len = seg.end - seg.start;
            let coverage = if ov_len == seg_len {
                "entire segment".to_string()
            } else {
                format!(
                    "{ov_len}/{seg_len} bytes of segment (bytes [{}..{}) within segment [{}..{}))",
                    ov_start, ov_end, seg.start, seg.end
                )
            };
            println!("    -> {} -- {coverage}", seg.kind.short());
            // For describing the segment's content we want its actual payload,
            // not the (possibly marker-aligned) overlap window.
            let payload_clip_start = ov_start.max(seg.payload_start);
            describe_payload(&bytes, &seg.kind, payload_clip_start, ov_end);
            i += 1;
        }
    }

    Ok(true)
}

fn describe_payload(bytes: &[u8], kind: &SegmentKind, ov_start: usize, ov_end: usize) {
    let slice = &bytes[ov_start..ov_end.min(bytes.len())];
    let scan = &slice[..slice.len().min(MAX_SCAN)];

    match kind {
        SegmentKind::Com(text) => {
            println!("       comment text: {:?}", truncate(text, 200));
        }
        SegmentKind::AppXmp => {
            // Strip the "http://ns.adobe.com/xap/1.0/\0" identifier prefix
            // if it's in the slice.
            let xmp_start = find_subslice(scan, b"<?xpacket")
                .or_else(|| find_subslice(scan, b"<x:xmpmeta"))
                .unwrap_or(0);
            let xmp_text = String::from_utf8_lossy(&scan[xmp_start..]);
            let trimmed = truncate(xmp_text.trim(), MAX_XMP);
            println!("       XMP content:");
            for line in trimmed.lines() {
                println!("         {line}");
            }
            if xmp_text.len() > MAX_XMP {
                println!("         [...truncated, full XMP is {} bytes]", xmp_text.len());
            }
        }
        SegmentKind::AppExif => {
            print_readable_runs("EXIF strings", scan);
        }
        SegmentKind::AppJfif => {
            // Parse JFIF version + density if we have the bytes.
            if scan.len() >= 14 && &scan[..5] == b"JFIF\0" {
                let ver_major = scan[5];
                let ver_minor = scan[6];
                let units = scan[7];
                let xd = u16::from_be_bytes([scan[8], scan[9]]);
                let yd = u16::from_be_bytes([scan[10], scan[11]]);
                let units_str = match units {
                    0 => "aspect ratio",
                    1 => "pixels/inch",
                    2 => "pixels/cm",
                    _ => "unknown",
                };
                println!(
                    "       JFIF v{ver_major}.{ver_minor:02}, density {xd}x{yd} ({units_str})"
                );
            } else {
                print_readable_runs("JFIF strings", scan);
            }
        }
        SegmentKind::AppIcc => {
            // ICC profile is mostly binary.  Header is "ICC_PROFILE\0" + seq/total bytes,
            // then a 128-byte ICC header in which bytes 4..8 are the preferred CMM
            // and bytes 12..16 are the profile/device class.
            print_readable_runs("ICC strings", scan);
        }
        SegmentKind::AppAdobe => {
            if scan.len() >= 12 && &scan[..5] == b"Adobe" {
                let transform = scan[11];
                let tx_str = match transform {
                    0 => "Unknown (RGB or CMYK)",
                    1 => "YCbCr",
                    2 => "YCCK",
                    _ => "reserved",
                };
                println!("       Adobe color transform = {transform} ({tx_str})");
            }
        }
        SegmentKind::AppPhotoshop => {
            print_readable_runs("Photoshop/IPTC strings", scan);
        }
        SegmentKind::AppMpf => {
            println!("       (binary MPF index)");
        }
        SegmentKind::AppOther { .. } => {
            print_readable_runs("readable strings", scan);
        }
        SegmentKind::EntropyData => {
            let zero_run = slice.iter().take_while(|&&b| b == 0).count();
            let ff_run = slice.iter().take_while(|&&b| b == 0xFF).count();
            let unique = {
                let mut seen = [false; 256];
                for &b in slice {
                    seen[b as usize] = true;
                }
                seen.iter().filter(|s| **s).count()
            };
            println!(
                "       this is compressed pixel data -- {unique} distinct byte values; \
                 leading zero run = {zero_run}, leading 0xFF run = {ff_run}"
            );
            if unique <= 2 {
                println!(
                    "       (note: very low byte diversity -- the range looks overwritten, \
                     not natural entropy)"
                );
            }
        }
        SegmentKind::Sof(_) => {
            // SOF payload: precision(1) height(2) width(2) num_components(1) ...
            if scan.len() >= 6 {
                let precision = scan[0];
                let h = u16::from_be_bytes([scan[1], scan[2]]);
                let w = u16::from_be_bytes([scan[3], scan[4]]);
                let n = scan[5];
                println!(
                    "       frame: {w}x{h} pixels, {n} component(s), {precision}-bit"
                );
            }
        }
        // For purely structural segments we already gave the short name above;
        // there's nothing user-facing to dump.
        SegmentKind::Dht
        | SegmentKind::Dqt
        | SegmentKind::Dri
        | SegmentKind::SosHeader
        | SegmentKind::Soi
        | SegmentKind::Eoi
        | SegmentKind::Standalone(_)
        | SegmentKind::Other(_)
        | SegmentKind::AppJumbfC2pa
        | SegmentKind::AppJumbfOther => {}
    }
}

fn print_readable_runs(label: &str, bytes: &[u8]) {
    let mut runs: Vec<String> = Vec::new();
    let mut cur = String::new();
    for &b in bytes {
        if (0x20..0x7F).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.len() >= MIN_RUN {
                runs.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
        if runs.len() >= MAX_RUNS {
            break;
        }
    }
    if cur.len() >= MIN_RUN && runs.len() < MAX_RUNS {
        runs.push(cur);
    }
    if runs.is_empty() {
        println!("       ({label}: none of length >= {MIN_RUN})");
        return;
    }
    println!("       {label} (up to {MAX_RUNS}):");
    for run in runs {
        println!("         {}", truncate(&run, 160));
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut out = s[..n].to_string();
        out.push_str("...");
        out
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn is_jumbf(kind: &SegmentKind) -> bool {
    matches!(
        kind,
        SegmentKind::AppJumbfC2pa | SegmentKind::AppJumbfOther
    )
}

/// Pull `(start, length)` pairs out of the active manifest's
/// `c2pa.hash.data` assertion as serialised by `Reader::detailed_json`.
fn extract_exclusions(detailed: &Value) -> Option<Vec<(u64, u64)>> {
    let active = detailed.get("active_manifest")?.as_str()?;
    let manifest = detailed.get("manifests")?.get(active)?;
    let assertion_store = manifest.get("assertion_store")?.as_object()?;
    // Key may be the bare label or include an instance suffix.
    let data_hash = assertion_store
        .iter()
        .find(|(k, _)| k.as_str() == "c2pa.hash.data" || k.starts_with("c2pa.hash.data"))?
        .1;
    let arr = data_hash.get("exclusions")?.as_array()?;
    let out: Vec<(u64, u64)> = arr
        .iter()
        .filter_map(|e| {
            let s = e.get("start")?.as_u64()?;
            let l = e.get("length")?.as_u64()?;
            Some((s, l))
        })
        .collect();
    Some(out)
}

/// Return every segment that intersects `[start, end)`, along with the clipped
/// overlap [ov_start, ov_end) within that segment.
fn segments_overlapping(
    segments: &[JpegSegment],
    start: usize,
    end: usize,
) -> Vec<(&JpegSegment, usize, usize)> {
    segments
        .iter()
        .filter_map(|s| {
            let ov_start = s.start.max(start);
            let ov_end = s.end.min(end);
            if ov_start < ov_end {
                Some((s, ov_start, ov_end))
            } else {
                None
            }
        })
        .collect()
}

/// Walk JPEG markers and return the full list of segments with absolute
/// byte ranges.  Treats the entropy-coded scan data as its own pseudo-segment
/// following the SOS header.
fn parse_jpeg_segments(bytes: &[u8]) -> Result<Vec<JpegSegment>> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        bail!("not a JPEG (missing SOI)");
    }
    let mut out = Vec::new();
    out.push(JpegSegment {
        start: 0,
        end: 2,
        payload_start: 2,
        kind: SegmentKind::Soi,
    });

    let mut i = 2usize;
    while i + 1 < bytes.len() {
        if bytes[i] != 0xFF {
            // Stray data outside a marker -- bail out gracefully.
            break;
        }
        let mut j = i + 1;
        while j < bytes.len() && bytes[j] == 0xFF {
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
        let marker = bytes[j];
        let seg_start = i;

        // Standalone (no length) markers.
        if marker == 0xD9 {
            out.push(JpegSegment {
                start: seg_start,
                end: j + 1,
                payload_start: j + 1,
                kind: SegmentKind::Eoi,
            });
            i = j + 1;
            continue;
        }
        if matches!(marker, 0xD0..=0xD7) || marker == 0x01 {
            out.push(JpegSegment {
                start: seg_start,
                end: j + 1,
                payload_start: j + 1,
                kind: SegmentKind::Standalone(marker),
            });
            i = j + 1;
            continue;
        }

        // Length-prefixed segment.
        if j + 3 > bytes.len() {
            return Err(anyhow!("truncated segment after marker FF{marker:02X}"));
        }
        let seg_len = u16::from_be_bytes([bytes[j + 1], bytes[j + 2]]) as usize;
        let payload_start = j + 3;
        let seg_end = j + 1 + seg_len;
        if seg_end > bytes.len() {
            return Err(anyhow!("segment FF{marker:02X} extends past EOF"));
        }
        let payload = &bytes[payload_start..seg_end];

        let kind = classify(marker, payload);

        let is_sos = matches!(kind, SegmentKind::SosHeader);
        out.push(JpegSegment {
            start: seg_start,
            end: seg_end,
            payload_start,
            kind,
        });

        if is_sos {
            // Entropy-coded data follows the SOS header until the next
            // non-restart marker (or EOF).
            let entropy_start = seg_end;
            let mut k = entropy_start;
            let entropy_end;
            loop {
                if k >= bytes.len() {
                    entropy_end = bytes.len();
                    break;
                }
                if bytes[k] == 0xFF {
                    let mut m = k + 1;
                    while m < bytes.len() && bytes[m] == 0xFF {
                        m += 1;
                    }
                    if m >= bytes.len() {
                        entropy_end = bytes.len();
                        break;
                    }
                    let nm = bytes[m];
                    // 0x00 is byte-stuffing inside entropy data, RSTn are also
                    // embedded; everything else terminates the scan.
                    if nm == 0x00 || matches!(nm, 0xD0..=0xD7) {
                        k = m + 1;
                        continue;
                    }
                    entropy_end = k;
                    break;
                }
                k += 1;
            }
            out.push(JpegSegment {
                start: entropy_start,
                end: entropy_end,
                payload_start: entropy_start,
                kind: SegmentKind::EntropyData,
            });
            i = entropy_end;
            continue;
        }

        i = seg_end;
    }

    Ok(out)
}

fn classify(marker: u8, payload: &[u8]) -> SegmentKind {
    match marker {
        // SOFn (excluding DHT=C4, JPG=C8, DAC=CC)
        0xC0..=0xCF if marker != 0xC4 && marker != 0xC8 && marker != 0xCC => {
            SegmentKind::Sof(marker)
        }
        0xC4 => SegmentKind::Dht,
        0xDB => SegmentKind::Dqt,
        0xDD => SegmentKind::Dri,
        0xDA => SegmentKind::SosHeader,
        0xFE => {
            let text = String::from_utf8_lossy(payload).to_string();
            SegmentKind::Com(text)
        }
        0xE0..=0xEF => classify_app(marker - 0xE0, payload),
        _ => SegmentKind::Other(marker),
    }
}

fn classify_app(n: u8, payload: &[u8]) -> SegmentKind {
    // Identifier is the leading null-terminated ASCII string, when present.
    let id_end = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
    let id = String::from_utf8_lossy(&payload[..id_end]).to_string();

    match (n, id.as_str()) {
        (0, "JFIF") | (0, "JFXX") => SegmentKind::AppJfif,
        (1, _) if id.starts_with("Exif") => SegmentKind::AppExif,
        (1, _) if id.starts_with("http://ns.adobe.com/xap/1.0/") => SegmentKind::AppXmp,
        (2, _) if id.starts_with("ICC_PROFILE") => SegmentKind::AppIcc,
        (2, "MPF") => SegmentKind::AppMpf,
        (11, _) => {
            // APP11 carries JPEG-2000 / JUMBF.  C2PA manifests live in JUMBF
            // boxes whose first four-character type is "jumb" and whose UUID
            // payload contains "c2pa".
            let is_jumbf = find_subslice(payload, b"jumb").is_some();
            let is_c2pa = find_subslice(payload, b"c2pa").is_some()
                || find_subslice(payload, b"c2ma").is_some();
            if is_jumbf && is_c2pa {
                SegmentKind::AppJumbfC2pa
            } else if is_jumbf {
                SegmentKind::AppJumbfOther
            } else {
                SegmentKind::AppOther { n, id }
            }
        }
        (13, _) if id.starts_with("Photoshop") => SegmentKind::AppPhotoshop,
        (14, _) if id.starts_with("Adobe") => SegmentKind::AppAdobe,
        _ => SegmentKind::AppOther { n, id },
    }
}
