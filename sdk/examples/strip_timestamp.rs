// Strip the RFC 3161 time-stamp from a C2PA-signed JPEG.
//
// Scenario:
//   The COSE_Sign1 in a C2PA manifest carries the RFC 3161 time-stamp as an
//   *unprotected* header (`sigTst` or `sigTst2`). Unprotected headers are not
//   covered by the COSE signature, so any holder of the signed asset can
//   delete the time-stamp without invalidating the underlying signature.
//   This script demonstrates the strip:
//
//     1. Read the input with full trust verification (using the test trust
//        list) and confirm the manifest carries a `timeStamp.trusted`
//        success code.
//     2. Reassemble the JUMBF from the JPEG's APP11 segments.
//     3. Locate the `c2pa.signature` super-box → CBOR uuid data-box → the
//        raw COSE_Sign1 bytes inside the JUMBF.
//     4. Remove the `sigTst` / `sigTst2` entry from the COSE_Sign1
//        unprotected header and grow the existing `pad` byte-string so the
//        re-encoded COSE_Sign1 is exactly the original byte length. This
//        keeps every JUMBF box length and JPEG segment length unchanged.
//     5. Splice the modified bytes back into the JUMBF, re-chunk into APP11
//        segments, and write the result.
//     6. Re-read the output and report whether the time-stamp success code
//        is now gone (it should be) and whether the signature itself still
//        validates (it should).
//
// Usage:
//   cargo run --release -p c2pa --example strip_timestamp -- \
//        <input.jpg> <output.jpg>

use std::io::Cursor;

use anyhow::{anyhow, bail, Context as _, Result};
use byteorder::{BigEndian, ReadBytesExt};
use c2pa::{settings::Settings, validation_status, Context, Reader};
use coset::{cbor::value::Value, CborSerializable, CoseSign1, Label, TaggedCborSerializable};
use img_parts::{
    jpeg::{markers, Jpeg, JpegSegment},
    Bytes, DynImage,
};
use jumbf::parser::{ChildBox, SuperBox};

mod common;
use common::mime_from_path;

const C2PA_MARKER: [u8; 4] = [0x63, 0x32, 0x70, 0x61]; // "c2pa"
const MAX_JPEG_MARKER_SIZE: usize = 64000;
const SIGNATURE_LABEL: &str = "c2pa.signature";
const SIGTST_LABELS: &[&str] = &["sigTst", "sigTst2"];
const PAD: &str = "pad";
const PAD2: &str = "pad2";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        bail!("Usage: strip_timestamp <input.jpg> <output.jpg>");
    }
    let input_path = &args[1];
    let output_path = &args[2];

    let format = mime_from_path(input_path)?;
    if format != "image/jpeg" {
        bail!("only image/jpeg is supported by this PoC (got {format})");
    }

    let input_bytes = std::fs::read(input_path)
        .with_context(|| format!("reading {input_path}"))?;

    // 1) Validate the input with the test trust list and confirm the manifest
    //    carries a `timeStamp.trusted` success code. We refuse to strip
    //    anything if the time-stamp wasn't actually trusted to begin with.
    let settings = Settings::new()
        .with_toml(include_str!("../tests/fixtures/test_settings.toml"))?;
    let context = Context::new()
        .with_settings(settings)?
        .into_shared();

    let mut cursor = Cursor::new(&input_bytes);
    let reader = Reader::from_shared_context(&context).with_stream(format, &mut cursor)?;

    let active = reader
        .validation_results()
        .and_then(|r| r.active_manifest())
        .ok_or_else(|| anyhow!("no active manifest in {input_path}"))?;

    let has_trusted = active
        .success()
        .iter()
        .any(|s| s.code() == validation_status::TIMESTAMP_TRUSTED);
    if !has_trusted {
        println!(
            "Input does NOT carry a `timeStamp.trusted` success code -- nothing to strip."
        );
        println!("Success codes present:");
        for s in active.success() {
            println!("  - {}", s.code());
        }
        bail!("aborting: time-stamp is not trusted in the source asset");
    }
    println!(
        "Source asset has a trusted RFC 3161 time-stamp in the COSE_Sign1 unprotected header."
    );

    // 2) Reassemble the JUMBF from APP11 segments.
    let jumbf = reassemble_jumbf_from_jpeg(&input_bytes)?;
    println!("Reassembled JUMBF: {} bytes.", jumbf.len());

    // 3) Find the COSE_Sign1 byte range inside the JUMBF buffer.
    let (cose_start, cose_end) = find_cose_sign1_range(&jumbf)?;
    let cose_bytes = &jumbf[cose_start..cose_end];
    println!(
        "COSE_Sign1 located at JUMBF[{cose_start}..{cose_end}] ({} bytes).",
        cose_bytes.len()
    );

    // 4) Strip the time-stamp and re-encode at the same byte length.
    let new_cose = strip_timestamp_preserve_size(cose_bytes)?;
    if new_cose.len() != cose_bytes.len() {
        bail!(
            "internal: padded COSE_Sign1 size {} != original {}",
            new_cose.len(),
            cose_bytes.len()
        );
    }
    println!(
        "Re-encoded COSE_Sign1 ({} bytes, padded to original length).",
        new_cose.len()
    );

    // Splice the new COSE_Sign1 back into the JUMBF buffer.
    let mut new_jumbf = jumbf.clone();
    new_jumbf[cose_start..cose_end].copy_from_slice(&new_cose);

    // 5) Re-embed the JUMBF in the JPEG.
    let output_bytes = embed_jumbf_in_jpeg(&input_bytes, &new_jumbf)?;
    std::fs::write(output_path, &output_bytes)?;
    println!(
        "Wrote stripped duplicate to {output_path} ({} bytes).",
        output_bytes.len()
    );

    // 6) Validate the output and report the new state.
    let mut out_cursor = Cursor::new(&output_bytes);
    let out_reader =
        Reader::from_shared_context(&context).with_stream(format, &mut out_cursor)?;
    println!("\n=== Validation of stripped asset ===");
    println!("  state = {:?}", out_reader.validation_state());
    if let Some(am) = out_reader
        .validation_results()
        .and_then(|r| r.active_manifest())
    {
        let still_trusted = am
            .success()
            .iter()
            .any(|s| s.code() == validation_status::TIMESTAMP_TRUSTED);
        let validated = am
            .success()
            .iter()
            .any(|s| s.code() == validation_status::TIMESTAMP_VALIDATED);
        println!("  timeStamp.trusted   present: {still_trusted}");
        println!("  timeStamp.validated present: {validated}");
        if !am.failure().is_empty() {
            println!("  failures:");
            for s in am.failure() {
                println!("    - {}", s.code());
            }
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// JPEG <-> JUMBF
// -----------------------------------------------------------------------------

/// Reassemble the C2PA JUMBF block by concatenating its APP11 segments.
///
/// Mirrors what `c2pa::asset_handlers::jpeg_io::JpegIO::read_cai` does
/// internally: the first segment contributes everything after the 8-byte
/// CI/En/Z prefix, and continuation segments contribute everything after the
/// 16-byte CI/En/Z/LBox/TBox prefix.
fn reassemble_jumbf_from_jpeg(jpeg_bytes: &[u8]) -> Result<Vec<u8>> {
    let dimg = DynImage::from_bytes(Bytes::copy_from_slice(jpeg_bytes))
        .map_err(|e| anyhow!("could not parse JPEG: {e:?}"))?
        .ok_or_else(|| anyhow!("not a JPEG"))?;

    let jpeg = match dimg {
        DynImage::Jpeg(j) => j,
        _ => bail!("only JPEG supported"),
    };

    let mut buffer: Vec<u8> = Vec::new();
    let mut cai_en: Vec<u8> = Vec::new();
    let mut cai_seg_cnt: u32 = 0;

    for segment in jpeg.segments_by_marker(markers::APP11) {
        let raw = segment.contents();
        if raw.len() <= 16 {
            continue;
        }
        let en = raw[2..4].to_vec();
        let mut z_cursor = Cursor::new(&raw[4..8]);
        let z = z_cursor.read_u32::<BigEndian>()?;

        let continuation = !cai_en.is_empty() && cai_en == en;

        if cai_seg_cnt > 0 && continuation {
            if z <= cai_seg_cnt {
                // non-contiguous reuse of the same identifier -- ignore.
                cai_en.clear();
                continue;
            }
            buffer.extend_from_slice(&raw[16..]);
            cai_seg_cnt += 1;
        } else if raw.len() > 28 {
            let jumb_type = &raw[24..28];
            if jumb_type == C2PA_MARKER {
                buffer.extend_from_slice(&raw[8..]);
                cai_seg_cnt = 1;
                cai_en.clone_from(&en);
            }
        }
    }

    if buffer.is_empty() {
        bail!("no C2PA JUMBF found in JPEG APP11 segments");
    }
    Ok(buffer)
}

/// Re-embed `new_jumbf` in `jpeg_bytes`, removing all existing CAI APP11
/// segments and inserting freshly chunked ones at the same logical position.
fn embed_jumbf_in_jpeg(jpeg_bytes: &[u8], new_jumbf: &[u8]) -> Result<Vec<u8>> {
    let mut jpeg = Jpeg::from_bytes(Bytes::copy_from_slice(jpeg_bytes))
        .map_err(|e| anyhow!("could not parse JPEG for write: {e:?}"))?;

    let insertion_point = delete_cai_segments(&mut jpeg)?
        .map(|i| if i > 0 { i - 1 } else { 0 })
        .unwrap_or(0);

    let jumbf_len = new_jumbf.len();
    let num_segments = (jumbf_len / MAX_JPEG_MARKER_SIZE) + 1;
    let mut chunks = new_jumbf.chunks(MAX_JPEG_MARKER_SIZE);

    for seg in 1..num_segments + 1 {
        // ISO 19566-5: every APP11 segment carries CI/En/Z/LBox/TBox (after the
        // first, LBox/TBox are duplicated from the JUMBF root box).
        let ci = vec![0x4a, 0x50]; // "JP"
        let en = vec![0x02, 0x11];
        let z = u32::try_from(seg).map_err(|_| anyhow!("too many JUMBF segments"))?;

        let mut seg_data: Vec<u8> = Vec::new();
        seg_data.extend(ci);
        seg_data.extend(en);
        seg_data.extend(z.to_be_bytes());
        if seg > 1 {
            // Duplicate the JUMBF root LBox/TBox in continuation segments.
            let lbox_tbox = new_jumbf
                .get(0..8)
                .ok_or_else(|| anyhow!("JUMBF too small to read LBox/TBox"))?;
            seg_data.extend(lbox_tbox);
        }
        if let Some(next) = chunks.next() {
            seg_data.extend(next);
        }

        let app11 = JpegSegment::new_with_contents(markers::APP11, Bytes::from(seg_data));
        let insert_at = seg + insertion_point;
        if insert_at > jpeg.segments().len() {
            bail!("JPEG JUMBF segment insertion overflow");
        }
        jpeg.segments_mut().insert(insert_at, app11);
    }

    let mut out: Vec<u8> = Vec::new();
    jpeg.encoder()
        .write_to(&mut out)
        .map_err(|e| anyhow!("writing JPEG: {e:?}"))?;
    Ok(out)
}

/// Remove every C2PA APP11 segment and return the index of the first one
/// (where new segments should be inserted to preserve ordering).
fn delete_cai_segments(jpeg: &mut Jpeg) -> Result<Option<usize>> {
    let cai_segs = find_cai_segments(jpeg)?;
    let insertion_point = cai_segs.first().copied();
    for idx in cai_segs.iter().rev() {
        jpeg.segments_mut().remove(*idx);
    }
    Ok(insertion_point)
}

fn find_cai_segments(jpeg: &Jpeg) -> Result<Vec<usize>> {
    let mut out = Vec::new();
    let mut cai_en: Vec<u8> = Vec::new();
    let mut cai_seg_cnt: u32 = 0;

    for (i, segment) in jpeg.segments().iter().enumerate() {
        if segment.marker() != markers::APP11 {
            continue;
        }
        let raw = segment.contents();
        if raw.len() <= 16 {
            continue;
        }
        let en = raw[2..4].to_vec();
        let continuation = !cai_en.is_empty() && cai_en == en;
        if cai_seg_cnt > 0 && continuation {
            cai_seg_cnt += 1;
            out.push(i);
        } else if raw.len() > 28 {
            let jumb_type = &raw[24..28];
            if jumb_type == C2PA_MARKER {
                out.push(i);
                cai_seg_cnt = 1;
                cai_en.clone_from(&en);
            }
        }
    }
    Ok(out)
}

// -----------------------------------------------------------------------------
// JUMBF -> COSE_Sign1 byte range
// -----------------------------------------------------------------------------

/// Locate the COSE_Sign1 byte range inside the assembled JUMBF buffer.
///
/// Walks: root super box -> manifest super box -> `c2pa.signature` super box
/// -> its first child data box (`uuid` content box). The data box payload is
/// `[16-byte UUID][COSE_Sign1 CBOR]`, so the COSE_Sign1 starts 16 bytes into
/// the payload.
fn find_cose_sign1_range(jumbf: &[u8]) -> Result<(usize, usize)> {
    let (root, _) =
        SuperBox::from_slice(jumbf).map_err(|e| anyhow!("parsing JUMBF: {e:?}"))?;

    // The root super box's children are manifest super boxes. We expect a
    // single active manifest containing a `c2pa.signature` sub-super-box.
    let sig_super = find_descendant_with_label(&root, SIGNATURE_LABEL)
        .ok_or_else(|| anyhow!("`{SIGNATURE_LABEL}` super box not found in JUMBF"))?;

    let sig_data = sig_super
        .child_boxes
        .iter()
        .find_map(|c| match c {
            ChildBox::DataBox(db) => Some(db),
            _ => None,
        })
        .ok_or_else(|| anyhow!("`{SIGNATURE_LABEL}` has no data box"))?;

    // The signature super-box's child can be either a `cbor` content box
    // (payload is the COSE_Sign1 bytes directly) or a legacy `uuid` content
    // box (payload is a 16-byte UUID followed by the COSE_Sign1 bytes).
    let cose_payload = match &sig_data.tbox.0 {
        b"cbor" => &sig_data.data[..],
        b"uuid" => {
            if sig_data.data.len() < 17 {
                bail!("signature `uuid` box too small to hold UUID + COSE_Sign1");
            }
            &sig_data.data[16..]
        }
        other => bail!(
            "expected `cbor` or `uuid` data box in {SIGNATURE_LABEL}, got `{}`",
            std::str::from_utf8(other).unwrap_or("?")
        ),
    };
    let start = offset_in(jumbf, cose_payload)?;
    let end = start + cose_payload.len();
    Ok((start, end))
}

fn find_descendant_with_label<'a>(root: &'a SuperBox<'a>, label: &str) -> Option<&'a SuperBox<'a>> {
    if root.desc.label == Some(label) {
        return Some(root);
    }
    for child in &root.child_boxes {
        if let ChildBox::SuperBox(sbox) = child {
            if let Some(found) = find_descendant_with_label(sbox, label) {
                return Some(found);
            }
        }
    }
    None
}

fn offset_in(parent: &[u8], child: &[u8]) -> Result<usize> {
    let parent_start = parent.as_ptr() as usize;
    let parent_end = parent_start + parent.len();
    let child_start = child.as_ptr() as usize;
    if child_start < parent_start || child_start + child.len() > parent_end {
        bail!("child slice is not inside parent buffer");
    }
    Ok(child_start - parent_start)
}

// -----------------------------------------------------------------------------
// COSE_Sign1 manipulation
// -----------------------------------------------------------------------------

/// Parse the COSE_Sign1, drop any `sigTst` / `sigTst2` entry from the
/// unprotected header, and re-encode at exactly the original byte length by
/// growing the existing `pad` byte-string (adding a `pad2` byte-string if a
/// single pad cannot land on the target size, exactly like `pad_cose_sig`
/// inside the SDK).
fn strip_timestamp_preserve_size(cose_bytes: &[u8]) -> Result<Vec<u8>> {
    let target_size = cose_bytes.len();
    let tagged = !cose_bytes.is_empty() && cose_bytes[0] == 0xD2;

    let mut sign1 = if tagged {
        CoseSign1::from_tagged_slice(cose_bytes)
            .map_err(|e| anyhow!("parsing tagged COSE_Sign1: {e:?}"))?
    } else {
        CoseSign1::from_slice(cose_bytes).map_err(|e| anyhow!("parsing COSE_Sign1: {e:?}"))?
    };

    let before = sign1.unprotected.rest.len();
    sign1.unprotected.rest.retain(|(label, _)| match label {
        Label::Text(s) => !SIGTST_LABELS.contains(&s.as_str()),
        _ => true,
    });
    let removed = before - sign1.unprotected.rest.len();
    if removed == 0 {
        bail!("no sigTst/sigTst2 entry in COSE_Sign1 unprotected header (nothing to strip)");
    }
    println!("Removed {removed} time-stamp entry from COSE_Sign1 unprotected header.");

    pad_to_size(&mut sign1, target_size, tagged)
}

/// Re-encode `sign1` at exactly `target_size` bytes by manipulating the
/// `pad` (and optionally `pad2`) byte-strings in the unprotected header.
fn pad_to_size(sign1: &mut CoseSign1, target_size: usize, tagged: bool) -> Result<Vec<u8>> {
    fn encode(s: &CoseSign1, tagged: bool) -> Result<Vec<u8>> {
        let s = s.clone();
        if tagged {
            s.to_tagged_vec()
                .map_err(|e| anyhow!("encoding tagged COSE_Sign1: {e:?}"))
        } else {
            s.to_vec()
                .map_err(|e| anyhow!("encoding COSE_Sign1: {e:?}"))
        }
    }

    fn pad_idx_or_create(sign1: &mut CoseSign1, name: &str) -> usize {
        if let Some(i) = sign1
            .unprotected
            .rest
            .iter()
            .position(|(l, _)| matches!(l, Label::Text(s) if s == name))
        {
            return i;
        }
        sign1
            .unprotected
            .rest
            .push((Label::Text(name.to_string()), Value::Bytes(Vec::new())));
        sign1.unprotected.rest.len() - 1
    }

    fn set_pad(sign1: &mut CoseSign1, idx: usize, len: usize) {
        sign1.unprotected.rest[idx].1 = Value::Bytes(vec![0u8; len]);
    }

    let pad_idx = pad_idx_or_create(sign1, PAD);

    let mut current = encode(sign1, tagged)?.len();
    if current > target_size {
        // No pad to give back -- the COSE_Sign1 is already larger than the
        // target with an empty pad. We could try to shrink an existing pad,
        // but pad_idx_or_create just set it to empty (or used what was
        // there). Shrinking below zero is impossible; bail.
        bail!(
            "COSE_Sign1 already exceeds target size ({current} > {target_size}) with empty pad"
        );
    }

    // First-pass: drive `pad` toward target.
    let mut pad_len: usize = 0;
    let mut overshoot = false;
    for _ in 0..64 {
        let deficit = target_size - current;
        pad_len += deficit;
        set_pad(sign1, pad_idx, pad_len);
        let new_size = encode(sign1, tagged)?.len();
        if new_size == target_size {
            return encode(sign1, tagged);
        }
        if new_size > target_size {
            overshoot = true;
            break;
        }
        current = new_size;
    }

    if !overshoot {
        bail!("padding loop did not converge for target {target_size}");
    }

    // Overshoot happened because growing the pad crossed a CBOR length
    // threshold (e.g. 24 -> 2-byte header, 256 -> 3-byte header) and added
    // an extra byte to the encoding. Drop back one byte of pad and add a
    // `pad2` entry to absorb the residual.
    pad_len = pad_len.saturating_sub(1);
    set_pad(sign1, pad_idx, pad_len);
    let mut after_pad = encode(sign1, tagged)?.len();
    if after_pad == target_size {
        return encode(sign1, tagged);
    }
    if after_pad > target_size {
        bail!(
            "could not back pad below target ({after_pad} > {target_size}) -- \
             unusual COSE_Sign1 layout"
        );
    }

    let pad2_idx = pad_idx_or_create(sign1, PAD2);
    let mut pad2_len: usize = 0;
    for _ in 0..64 {
        let deficit = target_size - after_pad;
        pad2_len += deficit;
        set_pad(sign1, pad2_idx, pad2_len);
        let new_size = encode(sign1, tagged)?.len();
        if new_size == target_size {
            return encode(sign1, tagged);
        }
        if new_size > target_size {
            pad2_len = pad2_len.saturating_sub(1);
            set_pad(sign1, pad2_idx, pad2_len);
            let final_size = encode(sign1, tagged)?.len();
            if final_size == target_size {
                return encode(sign1, tagged);
            }
            bail!(
                "unable to land on target {target_size} (got {final_size} after pad2 tuning)"
            );
        }
        after_pad = new_size;
    }
    bail!("pad2 tuning did not converge")
}
