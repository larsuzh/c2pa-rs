// Strip the stapled OCSP response from a C2PA-signed JPEG.
//
// The COSE_Sign1 in a C2PA manifest carries stapled revocation data as an
// `rVals` entry in its *unprotected* header (RFC 9360 / C2PA §15.9.1). The
// useful contents are an `ocspVals` array of DER-encoded OCSPResponse
// blobs.
//
// What this script does:
//   * Verifies the input parses, has a stapled OCSP response in `rVals`.
//   * Reassembles the JUMBF from the JPEG's APP11 segments.
//   * Locates the `c2pa.signature` super-box -> raw COSE_Sign1 bytes.
//   * Parses the COSE_Sign1; removes `ocspVals` from the `rVals` map, and
//     drops `rVals` entirely if it becomes empty.
//   * Re-pads with the `pad` byte-string so the re-encoded COSE_Sign1 is
//     exactly the original byte length, splices it back into the JUMBF,
//     and re-chunks into APP11 segments.
//   * Re-validates the output and reports the new revocation state.
//
// Usage:
//   cargo run -p c2pa --example strip_ocsp -- <input.jpg> <output.jpg>

use std::io::Cursor;

use anyhow::{anyhow, bail, Context as _, Result};
use byteorder::{BigEndian, ReadBytesExt};
use c2pa::{settings::Settings, Context, Reader};
use coset::{
    cbor::value::Value, CborSerializable, CoseSign1, Label, TaggedCborSerializable,
};
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
const RVALS_LABEL: &str = "rVals";
const OCSPVALS_KEY: &str = "ocspVals";
const PAD: &str = "pad";
const PAD2: &str = "pad2";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        bail!("Usage: strip_ocsp <input.jpg> <output.jpg>");
    }
    let input_path = &args[1];
    let output_path = &args[2];

    let format = mime_from_path(input_path)?;
    if format != "image/jpeg" {
        bail!("only image/jpeg is supported by this PoC (got {format})");
    }

    let input_bytes = std::fs::read(input_path)
        .with_context(|| format!("reading {input_path}"))?;

    // 1) Validate the input under the test trust list so we can report the
    //    revocation state before/after meaningfully.
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

    println!("Input validation summary:");
    println!("  state = {:?}", reader.validation_state());
    let in_not_revoked = active.success().iter().any(|s| {
        let c = s.code();
        c == "signingCredential.ocsp.notRevoked"
    });
    let in_no_info = active.informational().iter().any(|s| {
        let c = s.code();
        c == "signingCredential.ocsp.noCheck" || c == "signingCredential.ocsp.skipped"
    });
    println!("  signingCredential.ocsp.notRevoked success: {in_not_revoked}");
    println!("  any 'no OCSP info' informational entry:   {in_no_info}");

    // 2) Reassemble JUMBF.
    let jumbf = reassemble_jumbf_from_jpeg(&input_bytes)?;
    println!("Reassembled JUMBF: {} bytes.", jumbf.len());

    // 3) Find COSE_Sign1.
    let (cose_start, cose_end) = find_cose_sign1_range(&jumbf)?;
    let cose_bytes = &jumbf[cose_start..cose_end];
    println!(
        "COSE_Sign1 located at JUMBF[{cose_start}..{cose_end}] ({} bytes).",
        cose_bytes.len()
    );

    // 4) Strip ocspVals.
    let new_cose = rewrite_cose_sign1(cose_bytes)?;
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

    // Splice back into the JUMBF buffer.
    let mut new_jumbf = jumbf.clone();
    new_jumbf[cose_start..cose_end].copy_from_slice(&new_cose);

    // 5) Re-embed.
    let output_bytes = embed_jumbf_in_jpeg(&input_bytes, &new_jumbf)?;
    std::fs::write(output_path, &output_bytes)?;
    println!(
        "Wrote stripped duplicate to {output_path} ({} bytes).",
        output_bytes.len()
    );

    // 6) Validate output and report.
    let mut out_cursor = Cursor::new(&output_bytes);
    let out_reader =
        Reader::from_shared_context(&context).with_stream(format, &mut out_cursor)?;
    println!("\n=== Validation of stripped asset ===");
    println!("  state = {:?}", out_reader.validation_state());
    if let Some(am) = out_reader
        .validation_results()
        .and_then(|r| r.active_manifest())
    {
        let still_not_revoked = am
            .success()
            .iter()
            .any(|s| s.code() == "signingCredential.ocsp.notRevoked");
        println!("  signingCredential.ocsp.notRevoked success: {still_not_revoked}");
        if !am.informational().is_empty() {
            println!("  informational codes:");
            for s in am.informational() {
                println!("    - {}", s.code());
            }
        }
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
// COSE_Sign1 rewrite -- the only step that differs from strip_timestamp.rs
// -----------------------------------------------------------------------------

/// Parse the COSE_Sign1, drop `ocspVals` from the `rVals` map in the
/// unprotected header (and `rVals` itself if it ends up empty), then
/// serialise the modified structure back to CBOR.
fn rewrite_cose_sign1(cose_bytes: &[u8]) -> Result<Vec<u8>> {
    let target_size = cose_bytes.len();
    let tagged = !cose_bytes.is_empty() && cose_bytes[0] == 0xD2;

    let mut sign1 = if tagged {
        CoseSign1::from_tagged_slice(cose_bytes)
            .map_err(|e| anyhow!("parsing tagged COSE_Sign1: {e:?}"))?
    } else {
        CoseSign1::from_slice(cose_bytes).map_err(|e| anyhow!("parsing COSE_Sign1: {e:?}"))?
    };

    let rvals_idx = sign1
        .unprotected
        .rest
        .iter()
        .position(|(l, _)| matches!(l, Label::Text(s) if s == RVALS_LABEL));
    let Some(rvals_idx) = rvals_idx else {
        bail!("no `rVals` entry in unprotected header -- nothing to strip");
    };

    let Value::Map(ref mut rvals_map) = sign1.unprotected.rest[rvals_idx].1 else {
        bail!("`rVals` is present but not a CBOR map");
    };

    let before = rvals_map.len();
    rvals_map.retain(|(k, _)| !matches!(k, Value::Text(s) if s == OCSPVALS_KEY));
    let removed = before - rvals_map.len();
    if removed == 0 {
        bail!("`rVals` has no `ocspVals` entry -- nothing to strip");
    }
    println!("Removed `ocspVals` from `rVals` ({removed} entry removed).");

    // If rVals is now empty, drop the whole entry. A map with no remaining
    // revocation data is just noise the validator has to walk.
    if rvals_map.is_empty() {
        sign1.unprotected.rest.remove(rvals_idx);
        println!("`rVals` was empty after the removal; dropped the entire `rVals` entry too.");
    }

    pad_to_size(&mut sign1, target_size, tagged)
}

/// Re-encode `sign1` at exactly `target_size` bytes by manipulating the
/// `pad` (and optionally `pad2`) byte-strings in the unprotected header.
/// Same approach as `strip_timestamp::pad_to_size`.
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

    // Start clean: drop any existing pad / pad2 entries.
    sign1.unprotected.rest.retain(|(l, _)| match l {
        Label::Text(s) => s != PAD && s != PAD2,
        _ => true,
    });

    let base = encode(sign1, tagged)?.len();
    if base > target_size {
        bail!(
            "COSE_Sign1 base size {base} exceeds target {target_size} -- \
             the stripped payload is somehow larger than the original"
        );
    }
    if base == target_size {
        return encode(sign1, tagged);
    }

    sign1
        .unprotected
        .rest
        .push((Label::Text(PAD.to_string()), Value::Bytes(Vec::new())));
    let pad_idx = sign1.unprotected.rest.len() - 1;

    let mut pad_len: usize = 0;
    let mut overshoot_size: Option<usize> = None;
    for _ in 0..256 {
        sign1.unprotected.rest[pad_idx].1 = Value::Bytes(vec![0u8; pad_len]);
        let size = encode(sign1, tagged)?.len();
        if size == target_size {
            return encode(sign1, tagged);
        }
        if size > target_size {
            overshoot_size = Some(size);
            break;
        }
        pad_len += target_size - size;
    }

    let overshoot_size = match overshoot_size {
        Some(s) => s,
        None => bail!("padding loop did not converge for target {target_size}"),
    };

    // Crossed a CBOR length boundary -- add a pad2 to fine-tune.
    const PAD2_HEADROOM: usize = 16;
    sign1
        .unprotected
        .rest
        .push((Label::Text(PAD2.to_string()), Value::Bytes(Vec::new())));
    let pad2_idx = sign1.unprotected.rest.len() - 1;

    let drop = (overshoot_size - target_size) + PAD2_HEADROOM;
    pad_len = pad_len.saturating_sub(drop);

    for _ in 0..PAD2_HEADROOM + 8 {
        sign1.unprotected.rest[pad_idx].1 = Value::Bytes(vec![0u8; pad_len]);
        sign1.unprotected.rest[pad2_idx].1 = Value::Bytes(Vec::new());
        let base = encode(sign1, tagged)?.len();
        if base > target_size {
            if pad_len == 0 {
                bail!("cannot fit COSE_Sign1 even with empty pads (base {base} > {target_size})");
            }
            pad_len = pad_len.saturating_sub(1);
            continue;
        }
        if base == target_size {
            sign1.unprotected.rest.pop();
            return encode(sign1, tagged);
        }

        let mut pad2_len: usize = 0;
        for _ in 0..256 {
            sign1.unprotected.rest[pad2_idx].1 = Value::Bytes(vec![0u8; pad2_len]);
            let size = encode(sign1, tagged)?.len();
            if size == target_size {
                return encode(sign1, tagged);
            }
            if size > target_size {
                break;
            }
            pad2_len += target_size - size;
        }
        if pad_len == 0 {
            break;
        }
        pad_len -= 1;
    }

    bail!(
        "unable to pad COSE_Sign1 to target {target_size} bytes -- \
         the stripped payload may be too close to the reservation limit"
    )
}

// -----------------------------------------------------------------------------
// JPEG <-> JUMBF -- byte-for-byte the same plumbing as `strip_timestamp.rs`
// -----------------------------------------------------------------------------

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
        let ci = vec![0x4a, 0x50]; // "JP"
        let en = vec![0x02, 0x11];
        let z = u32::try_from(seg).map_err(|_| anyhow!("too many JUMBF segments"))?;

        let mut seg_data: Vec<u8> = Vec::new();
        seg_data.extend(ci);
        seg_data.extend(en);
        seg_data.extend(z.to_be_bytes());
        if seg > 1 {
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
// JUMBF -> COSE_Sign1 byte range -- same as `strip_timestamp.rs`
// -----------------------------------------------------------------------------

fn find_cose_sign1_range(jumbf: &[u8]) -> Result<(usize, usize)> {
    let (root, _) =
        SuperBox::from_slice(jumbf).map_err(|e| anyhow!("parsing JUMBF: {e:?}"))?;

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
