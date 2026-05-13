// Strip or replace the RFC 3161 time-stamp on a C2PA-signed JPEG.
//
// The COSE_Sign1 in a C2PA manifest carries the RFC 3161 time-stamp as an
// *unprotected* header (`sigTst` or `sigTst2`). Unprotected headers are not
// covered by the COSE signature, so any holder of the signed asset can
// delete or substitute the time-stamp without invalidating the underlying
// COSE signature.
//
// Modes:
//   drop     -- remove sigTst / sigTst2 from the unprotected header
//   <URL>    -- remove sigTst / sigTst2 and request a fresh RFC 3161 token
//               from the given TSA, install it as sigTst2 (CTT model)
//
// Steps:
//   1. Read the input with full trust verification and confirm it carries a
//      `timeStamp.trusted` success code.
//   2. Reassemble the JUMBF from the JPEG's APP11 segments.
//   3. Locate the `c2pa.signature` super-box -> the raw COSE_Sign1 bytes
//      inside the JUMBF.
//   4. Parse the COSE_Sign1; remove existing time-stamp entries; if a TSA
//      URL was given, request a fresh token over the COSE signature
//      countersignature TBS and insert it as sigTst2.
//   5. Re-pad with the `pad` byte-string so the re-encoded COSE_Sign1 is
//      exactly the original byte length, splice back into the JUMBF, and
//      re-chunk into APP11 segments.
//   6. Re-read the output and report the new time-stamp / signature state.
//
// Usage:
//   cargo run -p c2pa --example strip_timestamp -- \
//        <input.jpg> <output.jpg> drop
//   cargo run -p c2pa --example strip_timestamp -- \
//        <input.jpg> <output.jpg> http://timestamp.digicert.com

use std::io::Cursor;

use anyhow::{anyhow, bail, Context as _, Result};
use byteorder::{BigEndian, ReadBytesExt};
use c2pa::{
    crypto::time_stamp::{default_rfc3161_message, default_rfc3161_request},
    http::SyncGenericResolver,
    settings::Settings,
    validation_status, Context, Reader,
};
use coset::{
    cbor::value::Value, sig_structure_data, CborSerializable, CoseSign1, Label, ProtectedHeader,
    SignatureContext, TaggedCborSerializable,
};
use img_parts::{
    jpeg::{markers, Jpeg, JpegSegment},
    Bytes, DynImage,
};
use jumbf::parser::{ChildBox, SuperBox};
use serde_bytes::ByteBuf;

mod common;
use common::mime_from_path;

const C2PA_MARKER: [u8; 4] = [0x63, 0x32, 0x70, 0x61]; // "c2pa"
const MAX_JPEG_MARKER_SIZE: usize = 64000;
const SIGNATURE_LABEL: &str = "c2pa.signature";
const SIGTST_LABELS: &[&str] = &["sigTst", "sigTst2"];
const PAD: &str = "pad";
const PAD2: &str = "pad2";

#[derive(Clone)]
enum Mode {
    Drop,
    Replace(String),
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        bail!(
            "Usage: strip_timestamp <input.jpg> <output.jpg> <mode>\n  \
             mode = \"drop\" | <TSA URL e.g. http://timestamp.digicert.com>"
        );
    }
    let input_path = &args[1];
    let output_path = &args[2];
    let mode_arg = &args[3];

    let mode = if mode_arg.eq_ignore_ascii_case("drop") {
        Mode::Drop
    } else if mode_arg.starts_with("http://") || mode_arg.starts_with("https://") {
        Mode::Replace(mode_arg.clone())
    } else {
        bail!("mode must be \"drop\" or an http(s) TSA URL, got `{mode_arg}`");
    };

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
    let has_validated = active
        .success()
        .iter()
        .any(|s| s.code() == validation_status::TIMESTAMP_VALIDATED);
    match (&mode, has_trusted) {
        (Mode::Drop, false) => {
            println!(
                "Input does NOT carry a `timeStamp.trusted` success code -- nothing to strip."
            );
            println!("Success codes present:");
            for s in active.success() {
                println!("  - {}", s.code());
            }
            bail!("aborting: time-stamp is not trusted in the source asset");
        }
        (Mode::Drop, true) => println!(
            "Source asset has a trusted RFC 3161 time-stamp in the COSE_Sign1 unprotected header."
        ),
        (Mode::Replace(_), _) => println!(
            "Replace mode: input timestamp trusted={has_trusted} / validated={has_validated} \
             (will be discarded)."
        ),
    }

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

    // 4) Strip / replace the time-stamp and re-encode at the same byte length.
    let new_cose = rewrite_cose_sign1(cose_bytes, &mode)?;
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
/// unprotected header, optionally request a fresh time-stamp and install it
/// as `sigTst2`, and re-encode at exactly the original byte length by
/// resizing the `pad` byte-string in the unprotected header.
fn rewrite_cose_sign1(cose_bytes: &[u8], mode: &Mode) -> Result<Vec<u8>> {
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
    println!("Removed {removed} existing time-stamp entry/entries from unprotected header.");

    match mode {
        Mode::Drop => {
            if removed == 0 {
                bail!("no sigTst/sigTst2 entry to drop");
            }
        }
        Mode::Replace(url) => {
            let token = fetch_fresh_tst_token(&sign1, url)?;
            let container = build_tst_container_value(&token);
            sign1
                .unprotected
                .rest
                .push((Label::Text("sigTst2".to_string()), container));
            println!("Installed fresh sigTst2 entry ({} byte token).", token.len());
        }
    }

    pad_to_size(&mut sign1, target_size, tagged)
}

/// Build the countersignature TBS for the COSE_Sign1's `signature` field
/// (CTT model used by `sigTst2`), POST to the TSA, and return the
/// DER-encoded TimeStampToken (i.e. just the `timeStampToken` field of the
/// `TimeStampResp`, suitable for inserting in a `tstContainer`).
fn fetch_fresh_tst_token(sign1: &CoseSign1, url: &str) -> Result<Vec<u8>> {
    // tbs = Sig_structure(CounterSignature, protected, none, ext_aad=[], CBOR(bstr(sig)))
    let sig_bytes = ByteBuf::from(sign1.signature.clone());
    let mut sig_cbor: Vec<u8> = Vec::new();
    coset::cbor::into_writer(&sig_bytes, &mut sig_cbor)
        .map_err(|e| anyhow!("encoding signature as CBOR bstr: {e:?}"))?;

    let protected: ProtectedHeader = sign1.protected.clone();
    let tbs = sig_structure_data(SignatureContext::CounterSignature, protected, None, &[], &sig_cbor);

    println!("Requesting RFC 3161 time-stamp from {url} ...");
    let req_body = default_rfc3161_message(&tbs)
        .map_err(|e| anyhow!("building TimeStampReq: {e:?}"))?;
    let resolver = SyncGenericResolver::new();
    let ts_resp = default_rfc3161_request(url, None, &req_body, &tbs, &resolver)
        .map_err(|e| anyhow!("TSA request to {url} failed: {e:?}"))?;
    println!("TSA returned a {}-byte response.", ts_resp.len());

    let tst_token = extract_timestamp_token(&ts_resp)?;
    println!("Extracted TimeStampToken: {} bytes.", tst_token.len());
    Ok(tst_token)
}

/// Build the CBOR value for a `tstContainer` carrying a single
/// TimeStampToken, as specified by the C2PA `sigTst2` header.
fn build_tst_container_value(tst_token: &[u8]) -> Value {
    let token_map = Value::Map(vec![(
        Value::Text("val".to_string()),
        Value::Bytes(tst_token.to_vec()),
    )]);
    Value::Map(vec![(
        Value::Text("tstTokens".to_string()),
        Value::Array(vec![token_map]),
    )])
}

/// Extract the `timeStampToken` field (a DER-encoded `ContentInfo`) from a
/// raw RFC 3161 `TimeStampResp` by walking the outer ASN.1 SEQUENCE and
/// skipping past the `PKIStatusInfo`.
fn extract_timestamp_token(resp: &[u8]) -> Result<Vec<u8>> {
    let (tag, len, content_start) = read_der_header(resp, 0)?;
    if tag != 0x30 {
        bail!("TimeStampResp: outer is not a SEQUENCE (tag 0x{tag:02X})");
    }
    let outer_end = content_start
        .checked_add(len)
        .ok_or_else(|| anyhow!("TimeStampResp: outer length overflow"))?;
    if outer_end > resp.len() {
        bail!("TimeStampResp: outer SEQUENCE truncated");
    }

    let (s_tag, s_len, s_content) = read_der_header(resp, content_start)?;
    if s_tag != 0x30 {
        bail!("TimeStampResp: PKIStatusInfo not SEQUENCE (tag 0x{s_tag:02X})");
    }
    let pki_end = s_content
        .checked_add(s_len)
        .ok_or_else(|| anyhow!("TimeStampResp: PKIStatusInfo length overflow"))?;
    if pki_end > outer_end {
        bail!("TimeStampResp: PKIStatusInfo overflows outer SEQUENCE");
    }

    // PKIStatusInfo's first field is PKIStatus INTEGER. 0 = granted,
    // 1 = grantedWithMods; everything else means the TSA refused.
    let (st_tag, st_len, st_content) = read_der_header(resp, s_content)?;
    if st_tag != 0x02 {
        bail!("TimeStampResp: PKIStatus not INTEGER (tag 0x{st_tag:02X})");
    }
    if st_len == 0 || st_len > 4 {
        bail!("TimeStampResp: PKIStatus has unexpected length {st_len}");
    }
    let mut status: u32 = 0;
    for i in 0..st_len {
        status = (status << 8) | resp[st_content + i] as u32;
    }
    if status != 0 && status != 1 {
        bail!("TSA refused: PKIStatus = {status}");
    }

    if pki_end == outer_end {
        bail!("TimeStampResp: no timeStampToken present (status = {status})");
    }
    Ok(resp[pki_end..outer_end].to_vec())
}

/// Read a DER tag-length header at `offset`. Returns `(tag, content_length,
/// content_start_offset)`. Supports definite-length forms only.
fn read_der_header(buf: &[u8], offset: usize) -> Result<(u8, usize, usize)> {
    if offset >= buf.len() {
        bail!("DER: offset {offset} out of range (len {})", buf.len());
    }
    let tag = buf[offset];
    let mut pos = offset + 1;
    if pos >= buf.len() {
        bail!("DER: truncated after tag at {offset}");
    }
    let lb = buf[pos];
    pos += 1;
    let len = if lb & 0x80 == 0 {
        lb as usize
    } else {
        let n = (lb & 0x7f) as usize;
        if n == 0 {
            bail!("DER: indefinite length form not supported");
        }
        if n > 8 {
            bail!("DER: length-of-length too large ({n})");
        }
        if pos + n > buf.len() {
            bail!("DER: truncated length bytes");
        }
        let mut l: usize = 0;
        for i in 0..n {
            l = (l << 8) | buf[pos + i] as usize;
        }
        pos += n;
        l
    };
    Ok((tag, len, pos))
}

/// Re-encode `sign1` at exactly `target_size` bytes by manipulating the
/// `pad` (and optionally `pad2`) byte-strings in the unprotected header.
/// Works both when the new COSE_Sign1 needs to grow (small / removed
/// payloads) and when it needs to shrink relative to the parsed sign1.
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
             the new payload is too big to fit in the original reservation"
        );
    }
    if base == target_size {
        return encode(sign1, tagged);
    }

    // Add a pad entry and iterate until the encoded size matches.
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

    // Crossed a CBOR length boundary -- a single byte of pad changed the
    // encoded size by more than one byte, so we can't land exactly with pad
    // alone. Drop enough pad to leave headroom for a `pad2` entry's CBOR
    // overhead (~6-10 bytes for label + empty byte string), then fine-tune
    // with pad2. Walk pad_len down from the overshoot point until we have a
    // pad-only size at least PAD2_HEADROOM bytes below target.
    const PAD2_HEADROOM: usize = 16;
    sign1
        .unprotected
        .rest
        .push((Label::Text(PAD2.to_string()), Value::Bytes(Vec::new())));
    let pad2_idx = sign1.unprotected.rest.len() - 1;

    // Initial pad_len drop sized to the overshoot plus headroom.
    let drop = (overshoot_size - target_size) + PAD2_HEADROOM;
    pad_len = pad_len.saturating_sub(drop);

    for _ in 0..PAD2_HEADROOM + 8 {
        sign1.unprotected.rest[pad_idx].1 = Value::Bytes(vec![0u8; pad_len]);
        sign1.unprotected.rest[pad2_idx].1 = Value::Bytes(Vec::new());
        let base = encode(sign1, tagged)?.len();
        if base > target_size {
            // pad_len still too large after the drop; reduce further.
            if pad_len == 0 {
                bail!("cannot fit COSE_Sign1 even with empty pads (base {base} > {target_size})");
            }
            pad_len = pad_len.saturating_sub(1);
            continue;
        }
        if base == target_size {
            // The pad2 entry isn't needed; remove it.
            sign1.unprotected.rest.pop();
            return encode(sign1, tagged);
        }

        // base < target -- iterate pad2_len.
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
        // Pad2 couldn't land exactly at this pad_len; shrink pad_len and retry.
        if pad_len == 0 {
            break;
        }
        pad_len -= 1;
    }

    bail!(
        "unable to pad COSE_Sign1 to target {target_size} bytes -- \
         the new payload may be too close to the reservation limit"
    )
}
