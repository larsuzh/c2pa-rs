// Walk every JPEG under `sdk/examples/assets`, reach into the COSE_Sign1's
// unprotected header, and report what (if anything) the signer "stapled" in
// the `rVals` map -- i.e. the OCSP responses that the C2PA spec allows a
// claim generator to embed.
//
// For each signed asset we:
//   * reassemble the JUMBF from the JPEG APP11 segments,
//   * walk down to the `c2pa.signature` super-box and pull out the
//     COSE_Sign1 bytes,
//   * parse the COSE_Sign1 with `coset` and list every label in the
//     unprotected header (so you can see at a glance whether a time-stamp,
//     pad, x5chain, etc. are there alongside any rVals),
//   * if `rVals` is present, decode each `ocspVals[i]` as an RFC 6960
//     OCSPResponse and print the fields a validator actually keys on:
//     responseStatus, producedAt, every SingleResponse's certId serial,
//     certStatus (good / revoked + reason / unknown), thisUpdate,
//     nextUpdate, and how many responder certs were embedded.
//
// Usage:
//   cargo run --release -p c2pa --example analyze_ocsp_stapling
//   cargo run --release -p c2pa --example analyze_ocsp_stapling -- <dir>

use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Result};
use byteorder::{BigEndian, ReadBytesExt};
use c2pa::Reader;
use coset::{cbor::value::Value, CborSerializable, CoseSign1, Label, TaggedCborSerializable};
use img_parts::{jpeg::markers, Bytes, DynImage};
use jumbf::parser::{ChildBox, SuperBox};
use rasn_ocsp::{BasicOcspResponse, CertStatus, OcspResponseStatus};
use rasn_pkix::CrlReason;

mod common;
use common::mime_from_path;

const DEFAULT_DIR: &str = "sdk/examples/assets";
const C2PA_MARKER: [u8; 4] = [0x63, 0x32, 0x70, 0x61]; // "c2pa"
const SIGNATURE_LABEL: &str = "c2pa.signature";

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

    let mut total_jpeg = 0usize;
    let mut signed = 0usize;
    let mut with_rvals = 0usize;
    let mut with_stapled_ocsp = 0usize;

    for path in entries {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let Ok(mime) = mime_from_path(name) else {
            continue;
        };
        // Keep JPEG-only -- other containers carry the JUMBF differently
        // (PNG iTXt/eXIf, BMFF box, etc.) and we'd need a per-container
        // reassembler. The same `rVals` analysis would apply to the
        // COSE_Sign1 inside.
        if mime != "image/jpeg" {
            continue;
        }
        total_jpeg += 1;

        match analyze(&path) {
            Ok(AnalyzeOutcome::Unsigned) => {}
            Ok(AnalyzeOutcome::Signed { has_rvals, has_ocsp }) => {
                signed += 1;
                if has_rvals {
                    with_rvals += 1;
                }
                if has_ocsp {
                    with_stapled_ocsp += 1;
                }
            }
            Err(e) => {
                println!("\n=== {} ===", path.display());
                println!("  error: {e:#}");
            }
        }
    }

    println!(
        "\n----\nScanned {total_jpeg} JPEG file(s); {signed} carry a C2PA manifest; \
         {with_rvals} have an `rVals` entry in the COSE_Sign1 unprotected header; \
         {with_stapled_ocsp} actually staple at least one OCSP response."
    );
    Ok(())
}

enum AnalyzeOutcome {
    Unsigned,
    Signed { has_rvals: bool, has_ocsp: bool },
}

fn analyze(path: &Path) -> Result<AnalyzeOutcome> {
    let bytes = fs::read(path)?;

    // Skip cleanly if the file isn't C2PA-signed -- the assets directory
    // intentionally mixes signed and unsigned originals.
    let mut cursor = Cursor::new(&bytes);
    if Reader::from_stream("image/jpeg", &mut cursor).is_err() {
        return Ok(AnalyzeOutcome::Unsigned);
    }

    println!("\n=== {} ===", path.display());

    let jumbf = reassemble_jumbf_from_jpeg(&bytes)?;
    let (cose_start, cose_end) = find_cose_sign1_range(&jumbf)?;
    let cose_bytes = &jumbf[cose_start..cose_end];
    let sign1 = parse_cose_sign1(cose_bytes)?;
    println!(
        "  COSE_Sign1 size: {} bytes ({} unprotected header entries)",
        cose_bytes.len(),
        sign1.unprotected.rest.len()
    );

    // List every label in the unprotected header so the rVals presence/absence
    // can be read in context. Time-stamp + rVals + pad is the typical mix.
    if !sign1.unprotected.rest.is_empty() {
        println!("  unprotected header labels:");
        for (label, val) in &sign1.unprotected.rest {
            let name = match label {
                Label::Text(s) => s.clone(),
                Label::Int(i) => format!("int({i})"),
            };
            println!("    - {name}  ({})", short_cbor_kind(val));
        }
    }

    let rvals = sign1.unprotected.rest.iter().find_map(|(l, v)| match l {
        Label::Text(s) if s == "rVals" => Some(v),
        _ => None,
    });
    let Some(rvals) = rvals else {
        println!("  no `rVals` entry -- no stapled revocation data in this asset.");
        return Ok(AnalyzeOutcome::Signed {
            has_rvals: false,
            has_ocsp: false,
        });
    };

    let Value::Map(rvals_map) = rvals else {
        println!("  `rVals` is present but not a CBOR map (got {}).", short_cbor_kind(rvals));
        return Ok(AnalyzeOutcome::Signed {
            has_rvals: true,
            has_ocsp: false,
        });
    };

    println!("  `rVals` keys:");
    for (k, v) in rvals_map {
        let key = match k {
            Value::Text(s) => s.clone(),
            other => format!("{other:?}"),
        };
        println!("    - {key}  ({})", short_cbor_kind(v));
    }

    let ocsp_vals = rvals_map.iter().find_map(|(k, v)| match k {
        Value::Text(s) if s == "ocspVals" => v.as_array(),
        _ => None,
    });
    let Some(ocsp_vals) = ocsp_vals else {
        println!("  `rVals` has no `ocspVals` array -- nothing stapled.");
        return Ok(AnalyzeOutcome::Signed {
            has_rvals: true,
            has_ocsp: false,
        });
    };

    if ocsp_vals.is_empty() {
        println!("  `ocspVals` is an empty array.");
        return Ok(AnalyzeOutcome::Signed {
            has_rvals: true,
            has_ocsp: false,
        });
    }

    println!("  stapled OCSP responses: {}", ocsp_vals.len());
    for (i, entry) in ocsp_vals.iter().enumerate() {
        let Some(der) = entry.as_bytes() else {
            println!("    response #{}: not a CBOR byte string ({})", i + 1, short_cbor_kind(entry));
            continue;
        };
        println!("\n    --- OCSP response #{} ({} bytes DER) ---", i + 1, der.len());
        if let Err(e) = describe_ocsp(der) {
            println!("      decode error: {e:#}");
        }
    }

    Ok(AnalyzeOutcome::Signed {
        has_rvals: true,
        has_ocsp: true,
    })
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

fn short_cbor_kind(v: &Value) -> &'static str {
    match v {
        Value::Integer(_) => "integer",
        Value::Bytes(_) => "byte string",
        Value::Text(_) => "text string",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tagged",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        Value::Float(_) => "float",
        _ => "other",
    }
}

// -----------------------------------------------------------------------------
// OCSP response decoding
// -----------------------------------------------------------------------------

fn describe_ocsp(der: &[u8]) -> Result<()> {
    let resp: rasn_ocsp::OcspResponse =
        rasn::der::decode(der).map_err(|e| anyhow!("decoding OcspResponse: {e}"))?;

    println!("      responseStatus: {}", status_str(&resp.status));
    if resp.status != OcspResponseStatus::Successful {
        // RFC 6960: if the status is not Successful the responseBytes field
        // is absent and there's nothing more to decode.
        return Ok(());
    }

    let Some(response_bytes) = resp.bytes else {
        println!("      responseStatus is Successful but `responseBytes` is absent.");
        return Ok(());
    };
    println!("      responseBytes.responseType OID: {}", response_bytes.r#type);

    let basic: BasicOcspResponse = rasn::der::decode(&response_bytes.response)
        .map_err(|e| anyhow!("decoding BasicOcspResponse: {e}"))?;
    let tbs = &basic.tbs_response_data;

    println!("      producedAt:     {}", tbs.produced_at);
    println!("      responderId:    {}", responder_id_str(&tbs.responder_id));
    println!("      signatureAlg:   {}", basic.signature_algorithm.algorithm);
    match &basic.certs {
        Some(certs) => println!("      responder certs embedded: {}", certs.len()),
        None => println!("      responder certs embedded: 0 (none -- responder unverifiable from staple alone)"),
    }

    println!("      singleResponses: {}", tbs.responses.len());
    for (i, sr) in tbs.responses.iter().enumerate() {
        println!(
            "        [{}] certId.serial = {}  hashAlg = {}",
            i, sr.cert_id.serial_number, sr.cert_id.hash_algorithm.algorithm
        );
        match &sr.cert_status {
            CertStatus::Good => println!("            certStatus = good"),
            CertStatus::Revoked(info) => {
                let reason = info
                    .revocation_reason
                    .as_ref()
                    .map(crl_reason_str)
                    .unwrap_or_else(|| "unspecified".to_string());
                println!(
                    "            certStatus = REVOKED at {} (reason: {reason})",
                    info.revocation_time
                );
            }
            CertStatus::Unknown(_) => println!("            certStatus = unknown"),
        }
        println!("            thisUpdate = {}", sr.this_update);
        match &sr.next_update {
            Some(nu) => println!("            nextUpdate = {nu}"),
            None => println!("            nextUpdate = (absent -- validator uses producedAt + 24h)"),
        }
    }

    Ok(())
}

fn status_str(s: &OcspResponseStatus) -> &'static str {
    match s {
        OcspResponseStatus::Successful => "successful (0)",
        OcspResponseStatus::MalformedRequest => "malformedRequest (1)",
        OcspResponseStatus::InternalError => "internalError (2)",
        OcspResponseStatus::TryLater => "tryLater (3)",
        OcspResponseStatus::SigRequired => "sigRequired (5)",
        OcspResponseStatus::Unauthorized => "unauthorized (6)",
    }
}

fn crl_reason_str(r: &CrlReason) -> String {
    // Match the names verbatim with RFC 5280 §5.3.1 so anyone cross-referencing
    // the spec sees the same words. removedFromCRL is the case §15.9.1
    // explicitly calls out as needing to be disambiguated from real revocation.
    match r {
        CrlReason::Unspecified => "unspecified",
        CrlReason::KeyCompromise => "keyCompromise",
        CrlReason::CaCompromise => "cACompromise",
        CrlReason::AffiliationChanged => "affiliationChanged",
        CrlReason::Superseded => "superseded",
        CrlReason::CessationOfOperation => "cessationOfOperation",
        CrlReason::CertificateHold => "certificateHold",
        CrlReason::RemoveFromCRL => "removedFromCRL",
        CrlReason::PrivilegeWithdrawn => "privilegeWithdrawn",
        CrlReason::AaCompromise => "aACompromise",
    }
    .to_string()
}

fn responder_id_str(r: &rasn_ocsp::ResponderId) -> String {
    match r {
        rasn_ocsp::ResponderId::ByName(_) => "byName(<X.500 Name>)".to_string(),
        rasn_ocsp::ResponderId::ByKey(hash) => {
            format!("byKey(sha1={})", hex_short(hash.as_ref()))
        }
    }
}

fn hex_short(bytes: &[u8]) -> String {
    let n = bytes.len().min(20);
    bytes[..n].iter().map(|b| format!("{b:02X}")).collect()
}

// -----------------------------------------------------------------------------
// JPEG -> JUMBF -> COSE_Sign1 (mirrors `strip_timestamp.rs`)
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
