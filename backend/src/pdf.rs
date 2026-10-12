//! Slices a gov.br-signed PDF into the raw pieces the circuits need.
//!
//! Untrusted helper: nothing here verifies a signature. If it slices the wrong bytes, a
//! circuit assertion fails and no proof is produced.

use crate::ber::{self, Tlv};
use sha2::{Digest, Sha256};

/// signedAttrs layout produced by gov.br (153 B): signingTime at 46, messageDigest at 121.
pub const SA_LEN: usize = 153;
pub const SA_TIME_OFF: usize = 46;
pub const SA_DIGEST_OFF: usize = 121;
pub const TBS_MAX: usize = 1536;

pub struct Signed {
    /// SHA-256 of `bytes[0..b) ‖ bytes[c..c+d)` — what gov.br actually signed (indirectly).
    pub doc_hash: [u8; 32],
    pub signed_attrs: Vec<u8>,
    pub signing_time: [u8; 13],
    pub leaf_sig: Vec<u8>,
    pub tbs: Vec<u8>,
    pub ca_sig: Vec<u8>,
    pub leaf_modulus: Vec<u8>,
    pub cpf: [u8; 11],
}

type R<T> = Result<T, String>;

fn e<T>(code: &str, m: impl std::fmt::Display) -> R<T> {
    Err(format!("{code}: {m}"))
}

fn child<'a>(v: &[Tlv<'a>], i: usize, tag: u8) -> R<Tlv<'a>> {
    match v.get(i) {
        Some(t) if t.tag == tag => Ok(*t),
        _ => e("E_PARSE", format!("expected tag {tag:#x} at child {i}")),
    }
}

fn kids(d: &[u8]) -> R<Vec<Tlv<'_>>> {
    ber::children(d).or_else(|m| e("E_PARSE", m))
}

fn read(d: &[u8]) -> R<Tlv<'_>> {
    ber::read(d).or_else(|m| e("E_PARSE", m))
}

pub fn parse(pdf: &[u8]) -> R<Signed> {
    // /ByteRange [0 b c d]: the last one must cover the file except the /Contents hole.
    let key = b"/ByteRange";
    let pos = pdf.windows(key.len()).rposition(|w| w == key).ok_or("E_NO_SIG: no /ByteRange")?;
    let rest = &pdf[pos + key.len()..];
    let open = rest.iter().position(|&c| c == b'[').ok_or("E_BYTERANGE: no [")?;
    let close = rest.iter().position(|&c| c == b']').ok_or("E_BYTERANGE: no ]")?;
    let nums: Vec<usize> = std::str::from_utf8(&rest[open + 1..close])
        .map_err(|_| "E_BYTERANGE: non-ascii")?
        .split_ascii_whitespace()
        .map(|t| t.parse().map_err(|_| "E_BYTERANGE: bad int".to_string()))
        .collect::<R<_>>()?;
    let [0, b, c, d] = nums[..] else { return e("E_BYTERANGE", "malformed array") };
    if b >= c || c + d != pdf.len() {
        return e("E_BYTERANGE", "range must end at EOF with a hole in between");
    }
    let hole = &pdf[b..c];
    if hole.len() < 2 || hole[0] != b'<' || hole[hole.len() - 1] != b'>' {
        return e("E_BYTERANGE", "hole is not a hex string");
    }
    let digits = &hole[1..hole.len() - 1];
    if digits.len() % 2 != 0 || !digits.iter().all(|c| c.is_ascii_hexdigit()) {
        return e("E_BYTERANGE", "hole has non-hex bytes");
    }
    let cms: Vec<u8> = digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let doc_hash: [u8; 32] = Sha256::new().chain_update(&pdf[..b]).chain_update(&pdf[c..]).finalize().into();

    // CMS ContentInfo → SignedData → certificates[0], signerInfos[0].
    let ci = kids(read(&cms)?.val)?;
    if child(&ci, 0, 0x06)?.val != [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02] {
        return e("E_CMS", "not signedData");
    }
    let sd = kids(child(&kids(child(&ci, 1, 0xa0)?.val)?, 0, 0x30)?.val)?;
    let certs = kids(child(&sd, 3, 0xa0)?.val)?;
    let infos = kids(sd.last().filter(|t| t.tag == 0x31).ok_or("E_CMS: no signerInfos")?.val)?;
    if infos.len() != 1 {
        return e("E_CMS", "expected one signerInfo");
    }
    let si = kids(child(&infos, 0, 0x30)?.val)?;
    let mut signed_attrs = child(&si, 3, 0xa0)?.raw.to_vec();
    signed_attrs[0] = 0x31; // RFC 5652 §5.4: signed as a SET
    let leaf_sig = child(&si, 5, 0x04)?.val.to_vec();

    if signed_attrs.len() != SA_LEN || signed_attrs[SA_DIGEST_OFF..] != doc_hash {
        return e("E_CMS", "signedAttrs is not the gov.br layout or messageDigest != ByteRange hash");
    }
    let signing_time: [u8; 13] = signed_attrs[SA_TIME_OFF..SA_TIME_OFF + 13].try_into().unwrap();

    // Leaf certificate (gov.br embeds only the leaf).
    let leaf = kids(child(&certs, 0, 0x30)?.val)?;
    let tbs = child(&leaf, 0, 0x30)?.raw.to_vec();
    let bits = child(&leaf, 2, 0x03)?.val;
    if bits.first() != Some(&0) || tbs.len() > TBS_MAX {
        return e("E_CERT", "bad signature bit string or TBS too long");
    }
    let ca_sig = bits[1..].to_vec();

    // TBS fields: SPKI modulus (index 6), SAN otherName 2.16.76.1.3.1 in extensions (index 7).
    let f = kids(read(&tbs)?.val)?;
    let spki = kids(child(&f, 6, 0x30)?.val)?;
    let bs = child(&spki, 1, 0x03)?.val;
    let rsa = kids(read(&bs[1..])?.val)?;
    let mut n = child(&rsa, 0, 0x02)?.val;
    while n.first() == Some(&0) {
        n = &n[1..];
    }
    if n.len() != 256 || child(&rsa, 1, 0x02)?.val != [1, 0, 1] {
        return e("E_CERT", "leaf key is not RSA-2048 / e=65537");
    }
    let mut san45 = None;
    for ext in kids(read(child(&f, 7, 0xa3)?.val)?.val)? {
        let x = kids(ext.val)?;
        if x[0].val != [0x55, 0x1d, 0x11] {
            continue;
        }
        for gn in kids(read(x.last().unwrap().val)?.val)?.iter().filter(|g| g.tag == 0xa0) {
            let on = kids(gn.val)?;
            if on[0].val == [0x60, 0x4c, 0x01, 0x03, 0x01] {
                san45 = Some(read(on[1].val)?.val.to_vec());
            }
        }
    }
    let leaf_modulus = n.to_vec();
    drop(f);
    let san45 = san45.filter(|s| s.len() == 45).ok_or("E_CERT: no 45-byte SAN 2.16.76.1.3.1")?;
    Ok(Signed {
        doc_hash,
        signed_attrs,
        signing_time,
        leaf_sig,
        tbs,
        ca_sig,
        leaf_modulus,
        cpf: san45[8..19].try_into().unwrap(),
    })
}

/// 11 ASCII digits with valid check digits (punctuation stripped by the caller).
pub fn cpf_valid(d: &[u8]) -> bool {
    if d.len() != 11 || !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let d: Vec<u32> = d.iter().map(|&c| (c - b'0') as u32).collect();
    let dv = |k: usize, w0: u32| {
        let r = (0..k).map(|i| d[i] * (w0 - i as u32)).sum::<u32>() % 11;
        if r < 2 { 0 } else { 11 - r }
    };
    dv(9, 10) == d[9] && dv(10, 11) == d[10]
}
