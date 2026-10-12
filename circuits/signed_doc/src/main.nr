// Proof 1 · `signed_doc` — "this gov.br container signs document hash H for CPF c".
//
// Private: the pieces of the PAdES/CMS container (signingTime, H, leaf certificate TBS,
// gov.br CA signature on it, CA modulus) and the CPF.
//
// Checks:
//   1. signedAttrs is rebuilt from the fixed gov.br layout with messageDigest = H, and hashed.
//   2. The leaf certificate TBS is signed by the CA key (RSA-4096) → issued by gov.br.
//   3. The TBS is walked field by field (DER, from offset 0) to extract the leaf RSA key, the
//      validity window, the gov.br policy OID and the SAN otherName 2.16.76.1.3.1.
//   4. The CPF inside that SAN equals the private CPF input (with valid check digits).
//   5. notBefore <= signingTime <= notAfter.
//
// The leaf signature over signedAttrs is NOT checked here; that is Proof 2 (`cpf_signer`).
// The two proofs are linked by (sa_hash, key_hash, cpf_commit), compared by the contract.
//
// Public output (11 fields):
//   [h_hi, h_lo, sa_hi, sa_lo, key_hi, key_lo, cpf_hi, cpf_lo, ca_hi, ca_lo, signed_day]
//   h          = SHA-256 of the PDF's /ByteRange bytes (anyone with the PDF can recompute it)
//   sa         = SHA-256(signedAttrs), the digest the citizen's key signed
//   key        = SHA-256(leaf RSA modulus)
//   cpf        = SHA-256("zk-assinar/cpf/v1" ‖ cpf ‖ salt), the on-chain pseudonym
//   ca         = SHA-256(CA modulus), compared on chain with the trusted gov.br CA
mod template;

use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use common::{assert_cpf, cpf_commit, split, to_limbs};
use noir_rsa::pkcs1v15::verify_sha256_pkcs1v15;
use template::SA_TEMPLATE;

global TBS_MAX: u32 = 1536;
global MAX_EXTS: u32 = 12;
global MAX_NAMES: u32 = 4;

// signedAttrs offsets of the signingTime and messageDigest values (gov.br layout, 153 B).
global SA_TIME_OFF: u32 = 46;
global SA_DIGEST_OFF: u32 = 121;

// AlgorithmIdentifier sha256WithRSAEncryption, NULL params.
global ALG_SHA256_RSA: [u8; 15] =
    [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00];
// SPKI prefix for RSA-2048: alg rsaEncryption, BIT STRING, RSAPublicKey SEQ, INTEGER (257 B).
global SPKI_PREFIX: [u8; 33] = [
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
    0x01, 0x01, 0x00,
];
global SPKI_EXP: [u8; 5] = [0x02, 0x03, 0x01, 0x00, 0x01];
// otherName type-id 2.16.76.1.3.1 (birth date ‖ CPF ‖ NIS ‖ RG).
global OID_SAN_PF: [u8; 7] = [0x06, 0x05, 0x60, 0x4c, 0x01, 0x03, 0x01];
// gov.br signature policy 2.16.76.3.2.1.1.
global OID_POLICY: [u8; 8] = [0x06, 0x06, 0x60, 0x4c, 0x03, 0x02, 0x01, 0x01];

/// DER header at `p`: (tag, length, header length). Definite lengths up to 2 bytes.
fn hdr<let M: u32>(b: [u8; M], p: u32) -> (u8, u32, u32) {
    let tag = b[p];
    let l0 = b[p + 1];
    if l0 < 0x80 {
        (tag, l0 as u32, 2)
    } else if l0 == 0x81 {
        let l = b[p + 2] as u32;
        assert(l >= 0x80);
        (tag, l, 3)
    } else {
        assert(l0 == 0x82);
        let l = (b[p + 2] as u32) * 256 + b[p + 3] as u32;
        assert(l >= 0x100);
        (tag, l, 4)
    }
}

/// Expect `tag` at `p`; return (value start, value end).
fn expect<let M: u32>(b: [u8; M], p: u32, tag: u8) -> (u32, u32) {
    let (t, l, h) = hdr(b, p);
    assert(t == tag);
    (p + h, p + h + l)
}

fn bytes_eq<let M: u32, let K: u32>(b: [u8; M], p: u32, want: [u8; K]) -> bool {
    let mut ok = true;
    for i in 0..K {
        ok &= b[p + i] == want[i];
    }
    ok
}

fn digit(c: u8) -> u64 {
    assert((c >= 0x30) & (c <= 0x39));
    (c - 0x30) as u64
}

fn two<let M: u32>(b: [u8; M], p: u32) -> u64 {
    digit(b[p]) * 10 + digit(b[p + 1])
}

/// UTCTime `YYMMDDHHMMSSZ` at `p` → Unix seconds (years 2000–2049).
fn utctime<let M: u32>(b: [u8; M], p: u32) -> u64 {
    let yy = two(b, p);
    let mo = two(b, p + 2);
    let d = two(b, p + 4);
    let hh = two(b, p + 6);
    let mi = two(b, p + 8);
    let ss = two(b, p + 10);
    assert(b[p + 12] == 0x5a); // 'Z'
    assert(yy < 50);
    assert((mo >= 1) & (mo <= 12) & (d >= 1) & (d <= 31) & (hh < 24) & (mi < 60) & (ss < 60));
    // days_from_civil (H. Hinnant); y >= 1999 so no negative eras.
    let y = 2000 + yy - (if mo <= 2 { 1 } else { 0 });
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hh * 3600 + mi * 60 + ss
}

fn main(
    h: [u8; 32],
    signing_time: [u8; 13],
    tbs: [u8; TBS_MAX],
    tbs_len: u32,
    ca_modulus: [u8; 512],
    ca_redc: [u128; 35],
    ca_sig: [u8; 512],
    cpf: [u8; 11],
    salt: [u8; 32],
) -> pub [Field; 11] {
    // 1. signedAttrs with messageDigest = H.
    let mut sa = SA_TEMPLATE;
    for i in 0..13 {
        sa[SA_TIME_OFF + i] = signing_time[i];
    }
    for i in 0..32 {
        sa[SA_DIGEST_OFF + i] = h[i];
    }
    let sa_hash = sha256::digest(sa);

    // 2. gov.br CA signature over the leaf certificate.
    let d_tbs = sha256::sha256_var(tbs, tbs_len);
    assert(ca_modulus[0] >= 0x80); // exactly 4096 bits
    let ca_params: BigNumParams<35, 4096> =
        BigNumParams::new(false, to_limbs(ca_modulus), ca_redc);
    assert(verify_sha256_pkcs1v15(d_tbs, RuntimeBigNum::from_be_bytes(ca_params, ca_sig), 65537));

    // 3. DER walk of the TBS from offset 0.
    let (body, end) = expect(tbs, 0, 0x30);
    assert(end == tbs_len);
    assert(bytes_eq(tbs, body, [0xa0, 0x03, 0x02, 0x01, 0x02])); // version v3
    let mut p = body + 5;
    let (_, e) = expect(tbs, p, 0x02); // serialNumber
    p = e;
    assert(bytes_eq(tbs, p, ALG_SHA256_RSA)); // signature algorithm
    p += 15;
    let (_, e) = expect(tbs, p, 0x30); // issuer
    p = e;
    let (v, e) = expect(tbs, p, 0x30); // validity: two UTCTimes
    assert(bytes_eq(tbs, v, [0x17, 0x0d]));
    assert(bytes_eq(tbs, v + 15, [0x17, 0x0d]));
    assert(e == v + 30);
    let not_before = utctime(tbs, v + 2);
    let not_after = utctime(tbs, v + 17);
    p = e;
    let (_, e) = expect(tbs, p, 0x30); // subject
    p = e;
    assert(bytes_eq(tbs, p, SPKI_PREFIX)); // subjectPublicKeyInfo
    let n_off = p + 33;
    assert(tbs[n_off] >= 0x80); // exactly 2048 bits
    assert(bytes_eq(tbs, n_off + 256, SPKI_EXP)); // e = 65537
    p = n_off + 261;
    let (x, ext_end) = expect(tbs, p, 0xa3);
    assert(ext_end == end);
    let (mut q, seq_end) = expect(tbs, x, 0x30);
    assert(seq_end == end);

    let mut san45 = [0 as u8; 45];
    let mut found_san = false;
    let mut found_policy = false;
    for _ in 0..MAX_EXTS {
        if q < seq_end {
            let (eb, ee) = expect(tbs, q, 0x30);
            if bytes_eq(tbs, eb, [0x06, 0x03, 0x55, 0x1d, 0x11]) {
                // subjectAltName: OCTET STRING { SEQUENCE OF GeneralName }
                let (ob, _) = expect(tbs, eb + 5, 0x04);
                let (mut g, gend) = expect(tbs, ob, 0x30);
                for _ in 0..MAX_NAMES {
                    if g < gend {
                        let (t, l, hl) = hdr(tbs, g);
                        if (t == 0xa0) & bytes_eq(tbs, g + hl, OID_SAN_PF) {
                            let (vb, _) = expect(tbs, g + hl + 7, 0xa0);
                            let (t2, l2, h2) = hdr(tbs, vb);
                            assert((t2 == 0x04) | (t2 == 0x13));
                            assert(l2 == 45);
                            for i in 0..45 {
                                san45[i] = tbs[vb + h2 + i];
                            }
                            assert(!found_san);
                            found_san = true;
                        }
                        g += hl + l;
                    }
                }
            } else if bytes_eq(tbs, eb, [0x06, 0x03, 0x55, 0x1d, 0x20]) {
                // certificatePolicies: the first PolicyInformation is the gov.br policy.
                let (ob, _) = expect(tbs, eb + 5, 0x04);
                let (pb, _) = expect(tbs, ob, 0x30);
                let (ib, _) = expect(tbs, pb, 0x30);
                found_policy = bytes_eq(tbs, ib, OID_POLICY);
            }
            q = ee;
        }
    }
    assert(q == seq_end);
    assert(found_san);
    assert(found_policy);

    // 4. CPF = san45[8..19] must equal the private input.
    assert_cpf(cpf);
    for i in 0..11 {
        assert(san45[8 + i] == cpf[i]);
    }

    // 5. Validity window.
    let t = utctime(signing_time, 0);
    assert(not_before <= t);
    assert(t <= not_after);

    let mut n_leaf = [0 as u8; 256];
    for i in 0..256 {
        n_leaf[i] = tbs[n_off + i];
    }
    let (h_hi, h_lo) = split(h);
    let (sa_hi, sa_lo) = split(sa_hash);
    let (k_hi, k_lo) = split(sha256::digest(n_leaf));
    let (c_hi, c_lo) = split(cpf_commit(cpf, salt));
    let (ca_hi, ca_lo) = split(sha256::digest(ca_modulus));
    [h_hi, h_lo, sa_hi, sa_lo, k_hi, k_lo, c_hi, c_lo, ca_hi, ca_lo, (t / 86400) as Field]
}
