// Shared helpers for the zk-assinar circuits.
//
// Both circuits expose 256-bit values as two field elements (hi = first 16 bytes,
// lo = last 16 bytes, big-endian) so the contract can compare them across proofs.

/// Domain tag for the CPF commitment: sha256("zk-assinar/cpf/v1" ‖ cpf ascii ‖ salt).
pub global DS_CPF: [u8; 17] = [
    0x7a, 0x6b, 0x2d, 0x61, 0x73, 0x73, 0x69, 0x6e, 0x61, 0x72, 0x2f, 0x63, 0x70, 0x66, 0x2f, 0x76,
    0x31,
];

/// Big-endian 32 bytes → (hi, lo) field elements.
pub fn split(b: [u8; 32]) -> (Field, Field) {
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = hi * 256 + b[i] as Field;
        lo = lo * 256 + b[16 + i] as Field;
    }
    (hi, lo)
}

/// Salted CPF commitment (the on-chain pseudonym). A bare hash of a CPF is brute-forceable
/// (~10^9 values), hence the 32-byte salt that only the signer keeps.
pub fn cpf_commit(cpf: [u8; 11], salt: [u8; 32]) -> [u8; 32] {
    let mut m = [0 as u8; 60];
    for i in 0..17 {
        m[i] = DS_CPF[i];
    }
    for i in 0..11 {
        m[17 + i] = cpf[i];
    }
    for i in 0..32 {
        m[28 + i] = salt[i];
    }
    sha256::digest(m)
}

/// Asserts 11 ASCII digits with valid mod-11 check digits.
pub fn assert_cpf(cpf: [u8; 11]) {
    let mut d = [0 as u64; 11];
    for i in 0..11 {
        assert((cpf[i] >= 0x30) & (cpf[i] <= 0x39));
        d[i] = (cpf[i] - 0x30) as u64;
    }
    let mut s1 = 0;
    let mut s2 = 0;
    for i in 0..9 {
        s1 += d[i] * (10 - i as u64);
        s2 += d[i] * (11 - i as u64);
    }
    let r1 = s1 % 11;
    let dv1 = if r1 < 2 { 0 } else { 11 - r1 };
    assert(d[9] == dv1);
    let r2 = (s2 + 2 * dv1) % 11;
    let dv2 = if r2 < 2 { 0 } else { 11 - r2 };
    assert(d[10] == dv2);
}

/// Big-endian bytes → 120-bit little-endian limbs (noir-bignum layout).
pub fn to_limbs<let NB: u32, let N: u32>(b: [u8; NB]) -> [u128; N] {
    let mut limbs = [0 as u128; N];
    for i in 0..NB {
        let k = NB - 1 - i;
        limbs[k / 15] += (b[i] as u128) << (((k % 15) * 8) as u128);
    }
    limbs
}

#[test]
fn test_cpf_check_digits() {
    // 111.444.777-35 is the standard synthetic valid CPF.
    assert_cpf([0x31, 0x31, 0x31, 0x34, 0x34, 0x34, 0x37, 0x37, 0x37, 0x33, 0x35]);
}

#[test(should_fail)]
fn test_cpf_bad_check_digit() {
    assert_cpf([0x31, 0x31, 0x31, 0x34, 0x34, 0x34, 0x37, 0x37, 0x37, 0x33, 0x36]);
}
