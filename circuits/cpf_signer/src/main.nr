// Proof 2 · `cpf_signer` — "the holder of key K, bound to CPF c, really signed digest D".
//
// Private: the citizen's RSA-2048 modulus, the signature from the CMS container, the CPF, salt.
//
// Checks: RSA PKCS#1 v1.5 signature recovery — sig^65537 mod n equals the encoded SHA-256
// DigestInfo of D = SHA-256(signedAttrs). This is what makes the metadata hash in Proof 1
// unforgeable: without the gov.br-issued key for this certificate nobody can produce `sig`.
//
// Proof 1 binds key K and CPF c to the same certificate; the contract checks both proofs
// output the same (sa_hash, key_hash, cpf_commit).
//
// Public output (6 fields): [sa_hi, sa_lo, key_hi, key_lo, cpf_hi, cpf_lo]
use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use common::{assert_cpf, cpf_commit, split, to_limbs};
use noir_rsa::pkcs1v15::verify_sha256_pkcs1v15;

fn main(
    sa_hash: [u8; 32],
    leaf_modulus: [u8; 256],
    leaf_redc: [u128; 18],
    leaf_sig: [u8; 256],
    cpf: [u8; 11],
    salt: [u8; 32],
) -> pub [Field; 6] {
    assert(leaf_modulus[0] >= 0x80); // exactly 2048 bits
    let params: BigNumParams<18, 2048> =
        BigNumParams::new(false, to_limbs(leaf_modulus), leaf_redc);
    assert(verify_sha256_pkcs1v15(sa_hash, RuntimeBigNum::from_be_bytes(params, leaf_sig), 65537));

    assert_cpf(cpf);
    let (sa_hi, sa_lo) = split(sa_hash);
    let (k_hi, k_lo) = split(sha256::digest(leaf_modulus));
    let (c_hi, c_lo) = split(cpf_commit(cpf, salt));
    [sa_hi, sa_lo, k_hi, k_lo, c_hi, c_lo]
}
