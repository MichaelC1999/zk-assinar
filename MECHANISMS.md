# How it works

**Goal (minimal flow).** On chain: *a gov.br-authenticated CPF holder signed the document with hash `H`*,
proven in zero knowledge. The CPF stays private; the chain sees a salted pseudonym. Proving *what the
document says* (flow step 5) is not built yet.

```
signed PDF ──► backend (slices the PDF; untrusted)
                 ├─► Proof 1 · signed_doc   "this gov.br container signs H, for CPF c"
                 └─► Proof 2 · cpf_signer   "the key bound to CPF c really signed it"
                                 │
                                 ▼
                     AttestationRegistry (verifies both, links them, records H → pseudonym)
```

## What gov.br actually signs

A gov.br PDF has a `/ByteRange`: the whole file except a gap holding the signature package (CMS).
gov.br does not sign the PDF bytes directly:

1. `H = SHA-256(signed byte ranges)`.
2. `H` goes into a 153-byte block of signed attributes (`signedAttrs`), together with the signing time.
3. The citizen's one-off RSA-2048 key signs `SHA-256(signedAttrs)`.
4. The gov.br CA (RSA-4096) signs the citizen's certificate, which carries the CPF in a SAN field.

## Backend (`backend/`, Rust)

Reads `/ByteRange`, slices the CMS and certificate as raw bytes, writes the circuit inputs, runs
`nargo execute` + `bb prove` for both circuits, then deletes the inputs and witnesses (they hold the CPF).
It verifies nothing cryptographically: if it slices the wrong bytes, a circuit fails. It generates a
random 32-byte salt that only the signer keeps.

## Proof 1 · `signed_doc` (≈296K gates)

Private: `H`, signing time, certificate body (TBS), CA signature, CA key, CPF, salt.

1. Rebuilds `signedAttrs` with `messageDigest = H` and hashes it.
2. Checks the **gov.br CA signature** on the certificate → it was issued by gov.br.
3. Reads the certificate field by field (DER walk from byte 0, not a byte search, so a forged pattern
   elsewhere can't pass as the CPF): leaf key, validity dates, gov.br policy OID, SAN with the CPF.
4. Asserts the **CPF in the certificate equals the private CPF** (and its check digits are valid).
5. Asserts signing time is inside the certificate's validity.

Outputs `H`, `SHA-256(signedAttrs)`, `SHA-256(leaf key)`, the CPF commitment, `SHA-256(CA key)`, signing day.

## Proof 2 · `cpf_signer` (≈52K gates)

Private: leaf key, leaf signature, CPF, salt. Checks the **RSA signature**: `sig^65537 mod n` decodes
to `SHA-256(signedAttrs)`. Only gov.br's key for that certificate can produce it, so the metadata in
Proof 1 is not a forgery. Outputs the same digest, key hash and CPF commitment as Proof 1.

**Why two proofs?** Each answers one question and stays small (~3 s total). They are tied together by
three shared outputs; a mismatch means they describe different signatures.

## CPF privacy

`pseudonym = SHA-256("zk-assinar/cpf/v1" ‖ CPF ‖ salt)`. A plain CPF hash is unsafe: there are only
~10⁹ CPFs, so anyone could hash them all. The salt makes it unguessable; the signer can later reveal
`(CPF, salt)` to a chosen party, who recomputes it. SHA-256 (not Poseidon) so anyone can check it
with standard tools.

## Contract (`AttestationRegistry`)

1. Verifies both proofs (generated UltraHonk verifiers; ≈6.5M gas for both).
2. Checks the three linking values match.
3. Checks the CA hash equals the trusted gov.br AC Final v1 key.
4. Rejects a second attestation of the same `H`; stores `H → (pseudonym, signing day, submitter)`.

## Not yet covered

- **`H` is not hashed from the PDF inside a circuit.** `H` is public, so anyone holding the PDF can
  recompute it (the test does). Proving it in-circuit for any file size needs chunked SHA-256 with
  recursion (the archived `hash_leaf`/`hash_node` design, ≈400 s for the sample).
- Document content (flow step 5), revocation, DeFi callback, the fixed `signedAttrs` layout
  (only verified on the sample so far).
