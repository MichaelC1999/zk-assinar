# zk-assinar — minimal

ZK attestation that a gov.br-signed PDF was signed by a (private) CPF. Design: `zk_assinar_minimal_flow.png`,
mechanisms: [MECHANISMS.md](MECHANISMS.md).

```bash
scripts/test.py        # build, prove the sample PDF, reconstruct + compare, negative cases, forge tests
```

| Path | What |
| --- | --- |
| `circuits/signed_doc` | Proof 1: signedAttrs ↔ `H`, gov.br CA signature on the cert, DER walk, CPF match |
| `circuits/cpf_signer` | Proof 2: RSA-2048 signature over `SHA-256(signedAttrs)` by the cert's key |
| `circuits/common` | CPF check digits, CPF commitment, helpers |
| `backend` | Rust: PDF → circuit inputs → `nargo` + `bb` → proofs (`zk-assinar prove <pdf> --cpf <cpf>`) |
| `backend/ca` | Public gov.br AC Final v1 modulus |
| `contracts` | `AttestationRegistry` + generated verifiers (Foundry) |
| `scripts/build.sh` | Compile circuits, write vks and Solidity verifiers, build backend |

Toolchain: nargo `1.0.0-beta.22`, bb `5.0.0-nightly.20260522`, noir_rsa `v0.12.0`. Proving both
circuits takes ~3 s on Apple Silicon. `work/` and PDFs are gitignored — they contain personal data.
Previous design archived at `../zk-assinar-archive-2026-10-18/`.
