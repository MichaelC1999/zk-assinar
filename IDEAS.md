# Ideas: proving property ownership from cartório certidões

Exploration notes, not built. Today's pipeline (see [MECHANISMS.md](MECHANISMS.md)) proves that a gov.br
signer signed a PDF containing a string `S`, and costs ~84 proofs / ~400 s because every signed byte is
hashed in the circuit. These ideas aim to prove **"CPF X is a registered owner of matrícula Y, and I am X"**
much more cheaply.

**What one real certidão showed** (public *inteiro teor* certidão, Pimenta Bueno/RO, May 2025):
- Signed by a cartório employee's personal ICP-Brasil e-CPF (A3, RSA-2048 / SHA-256).
- `ETSI.CAdES.detached`, with no ICP-Brasil signature policy and no timestamp.
- The matrícula itself is a **scanned image**: owners and CPFs are pixels only.
- The signer's certificate holds the *signer's* CPF, never the owner's.

---

## Idea 1 — Bind the owner with a tiny gov.br-signed claim PDF

**Problem.** We want two facts in one proof:
- the cartório signed certidão `H_cartório` naming CPF X as owner;
- the person proving is X.

The obvious route is for the owner to gov.br-sign the certidão itself. But then the two hashes can never be
compared:
- Each signature hashes the whole file *except its own* signature hole.
- The owner's signature is added later as an update, so its hash covers the cartório's revision **plus**
  the cartório's signature bytes and the new update.
- The hashes always differ. Proving that one revision is contained in the other means hashing the whole
  file in the circuit again, which is the expensive hash tree we want to avoid.

**Idea.** Don't sign the certidão. The owner gov.br-signs a **tiny claim PDF that we generate**. Its one
page holds `H_cartório` and a wallet address or nonce, in an **uncompressed** content stream, so no
decompression is needed.

```
certidão (cartório-signed) ──► H_cartório ─┐
                                           ├─► tiny claim PDF ──► owner signs with gov.br
wallet / nonce ────────────────────────────┘
```

**What the circuit checks (one proof):**
1. **Cartório signature.** The signer's RSA signature over its signed attributes, which contain
   `H_cartório`, plus the certificate's CA signature. The signer's CPF is on an allowlist of authorised
   staff for that cartório. The certidão file itself is **not** hashed.
2. **Ownership statement.** An interpreter (a person, or OCR with review) has read the certidão and signed
   `(H_cartório, CNM / matrícula, owner CPF, issue date)`. The circuit verifies that signature and checks it
   names the same `H_cartório`.
3. **Claim PDF.** It checks the existing gov.br signer proof (M2) on the claim PDF and hashes the claim PDF
   in one circuit:
   - our page is about 2–8 KB;
   - the gov.br portal adds about 11 KB (measured on the bank sample);
   - that's about 3 hash chunks, roughly 4M gates (an estimate, not measured).
4. **Fixed template, no parsing.** We generate the claim PDF byte for byte, so the circuit compares its
   original revision against a fixed template with two slots, `H_cartório` and the wallet/nonce. This is
   the same trick as the `signedAttrs` template in M2.
5. **CPF match.** The gov.br certificate's CPF equals the owner CPF in the interpreter's statement. The
   output is `signerCommit` (M5), so no CPF goes on chain.

**Public outputs:**
- the CNM / matrícula and the cartório
- the issue date
- `docId` derived from `H_cartório`
- `signerCommit`
- the wallet or request it's bound to

**Trust.**
- The cartório and gov.br signatures are checked in the circuit.
- The interpreter is trusted only to read the record correctly. It can't invent a document, and anyone
  holding the PDF can recompute `H_cartório` and audit its reading.
- The staff allowlist is curated off chain.

**Open items:**
- Confirm the gov.br portal accepts our generated PDF and keeps it byte for byte as a prefix. It did on the
  bank sample.
- Who runs the interpreter, and with what key.
- Revocation: there's no timestamp, and the signer's certificate on the sample has already expired.
- The certidão is ownership **as of issuance**; it's valid for 30 days.

---

## Idea 2 — Use the Certidão da Situação Jurídica Atualizada instead

**What it is.** Created by Lei 14.382/2022 (Lei 6.015, art. 19 §9). The registrar issues a summary of the
property's **current** state: description, owners, other real rights, encumbrances and restrictions. The
*inteiro teor* certidão is instead a copy of the full history. It's due within one business day.

Its layout, from the Rio Grande do Sul registrar associations' model (`work/situacao_samples/`):

```
CERTIDÃO DE SITUAÇÃO JURÍDICA DE IMÓVEL
CÓDIGO NACIONAL DA MATRÍCULA - CNM: …     Matrícula n. …
1) IMÓVEL: …
2) PROPRIETÁRIO(S): …
3) CADASTRO: …
4) ÔNUS, GRAVAMES, RESTRIÇÕES …: 4.1 servidão, 4.3 hipoteca, 4.4 alienação fiduciária, 4.5 penhora …
```

**Why it makes the circuit easier:**

| | Inteiro teor (sample) | Situação jurídica |
| --- | --- | --- |
| Who interprets ownership | Us: replay every entry and rule out a later transfer | **The registrar**, who is legally competent and states current owners directly |
| Ownership rule in circuit | Infeasible: full history, page order, legal nuance | **"CPF is inside the `2) PROPRIETÁRIO(S)` section"** |
| Content | Often a scanned image | Written fresh by the registrar, so likely text |
| Size | Many pages, with images | One or two pages |
| How much to read | Everything (no early stop) | One section near the top |

**What this enables:**
- **Remove the interpreter.** With a text certidão, the circuit can read the owners section itself:
  - hash the certidão;
  - decompress the stream that holds section 2, in 1–3 steps;
  - anchor on the `2) PROPRIETÁRIO(S)` heading, so a CPF from section 4 (a creditor, say) can't pass as an
    owner.

  This brings back some file hashing, but on a short file. The registrar becomes the only interpreter.
- **Hash only the tail.** Start from a precomputed SHA-256 state and hash from the owners section to the end
  of the file. This is sound here because the cartório wrote every byte, so the holder can't plant
  content.
- **Possibly structured data.** ONR's ITN 004/2026 (May 2026) defines a born-digital situação jurídica
  document and its certidão (Annexes VII and VIII), with the data modelled in JSON. If the certidão carries
  that data **signed**, the circuit hashes a few KB and reads fields directly. That would be one small proof
  with no decompression and no interpreter.

**Caveats:**
- Under a fiduciary sale, the **bank** is listed as *proprietário fiduciário* and the buyer as *alienante
  fiduciante*. The rule must decide which role counts as owner.
- The layout is free text and varies by cartório. The RS model is a suggestion, not a national format.
- Not yet seen: a real, signed situação jurídica certidão; the ITN 004 annexes; how widely cartórios have
  adopted it.

---

## Next steps

1. Order one real Certidão da Situação Jurídica Atualizada through RI Digital. Check whether it's text or
   scanned, how it's signed, and how the CPF is written.
2. Read the ITN 004/2026 annexes (ridigital.org.br) for the structured format and its signature.
3. Prototype Idea 1 by reusing the `signer` circuit for the cartório's signature; it's the same CPF field
   (2.16.76.1.3.1) and a similar certificate layout.
