//! zk-assinar backend: PDF in → two proofs out.
//!
//!   zk-assinar prove <signed.pdf> --cpf <cpf> [--salt <64 hex>] [--out <dir>]
//!   zk-assinar cpf <signed.pdf>          (test helper: prints the certificate's CPF)
//!
//! `prove` slices the PDF (pdf.rs), writes the circuit inputs, runs `nargo execute` and
//! `bb prove` for both circuits, and writes to <dir>:
//!   signed_doc/{proof,public_inputs}, cpf_signer/{proof,public_inputs}  — go on chain
//!   public.json                                                          — readable summary
//!   salt.hex                                                             — PRIVATE, signer keeps
//! Witnesses and Prover inputs are deleted after proving: they contain the CPF.
#![forbid(unsafe_code)]

mod ber;
mod pdf;

use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::{fmt::Write as _, fs, path::{Path, PathBuf}, process::{exit, Command}};

const JOB: &str = "job"; // Prover file name inside each circuit dir (gitignored, deleted after use)

fn die(m: impl std::fmt::Display) -> ! {
    eprintln!("error: {m}");
    exit(2)
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        die("bad hex");
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn bytes(b: &[u8]) -> String {
    format!("[{}]", b.iter().map(u8::to_string).collect::<Vec<_>>().join(", "))
}

/// Barrett reduction parameter expected by noir-bignum, as 120-bit limbs.
fn redc(modulus: &[u8], bits: usize, limbs: usize) -> String {
    let r = (BigUint::from(1u8) << (2 * bits + 6)) / BigUint::from_bytes_be(modulus);
    let mask = (BigUint::from(1u8) << 120) - 1u8;
    let v: Vec<String> = (0..limbs).map(|i| format!("\"0x{:x}\"", (&r >> (120 * i)) & &mask)).collect();
    format!("[{}]", v.join(", "))
}

fn run(cmd: &mut Command, what: &str) {
    let out = cmd.output().unwrap_or_else(|e| die(format!("{what}: {e}")));
    if !out.status.success() {
        die(format!("{what} failed:\n{}", String::from_utf8_lossy(&out.stderr).lines().take(20).collect::<Vec<_>>().join("\n")));
    }
}

/// nargo execute + bb prove for one circuit; deletes the inputs and witness afterwards.
fn prove(circuits: &Path, name: &str, toml: String, out: &Path) {
    let dir = circuits.join(name);
    let input = dir.join(format!("{JOB}.toml"));
    let witness = dir.join(format!("target/{JOB}.gz"));
    fs::write(&input, toml).unwrap();
    let cleanup = || {
        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&witness);
    };
    let bb = std::env::var("BB").unwrap_or_else(|_| format!("{}/.bb/bb", std::env::var("HOME").unwrap()));
    let ok = Command::new("nargo")
        .args(["execute", "--prover-name", JOB, JOB])
        .current_dir(&dir)
        .output()
        .map(|o| (o.status.success(), String::from_utf8_lossy(&o.stderr).into_owned()));
    match ok {
        Ok((true, _)) => {}
        Ok((false, err)) => {
            cleanup();
            die(format!("{name}: circuit rejected the inputs\n{}", err.lines().take(12).collect::<Vec<_>>().join("\n")))
        }
        Err(e) => {
            cleanup();
            die(format!("nargo: {e}"))
        }
    }
    let od = out.join(name);
    fs::create_dir_all(&od).unwrap();
    run(
        Command::new(bb)
            .args(["prove", "-t", "evm", "-b"])
            .arg(dir.join(format!("target/{name}.json")))
            .arg("-w")
            .arg(&witness)
            .arg("-k")
            .arg(dir.join("target/vk"))
            .arg("-o")
            .arg(&od),
        &format!("bb prove {name}"),
    );
    cleanup();
}

/// public_inputs file (32-byte words) → hex strings.
fn words(path: &Path) -> Vec<String> {
    fs::read(path).unwrap().chunks(32).map(|w| format!("0x{}", hex(w))).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: zk-assinar prove <signed.pdf> --cpf <cpf> [--salt <hex32>] [--out <dir>] | cpf <signed.pdf>";
    let (cmd, path) = match &a[..] {
        [c, p, ..] => (c.as_str(), p),
        _ => die(usage),
    };
    let flag = |k: &str| a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).cloned();
    let raw = fs::read(path).unwrap_or_else(|e| die(format!("{path}: {e}")));
    let s = pdf::parse(&raw).unwrap_or_else(|m| die(m));

    match cmd {
        "cpf" => println!("{}", String::from_utf8_lossy(&s.cpf)),
        "prove" => {
            let cpf: Vec<u8> = flag("--cpf").unwrap_or_else(|| die(usage)).bytes().filter(|c| !b".- ".contains(c)).collect();
            if !pdf::cpf_valid(&cpf) {
                die("--cpf must be 11 digits with valid check digits");
            }
            let salt = match flag("--salt") {
                Some(h) => unhex(&h),
                None => {
                    let mut b = vec![0u8; 32];
                    getrandom::getrandom(&mut b).unwrap();
                    b
                }
            };
            if salt.len() != 32 {
                die("--salt must be 32 bytes");
            }
            let out = PathBuf::from(flag("--out").unwrap_or_else(|| "work/out".into()));
            fs::create_dir_all(&out).unwrap();
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
            let circuits = root.join("circuits");
            let ca = unhex(&fs::read_to_string(root.join("backend/ca/ac_final_v1.modulus.hex")).unwrap());

            let mut tbs = s.tbs.clone();
            tbs.resize(pdf::TBS_MAX, 0);
            let doc = format!(
                "h = {}\nsigning_time = {}\ntbs = {}\ntbs_len = {}\nca_modulus = {}\nca_redc = {}\nca_sig = {}\ncpf = {}\nsalt = {}\n",
                bytes(&s.doc_hash),
                bytes(&s.signing_time),
                bytes(&tbs),
                s.tbs.len(),
                bytes(&ca),
                redc(&ca, 4096, 35),
                bytes(&s.ca_sig),
                bytes(&cpf),
                bytes(&salt),
            );
            let sa_hash: [u8; 32] = Sha256::digest(&s.signed_attrs).into();
            let signer = format!(
                "sa_hash = {}\nleaf_modulus = {}\nleaf_redc = {}\nleaf_sig = {}\ncpf = {}\nsalt = {}\n",
                bytes(&sa_hash),
                bytes(&s.leaf_modulus),
                redc(&s.leaf_modulus, 2048, 18),
                bytes(&s.leaf_sig),
                bytes(&cpf),
                bytes(&salt),
            );
            prove(&circuits, "signed_doc", doc, &out);
            prove(&circuits, "cpf_signer", signer, &out);

            fs::write(out.join("salt.hex"), hex(&salt)).unwrap();
            let summary = serde_json::json!({
                "signed_doc": words(&out.join("signed_doc/public_inputs")),
                "cpf_signer": words(&out.join("cpf_signer/public_inputs")),
            });
            fs::write(out.join("public.json"), serde_json::to_string_pretty(&summary).unwrap()).unwrap();
            println!("proofs written to {}", out.display());
        }
        _ => die(usage),
    }
}
