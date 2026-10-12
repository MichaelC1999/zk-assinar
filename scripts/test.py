#!/usr/bin/env python3
"""End-to-end check: prove the sample PDF, then reconstruct what the proofs claim from the PDF
and CPF alone and compare.

    scripts/test.py [signed.pdf]        (CPF from $ZK_CPF, else read from the PDF's certificate)

Never prints the CPF or salt.
"""
import hashlib, json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PDF = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "Bank_Account_06_30_2026_assinado.pdf")
BIN = os.path.join(ROOT, "backend/target/release/zk-assinar")
BB = os.environ.get("BB", os.path.expanduser("~/.bb/bb"))
OUT = os.path.join(ROOT, "work/out")
fails = 0


def check(name, ok):
    global fails
    fails += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")


def run(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def join(hi, lo):  # two 128-bit public-input words -> 32 bytes
    return bytes.fromhex(hi[-32:] + lo[-32:])


print("build + prove")
subprocess.run([os.path.join(ROOT, "scripts/build.sh")], check=True, stdout=subprocess.DEVNULL)
cpf = os.environ.get("ZK_CPF") or run(BIN, "cpf", PDF).stdout.strip()
cpf = re.sub(r"[.\- ]", "", cpf)
r = run(BIN, "prove", PDF, "--cpf", cpf, "--out", OUT)
check("backend produced both proofs", r.returncode == 0)
if r.returncode:
    sys.exit(r.stderr)
pub = json.load(open(os.path.join(OUT, "public.json")))
doc, sig = pub["signed_doc"], pub["cpf_signer"]
salt = bytes.fromhex(open(os.path.join(OUT, "salt.hex")).read())

print("verify proofs (bb)")
for c in ("signed_doc", "cpf_signer"):
    v = run(BB, "verify", "-t", "evm", "-k", f"{ROOT}/circuits/{c}/target/vk",
            "-p", f"{OUT}/{c}/proof", "-i", f"{OUT}/{c}/public_inputs")
    check(f"{c} proof verifies", v.returncode == 0)

print("reconstruct from PDF + CPF")
pdf = open(PDF, "rb").read()
b, c, d = map(int, re.findall(rb"/ByteRange\s*\[\s*0\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", pdf)[-1])
doc_hash = hashlib.sha256(pdf[:b] + pdf[c:c + d]).digest()
check("doc hash in proof == SHA-256(PDF /ByteRange bytes)", join(doc[0], doc[1]) == doc_hash)
commit = lambda cpf, salt: hashlib.sha256(b"zk-assinar/cpf/v1" + cpf.encode() + salt).digest()
check("CPF commitment in proof == SHA-256(tag | CPF | salt)", join(doc[6], doc[7]) == commit(cpf, salt))
ca = bytes.fromhex(open(f"{ROOT}/backend/ca/ac_final_v1.modulus.hex").read().strip())
check("CA in proof == gov.br AC Final v1", join(doc[8], doc[9]) == hashlib.sha256(ca).digest())
check("proofs linked: signedAttrs digest, leaf key, CPF commitment", doc[2:8] == sig)

print("negative cases")
tampered = bytearray(pdf); tampered[100] ^= 1
check("one flipped PDF byte -> different doc hash",
      hashlib.sha256(bytes(tampered[:b] + tampered[c:c + d])).digest() != join(doc[0], doc[1]))
check("other CPF does not open the commitment", commit("11144477735", salt) != join(doc[6], doc[7]))
check("other salt does not open the commitment", commit(cpf, bytes(32)) != join(doc[6], doc[7]))
if cpf != "11144477735":
    r = run(BIN, "prove", PDF, "--cpf", "11144477735", "--out", os.path.join(ROOT, "work/neg"))
    check("other CPF cannot produce a proof", r.returncode != 0 and "signed_doc: circuit rejected" in r.stderr)

print("contract (forge)")
f = run("forge", "test", cwd=os.path.join(ROOT, "contracts"))
check("AttestationRegistry tests", f.returncode == 0)

print("ALL PASSED" if not fails else f"{fails} FAILED")
sys.exit(1 if fails else 0)
