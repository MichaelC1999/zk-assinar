#!/usr/bin/env bash
# Compile both circuits, write their EVM verification keys and Solidity verifiers,
# and build the backend.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BB=${BB:-$HOME/.bb/bb}
for c in signed_doc cpf_signer; do
  (cd "$ROOT/circuits/$c" && nargo compile >/dev/null &&
    "$BB" write_vk -b "target/$c.json" -o target -t evm >/dev/null 2>&1)
  # Each generated file defines HonkVerifier; give each a unique contract name.
  name=$(python3 -c "print(''.join(w.title() for w in '$c'.split('_')))")Verifier
  "$BB" write_solidity_verifier -k "$ROOT/circuits/$c/target/vk" -o "$ROOT/contracts/src/$name.sol" -t evm >/dev/null 2>&1
  sed -i '' "s/contract HonkVerifier /contract $name /" "$ROOT/contracts/src/$name.sol"
  echo "$c: $("$BB" gates -b "$ROOT/circuits/$c/target/$c.json" 2>/dev/null | grep -o '"circuit_size": [0-9]*')"
done
cargo build --release --quiet --manifest-path "$ROOT/backend/Cargo.toml"
