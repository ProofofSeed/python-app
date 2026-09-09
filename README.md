# proofofseed (Python)

Creates and verifies zero-knowledge proofs of seed for software wallets: ZKBoo proofs that a BIP-39/BIP-32/SLIP-10-derived key was derived from a held seed, bound to a verifier-chosen context.
The package is a typed, `mypy --strict` wrapper built with [Maturin](https://www.maturin.rs/)/PyO3 over the shared `proofofseed-host` Rust library, the same library the `proofofseed` CLI and the ProofofSeed Ledger app use, so its proofs are byte-identical to the CLI's and — for the derived-key statements — to a device holding the same seed.

## Usage

```python
import proofofseed as pos

# The public output a verifier will pin.
d = pos.derive("ethereum-address", mnemonic=phrase, path="m/44'/60'/0'/0/0")

# A proof of it, streamed to disk with its sidecar alongside.
sidecar = pos.prove(
    "ethereum-address", mnemonic=phrase, path="m/44'/60'/0'/0/0",
    binding=tx_hash, out_path="proof.pos",
)
assert pos.verify("proof.pos", min_responses=pos.DEFAULT_RESPONSES)

# Resumable or parallel ranges of one proof, then assembly.
pos.prove("hardened-child", mnemonic=phrase, path="m/84'/0'", index="0'",
          responses=438, range=(0, 219), out_path="a.pos", binding=tx_hash)
pos.prove("hardened-child", mnemonic=phrase, path="m/84'/0'", index="0'",
          responses=438, range=(219, 438), out_path="b.pos", binding=tx_hash)
pos.assemble(["a.pos", "b.pos"], out_path="full.pos", expected_output=d.output)
```

`profile(statement)` reports size and memory numbers without a witness.
The default response count is 438, a soundness error of `(2/3)^438 <= 2^-256` and 128-bit post-quantum.
`verify` and `assemble` refuse fewer than `min_responses` responses regardless of what a relayed sidecar claims.

## Security

The package takes the raw mnemonic into process memory, which is a higher-stakes witness than a hardware wallet's derived keys; run it on a trusted, ideally air-gapped host.
It never reads the mnemonic from the command line or the environment.
Proof files and sidecars are created mode 0600, and a sidecar carries the parent chain code for child statements.
Ranged proofs must be produced with one build across all runs.
The full posture is in [`knowledge/security.md`](knowledge/security.md).

## Building

The `proofofseed-core` and `zkboo` crates are resolved by path until they are published.
With [uv](https://docs.astral.sh/uv/):

```sh
uv venv --python 3.13 && uv pip install maturin mypy black pytest
.venv/bin/maturin develop --release
.venv/bin/pytest && .venv/bin/mypy python && .venv/bin/black --check python tests
```

## Structure

- `python/proofofseed/` — the typed Python API: `__init__.py` (the public surface), `sidecar.py` (the metadata record), `_fs.py` (exclusive 0600 file creation), `_proofofseed.pyi` (stubs for the compiled extension).
- `src/lib.rs` — the PyO3 bindings over `proofofseed-host`.
- `tests/` — round trips, refusals, and byte-parity against the CLI.
- `knowledge/` — design records.

Licensed LGPL-3.0-or-later; every source file carries an SPDX header.
