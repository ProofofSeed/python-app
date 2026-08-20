# proofofseed (Python)

Create and verify zero-knowledge **proofs of seed** for software wallets from Python: ZKBoo proofs that a BIP-39/BIP-32/SLIP-10-derived key was derived from the seed you hold, bound to a verifier-chosen context.

A typed, `mypy --strict` wrapper (built with [Maturin](https://www.maturin.rs/)/PyO3) over the shared `proofofseed-host` Rust library — the same library the `proofofseed` CLI and the Ledger app use — so proofs produced here are byte-identical to the CLI's, and for the derived-key statements to a device holding the same seed. The two tools verify and assemble each other's proofs.

## Usage

```python
import proofofseed as pos

# Derive the public output a verifier will pin (an Ethereum address here):
d = pos.derive("ethereum-address", mnemonic=phrase, path="m/44'/60'/0'/0/0")

# Prove it (streams to disk; writes proof.pos.json alongside):
sidecar = pos.prove(
    "ethereum-address", mnemonic=phrase, path="m/44'/60'/0'/0/0",
    binding=tx_hash, out_path="proof.pos",
)
assert pos.verify("proof.pos", min_responses=pos.DEFAULT_RESPONSES)

# Resumable / parallel ranges of one proof, then assemble:
pos.prove("hardened-child", mnemonic=phrase, path="m/84'/0'", index="0'",
          responses=438, range=(0, 219), out_path="a.pos", binding=tx_hash)
pos.prove("hardened-child", mnemonic=phrase, path="m/84'/0'", index="0'",
          responses=438, range=(219, 438), out_path="b.pos", binding=tx_hash)
pos.assemble(["a.pos", "b.pos"], out_path="full.pos", expected_output=d.output)
```

`profile(statement)` returns size/memory numbers with no witness. The default response count is **438** (soundness error `(2/3)^438 ≤ 2^-256`, 128-bit post-quantum); `verify`/`assemble` refuse fewer than `min_responses` (default 438) regardless of what a relayed sidecar claims.

## Security

This library takes the **raw mnemonic** into process memory — a higher-stakes secret than a hardware wallet's derived keys. It does *not* read the mnemonic from the command line or environment; the caller sources it. Run on a trusted, ideally air-gapped host. Proof files and sidecars are written mode 0600; the sidecar carries the parent chain code for child statements (an extended-key component — treat it as sensitive). Ranged proofs must be produced with one build across all runs.

## Building

Requires the `proofofseed-core` and `zkboo` crates (local paths until published). With [uv](https://docs.astral.sh/uv/):

```sh
uv venv --python 3.13 && uv pip install maturin mypy black pytest
.venv/bin/maturin develop --release
.venv/bin/pytest && .venv/bin/mypy python && .venv/bin/black --check python tests
```
