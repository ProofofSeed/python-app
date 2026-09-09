# Proof files, sidecars and assembly

## The proof file

The proof file is the raw byte stream, identical to what a device emits for the same request.
It carries no header of its own, which is what makes it interoperable with the device and with the `proofofseed` CLI.

## The sidecar

Metadata is written alongside the proof as `<proof>.json`, in the format `proofofseed-sidecar/1` shared with the CLI, so the two tools verify and assemble each other's proofs.
Verification never trusts the sidecar for soundness: the verifier re-derives everything from the stream under the parameters it chooses to trust.

Secrecy rule: for statements whose public output is itself key material (master key, hardened child, normal child, BIP-39 seed) the sidecar stores only `output_keccak256`.
The verifier supplies the expected output out of band and the commitment cross-checks it.
The genuinely public outputs (public key, Ethereum address) are stored plainly in `output`.

## Witness shape

The seed statements allocate one circuit input per witness byte, so the witness length is a public parameter of the circuit rather than an internal detail.
A verifier that does not receive it rebuilds the canonical test-vector circuit and rejects every real proof.
`witness_len` therefore travels in the sidecar, and `tests/test_proofofseed.py` keeps a negative that strips it and requires the same proof to stop verifying.

For BIP-39 the salt is `"mnemonic"` followed by the passphrase, and its bytes are witness.
Only `salt_len` travels.
A verifier rebuilds the circuit from the two lengths and never receives the passphrase; what it can infer is how long one is (`salt_len - 8`), or that there is none (`salt_len == 8`).

## Assembly

Ranges of one proof are assembled by checking that they share one request and version set, that their ranges exactly partition the response sequence, and that each file matches its recorded digest.
The assembled proof is verified before anything is written.

The version component of the assembly key is `deterministic_entropy_version`, not the tool's own version string.
That version is the only one governing whether two ranges share prover entropy, so a CLI range and a Python range of the same request assemble together while a change to the entropy transcript separates them.

Ranged proving requires one build across all runs of a proof.
