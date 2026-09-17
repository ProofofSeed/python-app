# Security posture

## The witness is the raw mnemonic

This package takes the mnemonic into process memory, and derives the seed and every intermediate key there.
That is a categorically higher-stakes witness than a hardware wallet's, which never exposes anything above the derived key the statement is about.
The recommended deployment is a trusted, ideally air-gapped host.

The package does not source the mnemonic itself: the caller passes it in.
It is never read from the command line or from an environment variable, and nothing in the package writes it to a file or a log.
No guarantee is made about swap or core dumps, because none is implemented.

Secrets stay on the Rust side of the binding.
The mnemonic and passphrase cross the FFI as bytes, are consumed by the derivation, and the derived key material is zeroized by `proofofseed-host`.
For a statement whose output is itself key material, `prove` returns only the Keccak-256 commitment, so the raw output never enters Python-managed memory.
`derive` refuses such a statement unless called with `reveal=True`, which is the one path that hands key material to Python; the refusal names the commitment instead.

## File creation

Proof files and sidecars are created with `O_WRONLY | O_CREAT | O_EXCL` and mode `0600` passed to `open`.

- `O_EXCL` refuses to overwrite an existing file and refuses to follow a symlink planted at the path, so a proof cannot be redirected into a shared directory.
- Setting the mode at open time leaves no window in which the file exists world-readable, which a create-then-`chmod` would.

The same rule governs the sidecar because the sidecar carries the parent chain code for a child statement.

## What the sidecar discloses

A chain code is an extended-key component.
Combined with the parent public key it forms an xpub, which makes every non-hardened descendant address linkable; for a `normal-child` proof, the chain code together with the revealed child private key reconstructs the parent private key.
Hand a sidecar only to the intended verifier, and prefer hardened statements where the verifier already holds the anchor independently.

## Soundness is the verifier's to demand

A sidecar travels with a relayed proof, so the response count it states is not evidence.
`verify` and `assemble` refuse any proof carrying fewer than `min_responses` responses (default 438), whatever the sidecar claims, and the stream verifier rejects a proof with unread trailing responses.
A 438-response proof therefore cannot be passed off as a weaker one, and a weaker one cannot be accepted by default.
