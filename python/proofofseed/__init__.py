# SPDX-License-Identifier: LGPL-3.0-or-later

"""Creates and verifies zero-knowledge proofs of seed for software wallets."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import _proofofseed as _rust
from ._fs import create_new_0600
from .sidecar import Sidecar, Versions

__version__ = "0.1.0"

DEFAULT_RESPONSES: int = _rust.DEFAULT_RESPONSES
MAX_RESPONSES: int = _rust.MAX_RESPONSES

STATEMENTS: tuple[str, ...] = (
    "master-key",
    "hardened-child",
    "bip39-seed",
    "public-key",
    "normal-child",
    "ethereum-address",
)
FAMILIES: tuple[str, ...] = ("bip32-secp256k1", "slip10-ed25519")

_HARDENED = 0x8000_0000


def parse_path(path: str) -> list[int]:
    """Parses a BIP-32 path into a list of u32 components with the hardened bit set."""
    text = path.strip()
    for prefix in ("m/", "M/"):
        if text.startswith(prefix):
            body = text[len(prefix) :]
            break
    else:
        if text in ("m", "M"):
            return []
        raise ValueError(f"path {path!r} must start with m/")
    if not body:
        return []
    return [parse_component(part) for part in body.split("/")]


def parse_component(component: str) -> int:
    """Parses a single path component or child index."""
    hardened = component.endswith(("'", "h", "H"))
    digits = component[:-1] if hardened else component
    try:
        value = int(digits)
    except ValueError:
        raise ValueError(f"invalid path component {component!r}") from None
    if not 0 <= value < _HARDENED:
        raise ValueError(f"path component {value} out of range (must be < 2**31)")
    return (_HARDENED | value) if hardened else value


def _as_bytes(value: str | bytes) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


@dataclass(frozen=True, slots=True)
class ProfileResult:
    """Size and memory numbers for a statement, derived without a witness."""

    response_bytes: int
    prover_memory: int
    executor_memory: int

    def full_proof_bytes(self, responses: int = DEFAULT_RESPONSES) -> int:
        return self.response_bytes * responses


@dataclass(frozen=True, slots=True)
class DeriveResult:
    """A statement's public output, with the parent chain code for a child statement."""

    output: bytes
    chain_code: bytes | None


def profile(
    statement: str, *, family: str = "bip32-secp256k1", rounds: int = 2048
) -> ProfileResult:
    """Reports the proof size and the prover and executor memory for a statement."""
    d = _rust.profile(statement, family, rounds)
    return ProfileResult(
        response_bytes=d["response_bytes"],
        prover_memory=d["prover_memory"],
        executor_memory=d["executor_memory"],
    )


def derive(
    statement: str,
    *,
    mnemonic: str | bytes,
    passphrase: str | bytes = b"",
    family: str = "bip32-secp256k1",
    path: str | list[int] | None = None,
    index: str | int | None = None,
    rounds: int = 2048,
) -> DeriveResult:
    """Derives a statement's public output from the mnemonic, for the verifier to pin."""
    comps = parse_path(path) if isinstance(path, str) else path
    idx = parse_component(index) if isinstance(index, str) else index
    output_hex, chain_code_hex = _rust.derive_output(
        statement,
        family,
        rounds,
        _as_bytes(mnemonic),
        _as_bytes(passphrase),
        comps,
        idx,
    )
    return DeriveResult(
        output=bytes.fromhex(output_hex),
        chain_code=bytes.fromhex(chain_code_hex) if chain_code_hex else None,
    )


def prove(
    statement: str,
    *,
    mnemonic: str | bytes,
    out_path: str | Path,
    passphrase: str | bytes = b"",
    family: str = "bip32-secp256k1",
    path: str | list[int] | None = None,
    index: str | int | None = None,
    responses: int = DEFAULT_RESPONSES,
    rounds: int = 2048,
    binding: bytes = b"",
    range: tuple[int, int] | None = None,
) -> Sidecar:
    """Creates a proof, streaming it to a file and writing its sidecar alongside."""
    if not 1 <= responses <= MAX_RESPONSES:
        raise ValueError(f"responses must be in 1..={MAX_RESPONSES}")
    if len(binding) > 255:
        raise ValueError(
            f"binding is {len(binding)} bytes; the wire format caps it at 255"
        )
    if range is not None:
        start, end = range
        if not 0 <= start < end <= responses:
            raise ValueError(f"range must satisfy 0 <= start < end <= {responses}")
    comps = parse_path(path) if isinstance(path, str) else path
    idx = parse_component(index) if isinstance(index, str) else index
    out = Path(out_path)
    meta = _rust.prove_to_file(
        str(out),
        statement,
        family,
        responses,
        rounds,
        binding,
        _as_bytes(mnemonic),
        _as_bytes(passphrase),
        comps,
        idx,
        range,
    )
    sidecar = Sidecar(
        statement=meta["statement"],
        family=meta["family"],
        num_iters=meta["num_iters"],
        rounds=meta["rounds"],
        path=meta["path"],
        index=meta["index"],
        chain_code=meta["chain_code"],
        binding=meta["binding"],
        range=tuple(meta["range"]) if meta["range"] is not None else None,
        entropy_mode=meta["entropy_mode"],
        output=None if meta["output_is_secret"] else meta["output"],
        output_keccak256=meta["output_keccak256"],
        stream_bytes=meta["stream_bytes"],
        stream_keccak256=meta["stream_keccak256"],
        witness_len=meta["witness_len"],
        salt_len=meta["salt_len"],
        versions=Versions(
            cli=__version__,
            deterministic_entropy_version=meta["deterministic_entropy_version"],
        ),
    )
    sidecar.write(out)
    return sidecar


def _resolve_expected_output(sidecar: Sidecar, expected_output: bytes | None) -> bytes:
    if expected_output is not None:
        if _rust.keccak256(expected_output).hex() != sidecar.output_keccak256:
            raise ValueError(
                "the supplied expected output does not match the sidecar's commitment"
            )
        return expected_output
    if sidecar.output is not None:
        return bytes.fromhex(sidecar.output)
    raise ValueError(
        f"the {sidecar.statement} output is secret and absent from the sidecar; "
        f"supply expected_output (commitment: {sidecar.output_keccak256})"
    )


def verify(
    proof_path: str | Path,
    *,
    expected_output: bytes | None = None,
    binding: bytes | None = None,
    min_responses: int = DEFAULT_RESPONSES,
) -> bool:
    """Verifies a proof file against its sidecar."""
    proof = Path(proof_path)
    sidecar = Sidecar.read(proof)
    if sidecar.range is not None:
        start, end = sidecar.range
        if end - start != sidecar.num_iters:
            raise ValueError(
                f"this file carries responses {start}..{end} of {sidecar.num_iters} — "
                f"a range, not a complete proof; assemble first"
            )
    if sidecar.num_iters < min_responses:
        raise ValueError(
            f"proof carries {sidecar.num_iters} responses; caller demands at least "
            f"{min_responses}. Pass min_responses to accept less."
        )
    output = _resolve_expected_output(sidecar, expected_output)
    stream = proof.read_bytes()
    return _rust.verify(
        sidecar.statement,
        sidecar.family,
        output,
        stream,
        sidecar.num_iters,
        binding if binding is not None else bytes.fromhex(sidecar.binding),
        sidecar.rounds,
        bytes.fromhex(sidecar.chain_code) if sidecar.chain_code else None,
        parse_component(sidecar.index) if sidecar.index else None,
        sidecar.witness_len,
        sidecar.salt_len,
    )


def assemble(
    inputs: list[str | Path],
    *,
    out_path: str | Path,
    expected_output: bytes | None = None,
    min_responses: int = DEFAULT_RESPONSES,
) -> Sidecar:
    """Assembles range-proof files into one complete proof."""
    if not inputs:
        raise ValueError("assemble needs at least one range-proof file")
    paths = [Path(p) for p in inputs]
    parts: list[tuple[Path, Sidecar]] = []
    for p in paths:
        sidecar = Sidecar.read(p)
        if sidecar.entropy_mode != "deterministic":
            raise ValueError(f"{p}: not a ranged (deterministic) proof")
        if sidecar.range is None:
            raise ValueError(f"{p}: sidecar carries no range")
        parts.append((p, sidecar))
    reference = parts[0][1]
    key = reference.assembly_key()
    for p, sidecar in parts[1:]:
        if sidecar.assembly_key() != key:
            raise ValueError(f"{parts[0][0]} and {p} are not ranges of the same proof")
    parts.sort(key=lambda ps: ps[1].range[0])  # type: ignore[index]
    expected_start = 0
    for p, sidecar in parts:
        assert sidecar.range is not None
        start, end = sidecar.range
        if start != expected_start:
            raise ValueError(
                f"gap in coverage: responses {expected_start}..{start} missing (file {p})"
                if start > expected_start
                else f"overlapping coverage at response {start} (file {p})"
            )
        expected_start = end
    if expected_start != reference.num_iters:
        raise ValueError(
            f"coverage ends at response {expected_start} of {reference.num_iters}"
        )
    if reference.num_iters < min_responses:
        raise ValueError(
            f"assembled proof would carry {reference.num_iters} responses; "
            f"demanded at least {min_responses}"
        )
    assembled = bytearray()
    for p, sidecar in parts:
        chunk = p.read_bytes()
        if (
            len(chunk) != sidecar.stream_bytes
            or _rust.keccak256(chunk).hex() != sidecar.stream_keccak256
        ):
            raise ValueError(f"{p} does not match its sidecar's stream digest")
        assembled.extend(chunk)
    output = _resolve_expected_output(reference, expected_output)
    ok = _rust.verify(
        reference.statement,
        reference.family,
        output,
        bytes(assembled),
        reference.num_iters,
        bytes.fromhex(reference.binding),
        reference.rounds,
        bytes.fromhex(reference.chain_code) if reference.chain_code else None,
        parse_component(reference.index) if reference.index else None,
    )
    if not ok:
        raise ValueError("the assembled proof does not verify — nothing written")
    out = Path(out_path)
    with create_new_0600(out) as f:
        f.write(assembled)
    sidecar = Sidecar(
        statement=reference.statement,
        family=reference.family,
        num_iters=reference.num_iters,
        rounds=reference.rounds,
        path=reference.path,
        index=reference.index,
        chain_code=reference.chain_code,
        binding=reference.binding,
        range=None,
        entropy_mode="deterministic",
        output=reference.output,
        output_keccak256=reference.output_keccak256,
        stream_bytes=len(assembled),
        stream_keccak256=_rust.keccak256(bytes(assembled)).hex(),
        versions=reference.versions,
    )
    sidecar.write(out)
    return sidecar


__all__ = [
    "DEFAULT_RESPONSES",
    "MAX_RESPONSES",
    "STATEMENTS",
    "FAMILIES",
    "ProfileResult",
    "DeriveResult",
    "Sidecar",
    "Versions",
    "parse_path",
    "parse_component",
    "profile",
    "derive",
    "prove",
    "verify",
    "assemble",
]
