# SPDX-License-Identifier: LGPL-3.0-or-later

"""The proof sidecar: JSON metadata written alongside a proof file, byte-format
compatible with the ``proofofseed`` CLI's sidecar (``proofofseed-sidecar/1``) so
the two tools can verify and assemble each other's proofs.

Metadata only: verification never trusts the sidecar for soundness. For the
statements whose public output is itself key material, only ``output_keccak256``
is stored; the genuinely public outputs are stored plainly in ``output``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import _proofofseed as _rust

FORMAT: str = _rust.SIDECAR_FORMAT


@dataclass(frozen=True, slots=True)
class Versions:
    """The tool versions a proof was produced with; ranged proofs must be
    assembled from one build (see the deterministic-entropy note)."""

    cli: str
    deterministic_entropy_version: int


@dataclass(frozen=True, slots=True)
class Sidecar:
    """A proof file's metadata record."""

    statement: str
    family: str
    num_iters: int
    rounds: int
    path: str | None
    index: str | None
    chain_code: str | None
    binding: str
    range: tuple[int, int] | None
    entropy_mode: str
    output: str | None
    output_keccak256: str
    stream_bytes: int
    stream_keccak256: str
    versions: Versions
    #: Witness byte length, for the seed statements whose circuit allocates one input
    #: per witness byte. A verifier needs it to rebuild the circuit; without it the
    #: verifier falls back to the canonical test vector and the proof is rejected.
    witness_len: int | None = None
    #: The byte length of the BIP-39 PBKDF2 salt (``"mnemonic"`` followed by the
    #: passphrase). The length only: the salt's bytes are witness, so a verifier rebuilds
    #: the circuit from the two lengths and never receives the passphrase. What it can
    #: infer is how long one is, or that there is none (``salt_len == 8``).
    salt_len: int | None = None

    @staticmethod
    def _sidecar_path(proof: Path) -> Path:
        return proof.with_name(proof.name + ".json")

    def to_json(self) -> str:
        record: dict[str, Any] = {
            "format": FORMAT,
            "statement": self.statement,
            "family": self.family,
            "num_iters": self.num_iters,
            "rounds": self.rounds,
            "path": self.path,
            "index": self.index,
            "chain_code": self.chain_code,
            "binding": self.binding,
            "range": list(self.range) if self.range is not None else None,
            "entropy_mode": self.entropy_mode,
            "output": self.output,
            "output_keccak256": self.output_keccak256,
            "stream_bytes": self.stream_bytes,
            "stream_keccak256": self.stream_keccak256,
            "witness_len": self.witness_len,
            "salt_len": self.salt_len,
            "versions": {
                "cli": self.versions.cli,
                "deterministic_entropy_version": (
                    self.versions.deterministic_entropy_version
                ),
            },
        }
        return json.dumps(record, indent=2)

    def write(self, proof: Path) -> None:
        # 0600 and O_EXCL like the proof file: the sidecar carries the anchored
        # parent chain code (an extended-key component), so it must not be
        # world-readable, overwrite a victim file, or follow a planted symlink.
        # The proof is always created fresh, so its sidecar never overwrites.
        from ._fs import create_new_0600

        path = self._sidecar_path(proof)
        with create_new_0600(path) as f:
            f.write((self.to_json() + "\n").encode("utf-8"))

    @classmethod
    def read(cls, proof: Path) -> Sidecar:
        path = cls._sidecar_path(proof)
        record = json.loads(path.read_text())
        if record.get("format") != FORMAT:
            raise ValueError(
                f"sidecar {path} has format {record.get('format')!r}, expected {FORMAT!r}"
            )
        num_iters = int(record["num_iters"])
        if not 1 <= num_iters <= _rust.MAX_RESPONSES:
            raise ValueError(
                f"sidecar {path} declares {num_iters} responses, outside 1..={_rust.MAX_RESPONSES}"
            )
        rng = record["range"]
        if rng is not None and len(rng) != 2:
            raise ValueError(f"sidecar {path} has a malformed range {rng!r}")
        range_: tuple[int, int] | None = (int(rng[0]), int(rng[1])) if rng else None
        if range_ is not None:
            start, end = range_
            if not start < end <= num_iters:
                raise ValueError(
                    f"sidecar {path} has range {start}..{end} outside its {num_iters} responses"
                )
        versions = record["versions"]
        return cls(
            statement=str(record["statement"]),
            family=str(record["family"]),
            num_iters=num_iters,
            rounds=int(record["rounds"]),
            path=record["path"],
            index=record["index"],
            chain_code=record["chain_code"],
            binding=str(record["binding"]),
            range=range_,
            entropy_mode=str(record["entropy_mode"]),
            output=record["output"],
            output_keccak256=str(record["output_keccak256"]),
            stream_bytes=int(record["stream_bytes"]),
            stream_keccak256=str(record["stream_keccak256"]),
            witness_len=(
                int(record["witness_len"])
                if record.get("witness_len") is not None
                else None
            ),
            salt_len=(
                int(record["salt_len"]) if record.get("salt_len") is not None else None
            ),
            versions=Versions(
                cli=str(versions["cli"]),
                deterministic_entropy_version=int(
                    versions["deterministic_entropy_version"]
                ),
            ),
        )

    def assembly_key(self) -> tuple[Any, ...]:
        """The fields that must agree across the ranges of one proof. The version
        component is the deterministic-entropy version — the only version that
        governs whether two ranges share prover entropy — not the tool's own
        version string, so a CLI range and a Python range assemble together."""
        return (
            self.statement,
            self.family,
            self.num_iters,
            self.rounds,
            self.path,
            self.index,
            self.chain_code,
            self.binding,
            self.output_keccak256,
            self.witness_len,
            self.salt_len,
            self.versions.deterministic_entropy_version,
        )
