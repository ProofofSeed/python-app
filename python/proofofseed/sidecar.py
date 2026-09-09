# SPDX-License-Identifier: LGPL-3.0-or-later

"""The JSON metadata record written alongside a proof file."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, final

from . import _proofofseed as _rust
from ._fs import create_new_0600

FORMAT: str = _rust.SIDECAR_FORMAT


@final
@dataclass(frozen=True, slots=True)
class Versions:
    """The tool versions a proof was produced with."""

    cli: str
    deterministic_entropy_version: int

    def __post_init__(self) -> None:
        if not self.cli:
            raise ValueError("cli version must not be empty")
        if self.deterministic_entropy_version < 0:
            raise ValueError("deterministic_entropy_version must not be negative")


@final
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
    #: The witness byte length, for the statements whose circuit allocates one input per
    #: witness byte.
    witness_len: int | None = None
    #: The byte length of the BIP-39 PBKDF2 salt.
    salt_len: int | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.num_iters <= _rust.MAX_RESPONSES:
            raise ValueError(
                f"num_iters {self.num_iters} is outside 1..={_rust.MAX_RESPONSES}"
            )
        if self.rounds < 1:
            raise ValueError(f"rounds must be positive, got {self.rounds}")
        if self.entropy_mode not in ("deterministic", "trng"):
            raise ValueError(f"unknown entropy mode {self.entropy_mode!r}")
        if self.range is not None:
            start, end = self.range
            if not 0 <= start < end <= self.num_iters:
                raise ValueError(
                    f"range {start}..{end} is outside the {self.num_iters} responses"
                )
        if self.stream_bytes < 0:
            raise ValueError("stream_bytes must not be negative")
        if self.witness_len is not None and self.witness_len < 1:
            raise ValueError("witness_len must be positive when present")
        if self.salt_len is not None and self.salt_len < 8:
            raise ValueError("salt_len must cover the eight-byte BIP-39 constant")

    @staticmethod
    def _sidecar_path(proof: Path) -> Path:
        return proof.with_name(proof.name + ".json")

    def to_json(self) -> str:
        """Renders the record as the sidecar file's JSON text."""
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
        """Writes the record beside a proof file, mode 0600 and refusing to overwrite."""
        path = self._sidecar_path(proof)
        with create_new_0600(path) as f:
            f.write((self.to_json() + "\n").encode("utf-8"))

    @classmethod
    def read(cls, proof: Path) -> Sidecar:
        """Reads the record written beside a proof file."""
        path = cls._sidecar_path(proof)
        record = json.loads(path.read_text())
        if record.get("format") != FORMAT:
            raise ValueError(
                f"sidecar {path} has format {record.get('format')!r}, expected {FORMAT!r}"
            )
        rng = record["range"]
        if rng is not None and len(rng) != 2:
            raise ValueError(f"sidecar {path} has a malformed range {rng!r}")
        versions = record["versions"]
        return cls(
            statement=str(record["statement"]),
            family=str(record["family"]),
            num_iters=int(record["num_iters"]),
            rounds=int(record["rounds"]),
            path=record["path"],
            index=record["index"],
            chain_code=record["chain_code"],
            binding=str(record["binding"]),
            range=(int(rng[0]), int(rng[1])) if rng else None,
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
        """The fields that must agree across the ranges of one proof."""
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
