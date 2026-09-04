# SPDX-License-Identifier: LGPL-3.0-or-later

"""Type stubs for the compiled Rust extension (`proofofseed._proofofseed`)."""

from typing import Any

DEFAULT_RESPONSES: int
MAX_RESPONSES: int
DETERMINISTIC_ENTROPY_VERSION: int
SIDECAR_FORMAT: str

def prove_to_file(
    out_path: str,
    statement: str,
    family: str,
    num_iters: int,
    rounds: int,
    binding: bytes,
    mnemonic: bytes,
    passphrase: bytes,
    path: list[int] | None = ...,
    index: int | None = ...,
    range: tuple[int, int] | None = ...,
) -> dict[str, Any]: ...
def derive_output(
    statement: str,
    family: str,
    rounds: int,
    mnemonic: bytes,
    passphrase: bytes,
    path: list[int] | None = ...,
    index: int | None = ...,
) -> tuple[str, str | None]: ...
def verify(
    statement: str,
    family: str,
    output: bytes,
    stream: bytes,
    num_iters: int,
    binding: bytes,
    rounds: int,
    chain_code: bytes | None = ...,
    index: int | None = ...,
    witness_len: int | None = ...,
    salt_len: int | None = ...,
) -> bool: ...
def profile(statement: str, family: str, rounds: int) -> dict[str, int]: ...
def expected_output(
    statement: str, rounds: int = ..., family: str = ...
) -> bytes | None: ...
def n_eps(bits: int) -> int: ...
def keccak256(data: bytes) -> bytes: ...
