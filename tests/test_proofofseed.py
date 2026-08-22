# SPDX-License-Identifier: LGPL-3.0-or-later

"""Milestone-3 acceptance tests for the ``proofofseed`` Python package.

Covers end-to-end round trips with the same refusals the CLI enforces, and the
load-bearing property: a proof produced through the Python API is byte-identical
to the CLI's for the same request (so the two interoperate and neither drifts
from the shared library or the device)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import proofofseed as pos
import pytest

MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"
)

# The CLI binary, if it has been built in the sibling repo — the byte-parity test
# skips cleanly when it is absent.
_CLI = (
    Path(__file__).resolve().parents[2]
    / "rust-app"
    / "target"
    / "release"
    / "proofofseed"
)


def test_derive_matches_the_published_address() -> None:
    d = pos.derive("ethereum-address", mnemonic=MNEMONIC, path="m/44'/60'/0'/0/0")
    assert d.output.hex().find("9858effd232b4033e47d90003d41ec34ecaeda94") != -1


def test_full_proof_round_trips(tmp_path: Path) -> None:
    proof = tmp_path / "p.pos"
    d = pos.derive("ethereum-address", mnemonic=MNEMONIC, path="m/44'/60'/0'/0/0")
    sidecar = pos.prove(
        "ethereum-address",
        mnemonic=MNEMONIC,
        path="m/44'/60'/0'/0/0",
        binding=b"\x00\x11",
        responses=2,
        out_path=proof,
    )
    assert sidecar.num_iters == 2
    assert (tmp_path / "p.pos.json").exists()
    assert pos.verify(proof, expected_output=d.output, min_responses=2)
    # A wrong expected output (mismatching the commitment) is refused.
    with pytest.raises(ValueError, match="commitment"):
        pos.verify(proof, expected_output=b"\x00" * 32, min_responses=2)
    # The soundness floor refuses a proof carrying fewer than demanded.
    with pytest.raises(ValueError, match="at least"):
        pos.verify(proof, expected_output=d.output)


def test_secret_output_statement_needs_the_output_supplied(tmp_path: Path) -> None:
    proof = tmp_path / "m.pos"
    pos.prove("master-key", mnemonic=MNEMONIC, responses=2, out_path=proof)
    sidecar = pos.Sidecar.read(proof)
    assert sidecar.output is None, "a secret output must not be stored in the sidecar"
    with pytest.raises(ValueError, match="secret"):
        pos.verify(proof, min_responses=2)


def test_ranged_partition_assembles_and_verifies(tmp_path: Path) -> None:
    d = pos.derive("hardened-child", mnemonic=MNEMONIC, path="m/84'/0'", index="0'")
    common = dict(
        mnemonic=MNEMONIC,
        path="m/84'/0'",
        index="0'",
        binding=b"tx",
        responses=6,
    )
    a = tmp_path / "a.pos"
    b = tmp_path / "b.pos"
    pos.prove("hardened-child", out_path=a, range=(0, 3), **common)  # type: ignore[arg-type]
    pos.prove("hardened-child", out_path=b, range=(3, 6), **common)  # type: ignore[arg-type]
    # A lone range is not a complete proof.
    with pytest.raises(ValueError, match="range, not a complete proof"):
        pos.verify(a, expected_output=d.output, min_responses=6)
    full = tmp_path / "full.pos"
    pos.assemble([a, b], out_path=full, expected_output=d.output, min_responses=6)
    assert pos.verify(full, expected_output=d.output, min_responses=6)
    # A gap refuses assembly.
    c = tmp_path / "c.pos"
    pos.prove("hardened-child", out_path=c, range=(4, 6), **common)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="gap in coverage"):
        pos.assemble(
            [a, c],
            out_path=tmp_path / "gap.pos",
            expected_output=d.output,
            min_responses=6,
        )


def test_trng_proofs_differ_between_runs(tmp_path: Path) -> None:
    p1 = tmp_path / "t1.pos"
    p2 = tmp_path / "t2.pos"
    for p in (p1, p2):
        pos.prove(
            "ethereum-address",
            mnemonic=MNEMONIC,
            path="m/44'/60'/0'/0/0",
            responses=1,
            out_path=p,
        )
    assert p1.read_bytes() != p2.read_bytes(), "TRNG runs must not share entropy"


def test_refuses_overwrite(tmp_path: Path) -> None:
    proof = tmp_path / "once.pos"
    pos.prove("master-key", mnemonic=MNEMONIC, responses=1, out_path=proof)
    with pytest.raises((ValueError, FileExistsError)):
        pos.prove("master-key", mnemonic=MNEMONIC, responses=1, out_path=proof)


@pytest.mark.skipif(not _CLI.exists(), reason="the proofofseed CLI is not built")
def test_python_proof_is_byte_identical_to_the_cli(tmp_path: Path) -> None:
    # The interop pin: a ranged (deterministic-entropy) proof from the Python API
    # equals the CLI's for the identical request, byte for byte.
    seed = tmp_path / "mnemonic.txt"
    seed.write_text(MNEMONIC)
    py_proof = tmp_path / "py.pos"
    pos.prove(
        "hardened-child",
        mnemonic=MNEMONIC,
        path="m/84'/0'",
        index="0'",
        binding=b"\xaa\xbb\xcc",
        responses=6,
        range=(1, 4),
        out_path=py_proof,
    )
    cli_proof = tmp_path / "cli.pos"
    subprocess.run(
        [
            str(_CLI),
            "prove",
            "--statement",
            "hardened-child",
            "--path",
            "m/84'/0'",
            "--index",
            "0'",
            "--binding",
            "aabbcc",
            "-n",
            "6",
            "--range",
            "1..4",
            "--seed-file",
            str(seed),
            "-o",
            str(cli_proof),
        ],
        check=True,
        capture_output=True,
    )
    assert py_proof.read_bytes() == cli_proof.read_bytes()


def _cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(_CLI), *args], capture_output=True, text=True, check=True
    )


@pytest.mark.skipif(not _CLI.exists(), reason="the proofofseed CLI is not built")
def test_cross_tool_assemble_both_directions(tmp_path: Path) -> None:
    # The CLI produces two ranges, Python assembles and verifies them; then Python
    # produces two ranges and the CLI assembles and verifies them. Exercises the
    # shared sidecar format and the tool-agnostic assembly key in both directions.
    seed = tmp_path / "mnemonic.txt"
    seed.write_text(MNEMONIC)
    d = pos.derive("hardened-child", mnemonic=MNEMONIC, path="m/84'/0'", index="0'")
    out_hex = tmp_path / "out.hex"
    out_hex.write_text(d.output.hex())

    def cli_prove(rng: str, out: Path) -> None:
        _cli(
            [
                "prove",
                "--statement",
                "hardened-child",
                "--path",
                "m/84'/0'",
                "--index",
                "0'",
                "--binding",
                "aabbcc",
                "-n",
                "6",
                "--range",
                rng,
                "--seed-file",
                str(seed),
                "-o",
                str(out),
            ]
        )

    # CLI ranges -> Python assemble + verify.
    ca, cb = tmp_path / "ca.pos", tmp_path / "cb.pos"
    cli_prove("0..3", ca)
    cli_prove("3..6", cb)
    full_py = tmp_path / "full_py.pos"
    pos.assemble([ca, cb], out_path=full_py, expected_output=d.output, min_responses=6)
    assert pos.verify(full_py, expected_output=d.output, min_responses=6)

    # Python ranges -> CLI assemble + verify.
    pa, pb = tmp_path / "pa.pos", tmp_path / "pb.pos"
    common = dict(
        mnemonic=MNEMONIC,
        path="m/84'/0'",
        index="0'",
        binding=b"\xaa\xbb\xcc",
        responses=6,
    )
    pos.prove("hardened-child", out_path=pa, range=(0, 3), **common)  # type: ignore[arg-type]
    pos.prove("hardened-child", out_path=pb, range=(3, 6), **common)  # type: ignore[arg-type]
    full_cli = tmp_path / "full_cli.pos"
    _cli(
        [
            "assemble",
            str(pa),
            str(pb),
            "-o",
            str(full_cli),
            "--expected-output-file",
            str(out_hex),
            "--min-responses",
            "6",
        ]
    )
    _cli(
        [
            "verify",
            "--proof",
            str(full_cli),
            "--expected-output-file",
            str(out_hex),
            "--min-responses",
            "6",
        ]
    )


def test_seed_statements_carry_their_witness_shape_and_verify(tmp_path: Path) -> None:
    """The seed statements allocate one circuit input per witness byte, so their
    witness length — and, for BIP-39, the PBKDF2 salt — are public parameters the
    verifier needs to rebuild the circuit. A sidecar that omits them leaves the
    verifier rebuilding the canonical test-vector circuit, which rejects every real
    proof: that is what these statements used to do."""
    for statement, kwargs, want_salt in (
        ("master-key", {}, False),
        ("bip39-seed", {"rounds": 2}, True),
    ):
        proof = tmp_path / f"{statement}.pos"
        sidecar = pos.prove(
            statement=statement,
            mnemonic=MNEMONIC,
            responses=8,
            out_path=proof,
            binding=b"\xaa\xbb",
            **kwargs,
        )
        assert sidecar.witness_len is not None and sidecar.witness_len > 0
        assert (sidecar.salt is not None) == want_salt
        secret = pos.derive(statement=statement, mnemonic=MNEMONIC, **kwargs)
        assert pos.verify(proof, expected_output=secret.output, min_responses=8)


def test_a_seed_proof_does_not_verify_without_its_shape(tmp_path: Path) -> None:
    """The negative that keeps the field from being dropped again: strip the shape
    from the sidecar and the same proof must stop verifying."""
    proof = tmp_path / "mk.pos"
    pos.prove(
        statement="master-key",
        mnemonic=MNEMONIC,
        responses=8,
        out_path=proof,
        binding=b"\xaa\xbb",
    )
    secret = pos.derive(statement="master-key", mnemonic=MNEMONIC)
    assert pos.verify(proof, expected_output=secret.output, min_responses=8)

    sidecar_path = proof.with_name(proof.name + ".json")
    record = sidecar_path.read_text().replace('"witness_len": 64', '"witness_len": null')
    sidecar_path.write_text(record)
    assert not pos.verify(proof, expected_output=secret.output, min_responses=8)
