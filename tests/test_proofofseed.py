# SPDX-License-Identifier: LGPL-3.0-or-later

"""Acceptance tests for the ``proofofseed`` Python package."""

from __future__ import annotations

import subprocess
from pathlib import Path

import proofofseed as pos
import pytest

MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"
)

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
    with pytest.raises(ValueError, match="commitment"):
        pos.verify(proof, expected_output=b"\x00" * 32, min_responses=2)
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
    d = pos.derive(
        "hardened-child", mnemonic=MNEMONIC, path="m/84'/0'", index="0'", reveal=True
    )
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
    with pytest.raises(ValueError, match="range, not a complete proof"):
        pos.verify(a, expected_output=d.output, min_responses=6)
    full = tmp_path / "full.pos"
    pos.assemble([a, b], out_path=full, expected_output=d.output, min_responses=6)
    assert pos.verify(full, expected_output=d.output, min_responses=6)
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


def _cli_prove_range(seed: Path, rng: str, out: Path) -> None:
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


@pytest.mark.skipif(not _CLI.exists(), reason="the proofofseed CLI is not built")
def test_cross_tool_assemble_both_directions(tmp_path: Path) -> None:
    seed = tmp_path / "mnemonic.txt"
    seed.write_text(MNEMONIC)
    d = pos.derive(
        "hardened-child", mnemonic=MNEMONIC, path="m/84'/0'", index="0'", reveal=True
    )
    out_hex = tmp_path / "out.hex"
    out_hex.write_text(d.output.hex())
    ca, cb = tmp_path / "ca.pos", tmp_path / "cb.pos"
    _cli_prove_range(seed, "0..3", ca)
    _cli_prove_range(seed, "3..6", cb)
    full_py = tmp_path / "full_py.pos"
    pos.assemble([ca, cb], out_path=full_py, expected_output=d.output, min_responses=6)
    assert pos.verify(full_py, expected_output=d.output, min_responses=6)
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
    """A seed statement's sidecar carries its witness shape, and never the passphrase."""
    for statement, kwargs, want_salt_len in (
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
        assert (sidecar.salt_len is not None) == want_salt_len
        assert 'salt"' not in sidecar.to_json()
        secret = pos.derive(
            statement=statement, mnemonic=MNEMONIC, reveal=True, **kwargs
        )
        assert pos.verify(proof, expected_output=secret.output, min_responses=8)


def test_a_seed_proof_does_not_verify_without_its_shape(tmp_path: Path) -> None:
    """A seed proof stops verifying once its witness shape is stripped from the sidecar."""
    proof = tmp_path / "mk.pos"
    pos.prove(
        statement="master-key",
        mnemonic=MNEMONIC,
        responses=8,
        out_path=proof,
        binding=b"\xaa\xbb",
    )
    secret = pos.derive(statement="master-key", mnemonic=MNEMONIC, reveal=True)
    assert pos.verify(proof, expected_output=secret.output, min_responses=8)
    sidecar_path = proof.with_name(proof.name + ".json")
    record = sidecar_path.read_text().replace(
        '"witness_len": 64', '"witness_len": null'
    )
    sidecar_path.write_text(record)
    assert not pos.verify(proof, expected_output=secret.output, min_responses=8)


def test_derive_guards_secret_outputs() -> None:
    """A secret output is returned only on request, and a public one always."""
    with pytest.raises(ValueError, match="secret key material"):
        pos.derive("hardened-child", mnemonic=MNEMONIC, path="m/84'/0'", index="0'")
    with pytest.raises(ValueError, match="secret key material"):
        pos.derive("master-key", mnemonic=MNEMONIC)
    revealed = pos.derive(
        "hardened-child", mnemonic=MNEMONIC, path="m/84'/0'", index="0'", reveal=True
    )
    assert len(revealed.output) > 0
    public = pos.derive("public-key", mnemonic=MNEMONIC, path="m/44'/60'/0'/0/0")
    assert len(public.output) > 0
