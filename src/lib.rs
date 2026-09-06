// SPDX-License-Identifier: LGPL-3.0-or-later

//! PyO3 bindings over `proofofseed-host`: the low-level prove / verify / derive /
//! profile primitives the Python package (`proofofseed`) wraps in a typed API.
//! Every proof-producing path goes through the shared `statement::resolve`, so
//! Python proofs are byte-identical to the CLI's and to a device's for the same
//! request. Secrets stay in Rust: the mnemonic and passphrase arrive as bytes,
//! are used for the derivation, and the derived key material is zeroized by the
//! shared library.

use std::io::Write as _;

use proofofseed_circuits::ranged::DETERMINISTIC_ENTROPY_VERSION;
use proofofseed_host::statement::{
    Statement, family_from_name, fresh_entropy, resolve, ResolveParams,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

const DEFAULT_RESPONSES: usize = 438;
const MAX_RESPONSES: usize = 512;
const SIDECAR_FORMAT: &str = "proofofseed-sidecar/1";

fn err(message: String) -> PyErr {
    PyValueError::new_err(message)
}

fn statement_of(name: &str) -> PyResult<Statement> {
    Statement::from_name(name).ok_or_else(|| err(format!("unknown statement {name:?}")))
}

fn family_of(name: &str) -> PyResult<proofofseed_circuits::request::Family> {
    family_from_name(name).ok_or_else(|| err(format!("unknown family {name:?}")))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn keccak(data: &[u8]) -> [u8; 32] {
    use zkboo::crypto::Hasher;
    let mut h = proofofseed_circuits::hasher::Keccak256Hasher::new();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_into(&mut out);
    out
}

/// A writer that Keccak-256-hashes everything written through it (so the proof
/// stream's digest is computed as it streams, without a re-read).
struct HashingWriter<W: std::io::Write> {
    inner: W,
    hasher: proofofseed_circuits::hasher::Keccak256Hasher,
}

impl<W: std::io::Write> std::io::Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use zkboo::crypto::Hasher;
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn format_path(path: &[u32]) -> String {
    let mut s = String::from("m");
    for &c in path {
        s.push('/');
        s.push_str(&(c & 0x7fff_ffff).to_string());
        if c & 0x8000_0000 != 0 {
            s.push('\'');
        }
    }
    s
}

fn format_index(index: u32) -> String {
    let mut s = (index & 0x7fff_ffff).to_string();
    if index & 0x8000_0000 != 0 {
        s.push('\'');
    }
    s
}

/// Resolve a request from a mnemonic and stream the proof to `out_path`,
/// returning a metadata dict the Python layer turns into a sidecar. `range` is
/// `(start, end)` or `None`; `path` is a list of u32 components (hardened bit
/// set) or `None`; `index` is a u32 or `None`.
#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (out_path, statement, family, num_iters, rounds, binding, mnemonic, passphrase, path=None, index=None, range=None))]
fn prove_to_file(
    py: Python<'_>,
    out_path: &str,
    statement: &str,
    family: &str,
    num_iters: usize,
    rounds: usize,
    binding: &[u8],
    mnemonic: &[u8],
    passphrase: &[u8],
    path: Option<Vec<u32>>,
    index: Option<u32>,
    range: Option<(u16, u16)>,
) -> PyResult<Py<PyDict>> {
    let stmt = statement_of(statement)?;
    let fam = family_of(family)?;
    let resolved = resolve(ResolveParams {
        statement: stmt,
        family: fam,
        path,
        index,
        num_iters,
        rounds,
        binding: binding.to_vec(),
        range,
        mnemonic,
        passphrase,
    })
    .map_err(err)?;
    let output = resolved.circuit.output();
    let entropy = match &resolved.digest {
        Some(digest) => resolved.circuit.entropy_for(digest),
        None => fresh_entropy().map_err(err)?,
    };
    let (start, end) = range.map_or((0, num_iters), |(a, b)| (a as usize, b as usize));
    // Create the proof mode 0600 at open time (O_EXCL refuses to overwrite or
    // follow a symlink; setting the mode on the OpenOptions avoids the brief
    // world-readable window a create-then-chmod would leave).
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(out_path)
        .map_err(|e| err(format!("cannot create {out_path}: {e} (refusing to overwrite)")))?;
    let mut writer = {
        use zkboo::crypto::Hasher;
        HashingWriter {
            inner: std::io::BufWriter::new(file),
            hasher: proofofseed_circuits::hasher::Keccak256Hasher::new(),
        }
    };
    let written = resolved
        .circuit
        .prove_to(num_iters, (start, end), &*entropy, &resolved.request.binding, &mut writer)
        .map_err(|e| err(format!("proof streaming failed: {e}")))?;
    writer.flush().map_err(|e| err(format!("proof streaming failed: {e}")))?;
    let stream_keccak = {
        use zkboo::crypto::Hasher;
        let mut out = [0u8; 32];
        writer.hasher.finalize_into(&mut out);
        out
    };
    let req = &resolved.request;
    let meta = PyDict::new(py);
    meta.set_item("format", SIDECAR_FORMAT)?;
    meta.set_item("statement", stmt.name())?;
    meta.set_item("family", family)?;
    meta.set_item("num_iters", num_iters)?;
    meta.set_item("rounds", rounds)?;
    meta.set_item("path", req.path.as_deref().map(format_path))?;
    meta.set_item("index", req.index.map(format_index))?;
    meta.set_item("chain_code", req.chain_code.map(|cc| hex(&cc)))?;
    meta.set_item("binding", hex(&req.binding))?;
    meta.set_item("range", range)?;
    meta.set_item("entropy_mode", if range.is_some() { "deterministic" } else { "trng" })?;
    // Only the commitment crosses the FFI for a secret-output statement; the raw
    // output (which is key material there) never enters Python-managed memory.
    meta.set_item("output_is_secret", stmt.output_is_secret())?;
    meta.set_item("output", (!stmt.output_is_secret()).then(|| hex(&output)))?;
    meta.set_item("output_keccak256", hex(&keccak(&output)))?;
    meta.set_item("stream_bytes", written)?;
    meta.set_item("stream_keccak256", hex(&stream_keccak))?;
    // The seed statements' circuits allocate one input per witness byte, so the shape
    // has to reach the verifier or it rebuilds the canonical test-vector circuit and
    // rejects the proof. Two lengths and nothing else: the salt's bytes are witness, so
    // a BIP-39 passphrase never leaves the prover.
    meta.set_item(
        "witness_len",
        resolved.witness_shape.as_ref().map(|(n, _)| *n),
    )?;
    meta.set_item(
        "salt_len",
        resolved.witness_shape.as_ref().and_then(|(_, salt_len)| *salt_len),
    )?;
    meta.set_item("deterministic_entropy_version", DETERMINISTIC_ENTROPY_VERSION)?;
    Ok(meta.into())
}

/// Derive a statement's public output (no proof); returns `(output, chain_code)`
/// as hex, `chain_code` being `None` for the non-child statements.
#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (statement, family, rounds, mnemonic, passphrase, path=None, index=None))]
fn derive_output(
    statement: &str,
    family: &str,
    rounds: usize,
    mnemonic: &[u8],
    passphrase: &[u8],
    path: Option<Vec<u32>>,
    index: Option<u32>,
) -> PyResult<(String, Option<String>)> {
    let stmt = statement_of(statement)?;
    let fam = family_of(family)?;
    let resolved = resolve(ResolveParams {
        statement: stmt,
        family: fam,
        path,
        index,
        num_iters: 1,
        rounds,
        binding: Vec::new(),
        range: None,
        mnemonic,
        passphrase,
    })
    .map_err(err)?;
    let output = hex(&resolved.circuit.output());
    let chain_code = resolved.request.chain_code.map(|cc| hex(&cc));
    Ok((output, chain_code))
}

/// Verify a streamed proof against the expected public output.
#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (statement, family, output, stream, num_iters, binding, rounds, chain_code=None, index=None, witness_len=None, salt_len=None))]
fn verify(
    statement: &str,
    family: &str,
    output: &[u8],
    stream: &[u8],
    num_iters: usize,
    binding: &[u8],
    rounds: usize,
    chain_code: Option<&[u8]>,
    index: Option<u32>,
    witness_len: Option<usize>,
    salt_len: Option<usize>,
) -> PyResult<bool> {
    let stmt = statement_of(statement)?;
    let fam = family_of(family)?;
    Ok(proofofseed_host::verify_with_shape(
        stmt.id(),
        output,
        stream,
        num_iters,
        binding,
        rounds,
        chain_code,
        index,
        fam as u8,
        witness_len,
        salt_len,
    ))
}

/// Proof size and memory numbers for a statement (no witness).
#[pyfunction]
#[pyo3(signature = (statement, family, rounds))]
fn profile(py: Python<'_>, statement: &str, family: &str, rounds: usize) -> PyResult<Py<PyDict>> {
    let stmt = statement_of(statement)?;
    let fam = family_of(family)?;
    let circuit =
        proofofseed_host::statement::dummy_circuit(stmt, fam, rounds).map_err(err)?;
    let prof = circuit.profile();
    let d = PyDict::new(py);
    d.set_item("response_bytes", prof.response_size::<[u8; 32], [u8; 32]>())?;
    d.set_item("prover_memory", prof.prover_mem_usage::<usize>().total())?;
    d.set_item("executor_memory", prof.executor_mem_usage::<usize>().total())?;
    Ok(d.into())
}

/// The off-device public output for a statement's canonical test vector, or
/// `None`; used to verify the secp256k1 statements.
#[pyfunction]
#[pyo3(signature = (statement, rounds=2048, family="bip32-secp256k1"))]
fn expected_output(
    py: Python<'_>,
    statement: &str,
    rounds: usize,
    family: &str,
) -> PyResult<Option<Py<PyBytes>>> {
    let stmt = statement_of(statement)?;
    let fam = family_of(family)?;
    Ok(proofofseed_host::expected_output(stmt.id(), rounds, fam as u8)
        .map(|b| PyBytes::new(py, &b).unbind()))
}

/// Responses needed for `bits` bits of soundness (`n_eps`).
#[pyfunction]
fn n_eps(bits: u32) -> usize {
    proofofseed_host::n_eps(bits)
}

/// Keccak-256 of `data` (the suite hash used by the proof sidecars).
#[pyfunction]
fn keccak256(py: Python<'_>, data: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, &keccak(data)).unbind()
}

#[pymodule]
fn _proofofseed(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("DEFAULT_RESPONSES", DEFAULT_RESPONSES)?;
    m.add("MAX_RESPONSES", MAX_RESPONSES)?;
    m.add("DETERMINISTIC_ENTROPY_VERSION", DETERMINISTIC_ENTROPY_VERSION)?;
    m.add("SIDECAR_FORMAT", SIDECAR_FORMAT)?;
    m.add_function(wrap_pyfunction!(prove_to_file, m)?)?;
    m.add_function(wrap_pyfunction!(derive_output, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(profile, m)?)?;
    m.add_function(wrap_pyfunction!(expected_output, m)?)?;
    m.add_function(wrap_pyfunction!(n_eps, m)?)?;
    m.add_function(wrap_pyfunction!(keccak256, m)?)?;
    Ok(())
}
