//! Wall-clock + peak-RSS probe for the Plonky2 prover hot path.
//!
//! ROADMAP step 9 ("R2 — measure on M3 Ultra") tracks three budgets that
//! the node binary must respect at production parameters (`MAX_IN_COINS`
//! = `MAX_OUT_COINS` = 8, Phase 2b outer at degree 16):
//!
//!   - warm `prove_*` wall ≤ 5 s (target ≤ 1 s)
//!   - cold start (`Prover::new` + first prove) ≤ 30 s
//!   - peak resident-set-size < 64 GB
//!
//! There is no automated path that produces those three numbers today.
//! The closest existing thing is the `#[ignore]`-d `prover_init_roundtrip`
//! integration test in `script-plonky2/src/lib.rs`, which only proves an
//! empty `Init` once and never reports RSS.
//!
//! This binary closes that gap. It is a standalone diagnostic tool —
//! NOT wired into `node`'s `main.rs`, never reached by Esplora /
//! Postgres / WebSocket code paths. It uses mimalloc as the global
//! allocator to match `node/src/main.rs` (PR #134), so the probe
//! measures the same allocator behaviour PRD experiences.
//!
//! ## Where to run
//!
//! Run **locally** on the Mac Studio M3 Ultra (96 GB) — that is the
//! reference machine ROADMAP step 9 budgets against. Do NOT run this
//! on the dfx01 self-hosted CI runner: a single warm sweep dominates
//! the m3-ultra runner slot for 5+ minutes and starves PR jobs.
//!
//! ```sh
//! cargo build --release -p node --bin probe_r2
//! RUST_LOG=warn ./target/release/probe_r2 \
//!     --warm-calls 5 \
//!     --output /tmp/r2-probe-$(date +%s).json
//! ```
//!
//! ## What it measures
//!
//! 1. `circuit_build_wall_ms` — `Prover::new()` (cold circuit
//!    construction; the slow fixed-point loop inside `build_circuit`).
//! 2. `prove_cold_wall_ms` — first `prove_initial` call (caches cold,
//!    rayon worker pool spun up for the first time).
//! 3. `prove_warm_wall_ms` — N follow-up `prove_account_update` calls
//!    against the SAME state + witness. These approximate the steady-
//!    state hot-path the live node hits per send.
//! 4. `peak_rss_kb` — high-water mark from `getrusage(RUSAGE_SELF)`.
//!    The kernel reports `ru_maxrss` in **bytes** on macOS and **KB**
//!    on Linux; this binary normalises both to KB and notes the
//!    convention in the JSON.
//!
//! Console output prints a ✓/✗ verdict against each of the three
//! ROADMAP budgets.
//!
//! ## What it intentionally does NOT do
//!
//! - No Postgres connection, no Esplora HTTP, no WebSocket subscription.
//! - No on-disk state — the AccountState + Coin witness lives in RAM.
//! - The warm sweep reuses the same `prev` proof + `cmp` witness;
//!   we want pure prove-wall, not the per-send bookkeeping overhead
//!   the live node carries (state lookups, MMR appends, DB writes).

// Match the production node binary's allocator (see node/src/main.rs
// and PR #134). The R2 budgets gate the PRD binary, so the probe
// must use the same allocator — otherwise warm-wall and peak-RSS
// numbers diverge from what PRD experiences.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use serde_json::json;

use zkcoins_program::circuit::main::MMR_PROOF_PATH_LEN;
use zkcoins_program::hash::{digest_to_bytes, hash_bytes, hash_concat, HashDigest, ZERO_HASH};
use zkcoins_program::inputs::CommitmentMerkleProofs;
use zkcoins_program::merkle::merkle_mountain_range::MerkleMountainRange;
use zkcoins_program::merkle::sparse_merkle_tree::SparseMerkleTree;
use zkcoins_program::types::{AccountState, MINTING_ADDRESS};
use zkcoins_prover::Prover;

// ROADMAP step 9 budgets (Mac Studio M3 Ultra reference).
const BUDGET_WARM_PROVE_MS: u128 = 5_000;
const BUDGET_COLD_START_MS: u128 = 30_000;
const BUDGET_PEAK_RSS_BYTES: u64 = 64 * 1024 * 1024 * 1024; // 64 GiB

// ===== CLI =====

#[derive(Debug)]
struct CliArgs {
    warm_calls: usize,
    output: Option<PathBuf>,
}

fn print_usage(program: &str) {
    eprintln!(
        "usage: {program} [--warm-calls N] [--output <path>]

  --warm-calls N   number of warm prove_account_update calls (default 5)
  --output PATH    write JSON report to PATH (default: stdout)

env: RUST_LOG (optional, log level — defaults to off here)
"
    );
}

fn parse_args(argv: Vec<String>) -> Result<CliArgs, String> {
    let mut iter = argv.into_iter();
    let program = iter.next().unwrap_or_else(|| "probe_r2".into());

    let mut warm_calls: usize = 5;
    let mut output: Option<PathBuf> = None;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--warm-calls" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--warm-calls requires a value".to_string())?;
                warm_calls = v
                    .parse::<usize>()
                    .map_err(|e| format!("--warm-calls: {e}"))?;
            }
            "--output" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--output requires a value".to_string())?;
                output = Some(PathBuf::from(v));
            }
            "-h" | "--help" => {
                print_usage(&program);
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(CliArgs { warm_calls, output })
}

// ===== Witness construction =====

/// Stable test pubkey, mirrors the helper in
/// `script-plonky2/src/lib.rs::tests::dummy_pubkey`.
fn dummy_pubkey(seed: u8) -> [u8; 33] {
    let mut pk = [0u8; 33];
    pk[0] = 0x02;
    for (i, b) in pk.iter_mut().enumerate().skip(1) {
        *b = seed.wrapping_add(i as u8);
    }
    pk
}

/// Off-circuit `CommitmentMerkleProofs` witness. Mirrors the private
/// `build_test_commitment_witness` helper in
/// `program-plonky2/src/circuit/main.rs` (test module — not reachable
/// from this crate). Reproduced here so the probe doesn't need a test
/// re-export.
fn build_commitment_witness(
    prev_asth: HashDigest,
    prev_ocr: HashDigest,
) -> (CommitmentMerkleProofs, HashDigest) {
    let pk_hash = hash_bytes(b"probe-r2-pubkey");
    let pk_key = digest_to_bytes(&pk_hash);

    let commitment = hash_concat(&prev_asth, &prev_ocr);

    let mut smt = SparseMerkleTree::new();
    smt.insert(pk_key, commitment)
        .expect("smt insert (fresh key into fresh tree)");
    let smt_root = smt.root();
    let (smt_inclusion, _) = smt
        .generate_inclusion_proof(&pk_key)
        .expect("smt inclusion proof");

    let prev_mmr_root = ZERO_HASH;
    let mmr_leaf = hash_concat(&smt_root, &prev_mmr_root);
    let mut mmr = MerkleMountainRange::new();
    mmr.append(mmr_leaf);
    let history_root_extended = mmr.root_extended(MMR_PROOF_PATH_LEN);
    let mmr_proof = mmr
        .get_proof(0)
        .expect("mmr proof for leaf 0")
        .extend_to(MMR_PROOF_PATH_LEN);

    let cmp = CommitmentMerkleProofs {
        commitment_root: smt_root,
        commitment_proof: smt_inclusion,
        commitment_root_history_proof: mmr_proof.clone(),
        commitment_root_mmr_sibling: prev_mmr_root,
        previous_root_history_proof: (smt_root, mmr_proof),
        commitment_account_state_hash: prev_asth,
        commitment_out_coins_root: prev_ocr,
    };
    (cmp, history_root_extended)
}

// ===== RSS sampling =====

/// Return current peak resident-set-size in KB.
///
/// `getrusage(RUSAGE_SELF).ru_maxrss` is the cleanest cross-platform
/// path. The unit differs by OS:
///
///   - Linux: kilobytes (already what we want).
///   - macOS / iOS / FreeBSD: bytes — divide by 1024.
///
/// `ru_maxrss` is the high-water mark over the process lifetime, so
/// calling this once at the end of the run is sufficient — sampling
/// during the prove loop would be wasted work.
fn peak_rss_kb() -> u64 {
    // SAFETY: `getrusage` is a POSIX syscall with no preconditions
    // beyond a valid out-param, which we provide as a fully-initialised
    // zeroed struct.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if rc != 0 {
        return 0;
    }
    let raw = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") || cfg!(target_os = "ios") || cfg!(target_os = "freebsd") {
        raw / 1024
    } else {
        raw
    }
}

// ===== Platform snapshot =====

fn cpu_brand() -> Option<String> {
    // macOS: `sysctl -n machdep.cpu.brand_string`. Best-effort —
    // silently None on Linux / other.
    if cfg!(target_os = "macos") {
        let out = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8(out.stdout).ok()?;
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    } else {
        None
    }
}

// ===== Main =====

fn run() -> Result<(), String> {
    let args = parse_args(std::env::args().collect())?;

    eprintln!("[probe_r2] starting — warm_calls={}", args.warm_calls);
    eprintln!(
        "[probe_r2] os={} arch={}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    // 1) Circuit build.
    eprintln!("[probe_r2] building circuit (cold) ...");
    let t = Instant::now();
    let prover = Prover::new();
    let circuit_build_wall_ms = t.elapsed().as_millis();
    eprintln!("[probe_r2] circuit_build_wall_ms = {circuit_build_wall_ms}");

    // 2) Account state for the init proof + downstream updates.
    let mut account_state = AccountState::new(dummy_pubkey(7));
    account_state.owner = *MINTING_ADDRESS;
    account_state.balance = 1_000_000;

    // 3) Cold prove — first prove_initial after build.
    eprintln!("[probe_r2] proving initial (cold) ...");
    let t = Instant::now();
    let init_proof = prover
        .prove_initial(&account_state, ZERO_HASH)
        .map_err(|e| format!("prove_initial: {e}"))?;
    let prove_cold_wall_ms = t.elapsed().as_millis();
    eprintln!("[probe_r2] prove_cold_wall_ms = {prove_cold_wall_ms}");

    // Verify the init proof once so a regression in the prove path
    // doesn't quietly produce garbage timings.
    prover
        .verify(&init_proof)
        .map_err(|e| format!("verify cold init: {e}"))?;

    // 4) Build the AccountUpdate witness ONCE and reuse it across
    //    warm calls. We want pure prove-wall, not witness-construction
    //    cost.
    let prev_asth = account_state.hash();
    // Empty out-coins root coincides with `DEFAULT_HASHES[0]`. The
    // probe doesn't depend on coin slots being populated — the
    // AccountUpdate branch with all-inactive in/out coins is the
    // minimal hot-path that still exercises the recursive verifier
    // gadget, which dominates prove wall.
    let prev_ocr = init_proof_out_coins_root_from_init(&prev_asth);
    let (cmp, history_root_extended) = build_commitment_witness(prev_asth, prev_ocr);

    // 5) Warm prove sweep.
    let mut prove_warm_wall_ms: Vec<u128> = Vec::with_capacity(args.warm_calls);
    for i in 0..args.warm_calls {
        eprintln!("[probe_r2] warm prove {} / {} ...", i + 1, args.warm_calls);
        let t = Instant::now();
        let update_proof = prover
            .prove_account_update(&account_state, history_root_extended, &init_proof, &cmp)
            .map_err(|e| format!("warm prove_account_update #{i}: {e}"))?;
        let ms = t.elapsed().as_millis();
        prove_warm_wall_ms.push(ms);
        eprintln!("[probe_r2] warm[{i}] = {ms} ms");

        // Verify once on the first warm prove only — verification
        // wall doesn't matter for the budget, but a broken proof
        // would otherwise be invisible.
        if i == 0 {
            prover
                .verify(&update_proof)
                .map_err(|e| format!("verify warm #{i}: {e}"))?;
        }
    }

    let peak_rss = peak_rss_kb();

    // ===== Report =====

    let cold_start_ms = circuit_build_wall_ms + prove_cold_wall_ms;
    let warm_min = prove_warm_wall_ms.iter().min().copied().unwrap_or(0);
    let warm_max = prove_warm_wall_ms.iter().max().copied().unwrap_or(0);
    let warm_mean = if prove_warm_wall_ms.is_empty() {
        0
    } else {
        prove_warm_wall_ms.iter().sum::<u128>() / prove_warm_wall_ms.len() as u128
    };

    let report = json!({
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cpu": cpu_brand(),
        },
        "build_profile": "release",
        "circuit_build_wall_ms": circuit_build_wall_ms,
        "prove_cold_wall_ms": prove_cold_wall_ms,
        "prove_warm_wall_ms": prove_warm_wall_ms,
        "peak_rss_kb": peak_rss,
        "rss_unit_note":
            "macOS reports ru_maxrss in bytes; Linux reports KB. This tool normalises to KB.",
        "budgets": {
            "warm_prove_ms_max": BUDGET_WARM_PROVE_MS,
            "cold_start_ms_max": BUDGET_COLD_START_MS,
            "peak_rss_bytes_max": BUDGET_PEAK_RSS_BYTES,
        },
    });

    let json_text =
        serde_json::to_string_pretty(&report).map_err(|e| format!("serialise report: {e}"))?;

    if let Some(path) = args.output.as_ref() {
        let mut f =
            fs::File::create(path).map_err(|e| format!("create {}: {e}", path.display()))?;
        f.write_all(json_text.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        f.write_all(b"\n")
            .map_err(|e| format!("write nl {}: {e}", path.display()))?;
        eprintln!("[probe_r2] report -> {}", path.display());
    } else {
        println!("{json_text}");
    }

    // Console verdict against the three ROADMAP budgets.
    let peak_rss_bytes = peak_rss.saturating_mul(1024);
    let warm_ok = warm_max <= BUDGET_WARM_PROVE_MS;
    let cold_ok = cold_start_ms <= BUDGET_COLD_START_MS;
    let rss_ok = peak_rss_bytes < BUDGET_PEAK_RSS_BYTES;

    eprintln!();
    eprintln!("===== ROADMAP step 9 budgets =====");
    eprintln!(
        "  warm prove (max over {} calls): {} ms   {}  [budget {} ms]",
        args.warm_calls,
        warm_max,
        check(warm_ok),
        BUDGET_WARM_PROVE_MS
    );
    eprintln!(
        "  cold start (build + first prove): {} ms   {}  [budget {} ms]",
        cold_start_ms,
        check(cold_ok),
        BUDGET_COLD_START_MS
    );
    eprintln!(
        "  peak RSS: {} KB ({} MiB)   {}  [budget {} GiB]",
        peak_rss,
        peak_rss / 1024,
        check(rss_ok),
        BUDGET_PEAK_RSS_BYTES / (1024 * 1024 * 1024)
    );
    eprintln!();
    eprintln!(
        "  warm distribution: min {} / mean {} / max {} ms",
        warm_min, warm_mean, warm_max
    );

    Ok(())
}

fn check(ok: bool) -> &'static str {
    if ok {
        "PASS"
    } else {
        "FAIL"
    }
}

/// The post-Init `coin_history_root` is conventionally
/// `DEFAULT_HASHES[0]` — the empty SMT root. Independent of `prev_asth`
/// but kept as a function so the call site reads symmetrically. We
/// hash a sentinel to obtain that empty-tree root without depending on
/// the `DEFAULT_HASHES` private indexing.
fn init_proof_out_coins_root_from_init(_prev_asth: &HashDigest) -> HashDigest {
    // The empty SparseMerkleTree's root equals `DEFAULT_HASHES[0]` by
    // construction. Building one is cheap and avoids re-exporting the
    // const.
    SparseMerkleTree::new().root()
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("probe_r2: {e}");
            ExitCode::FAILURE
        }
    }
}
