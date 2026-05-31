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
//! ## Persistence (`--persist`)
//!
//! When `--persist` is set the probe writes its results into Postgres
//! via the `node::r2_probe` module (migration 0013):
//!
//!   * one row in `r2_probe_hosts` (idempotent on the natural key);
//!   * one row in `r2_probe_runs` with every scalar measurement plus
//!     run-time context (git sha, rustc version, allocator, circuit
//!     params) and the R2 budgets the run was checked against;
//!   * N rows in `r2_probe_warm_calls`, one per warm call.
//!
//! Requires `DATABASE_URL` — same env var the node binary uses; the
//! probe panics on bootstrap if it is unset, mirroring `node::DATABASE_URL`.
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
//! Console output prints a PASS/FAIL verdict against each of the three
//! ROADMAP budgets.
//!
//! ## What it intentionally does NOT do
//!
//! - No Esplora HTTP, no WebSocket subscription.
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
use sqlx::postgres::PgPoolOptions;
use tokio::runtime::Runtime;

use node::r2_probe::{
    detect, fetch_recent_summary, insert_run, insert_warm_calls, upsert_host, ProbeRun, SummaryRow,
};
use zkcoins_program::circuit::main::{MAX_IN_COINS, MAX_OUT_COINS, MMR_PROOF_PATH_LEN};
use zkcoins_program::hash::{digest_to_bytes, hash_bytes, hash_concat, HashDigest, ZERO_HASH};
use zkcoins_program::inputs::CommitmentMerkleProofs;
use zkcoins_program::merkle::merkle_mountain_range::MerkleMountainRange;
use zkcoins_program::merkle::sparse_merkle_tree::SparseMerkleTree;
use zkcoins_program::types::{AccountState, MINTING_ADDRESS};
use zkcoins_prover::Prover;

// ROADMAP step 9 budgets (Mac Studio M3 Ultra reference). These are
// the defaults; the CLI accepts overrides for experimentation.
const BUDGET_WARM_PROVE_MS: i64 = 5_000;
const BUDGET_COLD_START_MS: i64 = 30_000;
const BUDGET_PEAK_RSS_KB: i64 = 64 * 1024 * 1024; // 64 GiB in KB

/// Inner-pad-bits constant the active Phase 2b shape was built with
/// (see `INNER_PAD_BITS_STAGE_5D_NEXT_5` in
/// `program-plonky2/src/circuit/main.rs`). Recorded so the R2
/// regression view can later answer "did the prove wall move when
/// we changed pad bits?".
const INNER_PAD_BITS: i32 = 15;

// ===== CLI =====

#[derive(Debug)]
struct CliArgs {
    warm_calls: usize,
    output: Option<PathBuf>,
    persist: bool,
    notes: Option<String>,
    tags: Vec<String>,
    warm_budget_ms: i64,
    cold_budget_ms: i64,
    mem_budget_kb: i64,
}

fn print_usage(program: &str) {
    eprintln!(
        "usage: {program} [--warm-calls N] [--output <path>] [--persist] \
                [--notes <text>] [--tags a,b,c] \
                [--warm-budget-ms <ms>] [--cold-budget-ms <ms>] [--mem-budget-kb <kb>]

  --warm-calls N      number of warm prove_account_update calls (default 5)
  --output PATH       write JSON report to PATH (default: stdout)
  --persist           persist results into Postgres (requires DATABASE_URL)
  --notes TEXT        free-form note attached to the persisted run
  --tags A,B,C        comma-separated tags attached to the persisted run
  --warm-budget-ms N  override warm prove budget (default {warm} ms)
  --cold-budget-ms N  override cold-start budget (default {cold} ms)
  --mem-budget-kb N   override peak-RSS budget (default {mem} KB)

env:
  DATABASE_URL  required when --persist is set
  GIT_SHA       optional override for the recorded git sha
  RUSTC_VERSION optional override for the recorded rustc version
  RUST_LOG      optional, log level (defaults to off here)
",
        warm = BUDGET_WARM_PROVE_MS,
        cold = BUDGET_COLD_START_MS,
        mem = BUDGET_PEAK_RSS_KB
    );
}

fn parse_args(argv: Vec<String>) -> Result<CliArgs, String> {
    let mut iter = argv.into_iter();
    let program = iter.next().unwrap_or_else(|| "probe_r2".into());

    let mut warm_calls: usize = 5;
    let mut output: Option<PathBuf> = None;
    let mut persist = false;
    let mut notes: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();
    let mut warm_budget_ms = BUDGET_WARM_PROVE_MS;
    let mut cold_budget_ms = BUDGET_COLD_START_MS;
    let mut mem_budget_kb = BUDGET_PEAK_RSS_KB;

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
            "--persist" => {
                persist = true;
            }
            "--notes" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--notes requires a value".to_string())?;
                notes = Some(v);
            }
            "--tags" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--tags requires a value".to_string())?;
                tags = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--warm-budget-ms" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--warm-budget-ms requires a value".to_string())?;
                warm_budget_ms = v
                    .parse::<i64>()
                    .map_err(|e| format!("--warm-budget-ms: {e}"))?;
            }
            "--cold-budget-ms" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--cold-budget-ms requires a value".to_string())?;
                cold_budget_ms = v
                    .parse::<i64>()
                    .map_err(|e| format!("--cold-budget-ms: {e}"))?;
            }
            "--mem-budget-kb" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--mem-budget-kb requires a value".to_string())?;
                mem_budget_kb = v
                    .parse::<i64>()
                    .map_err(|e| format!("--mem-budget-kb: {e}"))?;
            }
            "-h" | "--help" => {
                print_usage(&program);
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(CliArgs {
        warm_calls,
        output,
        persist,
        notes,
        tags,
        warm_budget_ms,
        cold_budget_ms,
        mem_budget_kb,
    })
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

// ===== Run-time context =====

fn detect_git_sha() -> String {
    if let Ok(v) = std::env::var("GIT_SHA") {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn detect_rustc_version() -> String {
    if let Ok(v) = std::env::var("RUSTC_VERSION") {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Compute a percentile (0..=100) of `samples` in milliseconds. Uses
/// the nearest-rank method — adequate for the small N this probe
/// captures (typically 5–20 warm calls).
fn percentile_ms(samples: &[i64], p: f64) -> Option<i64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let rank = ((p / 100.0) * n as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(n - 1);
    Some(sorted[idx])
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

    let host_info = detect();
    let git_sha = detect_git_sha();
    let rustc_version = detect_rustc_version();

    // 1) Circuit build.
    eprintln!("[probe_r2] building circuit (cold) ...");
    let t = Instant::now();
    let prover = Prover::new();
    let circuit_build_wall_ms = t.elapsed().as_millis() as i64;
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
    let prove_cold_wall_ms = t.elapsed().as_millis() as i64;
    eprintln!("[probe_r2] prove_cold_wall_ms = {prove_cold_wall_ms}");

    // Verify the init proof once so a regression in the prove path
    // doesn't quietly produce garbage timings.
    let t = Instant::now();
    prover
        .verify(&init_proof)
        .map_err(|e| format!("verify cold init: {e}"))?;
    let verify_wall_ms = t.elapsed().as_millis() as i64;

    // 4) Build the AccountUpdate witness ONCE and reuse it across
    //    warm calls. We want pure prove-wall, not witness-construction
    //    cost.
    let prev_asth = account_state.hash();
    let prev_ocr = init_proof_out_coins_root_from_init(&prev_asth);
    let (cmp, history_root_extended) = build_commitment_witness(prev_asth, prev_ocr);

    // 5) Warm prove sweep.
    let mut prove_warm_wall_ms: Vec<i64> = Vec::with_capacity(args.warm_calls);
    for i in 0..args.warm_calls {
        eprintln!("[probe_r2] warm prove {} / {} ...", i + 1, args.warm_calls);
        let t = Instant::now();
        let update_proof = prover
            .prove_account_update(&account_state, history_root_extended, &init_proof, &cmp)
            .map_err(|e| format!("warm prove_account_update #{i}: {e}"))?;
        let ms = t.elapsed().as_millis() as i64;
        prove_warm_wall_ms.push(ms);
        eprintln!("[probe_r2] warm[{i}] = {ms} ms");

        if i == 0 {
            prover
                .verify(&update_proof)
                .map_err(|e| format!("verify warm #{i}: {e}"))?;
        }
    }

    let peak_rss = peak_rss_kb() as i64;

    // ===== Report =====

    let cold_start_ms = circuit_build_wall_ms + prove_cold_wall_ms;
    let warm_p50 = percentile_ms(&prove_warm_wall_ms, 50.0);
    let warm_p90 = percentile_ms(&prove_warm_wall_ms, 90.0);
    let warm_p99 = percentile_ms(&prove_warm_wall_ms, 99.0);
    let warm_min = prove_warm_wall_ms.iter().min().copied().unwrap_or(0);
    let warm_max = prove_warm_wall_ms.iter().max().copied().unwrap_or(0);
    let warm_mean = if prove_warm_wall_ms.is_empty() {
        0
    } else {
        prove_warm_wall_ms.iter().sum::<i64>() / prove_warm_wall_ms.len() as i64
    };

    let report = json!({
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "hostname": host_info.hostname,
            "cpu_brand": host_info.cpu_brand,
            "cpu_cores": host_info.cpu_cores,
            "total_ram_gb": host_info.total_ram_gb,
        },
        "git_sha": git_sha,
        "rustc_version": rustc_version,
        "build_profile": "release",
        "allocator": "mimalloc",
        "max_in_coins": MAX_IN_COINS,
        "max_out_coins": MAX_OUT_COINS,
        "inner_pad_bits": INNER_PAD_BITS,
        "warm_calls_requested": args.warm_calls,
        "circuit_build_wall_ms": circuit_build_wall_ms,
        "prove_cold_wall_ms": prove_cold_wall_ms,
        "verify_wall_ms": verify_wall_ms,
        "prove_warm_wall_ms": prove_warm_wall_ms,
        "prove_warm_p50_ms": warm_p50,
        "prove_warm_p90_ms": warm_p90,
        "prove_warm_p99_ms": warm_p99,
        "peak_rss_kb": peak_rss,
        "rss_unit_note":
            "macOS reports ru_maxrss in bytes; Linux reports KB. This tool normalises to KB.",
        "budgets": {
            "warm_prove_ms_max": args.warm_budget_ms,
            "cold_start_ms_max": args.cold_budget_ms,
            "peak_rss_kb_max": args.mem_budget_kb,
        },
        "notes": args.notes,
        "tags": args.tags,
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

    // ===== Optional persistence =====

    let mut history_after: Option<Vec<SummaryRow>> = None;
    if args.persist {
        let database_url = std::env::var("DATABASE_URL").map_err(|_| {
            "--persist requires DATABASE_URL to be set (e.g. \
             postgresql://zkcoins:<pw>@postgres:5432/zkcoins)"
                .to_string()
        })?;
        eprintln!("[probe_r2] persisting to DATABASE_URL ...");

        let rt = Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
        let rows = rt.block_on(async {
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&database_url)
                .await
                .map_err(|e| format!("connect DATABASE_URL: {e}"))?;
            let host_id = upsert_host(&pool, &host_info)
                .await
                .map_err(|e| format!("upsert_host: {e}"))?;
            let run_row = ProbeRun {
                host_id,
                git_sha: git_sha.clone(),
                binary_version: env!("CARGO_PKG_VERSION").to_string(),
                rustc_version: rustc_version.clone(),
                build_profile: "release".to_string(),
                allocator: "mimalloc".to_string(),
                max_in_coins: MAX_IN_COINS as i32,
                max_out_coins: MAX_OUT_COINS as i32,
                inner_pad_bits: INNER_PAD_BITS,
                warm_calls_requested: args.warm_calls as i32,
                circuit_build_wall_ms,
                prove_cold_wall_ms,
                verify_wall_ms,
                peak_rss_kb: peak_rss,
                prove_warm_p50_ms: warm_p50,
                prove_warm_p90_ms: warm_p90,
                prove_warm_p99_ms: warm_p99,
                succeeded: true,
                error_message: None,
                notes: args.notes.clone(),
                tags: args.tags.clone(),
                r2_warm_budget_ms: args.warm_budget_ms,
                r2_cold_budget_ms: args.cold_budget_ms,
                r2_mem_budget_kb: args.mem_budget_kb,
            };
            let run_id = insert_run(&pool, &run_row)
                .await
                .map_err(|e| format!("insert_run: {e}"))?;
            insert_warm_calls(&pool, run_id, &prove_warm_wall_ms)
                .await
                .map_err(|e| format!("insert_warm_calls: {e}"))?;
            let rows = fetch_recent_summary(&pool, 5)
                .await
                .map_err(|e| format!("fetch_recent_summary: {e}"))?;
            Ok::<Vec<SummaryRow>, String>(rows)
        })?;
        eprintln!(
            "[probe_r2] persisted run; {} recent rows read back",
            rows.len()
        );
        history_after = Some(rows);
    }

    // Console verdict against the three ROADMAP budgets.
    let warm_ok = (warm_p50.unwrap_or(i64::MAX)) <= args.warm_budget_ms;
    let cold_ok = cold_start_ms <= args.cold_budget_ms;
    let rss_ok = peak_rss <= args.mem_budget_kb;

    eprintln!();
    eprintln!("===== ROADMAP step 9 budgets =====");
    eprintln!(
        "  warm prove p50 over {} calls: {} ms   {}  [budget {} ms]",
        args.warm_calls,
        warm_p50
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".into()),
        check(warm_ok),
        args.warm_budget_ms
    );
    eprintln!(
        "  cold start (build + first prove): {} ms   {}  [budget {} ms]",
        cold_start_ms,
        check(cold_ok),
        args.cold_budget_ms
    );
    eprintln!(
        "  peak RSS: {} KB ({} MiB)   {}  [budget {} KB]",
        peak_rss,
        peak_rss / 1024,
        check(rss_ok),
        args.mem_budget_kb
    );
    eprintln!();
    eprintln!(
        "  warm distribution: min {} / mean {} / max {} ms",
        warm_min, warm_mean, warm_max
    );

    if let Some(rows) = history_after.as_ref() {
        print_history_table(rows);
    }

    Ok(())
}

fn check(ok: bool) -> &'static str {
    if ok {
        "PASS"
    } else {
        "FAIL"
    }
}

/// ASCII trend table — last few persisted runs newest first. Width
/// is tuned for an 80-column terminal; the columns map 1:1 to the
/// `r2_probe_runs_summary` view.
///
/// `coldstart_ms` is `circuit_build_wall_ms + prove_cold_wall_ms` to
/// match the cold-start budget (`BUDGET_COLD_START_MS`, ROADMAP §Step
/// 9). The `C` pass marker in the same row reads the view's
/// `r2_cold_pass` which is computed against the same sum — so the
/// number the operator sees is exactly what the pass/fail is judged
/// against.
fn print_history_table(rows: &[SummaryRow]) {
    eprintln!();
    eprintln!("===== Recent runs (from DB) =====");
    eprintln!(
        "  {:<25} {:<14} {:>12} {:>9} {:>10}  W  C  M",
        "ran_at", "git_sha", "coldstart_ms", "warm_p50", "rss_kb"
    );
    for r in rows {
        let git_sha_short = r.git_sha.chars().take(12).collect::<String>();
        let warm_p50 = r
            .prove_warm_p50_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".into());
        let cold_start_ms = r.circuit_build_wall_ms + r.prove_cold_wall_ms;
        eprintln!(
            "  {:<25} {:<14} {:>12} {:>9} {:>10}  {} {} {}",
            r.ran_at,
            git_sha_short,
            cold_start_ms,
            warm_p50,
            r.peak_rss_kb,
            pass_marker(r.r2_warm_pass),
            pass_marker(r.r2_cold_pass),
            pass_marker(r.r2_mem_pass),
        );
    }
}

fn pass_marker(ok: bool) -> &'static str {
    if ok {
        "+"
    } else {
        "-"
    }
}

/// The post-Init `coin_history_root` is conventionally
/// `DEFAULT_HASHES[0]` — the empty SMT root. Independent of `prev_asth`
/// but kept as a function so the call site reads symmetrically. We
/// hash a sentinel to obtain that empty-tree root without depending on
/// the `DEFAULT_HASHES` private indexing.
fn init_proof_out_coins_root_from_init(_prev_asth: &HashDigest) -> HashDigest {
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
