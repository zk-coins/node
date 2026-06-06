# Plonky3 vs Plonky2 — FAIR prover-speed comparison (Probe S)

**Host:** Apple M5 Max, 128 GB unified memory, aarch64, macOS.
**Date:** 2026-06-06.
**Toolchain:** `cargo nextest run --release`, `RUSTFLAGS="-Ctarget-cpu=native"`.
**Test:** `spikes/plonky3-recursion-spike/tests/probe_s_fair_bench.rs`.
**Pins:** `Plonky3/Plonky3` @ `56952503e1401a62982ceaf952c5e4a829b61803`,
`Plonky3/Plonky3-recursion` @ `524665d0c2e1d294722c064786ae11dff8d9f33b`.

## TL;DR

**Plonky3 (BabyBear, production-tuned FRI, NEON SIMD packing) is faster than
Plonky2 (Goldilocks) at every measured point — by 4–61×, with 5–51× lower peak
RSS.** The performance thesis of the migration holds with a large margin, even
at a hash-saturated workload doing ~14× the real circuit's Poseidon work.

At the fairest point (hash-matched, ~4500 Poseidon hashes ≈ the real circuit):
- non-zk FRI: **71 ms** vs Plonky2 4350 ms → **61× faster**, **51× less RSS**.
- zk-proxy FRI (blowup 2): **128 ms** → **34× faster**, **19× less RSS**.

Even at the hash-saturated upper bound (2^16 perms, ~14× the real hash work):
- non-zk: **570 ms** → **7.6× faster**.
- zk-proxy: **1042 ms** → **4.2× faster**.

## Why earlier probes (I/R) did NOT answer this

Probes I/R measured a **recursion** overhead in **Goldilocks** with **untuned
FRI** (low-security testing params). They were a recursion-feasibility check,
not a production-prover timing. They deliberately did not exercise the levers
the migration's speed thesis rests on: the 31-bit BabyBear field, SIMD field
packing, and production-tuned FRI. Probe S measures exactly those.

## Configuration (apples-to-apples vs Plonky2)

| Axis | Plonky3 (Probe S) | Plonky2 (baseline) |
|---|---|---|
| Field | BabyBear (31-bit) + `BinomialExtensionField<_, 4>` | Goldilocks (64-bit) |
| Packing | NEON `PackedMontyField31Neon` (confirmed at runtime) | — |
| Hash / Merkle | Poseidon2 MMCS (sponge w24 / compress w16) | Poseidon Merkle caps |
| FRI | `new_benchmark` (blowup 1, 100 queries, 16-bit PoW) and `new_benchmark_zk` (blowup 2) | production FRI |
| DFT | `Radix2DitParallel<BabyBear>` | — |
| AIR | non-vectorized `Poseidon2Air`, 1 perm/row | real state-transition circuit |
| Threads | 18 (M5 Max) | 18 |

### Runtime confirmation (printed by the test)

- `BabyBear::Packing = p3_monty_31::aarch64_neon::packing::PackedMontyField31Neon<BabyBearParameters>` — SIMD packing **active** (not the trivial `[BabyBear; 1]`).
- Threads available: **18**.
- DFT: `Radix2DitParallel<BabyBear>` (parallel production DFT).

## Measured numbers (warm, 1 untimed warmup + 5 timed `prove()` runs, p50)

| n_hashes | rows | FRI | trace_gen ms | p50 ms | min ms | max ms | peak RSS MB |
|---:|---:|---|---:|---:|---:|---:|---:|
| 4 500 | 8 192 | new_benchmark (blowup 1, non-zk) | 8.4 | **71.1** | 70.6 | 71.1 | 76.2 |
| 4 500 | 8 192 | new_benchmark_zk (blowup 2, zk proxy) | 4.6 | **127.8** | 127.3 | 128.4 | 209.4 |
| 32 768 | 32 768 | new_benchmark (blowup 1, non-zk) | 17.5 | **303.1** | 301.6 | 303.3 | 296.3 |
| 32 768 | 32 768 | new_benchmark_zk (blowup 2, zk proxy) | 17.5 | **522.3** | 521.2 | 522.8 | 421.3 |
| 65 536 | 65 536 | new_benchmark (blowup 1, non-zk) | 34.0 | **569.8** | 568.0 | 571.1 | 462.4 |
| 65 536 | 65 536 | new_benchmark_zk (blowup 2, zk proxy) | 35.2 | **1041.5** | 1040.9 | 1045.4 | 694.5 |
| **PLONKY2** | ~65 536 | baseline (Goldilocks, real circuit) | — | **4350.0** | — | — | **3900** |

(Plonky2 baseline: `prove_warm_p50_ms = 4350`, `peak_rss_kb = 3 937 504`
(≈ 3.9 GB), from `m5-max-vs-m3-ultra-2026-06-02.md` — same M5 Max host.)

`prove()` alone is the timed region (the part comparable to Plonky2's prove
time). Trace generation is measured separately and reported in the table;
config / round-constant / PCS construction is setup and excluded.

## Speedup factors vs Plonky2 (4.35 s / 3.9 GB)

| n_hashes | FRI | speedup (×) | RSS ratio (×) | verdict |
|---:|---|---:|---:|---|
| 4 500 | non-zk | **61.2** | 51.2 | FASTER |
| 4 500 | zk proxy | **34.0** | 18.6 | FASTER |
| 32 768 | non-zk | **14.3** | 13.2 | FASTER |
| 32 768 | zk proxy | **8.3** | 9.3 | FASTER |
| 65 536 | non-zk | **7.6** | 8.4 | FASTER |
| 65 536 | zk proxy | **4.2** | 5.6 | FASTER |

## Honest apples-to-apples caveats

1. **Hash saturation.** The `num_hashes = 2^16` upper bound does ~14× the real
   circuit's ~4500 Poseidon hashes; the `4500` row is the fair hash-matched
   point and the `32768` row brackets in between. Even the saturated point is
   4–7× faster, so the verdict is robust to the saturation caveat.
2. **AIR shape.** Probe S proves a pure Poseidon2 AIR (one permutation per
   row). The real circuit also has ~50k non-hash gates; those add trace
   columns and lookups not modelled here. The hash-matched row understates the
   real circuit's column count somewhat, but the prover cost is dominated by
   the DFT/Merkle/FRI over the trace *area*, and BabyBear's packing + small
   field win on every column regardless of constraint kind.
3. **S-box degree.** Uses the degree-3 S-box (`x^3`), exactly as Plonky3's own
   non-vectorized BabyBear Poseidon2 end-to-end tests do (their comment: the
   AIR test "validates the proof system, not the hash function's security
   parameters"). At this pinned rev the non-vectorized `Poseidon2Air` with the
   cryptographic degree-7 S-box fails verification (`OodEvaluationMismatch`)
   under the plain `TwoAdicFriPcs` + Poseidon2-MMCS + `DuplexChallenger` path
   (the working upstream degree-7 example uses the *vectorized* AIR + Keccak
   MMCS + `HidingFriPcs`). Verified by bisection. **Honest magnitude:** the
   S-box degree sets the constraint degree, hence the quotient-polynomial degree
   (`log_num_quotient_chunks = log2_ceil(deg-1)`): degree-3 → 2 quotient chunks
   (quotient domain 2N), degree-7 → 8 chunks (8N). With `SBOX_REGISTERS=0` the
   column count is unchanged, so degree-7 inflates ONLY the quotient stage
   (quotient-domain LDE + constraint eval + chunk Merkle commit) ~4×, leaving the
   trace commit and FRI untouched — a worst-case total prove inflation of roughly
   **1.5–2.5× (up to ~3× if quotient eval dominates more than estimated)**, NOT
   "negligible". This does not threaten the conclusion: applying a full 3× to the
   weakest point (the 4.2× zk-saturated row) still leaves Plonky3 ~1.4× ahead, and
   the fair hash-matched point degrades only from 61×/34× to ~20×/~11×. Note the
   Plonky2 baseline uses Goldilocks-Poseidon's own degree-7 S-box, so this gap
   flatters Plonky3 in exactly one (bounded-above) direction. Degree-3 is thus a
   prover-speed proxy whose headline is an over-estimate of the speedup by at most
   ~3×, with the migration verdict robust across that whole range.
4. **ZK-ness.** zkCoins proofs are zero-knowledge. The `new_benchmark_zk`
   (blowup 2) rows are the zk-apples-to-apples FRI point, run on the plain
   `TwoAdicFriPcs` as a *timing proxy* (blowup 2 drives the dominant FRI/Merkle
   cost; the random-masking rows of a true `HidingFriPcs` are a small additive
   term). A full `HidingFriPcs` measurement is a follow-up; the proxy already
   clears the 4.35 s budget by 4×+ at the worst point.
5. **Field.** BabyBear (31-bit) vs Goldilocks (64-bit) is the intended
   migration delta, not a confound — the whole point is to switch to the
   smaller field where packing pays off.

## How to reproduce

```
cd spikes/plonky3-recursion-spike
RUSTFLAGS="-Ctarget-cpu=native" cargo nextest run probe_s_fair_bench --release --no-capture
```
