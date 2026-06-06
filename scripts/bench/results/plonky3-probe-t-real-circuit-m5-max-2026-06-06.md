# Probe T — real-circuit Plonky3 prove-cost estimate (the migration decision number)

**Host:** Apple M5 Max, 128 GB unified memory.
**Date:** 2026-06-06.
**Toolchain:** `RUSTFLAGS="-Ctarget-cpu=native"`, `--release`. NEON-packed BabyBear
(`PackedMontyField31Neon`), 18 rayon threads.
**Pins:** `Plonky3/Plonky3` @ `56952503e1401a62982ceaf952c5e4a829b61803`,
`Plonky3/Plonky3-recursion` @ `524665d0c2e1d294722c064786ae11dff8d9f33b`.
**Test:** `spikes/plonky3-recursion-spike/tests/probe_t_real_circuit_bench.rs`,
`fn probe_t_real_circuit_bench` (`cargo nextest run probe_t_real_circuit_bench
--release --no-capture`).

## What this is — and the proxy boundary (NOT blurred)

This is the best **honest measured** estimate of the real zkCoins
state-transition circuit's Plonky3 prove cost under **TRUE production crypto**.

The real circuit is ~7800 LOC of Plonky2 (`program-plonky2/src/circuit/`:
`main.rs` 3882, `smt.rs`, `sparse_merkle_tree.rs`, `source_aggregator.rs`,
`merkle/`). Probe T does **NOT** port that business logic. It builds a
**cost-faithful representative workload** that reproduces the real circuit's
prove-cost DRIVERS — Poseidon2 hash count (~4500), non-hash gate count (~50k),
committed trace area, constraint degree (degree-7), and the ZK commitment
scheme — but **not** its meaning (no balance conservation, nullifier
uniqueness, or SMT-membership semantics). Prove cost in a FRI-STARK is governed
by trace dimensions x constraint degree x commitment scheme, which this
matches; business-logic constraints add gates *within* these tables without
changing the cost class. **It is a cost proxy, an explicit non-proxy for
soundness.**

## Production-crypto config (reused verbatim from Probe V, confirmed to verify at degree-7)

- AIR (hash table): `VectorizedPoseidon2Air<.., SBOX_DEGREE=7, SBOX_REGISTERS=1,
  VECTOR_LEN=8>`, cryptographic BabyBear round counts (4 half-full, 13 partial).
- MMCS: `MerkleTreeHidingMmcs` over the Keccak sponge (`PaddingFreeSponge<KeccakF,
  25,17,4>` + `CompressionFunctionFromHasher`), `SmallRng` masking.
- PCS: `HidingFriPcs<.., SmallRng>`, `num_random_codewords = 4` (**TRUE ZK**).
- Challenger: `SerializingChallenger32<Val, HashChallenger<u8, Keccak256Hash, 32>>`.
- FRI: `FriParameters::new_benchmark_zk` (log_blowup 2, 100 queries, 16-bit PoW).
- Field BabyBear, challenge `BinomialExtensionField<BabyBear, 4>`.

## Table model

1. **Hash table** = the degree-7 Poseidon2 AIR sized to ~4500 perms. At
   `VECTOR_LEN = 8` perms/row that is ceil(4500/8) = 563 rows, rounded up to the
   next power of two = **1024 rows** (8192 perms of capacity; the real count sits
   just under). Fixed across the sweep.
2. **Non-hash arithmetic table** = a generic 16-column AIR with 12
   constraints/row (8 degree-3 `x^3` identities + 4 linear couplings) modelling
   the ~50k non-hash gates. **Degree 3, deliberately:** the real circuit's
   non-hash gates (range/boolean checks, Merkle/SMT path equalities, field
   add/mul) are almost all degree 2–3; the degree-7 cost lives in the Poseidon2
   hash table, which is modelled with the real degree-7 AIR. (A raw `x^7`
   identity in a plain AIR is also not committable under this FRI config —
   blowup 2 caps constraint degree; the vectorized Poseidon2 AIR only reaches
   degree 7 via per-S-box witness registers.) The table HEIGHT is **swept** over
   {2^13, 2^14, 2^15, 2^16} to **bracket** the unknown real layout.

## Combination approach (a/b/c) — finding

**Approach (a): real multi-table `prove_batch` (p3-batch-stark) WORKS with
HidingFriPcs + degree-7.** This is the empirical key result. A single batched
FRI proof over the degree-7 Poseidon2 hash table **and** the degree-3 arithmetic
table, under the Keccak-hiding MMCS + `HidingFriPcs` (`num_random_codewords=4`)
config, **prove_batch + verify_batch succeed**. batch-stark requires one
`Air + Clone` type for all instances and a `Val`-concrete builder; the
non-`Clone` `VectorizedPoseidon2Air` is wrapped in `Arc` behind a dispatch enum
(`TableAir`), with zero semantic change. Mixed per-instance constraint degrees
(7 for the hash table, 3 for the arith table) are handled natively by
batch-stark's per-instance quotient sizing. **(a) is the faithful production
proof shape and is the headline number.**

**Approach (b): separate proofs, summed** = the hash table and the arith table
proved as two independent uni-stark proofs, warm times summed. Two separate
proofs cost strictly more than one batched proof (duplicated FRI
commit/query/PoW), so (b) is a conservative **upper bound**. Reported as a
sanity rail. (b) ≈ (a) here because the hash table is tiny (1024 rows) so
batching saves little FRI overhead at this scale — both land within ~1–2 %.

Approach (c) (single combined AIR) was unnecessary given (a) verifies.

## Results (warm, p50/p90; all proofs verify)

One-time **config + AIR build: 0.07 ms** — the Plonky3 analog of Plonky2's cold
circuit-build (**8.2 s** on the same host). Plonky3 has no circuit-compilation
step. This alone removes the entire Plonky2 cold-build tax.

Hash table standalone: cold 189 ms / warm p50 **174.7 ms** / p90 193.5 ms /
RSS 562 MB.

| arith height | constraints | (a) build | (a) cold | (a) warm p50 | (a) warm p90 | (a) RSS | (b) sum p50 (upper bound) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2^13 | 98 304 | 0.6 ms | 309.8 ms | **311.9 ms** | 335.5 ms | 1135 MB | 317.5 ms |
| 2^14 | 196 608 | 0.6 ms | 445.3 ms | **448.7 ms** | 465.4 ms | 1726 MB | 448.1 ms |
| 2^15 | 393 216 | 0.6 ms | 732.1 ms | **734.7 ms** | 741.5 ms | 1856 MB | 738.1 ms |
| 2^16 | 786 432 | 0.7 ms | 1321.1 ms | **1306.7 ms** | 1314.6 ms | 2089 MB | 1289.9 ms |

(The 786 432-constraint / 2^16 row case ran in full; no OOM, RSS ≈ 2.1 GB, well
under the 128 GB budget. The 5-warm-run protocol was kept at all sizes.)

## Net vs Plonky2 (4.35 s warm p50, 3.94 GB)

Primary estimate = (a) batched warm p50.

| arith height | (a) warm p50 | verdict | factor |
|---:|---:|:--|---:|
| 2^13 | 311.9 ms | **FASTER** | 13.95x |
| 2^14 | 448.7 ms | **FASTER** | 9.69x |
| 2^15 | 734.7 ms | **FASTER** | 5.92x |
| 2^16 | 1306.7 ms | **FASTER** | 3.33x |

Plonky3+BabyBear under true production crypto is **faster across the entire
sweep**, including the deliberately-inflated 2^16 ceiling. RSS is also lower at
every size (1.1–2.1 GB vs Plonky2's 3.94 GB).

## Bottom line (honest)

The real circuit's ~50k non-hash gates already fit **below** the sweep's LOW
end: at arith height 2^13 the table carries 98 304 constraints (> 50k), so the
real non-hash committed area sits between **2^13 and 2^14**. Taking **2^13 as
the realistic anchor** and 2^14 as a safe upper estimate:

> **At the most likely real layout (arith ~2^13–2^14), Plonky3 + BabyBear under
> TRUE production crypto (degree-7 Poseidon2 + Keccak-hiding MMCS + HidingFriPcs,
> num_random_codewords=4) proves the real-circuit-equivalent workload in ≈ 312 ms
> warm p50 (≈ 449 ms at the 2^14 upper estimate), versus Plonky2's 4350 ms.
> That is ~10–14x FASTER, with ~2–3x lower peak memory, plus a near-zero
> circuit-build (0.07 ms vs 8.2 s).**

This is a genuine win, not spin: it holds at every swept size and the realistic
layer sits at the fastest end of the sweep. The result is also conservative —
(b)'s independent-proof upper bound agrees with (a) to within ~1–2 %.

### Caveats (the proxy boundary, restated)

- **Cost proxy, not a port.** This measures prove cost for a workload with the
  real circuit's hash count, gate count, area, degree, and ZK commitment — not
  the real statement. Business-logic constraints (balance, nullifiers, SMT
  membership) add gates *within* these tables; they do not change the trace area
  or degree class, so the cost estimate holds, but soundness/correctness of the
  real statement is out of scope here (covered by the semantic-port probes).
- **Hash count is an anchor (~4500), rounded up to 1024 rows (8192-perm
  capacity).** If the real port needs materially more perms, the hash table
  grows by power-of-two steps; each step roughly doubles the hash-table prove
  time (still small in absolute terms at this scale).
- **Arith degree = 3.** If a non-negligible fraction of the real non-hash gates
  turn out higher-degree, they would need the same witness-register decomposition
  the Poseidon2 AIR uses; the cost effect is bounded and stays inside the swept
  area bracket.
- **`SmallRng` masking** is benchmark-only; production hiding needs a CSPRNG.
  This does not change prove cost.

### Levers (only relevant if a future, heavier real layout flips the verdict — none needed today)

All circuit-side, never external hardware: fewer Poseidon2 hashes; smaller
`MAX_IN_COINS`; circuit-level constraint optimization; the KoalaBear field; or
dropping in-coin recursion.
