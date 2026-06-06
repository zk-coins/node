# Plonky3 recursion spike — single-layer cost (P0-T5)

**Host:** Apple M5 Max, 128 GB unified memory.
**Date:** 2026-06-06.
**Toolchain:** nightly (rust-toolchain pin), `--profile dev` with `opt-level = 3`.
**Pins:** `Plonky3/Plonky3-recursion` @ `524665d0c2e1d294722c064786ae11dff8d9f33b`,
`Plonky3/Plonky3` @ `56952503e1401a62982ceaf952c5e4a829b61803`.
**Field/hash:** Goldilocks, D=2, Poseidon2 width 8 / rate 4, 4-element digest.
**FRI params:** `log_blowup=2, max_log_arity=2, log_final_poly_len=1, query_pow_bits=8`
(spike defaults — untuned, chosen to keep prove time low while exercising the
real FRI/Merkle in-circuit verifier path).

## Single recursion-layer cost (Probe A, trivial counter AIR)

`prove_next_layer` over a `BatchOnly` predecessor proof:

| Layer | Verifier-circuit `witness_count` | Prove time |
|------:|---------------------------------:|-----------:|
| 1 (verifies base counter circuit) | 25 567 | 1.17 s |
| 2 (verifies layer 1) | 104 630 | 4.65 s |
| 3 (verifies layer 2) | 107 957 | 4.66 s |
| 4 (verifies layer 3) | **107 957** (fixed point) | 4.67 s |

**Per stabilized recursion layer: ≈ 4.65 s prove, witness_count 107 957.**

## Peak memory

Full 4-test spike suite (incl. parallel fan-in-4 aggregation): **peak RSS ≈ 1.04 GB**.
Upstream `recursive_fibonacci --field goldilocks --num-recursive-layers 5`:
peak RSS ≈ 0.51 GB.

Both are ~50–60× under the 64 GB budget (`CONTRIBUTING.md` §hardware).

## Reading these numbers

- These are for a **trivial counter AIR** with **untuned FRI params**, so the
  ~4.65 s is an *indicative recursion-layer overhead floor*, NOT a projection of
  the real zkCoins state-transition prove time. The real circuit is far heavier;
  recursion overhead is additive on top.
- The `≤ 5 s warm / ≤ 1 s ideal` budget applies to the full warm-prove of a real
  transition, measured in Phase 8 via `probe_r2`. This spike only establishes
  that one recursion layer's *own* cost and memory are modest and that the
  per-layer shape is constant (so cost does not grow with chain depth).
- No external/CUDA hardware was used or needed (single Apple-Silicon host).
