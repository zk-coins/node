> **STATUS — DONE / HISTORICAL — SUPERSEDED BY STAGE 5D-NEXT-5.**
> Stage 5d-next-4 was deferred per [`../MIGRATION_RESEARCH.md`](../MIGRATION_RESEARCH.md) §7.21
> (two Plonky2 1.1.0 shape blockers). The work was completed under
> Stage 5d-next-5 (PR [#23](https://github.com/zk-coins/node/pull/23))
> using the **aggregator pattern (Option B below)**, not the
> originally-recommended Option A. See [`../MIGRATION_RESEARCH.md`](../MIGRATION_RESEARCH.md) §7.22
> for the empirical resolution (`ConstantGate::new(2)` injection +
> `helper_degree = pad_bits + 1`). All 11 SPEC §13 negatives are now
> covered. This file is the design sketch preserved as the historical
> record.

# Stage 5d-next-4 design — source-side verification for in-coins

Read-only design document for the deferred 5d-next-4 work. Captures
the open architectural decisions and the scope of the remaining SPEC
§8 in-coins predicate so the next session can hit the ground running.

## What's deferred

Per SPEC §8 step 2 the in-coins loop's per-coin predicate is:

```
for (i, coin) in inputs.in_coins.iter().enumerate():
    cp := verify_proof(inputs.in_coin_proofs_public_values[i], vk)  // recursive
    assert vk == cp.vk
    assert inputs.in_coins_inclusion_proofs[i].verify(coin.identifier, cp.output_coins_root)
    mp := inputs.in_coin_proofs_history_proofs[i]
    assert cp.output_coins_root == mp.commitment_out_coins_root
    assert mp.verify_commitment(history_root)
    assert mp.verify_previous_root(cp.commitment_history_root, history_root)
    // (then SMT non-inclusion + insert + apply_coin — already wired in 5d)
```

Stage 5d shipped the **coin-history side** (non-inclusion + insert
into `coin_history_root`) and `apply_coin` (recipient + balance with
overflow). Stage 5d-next-4 owes the **source side**: per in-coin,
prove that the coin was *legitimately emitted* by another instance
of the same circuit and that the source's commitment is recorded in
the global history MMR.

## Per-in-coin witnesses (8 × MAX_IN_COINS)

- `source_proof: ProofWithPublicInputs<F, C, D>` — the recursive
  proof of the source's transition. Its public inputs are a
  `ProofData` (4 hash fields = 16 elements).
- `source_inclusion_proof: InclusionProof` (256 siblings) — proves
  `coin.identifier` is in `source.output_coins_root`.
- `source_cmp: CommitmentMerkleProofs` — full bundle (SMT + 2× MMR
  proofs) proving `source.commitment` is in `history_root` and
  `source.commitment_history_root` is a prefix of `history_root`.

## In-circuit constraints per slot

All masked by the slot's `active` bit (5d's pattern):

1. **Recursive verify** of `source_proof` against `circuit.data.verifier_only`
   (binds `vk == source.vk` — SPEC §8 `assert vk == cp.vk`).
2. Extract `source_output_coins_root` from
   `source_proof.public_inputs[4..8]`, `source_commitment_history_root`
   from `public_inputs[8..12]`.
3. **SMT inclusion** of `coin.identifier` in `source_output_coins_root`
   via `source_inclusion_proof`.
4. SPEC §8 (c)/(d)/(e) on `source_cmp`:
   - `coin.recipient` (= account.owner via 5d's apply_coin) does NOT
     play here — the cmp's `commitment_account_state_hash` is the
     SOURCE account's hash. So (c) becomes `cp.account_state_hash ==
     source_cmp.commitment_account_state_hash`.
   - (d) commitment in history.
   - (e) source's prev history is prefix of `history_root`.
5. `source_output_coins_root == source_cmp.commitment_out_coins_root`
   — couples the inclusion-proof root to the commitment in history.

## The hard architectural decision

Plonky2 1.1.0's `conditionally_verify_cyclic_proof_or_dummy::<C>`
verifies **one** inner proof per call. The current `build_circuit`
makes a single call for the `prev_account` recursive proof.

Stage 5d-next-4 needs `MAX_IN_COINS + 1 = 9` recursive verifies (one
for prev_account, one for each in-coin's source proof). Options:

### Option A — N parallel cyclic-verify calls

Call `conditionally_verify_cyclic_proof_or_dummy::<C>` N times
inside `build_circuit`. The `common_data_for_recursion_c` helper
must be updated to model N verify_proof calls in pass 3 so the
inner shape matches the outer.

**Pros:** mirrors the existing pattern; straightforward to extend.
**Cons:** the outer circuit's gate count grows linearly with N (each
verify is ~10k gates per Plonky2 estimates). N=9 means ~90k gates,
INNER_PAD_BITS must rise to 17 (1 << 17 = 131_072). Proof time
scales roughly with degree_bits — at 17 each test could take 30+
minutes wall clock.

### Option B — recursive aggregator first

Fold the N inner proofs into a single aggregated proof off-circuit,
then verify the aggregate. Plonky2 has primitives for this. The
outer circuit only verifies the aggregate.

**Pros:** outer circuit stays compact; consistent shape.
**Cons:** requires designing the aggregator circuit; another
recursion layer with its own `circuit_digest`. The protocol becomes
two-layer: clients prove their per-account transition, then a
batcher proves "I verified N of these correctly". Architectural
shift.

### Option C — sequential proof chain

Have the user submit the N source proofs as a *chain*: each one
verifies the previous, building up a single aggregated proof at the
end. The outer circuit only verifies the head of the chain.

**Pros:** outer circuit stays compact like Option B.
**Cons:** chain depth = N, so prove time is O(N). Bad UX for users
with many in-coins. Probably the worst option.

### Recommendation

**Option A** for the MVP if N=8 stays. Outer gets fat but proof
time is bounded (single proof). Option B becomes attractive if
MAX_IN_COINS grows beyond ~16.

## `common_data_for_recursion_c` update for Option A

The current 3-pass helper does one `verify_proof` per pass. For N
inner proofs in the outer, pass 3 needs N `verify_proof` calls:

```rust
fn common_data_for_recursion_c() -> CommonCircuitData<F, D> {
    // Pass 1: empty seed.
    let builder = CircuitBuilder::<F, D>::new(...);
    let data = builder.build::<C>();

    // Pass 2: verify seed once.
    let mut builder = ...;
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(...);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    // Pass 3: verify pass-2 shape N times + NoopGate pad to power of 2.
    let mut builder = ...;
    let verifier_data = builder.add_virtual_verifier_data(...);
    for _ in 0..N_RECURSIVE_VERIFIES {
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    }
    while builder.num_gates() < 1 << INNER_PAD_BITS {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}
```

`N_RECURSIVE_VERIFIES = MAX_IN_COINS + 1` = 9 for the current
MAX_IN_COINS.

## Witness population

Per slot the prover supplies the source proof object plus
inclusion/commitment proofs. The same `cmp` machinery from 5c+ is
reused.

For inactive slots (`active = false`), the source proof slot can be
filled with `cyclic_base_proof` (a dummy), same as 5c+ does for the
prev account proof on Initial branch.

## Test budget

At N=9 recursive verifies + MAX_IN_COINS=8 + MAX_OUT_COINS=8 the
outer circuit reaches ~100k gates. INNER_PAD_BITS ≥ 17. Each test
build + prove will likely take 20-40 minutes wall. A full
cargo-test sweep with 25+ cyclic-recursion tests becomes
prohibitive.

**Mitigation:** introduce a `lazy_static!` / `OnceLock`-cached
`StateTransitionCircuit` so the heavy build runs once per test
binary instead of per test. CircuitData isn't `Sync` out of the
box; wrap in `Mutex` or build lazily on first use. Tests then only
pay the prove cost (~5-10 min each at MAX_IN_COINS=8) instead of
build+prove.

## Open question: source proof type

The current `StateTransitionCircuit` IS the circuit that emits
proofs verifiable as in-coin source. So `source_proof: ProofWithPublicInputs<F, C, D>`
naturally pairs with the same circuit. The only complication:
production deployments will need a way to bootstrap (the very first
proof has no prior in-coins). Stage 5b's Initial branch already
supports `condition = false` + dummy inner; the same mechanism
trivially supports `active = false` for every in-coin source slot.

## File-level scope

- `circuit/main.rs`: add `source_proofs: Vec<ProofWithPublicInputsTarget<D>>`
  to `StateTransitionCircuit`; add `source_cmps: Vec<CommitmentMerkleProofsTargets>`
  and `source_inclusion_paths: Vec<Vec<HashOutTarget>>`. Wire the
  constraints inside the in-coin loop. Update `common_data_for_recursion_c`
  to match the new shape.
- `circuit/smt.rs`, `circuit/mmr.rs`: unchanged.
- `merkle/sparse_merkle_tree.rs`, `merkle/merkle_mountain_range.rs`: unchanged.
- Tests: positive Init→Update chain with one real in-coin source proof
  (~8-15 min build + 5-10 min prove each); negatives for SPEC §13
  items currently deferred.

## Acceptance criteria

- All 11 SPEC §13 negatives covered (currently 8 of 11).
- The remaining 3 are: (a) source-proof not in history, (b) coin
  identifier not in source's `output_coins_root`, (c) wrong `vk`
  on recursive source proof.
- `cargo llvm-cov --fail-under-lines 100` still passes.
- Test budget realistic — at most ~1 hour for the full suite.
