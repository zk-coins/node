# script-plonky2 — host-side Plonky2 prover wrapper

Companion crate to `program-plonky2/` providing a high-level
[`Prover`] struct around the low-level
`zkcoins_program_plonky2::circuit::main::prove_*` API. Mirrors the
shape of the SP1-era `script/` crate so node-side integration
follows the same pattern.

## Why a separate crate?

Two reasons:

1. **Toolchain isolation.** Plonky2 requires nightly Rust
   (`feature(specialization)`). Both `program-plonky2/` and
   `script-plonky2/` use a shared nightly toolchain via the
   `rust-toolchain.toml` symlink. The parent stable workspace
   (node, SP1-era crates) cannot directly depend on either.
2. **Separation of concerns.** `program-plonky2/` builds the cyclic
   state-transition circuit and exposes the raw `prove_*` /
   `verify` APIs. `script-plonky2/` wraps them in a `Prover` that
   owns the built circuit, so successive proofs amortise the build
   cost. Node code wires against the `Prover` API.

## How to call this from the stable workspace

Two options for the upcoming step-7 node replacement:

- **Option A: subprocess boundary.** Add a `[[bin]]` target to
  `script-plonky2/` that takes JSON input on stdin and emits proof
  bytes on stdout. The stable-workspace `node/` crate spawns it via
  `tokio::process`. Keeps toolchain isolation but pays IPC overhead
  per proof (~10–100 ms serialisation, negligible against ~5–15 min
  proof time).
- **Option B: workspace consolidation.** Migrate the entire
  workspace to the same nightly toolchain `program-plonky2/` uses,
  then include `script-plonky2/` in `workspace.members` and depend
  directly. Simpler call path but couples the whole workspace's
  toolchain to Plonky2's requirements.

The step-7 ROADMAP entry will pick one and document the choice.

## Test runtime

The single smoke test (`prover_init_roundtrip`) is flagged
`#[ignore]` because it builds the cyclic circuit (~10 s) + proves an
empty Init transition (~3–15 min wall at production parameters).
Run explicitly:

```bash
cargo test --release prover_init_roundtrip -- --ignored --nocapture
```

The smoke test exists to prove the wrapper compiles + threads the
underlying APIs end-to-end. The hard correctness coverage lives in
`program-plonky2/`'s 100+ tests.

## What's NOT in this crate

- Off-circuit hash / SMT / MMR / account-state logic — those live in
  `program-plonky2/src/{hash,merkle,types}.rs`. Re-export from there
  rather than duplicating.
- The `ProgramInputs` builder that the SP1-era `script/` crate uses.
  Plonky2's cyclic recursion threads its inputs slot-by-slot
  (`InCoinSlotTargets` / `OutCoinSlotTargets` per-slot witnesses)
  instead of the SP1-era batched `ProgramInputs`. The node can
  construct slot tuples directly without an intermediate builder.
- CLI / RPC plumbing for Option A above. Add a `[[bin]]` target if
  the step-7 ROADMAP entry picks subprocess boundary.
