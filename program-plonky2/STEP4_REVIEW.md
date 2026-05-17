# Step 4 Critical Review

Independent review of the Step 4 gadget set (`4a`, `4b`, `4c`, `4c+`,
`4d`) at commit `fa2532f`. Read-only review — no code changes — to
avoid merge conflicts with the parallel Step 5 work.

Reviewer scope: algorithmic correctness, off-circuit ↔ in-circuit
consistency, test coverage of the negative paths, code quality, doc
clarity. **Not** in scope: low-level Plonky2 gate-counting or
constraint-degree analysis (left to Plonky2 ecosystem benchmarks).

This file should be folded into `MIGRATION_RESEARCH.md` §7 (Lessons
Learned) at the end of Step 5, or deleted if all findings end up
mooted by the monolithic circuit work.

---

## TL;DR

**Step 4 is sound.** **Zero bugs.** Zero must-fix items. All findings
below are *nice-to-have improvements* that can wait until Step 5
merges or even later — none block forward progress.

72/72 tests pass at 100% line / function / region coverage. The new
`verify_smt_insert` (commit `6cf949c`) is well-structured and unifies
Case A and Case B via the same `is_case_a` selector that already
exists in `verify_smt_non_inclusion`.

---

## Classification

This report distinguishes strictly between:

- **🐛 BUG / MUST FIX NOW** — a real defect that produces wrong results, allows unsound proofs, prevents valid usage, or violates a project invariant. **Step 4 currently has zero of these.**
- **💡 NICE TO HAVE** — improvements that would make the code easier to read, less brittle to future changes, or close edge cases that aren't reached in practice. **All findings below fall here.**

If anything moves from the second category to the first, this report
must be updated.

---

## 🐛 Bugs / Must Fix Now

**None.** Algorithmic correctness, off-circuit ↔ in-circuit
consistency, negative-test coverage, and the 100% gate all pass.

---

## 💡 Nice to Have (none block Step 5)

### N1 — `verify_smt_insert` cannot handle divergence at bit 255 (the LSB)

**Where:** `program-plonky2/src/circuit/smt.rs`, line ~245
(`key_bits.len() > combined_len` assertion).

**Observation:** the assertion requires `key_bits.len() > path.len() + extension.len()` because the gadget always reads `key_bits[combined_len]` (the divergence bit) regardless of which case is active. For full-256-bit keys, `combined_len ≤ 255` must hold.

If two keys differ only at the very last bit (bit 255), `combined_len = 256` and the assertion fires at circuit-build time. The SMT supports this configuration in principle; no test currently exercises it.

**Why not a bug:** the assertion is a *build-time check*, not a runtime soundness issue. If a prover attempted this configuration the circuit would refuse to build, not produce a wrong proof. The configuration is exotic (probability ~2^-255 for random keys) and not reached by any test.

**If you want to address it:** either (a) document the constraint explicitly in the gadget's rustdoc as "supports divergence at bits 0..254" (cheap, recommended), or (b) restructure so `key_bits[combined_len]` is only read when `is_case_a == 0` and relax the assertion for Case A.

### N2 — `case_b_extension` is a test-only helper; production host (Step 7) will need it too

**Where:** `program-plonky2/src/circuit/smt.rs`, ~line 676 (inside `#[cfg(test)] mod tests`).

**Observation:** the helper that mirrors the off-circuit `NonInclusionProof::insert` padding loop and produces the `extension` siblings vector is currently inside the test module. The monolithic circuit (Step 5) and the eventual server prover wiring (Step 7) will need exactly this logic on the host side.

**Why not a bug:** tests pass. The helper is local to the test module by design; nothing depends on it externally yet.

**If you want to address it:** when Step 5 or Step 7 needs it, expose `NonInclusionProof::insert_extension_siblings()` (or a free function in the merkle module) and have the test helper delegate to it. Cover the new method by the existing 100% gate.

### N3 — Old-root walk and new-root walk use different bit sources (documentation clarity)

**Where:** `program-plonky2/src/circuit/smt.rs`, the old-root walk loop (~line 278) uses `other_key_bits`; the new-root walk (~line 327) uses `key_bits`.

**Observation:** This is **correct** — above the divergence level the two keys share bits, so either source works for the old-root walk. But the code as written is hard to follow without that justification.

**Why not a bug:** algorithm is right; only the rationale is implicit.

**If you want to address it:** a 2–3 line comment immediately above the old-root walk explaining why `other_key_bits` is used (any walk above divergence is bit-equivalent for both keys; choosing `other_key_bits` matches the off-circuit `NonInclusionProof::verify` for symmetry with `verify_smt_non_inclusion`).

### N4 — `verify_smt_insert` is the constraint-heaviest gadget; expect Step 5 throughput hit

**Where:** `program-plonky2/src/circuit/smt.rs` insert tests (especially `smt_insert_case_b_deep_divergence` with `combined_len ≈ 248`).

**Observation:** Each level adds 4 `select` gates + 1 Poseidon two-to-one + ordering bookkeeping. At `combined_len = 248` the gadget instantiates close to 1000 constraints for the new-root walk plus an equivalent for the old-root walk. The monolithic circuit (Step 5) will instantiate this gadget for *every* in-coin's `coin_history` insertion and for every output-coins-tree insertion — with `MAX_IN_COINS = 8`, that's potentially 9 deep-divergence inserts in one proof.

**Why not a bug:** Step 4c+ on its own is fine. The concern is downstream throughput for Step 5.

**If you want to address it:** measure actual Plonky2 constraint count and prove-time impact during Step 5's first end-to-end. If the M3-Ultra performance budget (warm proof ≤ 5 s) is missed, the R2 risk-register knobs apply (reduce `MAX_IN_COINS`, drop in-coin recursion, switch to folding). Not a defect of Step 4c+.

### N5 — `verify_smt_insert` name reads ambiguously

**Where:** Public function name at line 224.

**Observation:** The name reads as "verify that an SMT insert happened". The actual semantic is "verify the (key, value, old_root, new_root) tuple represents a valid non-inclusion-and-insert transition". A name like `verify_smt_non_inclusion_and_insert` would be more consistent with `verify_smt_non_inclusion`.

**Why not a bug:** function does the right thing.

**If you want to address it:** leave the name as-is for v1 (renaming a public API after Step 5 callers exist is churn). Add 1–2 lines of rustdoc clarifying the semantic.

### N6 — `ProgramInputs` is declared but no gadget consumes it yet

**Where:** `program-plonky2/src/inputs.rs`, the `ProgramInputs` struct.

**Observation:** `ProgramInputs` is fully defined and tested off-circuit. No gadget reads it yet because no monolithic circuit exists yet — that's Step 5.

**Why not a bug:** by design. Off-circuit tests cover `verify_commitment` and `verify_previous_root`, so the 100% coverage gate still passes.

**If you want to address it:** nothing now. Step 5 will introduce a `ProgramInputsTarget` and a host helper to set witnesses from a `ProgramInputs`. Just track the dependency.

---

## Per-gadget checklist

| Gadget | Algorithm | Tests | Negatives | Docs | Coverage |
| ------ | --------- | ----- | --------- | ---- | -------- |
| 4a `verify_mmr_inclusion` + `*_with_index` | ✅ LSB-first bit indexing, matches `MMRProof::verify` | 5 positive | tampered root | clear | 100% |
| 4b `verify_smt_inclusion` | ✅ MSB-first via `key_bits_msb_first` | 4 positive (incl. growing tree) | tampered leaf, length-mismatch panic | clear | 100% |
| 4c `verify_smt_non_inclusion` | ✅ unified Case A / Case B via `is_case_a` selector | 3 positive | wrong default in Case A, length-mismatch panic | clear | 100% |
| 4c+ `verify_smt_insert` | ✅ extends 4c by adding new-root computation; same `is_case_a` selector | 3 positive (Case A, Case B shallow, Case B deep) | tampered new-value, tampered new-root, Case-A invariant, two build-time assertions | mostly clear (see M3) | 100% |
| 4d `ProgramInputs` + `CommitmentMerkleProofs` | ✅ off-circuit only; mirrors SP1 protocol shape | 4 tests including e2e SMT+MMR roundtrip | none directly (uncovered code is the unused circuit-side; tracked as M6) | clear | 100% |

---

## Conclusion

Step 4 is **professional and consistent** and meets the MVP definition
(minimal feature surface + 100% coverage). **No bugs, no must-fix
items.** All findings are nice-to-haves to consider after Step 5 lands.

The implementation work is ready to be composed into the monolithic
state-transition circuit.

Once Step 5 merges, the recommended (optional) follow-ups are:
1. N2: surface the host-side extension-siblings helper as a public method when Step 7 needs it.
2. N3: add the 2–3 line explanatory comment above the old-root walk.
3. N1: pick documentation vs. relaxation for the bit-255 edge case.
4. N4: measure actual constraint count and prove-time during Step 5's first e2e; act on R2 only if the budget is missed.
5. Move this file's findings into `MIGRATION_RESEARCH.md` §7 (Lessons Learned) and delete this file.
