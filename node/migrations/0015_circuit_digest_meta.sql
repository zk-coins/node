-- Persist the active circuit's `circuit_digest` so the boot path can
-- detect a breaking circuit change and self-heal the state.
--
-- Background. The Plonky2 state-transition circuit is cyclic: every
-- proof the node emits is fed back as the recursive *inner* proof on the
-- next transition (`account_node::send_coins_inner`). When the circuit
-- changes in a way that breaks recursion, persisted `account.proof`
-- blobs become incompatible: the next AccountUpdate send/mint hands the
-- stale proof to the new circuit and Plonky2's witness generator aborts
-- with a "Partition ... was set twice with different values" copy-
-- constraint conflict, surfaced to the wallet as "prove failed". This
-- took DEV down.
--
-- IMPORTANT (verified against the live DEV dump): the breakage does NOT
-- always change the verifier-key `circuit_digest`. Plonky2's
-- `circuit_digest` is a Poseidon hash over the constants/sigmas Merkle
-- cap + domain separator + degree — it does NOT encode the gate
-- *constraints* (see the upstream `circuit_builder.rs` "TODO: This
-- should also include an encoding of gate constraints"). The DEV
-- proofs' embedded digest was byte-identical to the current build's,
-- `Prover::verify` passed on them, yet the recursive prove still failed.
-- So a `circuit_digest` comparison (and `Prover::verify`) catches the
-- digest-changing class but MISSES the constraint-only class.
--
-- The boot self-heal therefore uses TWO detectors (see
-- `node::self_heal`): (1) compare the persisted digest against the live
-- one — the cheap steady-state fast path; (2) on the adoption boundary
-- (no digest recorded yet) additionally run a CANARY recursion — recurse
-- a persisted proof through the live circuit's AccountUpdate branch with
-- the real commitment-merkle witnesses; failure ⇒ stale. On a mismatch
-- or stale canary the whole proof-dependent state is reset to genesis
-- (the same consistent tabula rasa as the documented `reset-zkcoins-node`
-- recovery) and the new digest is stored. A full reset is the only
-- provably-consistent option: a circuit change invalidates EVERY proof
-- at once (per-account `account.proof`, queued `CoinProof` source
-- proofs, distributed recipient proofs), and the global SMT/MMR are
-- append-only and shared across accounts, so they cannot be partially
-- unwound per account without a global-vs-account mismatch. Closed-test-
-- env wipes are permitted (CONTRIBUTING § "Closed test environment").
--
-- Singleton table keyed on `id = 1`, matching the `smt_state` /
-- `mmr_state` / `latest_block` convention. `digest` is the bincode
-- encoding of the circuit's `HashOut<GoldilocksField>` (4 field
-- elements) — opaque to SQL, compared byte-for-byte in the application
-- layer.

CREATE TABLE circuit_digest_meta (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    digest BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
