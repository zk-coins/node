-- MMR root index persistence (Phase C of the post-PR-A* state-layer
-- hardening, follow-on to PR #107's pending_inscriptions table).
--
-- `State::root_indices` is the in-memory `HashMap<prev_mmr_root,
-- (smt_root, leaf_index)>` consulted by `State::get_mmr_inclusion_proof`
-- whenever an account's prior proof references a historical
-- `commitment_history_root`. Before this migration the map was rebuilt
-- empty on every bootstrap (`State::new` / `load_from_pg`), which meant
-- any account whose latest proof pointed at a `commitment_history_root`
-- produced before the container restart could never produce a new send
-- or mint: the lookup returned `Err` and the handler surfaced 422
-- `Unable to get mmr inclusion proof for the previous root`.
--
-- The table mirrors the in-memory shape one row per `(prev_mmr_root)`
-- key. `INSERT … ON CONFLICT DO NOTHING` handles legitimate replays
-- (the same `prev_mmr_root` cannot legitimately map to two distinct
-- `(smt_root, leaf_index)` tuples — the MMR append is monotonic, so
-- the first writer's value is also the correct value).
--
-- Schema notes:
--   * `prev_mmr_root` is the `HashDigest` byte-encoding produced by
--     `zkcoins_program::hash::digest_to_bytes` — 32 raw bytes,
--     reinterpreting a Poseidon `HashOut<F>`. The column is BYTEA
--     PRIMARY KEY; Postgres TEXT would force hex round-trips for no
--     benefit (same rationale as the address columns in 0001).
--   * `leaf_index` is the MMR leaf position assigned at append time.
--     In-memory it is a `usize` (matches `mmr.leaf_count()`); we
--     persist it as BIGINT and check at read time that the value fits
--     `u64`/`usize` (defensive cast — see `db::load_root_indices`).
--   * `created_at` is informational only; no application invariant
--     depends on it. Useful for ops triage after a recovery event.

CREATE TABLE mmr_root_index (
    prev_mmr_root  BYTEA       PRIMARY KEY,
    smt_root       BYTEA       NOT NULL,
    leaf_index     BIGINT      NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
