-- Faucet minting counter persistence (PR-A3).
--
-- The legacy `minting_num_pubkeys.bin` sibling file tracked the
-- monotonically increasing BIP-32 child index the faucet uses to
-- generate each mint's commitment public key. The counter MUST survive
-- process restarts; otherwise the next mint sends the wrong
-- `prev_commitment_pubkey` and `send_coins` rejects the transition.
--
-- A standalone singleton table is the simplest fit:
--   * the row is tiny (one `BIGINT`) and updated at most once per mint
--     (a feature-gated, low-frequency endpoint),
--   * it is logically independent of the per-address `accounts` rows,
--   * `ON CONFLICT (id) DO UPDATE` makes the upsert race-free at the
--     SQL layer (matches the rest of the state-layer's idempotent
--     write pattern).
--
-- `num_pubkeys` is stored as `BIGINT` (signed) even though the in-
-- memory `ClientAccount.num_pubkeys` is `u32`: Postgres has no
-- unsigned integer type, and `BIGINT` covers the full `u32` range
-- without any cast contortion. The application layer rejects values
-- outside `0..=u32::MAX` when loading.

CREATE TABLE minting_meta (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    num_pubkeys BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
