-- Initial Postgres schema for the zkCoins server state-layer.
--
-- This migration is part of PR-A1 in the 3-PR Postgres migration
-- series (file-based bincode -> Postgres). The schema is installed
-- by `db::connect_and_migrate`; nothing here is wired into the
-- server bootstrap yet — that happens in PR-A2 (state + latest block)
-- and PR-A3 (accounts + usernames).
--
-- Design notes:
--   * `smt_state`, `mmr_state`, `latest_block` are singletons keyed
--     on a fixed `id = 1` row. The CHECK constraint prevents
--     accidental multi-row inserts that would silently break
--     `load_*` callers.
--   * BYTEA is used for binary blobs (bincode-serialized SMT/MMR,
--     32-byte block hashes, 32-byte account addresses, raw account
--     blobs). Postgres TEXT would force base64/hex round-trips for
--     no benefit.
--   * `updated_at` / `created_at` audit columns default to NOW().
--     They are not part of any application invariant — purely for
--     ops triage.

CREATE TABLE smt_state (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    data BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE mmr_state (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    data BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE accounts (
    address BYTEA PRIMARY KEY,
    data BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE usernames (
    name TEXT PRIMARY KEY,
    address BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE latest_block (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    block_hash BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
