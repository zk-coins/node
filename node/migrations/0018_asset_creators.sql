-- Per-asset creator binding table (node-side, off-circuit).
--
-- ## What changes
--
-- The neutral, permissionless multi-asset model binds each `asset_id`
-- to the public key that first minted it. v1 of MULTI_ASSET.md §5.3
-- ("off-circuit verify") keeps this binding OUT of the Plonky2 circuit
-- and OUT of the insert-only commitment SMT: instead the node records
-- `asset_id -> creator_pubkey` here and, at mint-commit time, requires
-- the wallet-signed `commitment.public_key` to equal the registered
-- creator key.
--
-- ## Why this table (and why the SMT key check moved out)
--
-- The mint previously set `next_public_key == creator_pubkey` so the
-- on-chain commitment committed under `sha256(creator_pubkey)`. That
-- doubled as the creator binding but also made the creator's FIRST
-- follow-up send re-commit under the same map key, which the
-- insert-only commitment SMT rejects ("Key already exists in the tree
-- with different value"). The mint now rotates `next_public_key` to a
-- fresh wallet key (like a normal send), so the binding can no longer
-- ride on the commitment key. This table carries it instead: a first
-- mint inserts the row, and any later mint of the same `asset_id` whose
-- creator key differs is rejected with 409 CONFLICT.
--
-- The `asset_id` is 32 bytes; the compressed secp256k1 `creator_pubkey`
-- is 33 bytes — the same CHECK shapes the other key columns use.

CREATE TABLE asset_creators (
    asset_id BYTEA PRIMARY KEY,
    creator_pubkey BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (octet_length(asset_id) = 32),
    CHECK (octet_length(creator_pubkey) = 33)
);
