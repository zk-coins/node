-- Multi-asset: permissionless token creation, minting, sending, receiving.
-- See issue #191 for the full design.

CREATE TABLE assets (
    asset_id              BYTEA       PRIMARY KEY,
    name                  TEXT        NOT NULL,
    decimals              SMALLINT    NOT NULL CHECK (decimals >= 0 AND decimals <= 18),
    mint_authority_pubkey BYTEA       NOT NULL,
    creator_address       BYTEA       NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX assets_name_idx ON assets (name);
CREATE INDEX assets_creator_idx ON assets (creator_address);
