// Postgres state-layer for the zkCoins server.
//
// Introduced in PR-A1 of the 3-PR Postgres migration series; the
// schema (see `server/migrations/*.sql`) and the typed API around
// `sqlx::PgPool` were defined there. PR-A2 wired the state-layer
// (`load_smt`, `load_mmr`, `load_latest_block`, `persist_state_tx`)
// into the bootstrap and scanner callback, fixing the cross-file
// inconsistency window flagged as issue #11. PR-A3 (this commit)
// wires the remaining `load_all_accounts` / `upsert_account` /
// `load_all_usernames` / `claim_username` / `resolve_username` calls
// into `AccountServer` and `UsernameStore`, and adds the
// `load_minting_num_pubkeys` / `upsert_minting_num_pubkeys` pair that
// replaces the legacy `minting_num_pubkeys.bin` sibling file.
//
// Choice of `sqlx::query` (runtime checked) over `sqlx::query!`
// (compile-time checked): all SQL in this module is short, hand-
// written, and exercised end-to-end by the test suite. Going with
// runtime-checked queries avoids forcing every contributor — and the
// CI Coverage-Gate job — to either run a Postgres container at build
// time or sync an `.sqlx/` offline cache. The trade-off is a slightly
// later failure mode for schema drift, which the tests catch on the
// first run.

use sqlx::{postgres::PgPoolOptions, PgPool};

/// Connect to `url` and run every migration in `./migrations` against
/// the pool. Returns the live pool on success.
///
/// Used in PR-A2 from `main.rs::main` before any state load.
pub async fn connect_and_migrate(url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| sqlx::Error::Migrate(Box::new(e)))?;
    Ok(pool)
}

// ---- State persistence (PR-A2) --------------------------------------------

/// Load the bincode-serialized Sparse Merkle Tree blob.
pub async fn load_smt(pool: &PgPool) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT data FROM smt_state WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(data,)| data))
}

/// Load the bincode-serialized Merkle Mountain Range blob.
pub async fn load_mmr(pool: &PgPool) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT data FROM mmr_state WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(data,)| data))
}

/// Load the 32-byte block hash of the last fully-processed block.
pub async fn load_latest_block(pool: &PgPool) -> Result<Option<[u8; 32]>, sqlx::Error> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT block_hash FROM latest_block WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    match row {
        None => Ok(None),
        Some((bytes,)) => {
            // The schema does not enforce a 32-byte length (BYTEA is
            // arbitrary), so we defensively reject anything else here
            // rather than panicking deep in the scanner. In practice
            // only `persist_state_tx` writes this column, and it takes
            // a `&[u8; 32]`, so this branch should be unreachable.
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                sqlx::Error::Decode(
                    format!(
                        "latest_block.block_hash has unexpected length {} (expected 32)",
                        bytes.len()
                    )
                    .into(),
                )
            })?;
            Ok(Some(arr))
        }
    }
}

/// Atomically write SMT, MMR, and `latest_block` in one transaction.
///
/// The whole point of moving these three blobs into Postgres is the
/// transactional guarantee — issue #11 documents the file-based
/// failure mode where a crash between `smt.bin`, `mmr.bin`, and
/// `latest_block.bin` leaves the three out of sync, and the next
/// start-up either replays already-processed commitments (dup
/// inserts into the SMT) or loses commitments outright. A single
/// `BEGIN; UPSERT; UPSERT; UPSERT; COMMIT` removes that window.
pub async fn persist_state_tx(
    pool: &PgPool,
    smt: &[u8],
    mmr: &[u8],
    latest_block: &[u8; 32],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO smt_state (id, data, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
    )
    .bind(smt)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO mmr_state (id, data, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
    )
    .bind(mmr)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO latest_block (id, block_hash, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET block_hash = EXCLUDED.block_hash, updated_at = EXCLUDED.updated_at",
    )
    .bind(&latest_block[..])
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

// ---- Account persistence (PR-A3) ------------------------------------------

/// Load every `(address, data)` pair from the `accounts` table.
///
/// Used at boot in PR-A3 to rebuild the in-memory `AccountServer`
/// map. Returns an empty vector if the table is empty.
pub async fn load_all_accounts(pool: &PgPool) -> Result<Vec<(Vec<u8>, Vec<u8>)>, sqlx::Error> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT address, data FROM accounts ORDER BY address")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// Upsert a single account row. The bincode blob in `data` is
/// considered authoritative — concurrent writers must serialize at
/// the application layer (`Arc<Mutex<AccountServer>>` in main.rs).
pub async fn upsert_account(pool: &PgPool, address: &[u8], data: &[u8]) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO accounts (address, data, updated_at) \
         VALUES ($1, $2, NOW()) \
         ON CONFLICT (address) DO UPDATE \
         SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
    )
    .bind(address)
    .bind(data)
    .execute(pool)
    .await?;
    Ok(())
}

// ---- Username persistence (PR-A3) -----------------------------------------

/// Load every `(name, address)` pair from the `usernames` table.
pub async fn load_all_usernames(pool: &PgPool) -> Result<Vec<(String, Vec<u8>)>, sqlx::Error> {
    let rows: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT name, address FROM usernames ORDER BY name")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// Attempt to claim `name` for `address`. Returns `Ok(true)` on a
/// fresh claim, `Ok(false)` if the name is already taken (no row
/// inserted, existing row left untouched). The `ON CONFLICT DO
/// NOTHING` makes this race-free at the SQL level.
///
/// `cfg`-gated on the `usernames` feature plus `test`: only the
/// gated `claim_username_handler` calls it in production. The unit
/// tests in `db_tests.rs` exercise it unconditionally.
#[cfg(any(feature = "usernames", test))]
pub async fn claim_username(
    pool: &PgPool,
    name: &str,
    address: &[u8],
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO usernames (name, address, created_at) \
         VALUES ($1, $2, NOW()) \
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(name)
    .bind(address)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Resolve a username to its bound address. Returns `Ok(None)` if
/// the name is not registered.
///
/// Currently unused on the read path — `UsernameStore` keeps the full
/// `name → address` map in memory after the bootstrap `load_all_usernames`
/// call, and `resolve` / `get_username` answer locally. Kept exposed
/// so a future `lnurl`-style read-through cache can call it directly
/// without re-introducing a `HashMap` mirror.
#[allow(dead_code)] // re-added when a read-through caller lands
pub async fn resolve_username(pool: &PgPool, name: &str) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT address FROM usernames WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(addr,)| addr))
}

// ---- Minting metadata (PR-A3) ---------------------------------------------

/// Load the faucet's monotonic `num_pubkeys` counter from the
/// `minting_meta` singleton row.
///
/// Returns `Ok(None)` when the row has never been written (fresh
/// database / no successful mint since bootstrap). Values outside the
/// `0..=u32::MAX` range are rejected as a decode error — the in-
/// memory counter is `u32` (BIP-32 child indices wrap at 2^31, so
/// `u32` is already more head-room than the derivation path supports).
///
/// `cfg`-gated on the `faucet` feature plus `test`: in non-faucet
/// production builds the function has no caller, and the
/// Coverage-Gate would flag it as uncovered. The unit-test suite
/// in `db_tests.rs` exercises it unconditionally.
#[cfg(any(feature = "faucet", test))]
pub async fn load_minting_num_pubkeys(pool: &PgPool) -> Result<Option<u32>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT num_pubkeys FROM minting_meta WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    match row {
        None => Ok(None),
        Some((n,)) => {
            // Defensive: BIGINT is signed and the column has no CHECK
            // constraint, so a manual operator INSERT could plant a
            // negative value or one above `u32::MAX`. Surface that as
            // a decode error rather than panicking on the `as u32`
            // cast.
            if !(0..=i64::from(u32::MAX)).contains(&n) {
                return Err(sqlx::Error::Decode(
                    format!(
                        "minting_meta.num_pubkeys out of u32 range: {} (must be 0..=u32::MAX)",
                        n
                    )
                    .into(),
                ));
            }
            Ok(Some(n as u32))
        }
    }
}

/// Upsert the faucet's monotonic `num_pubkeys` counter. Idempotent
/// on conflict — the singleton row is keyed on `id = 1`. See
/// `load_minting_num_pubkeys` for the matching read and the rationale
/// behind the `faucet`-feature gate.
#[cfg(any(feature = "faucet", test))]
pub async fn upsert_minting_num_pubkeys(pool: &PgPool, n: u32) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO minting_meta (id, num_pubkeys, updated_at) \
         VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE \
         SET num_pubkeys = EXCLUDED.num_pubkeys, updated_at = EXCLUDED.updated_at",
    )
    .bind(i64::from(n))
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
#[path = "db_tests.rs"]
mod tests;
