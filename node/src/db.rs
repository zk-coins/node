// Postgres state-layer for the zkCoins server.
//
// Introduced in PR-A1 of the 3-PR Postgres migration series; the
// schema (see `node/migrations/*.sql`) and the typed API around
// `sqlx::PgPool` were defined there. PR-A2 wired the state-layer
// (`load_smt`, `load_mmr`, `load_latest_block`, `persist_state_tx`)
// into the bootstrap and scanner callback, fixing the cross-file
// inconsistency window flagged as issue #11. PR-A3 wired the
// `load_all_accounts` / `upsert_account` / `load_all_usernames` /
// `claim_username` / `resolve_username` calls into `AccountNode` and
// `UsernameStore`. The Phase-D rework dropped the
// `load_minting_num_pubkeys` / `upsert_minting_num_pubkeys` pair and
// the optimistic counter-bump step inside `commit_mint_tx`: the
// minting account's `num_pubkeys` is now derived from SMT membership
// at runtime (see `state::derive_num_pubkeys_from_smt`). Migration
// 0005 drops the `minting_meta` table outright.
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
use zkcoins_program::hash::{digest_from_bytes, digest_to_bytes, HashDigest};

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

/// Atomically write SMT, MMR, `latest_block`, and (optionally) the
/// freshly-inserted `mmr_root_index` row in one transaction.
///
/// The whole point of moving these blobs into Postgres is the
/// transactional guarantee — issue #11 documents the file-based
/// failure mode where a crash between `smt.bin`, `mmr.bin`, and
/// `latest_block.bin` leaves the three out of sync, and the next
/// start-up either replays already-processed commitments (dup
/// inserts into the SMT) or loses commitments outright. A single
/// `BEGIN; UPSERT; UPSERT; UPSERT; INSERT; COMMIT` removes that window.
///
/// The Phase-C `mmr_root_index` write is part of the SAME transaction
/// because a crash between the state snapshot and the root_index INSERT
/// is catastrophic for replay healing: on restart the scanner resumes
/// from the saved `latest_block` and re-scans the same commit tx →
/// `state.update` runs again → SMT insert is idempotent but `mmr.append`
/// is NOT → MMR diverges → `prev_mmr_root` becomes a NEW key → fresh
/// `root_indices` entry written under the new key → the original
/// missing entry is never healed. Folding the INSERT into the same tx
/// means either both land or neither does; on a crash before COMMIT,
/// the next start-up re-runs `state.update` against the SAME unchanged
/// MMR and writes the SAME `(prev_mmr_root, smt_root, leaf_index)` —
/// `ON CONFLICT (prev_mmr_root) DO NOTHING` makes that a no-op on the
/// row that did land, or a fresh insert on the row that did not.
///
/// `root_index_entry` is `Option<…>` because the first call from a
/// fresh database (no `State::update` has fired yet) has nothing to
/// write — only the bootstrap path which seeds an empty SMT/MMR would
/// hit that case in practice. Today every scanner-callback caller
/// passes `Some(...)`.
pub async fn persist_state_tx(
    pool: &PgPool,
    smt: &[u8],
    mmr: &[u8],
    latest_block: &[u8; 32],
    root_index_entry: Option<(&HashDigest, &HashDigest, u64)>,
) -> Result<(), sqlx::Error> {
    // Pre-encode the optional root_index columns OUTSIDE the tx so a
    // bad `leaf_index` (e.g. > i64::MAX in some hypothetical future)
    // surfaces before we open a Postgres connection. Today the value
    // comes from `mmr.leaf_count()` so the conversion is infallible in
    // practice; keep the defensive error for symmetry with the
    // standalone `insert_root_index` helper.
    let root_index_bytes = match root_index_entry {
        None => None,
        Some((prev_root, smt_root, leaf_index)) => {
            let leaf_i64 = i64::try_from(leaf_index).map_err(|_| {
                sqlx::Error::Encode(
                    format!("leaf_index {} does not fit in i64 (BIGINT)", leaf_index).into(),
                )
            })?;
            Some((
                digest_to_bytes(prev_root),
                digest_to_bytes(smt_root),
                leaf_i64,
            ))
        }
    };

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
    if let Some((prev_bytes, smt_bytes, leaf_i64)) = root_index_bytes {
        sqlx::query(
            "INSERT INTO mmr_root_index (prev_mmr_root, smt_root, leaf_index, created_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (prev_mmr_root) DO NOTHING",
        )
        .bind(&prev_bytes[..])
        .bind(&smt_bytes[..])
        .bind(leaf_i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

// ---- Account persistence (PR-A3) ------------------------------------------

/// Load every `(address, data)` pair from the `accounts` table.
///
/// Used at boot in PR-A3 to rebuild the in-memory `AccountNode`
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
/// the application layer (`Arc<Mutex<AccountNode>>` in main.rs).
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

// ---- Minting commit transaction (Phase D) ---------------------------------

/// Atomically upsert every account row mutated by a successful mint.
///
/// Phase D removed the optimistic `minting_meta.num_pubkeys` counter
/// bump that used to sit at the head of this transaction: the
/// minting-account `num_pubkeys` is now derived from SMT membership at
/// runtime (`state::derive_num_pubkeys_from_smt`), so the only DB-side
/// work left is the per-account UPSERT bundle. The signature still
/// returns `Result<(), sqlx::Error>` to keep the call-site shape
/// symmetric with the other helpers; the `bool` "race lost"
/// discriminator on the old API is gone because the in-process
/// concurrency gate has moved out of Postgres (see `mint_handler` for
/// the new gate).
///
/// All UPSERTs share one transaction so the bundle is atomic even on
/// a partial DB failure — either every recipient + the mutated minting
/// account land, or none do.
pub async fn commit_mint_tx(pool: &PgPool, accounts: &[(&[u8], &[u8])]) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for (address, data) in accounts {
        sqlx::query(
            "INSERT INTO accounts (address, data, updated_at) \
             VALUES ($1, $2, NOW()) \
             ON CONFLICT (address) DO UPDATE \
             SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
        )
        .bind(*address)
        .bind(*data)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

// ---- Pending inscription persistence (Phase B) ----------------------------

/// State-machine label persisted in `pending_inscriptions.status`.
///
/// The four in-progress states (`constructed`, `commit_broadcast`,
/// `reveal_broadcast`) track the publisher's progress through the
/// commit + reveal broadcast pair. `complete` is terminal-success;
/// `failed` is reserved for future use (today the resumer treats
/// every non-complete row as retryable).
pub const PENDING_STATUS_CONSTRUCTED: &str = "constructed";
pub const PENDING_STATUS_COMMIT_BROADCAST: &str = "commit_broadcast";
pub const PENDING_STATUS_REVEAL_BROADCAST: &str = "reveal_broadcast";
pub const PENDING_STATUS_COMPLETE: &str = "complete";

/// In-memory representation of a `pending_inscriptions` row loaded by
/// [`load_pending_in_progress`]. The blob columns are returned raw —
/// callers deserialize via the same `bitcoin::consensus::deserialize`
/// shape used at write time.
#[derive(Debug, Clone)]
pub struct PendingInscriptionRow {
    pub id: i64,
    pub commit_txid: Vec<u8>,
    pub status: String,
    pub commitment: Vec<u8>,
    pub commit_tx: Vec<u8>,
    pub reveal_tx: Vec<u8>,
    pub commit_output_value: i64,
}

/// Insert a fresh `constructed` row before the publisher attempts the
/// first commit broadcast. `commit_txid` is the deterministic txid of
/// the supplied `commit_tx` bytes; callers compute it once and pass it
/// in so retries can match the UNIQUE constraint.
///
/// On UNIQUE-violation (a previous attempt persisted the same pair and
/// crashed before completing), the function returns `Ok(false)` so the
/// caller can carry on with the existing row instead of double-
/// inserting. Every other DB error propagates.
pub async fn insert_pending_inscription(
    pool: &PgPool,
    commit_txid: &[u8],
    commitment: &[u8],
    commit_tx: &[u8],
    reveal_tx: &[u8],
    commit_output_value: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO pending_inscriptions \
         (commit_txid, status, commitment, commit_tx, reveal_tx, commit_output_value) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (commit_txid) DO NOTHING",
    )
    .bind(commit_txid)
    .bind(PENDING_STATUS_CONSTRUCTED)
    .bind(commitment)
    .bind(commit_tx)
    .bind(reveal_tx)
    .bind(commit_output_value)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Advance a row to the supplied status. The caller is responsible for
/// passing a status that the CHECK constraint accepts — using the
/// `PENDING_STATUS_*` constants guarantees that.
pub async fn update_pending_status(
    pool: &PgPool,
    commit_txid: &[u8],
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE pending_inscriptions \
         SET status = $1, updated_at = NOW() \
         WHERE commit_txid = $2",
    )
    .bind(status)
    .bind(commit_txid)
    .execute(pool)
    .await?;
    Ok(())
}

/// Load every row whose status is not `complete`, ordered by `id` so
/// the resumer walks them in insertion order. The partial index
/// `pending_inscriptions_status_idx` keeps this scan O(pending), not
/// O(total).
pub async fn load_pending_in_progress(
    pool: &PgPool,
) -> Result<Vec<PendingInscriptionRow>, sqlx::Error> {
    // Tuple layout: (id, commit_txid, status, commitment, commit_tx,
    // reveal_tx, commit_output_value). Aliased to keep the
    // `sqlx::query_as` annotation under clippy's `type_complexity`
    // threshold.
    type RawRow = (i64, Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>, i64);
    let rows: Vec<RawRow> = sqlx::query_as(
        "SELECT id, commit_txid, status, commitment, commit_tx, reveal_tx, commit_output_value \
         FROM pending_inscriptions \
         WHERE status <> 'complete' \
         ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, commit_txid, status, commitment, commit_tx, reveal_tx, commit_output_value)| {
                PendingInscriptionRow {
                    id,
                    commit_txid,
                    status,
                    commitment,
                    commit_tx,
                    reveal_tx,
                    commit_output_value,
                }
            },
        )
        .collect())
}

// ---- MMR root index persistence (Phase C) ---------------------------------

/// Insert a single `(prev_mmr_root) -> (smt_root, leaf_index)` row.
///
/// Called from the scanner callback right after `State::update`
/// successfully appended a new MMR leaf. `ON CONFLICT DO NOTHING` makes
/// replays idempotent: an MMR append is monotonic, so the same
/// `prev_mmr_root` key cannot legitimately resolve to two distinct
/// `(smt_root, leaf_index)` tuples — the first writer's value is
/// authoritative and a re-entrant retry (e.g. a scanner re-scan after a
/// crash that already persisted this entry) is a no-op.
///
/// `leaf_index` is the in-memory `usize` from `mmr.leaf_count()`. We
/// cast through `i64` because Postgres has no unsigned BIGINT — the
/// load path rejects negative values, so this round-trip is safe up to
/// `i64::MAX`, well above any plausible MMR depth.
pub async fn insert_root_index(
    pool: &PgPool,
    prev_root: &HashDigest,
    smt_root: &HashDigest,
    leaf_index: u64,
) -> Result<(), sqlx::Error> {
    let prev_bytes = digest_to_bytes(prev_root);
    let smt_bytes = digest_to_bytes(smt_root);
    let leaf_i64 = i64::try_from(leaf_index).map_err(|_| {
        sqlx::Error::Encode(
            format!("leaf_index {} does not fit in i64 (BIGINT)", leaf_index).into(),
        )
    })?;
    sqlx::query(
        "INSERT INTO mmr_root_index (prev_mmr_root, smt_root, leaf_index, created_at) \
         VALUES ($1, $2, $3, NOW()) \
         ON CONFLICT (prev_mmr_root) DO NOTHING",
    )
    .bind(&prev_bytes[..])
    .bind(&smt_bytes[..])
    .bind(leaf_i64)
    .execute(pool)
    .await?;
    Ok(())
}

/// Load every `(prev_mmr_root, smt_root, leaf_index)` row from the
/// `mmr_root_index` table, ordered by `leaf_index` so the caller can
/// rebuild the in-memory map deterministically (and so the highest
/// `leaf_index` entry — used to restore `State::prev_mmr_root` — is
/// always the last element).
///
/// Returns an empty vector when the table has never been written
/// (fresh database). Length / digest decoding mirrors the defensive
/// branch in [`load_latest_block`]: 32 bytes for each digest, with a
/// `sqlx::Error::Decode` surface on length mismatch rather than a
/// panic deep in the bootstrap.
pub async fn load_root_indices(
    pool: &PgPool,
) -> Result<Vec<(HashDigest, HashDigest, u64)>, sqlx::Error> {
    let rows: Vec<(Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT prev_mmr_root, smt_root, leaf_index FROM mmr_root_index ORDER BY leaf_index",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (prev_bytes, smt_bytes, leaf_i64) in rows {
        let prev_arr: [u8; 32] = prev_bytes.as_slice().try_into().map_err(|_| {
            sqlx::Error::Decode(
                format!(
                    "mmr_root_index.prev_mmr_root has unexpected length {} (expected 32)",
                    prev_bytes.len()
                )
                .into(),
            )
        })?;
        let smt_arr: [u8; 32] = smt_bytes.as_slice().try_into().map_err(|_| {
            sqlx::Error::Decode(
                format!(
                    "mmr_root_index.smt_root has unexpected length {} (expected 32)",
                    smt_bytes.len()
                )
                .into(),
            )
        })?;
        if leaf_i64 < 0 {
            return Err(sqlx::Error::Decode(
                format!(
                    "mmr_root_index.leaf_index out of u64 range: {} (must be >= 0)",
                    leaf_i64
                )
                .into(),
            ));
        }
        out.push((
            digest_from_bytes(&prev_arr),
            digest_from_bytes(&smt_arr),
            leaf_i64 as u64,
        ));
    }
    Ok(out)
}

#[cfg(test)]
#[path = "db_tests.rs"]
mod tests;
