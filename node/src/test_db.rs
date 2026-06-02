//! Shared-Postgres test infrastructure (Optimisation B from
//! zk-coins/node#181).
//!
//! ## Why this exists
//!
//! Before this module, every Postgres-touching test in the node crate
//! spun its own `postgres:17` container via `testcontainers_modules::
//! postgres::Postgres::default().with_tag("17").start()`. Container
//! boot is ~3 s wall on the M3 Ultra runner — multiplied across
//! ~220 DB-touching tests under `--test-threads=1` that is ~11 min
//! of pure container-spawn overhead per CI run.
//!
//! ## What changes
//!
//! - One `postgres:17` container is reused across the entire test
//!   run via testcontainers' `ReuseDirective::Always` + a stable
//!   container name (`zkcoins-test-shared-pg`). `cargo nextest`
//!   spawns one process per test, so a process-local `OnceCell`
//!   does NOT actually share state across tests — it would degrade
//!   to one container per test. The reuse flag tells testcontainers
//!   to look up the named container on the daemon and attach to it
//!   if present, only starting a fresh one when nothing matches.
//!   The container outlives every test binary in the run and is
//!   torn down by the CI's post-test `docker rm -f
//!   zkcoins-test-shared-pg` cleanup step.
//! - Each call to [`setup_pool`] creates a fresh, UUID-named schema
//!   in that shared container, runs the full migration suite scoped
//!   to that schema (via a per-pool `SET search_path` `after_connect`
//!   hook), and hands back a [`SchemaScope`] holding the pool.
//! - When the scope is dropped, a detached tokio task issues
//!   `DROP SCHEMA IF EXISTS "<name>" CASCADE` on its own admin
//!   connection. Best-effort: if the test panicked or the runtime is
//!   shutting down, the schema may leak — acceptable because the
//!   CI cleanup step removes the entire container anyway.
//!
//! ## Migration SQL precondition
//!
//! `search_path`-based schema isolation only works if no migration
//! SQL hardcodes a schema name. As of issue #181 a
//! `grep -E 'public\.|CREATE SCHEMA|SET search_path' node/migrations/`
//! returns empty — every CREATE/ALTER targets an unqualified table
//! name, so it lands in whichever schema is first on `search_path`.
//! New migrations MUST preserve this property.
//!
//! ## Cross-process attach-or-create race (issue #181 Opt A)
//!
//! `testcontainers` 0.27 does NOT atomicise the lookup-or-create
//! path behind `with_reuse(ReuseDirective::Always)`. The flow is:
//! `GET /containers/<name>/json` → on 404, `POST /containers/create`
//! → `POST /containers/<id>/start`. Two processes racing this
//! sequence both observe 404, both POST `create`, the Docker daemon
//! serialises the `create` calls and returns 409 Conflict to every
//! loser because the second `create` collides on the requested name.
//! At `--test-threads=1` this is dormant (one process at a time);
//! at `--test-threads=8` (the post-#181 default) it deterministically
//! breaks 6+/8 nextest processes on every cold-cache run.
//!
//! Workaround: a process-shared exclusive file lock around the
//! `testcontainers` call in [`init_shared_pg`]. The lock file lives
//! under `$TMPDIR` (falls back to `/tmp`) so every test process on
//! the same host serialises through the same inode. The lock is
//! held only across the attach-or-create call (typically <1 s for
//! an attach, ~3 s for the one cold create that wins the race) and
//! released the moment the container handle is in hand. The Drop
//! impl on `fs2`'s lock guard unlocks automatically; we also `drop`
//! the file explicitly to make intent obvious.
//!
//! ## No polling
//!
//! `OnceCell::get_or_init` is event-driven; the first caller spawns
//! the container, every subsequent caller awaits the same future.
//! Per the repo's "No polling — events only" rule (CONTRIBUTING.md)
//! there is no `sleep`-loop fallback path here. The cross-process
//! file lock above is `flock(2)`-based (blocking on the kernel),
//! not a poll loop.

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};
use std::sync::Arc;
use std::time::Duration;
use testcontainers::core::ReuseDirective;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use tokio::sync::OnceCell;

/// Stable name the shared Postgres container is registered under on
/// the local Docker daemon. The `with_reuse(ReuseDirective::Always)`
/// lookup matches on this name plus the image config, so every
/// `cargo nextest` test process attaches to the same container.
const SHARED_PG_CONTAINER_NAME: &str = "zkcoins-test-shared-pg";

/// Lazily-initialised, process-wide (per test binary) Postgres
/// container. `Arc` wrapping lets [`SchemaScope::Drop`] capture a
/// cheap clone of `base_url` without borrowing from the `OnceCell`.
static SHARED_PG: OnceCell<Arc<SharedPg>> = OnceCell::const_new();

/// Single shared Postgres container plus the admin base URL.
///
/// The container handle is retained for the lifetime of the test
/// binary so the daemon does not garbage-collect it before the last
/// test finishes. `_container` is intentionally underscored — nothing
/// else reads it.
pub(crate) struct SharedPg {
    _container: ContainerAsync<Postgres>,
    pub base_url: String,
}

/// A per-test schema scoped against [`SHARED_PG`].
///
/// The held `pool` only ever sees the per-test schema (via the
/// `after_connect` hook that sets `search_path`), so test queries
/// never need to qualify table names. When the scope is dropped,
/// the schema is removed on a detached task — see the module docs
/// for the leak-on-panic caveat.
pub struct SchemaScope {
    pub pool: PgPool,
    schema: String,
    base_url: String,
}

impl SchemaScope {
    /// Name of the isolated per-test schema (`t_<uuid_simple>`).
    /// Exposed so a small number of introspection tests can scope
    /// their `information_schema` queries to the right schema
    /// (otherwise they would see the always-empty `public`).
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Admin base URL for the shared container (`postgres://...
    /// /postgres`, no `search_path` set). Exposed for the two
    /// `db_tests::connect_and_migrate_*` error-path tests that need
    /// to feed a URL into the real `db::connect_and_migrate` while
    /// still landing inside this test's isolated schema. Callers
    /// should append `?options=-c%20search_path%3D<schema>` to
    /// constrain the resulting pool.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for SchemaScope {
    fn drop(&mut self) {
        // Detached, best-effort cleanup. Connecting back to the admin
        // database and issuing a CASCADE drop happens on a fresh
        // connection so we don't risk the per-test pool already being
        // closed by the surrounding tokio runtime. Failures are
        // swallowed: the container teardown at test-binary exit wipes
        // everything regardless.
        let schema = self.schema.clone();
        let base = self.base_url.clone();
        // `tokio::spawn` panics outside a runtime; guard so a
        // synchronous test that holds a `SchemaScope` (currently
        // none, but defensive) does not abort.
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(async move {
                if let Ok(admin) = PgPool::connect(&base).await {
                    let _ = admin
                        .execute(format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE").as_str())
                        .await;
                    admin.close().await;
                }
            });
        }
    }
}

/// Start (or reuse) the shared Postgres container, create a fresh
/// per-test schema, run all migrations scoped to that schema, and
/// return a [`SchemaScope`] whose `pool` field is a `PgPool` whose
/// every connection has `search_path` pinned to the schema.
///
/// Drop the returned scope at the end of the test to surrender the
/// schema. Tests that wrap the pool in `Arc` should keep the scope
/// alive (`let scope = setup_pool().await; let pool =
/// Arc::new(scope.pool.clone());`) — `PgPool::clone` is cheap
/// (it is `Arc`-backed internally).
pub async fn setup_pool() -> SchemaScope {
    let pg = SHARED_PG.get_or_init(init_shared_pg).await.clone();

    let schema = format!("t_{}", uuid::Uuid::new_v4().simple());

    // CREATE SCHEMA via an admin pool (search_path = public) so we
    // do not depend on the chicken-and-egg state of the per-test
    // pool's `after_connect` hook.
    let admin = PgPool::connect(&pg.base_url)
        .await
        .expect("connect admin pool");
    admin
        .execute(format!("CREATE SCHEMA \"{schema}\"").as_str())
        .await
        .expect("create per-test schema");
    admin.close().await;

    // Per-test pool: every connection sets search_path to the
    // isolated schema (with `public` as a fallback so any
    // accidentally-extension-installed objects remain visible). The
    // migration runner below picks up the same `after_connect` hook,
    // so all `CREATE TABLE` statements land in `<schema>` instead of
    // `public`.
    let schema_for_hook = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(60))
        .after_connect(move |conn, _meta| {
            let s = schema_for_hook.clone();
            Box::pin(async move {
                conn.execute(format!("SET search_path TO \"{s}\", public").as_str())
                    .await?;
                Ok(())
            })
        })
        .connect(&pg.base_url)
        .await
        .expect("connect per-test pool");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations in per-test schema");

    SchemaScope {
        pool,
        schema,
        base_url: pg.base_url.clone(),
    }
}

/// Boot OR attach to the shared container. Called via
/// `OnceCell::get_or_init` so concurrent callers within one process
/// await the same future. Across processes (the nextest default),
/// `ReuseDirective::Always` + the stable container name make
/// testcontainers attach to the already-running container instead
/// of spawning a new one.
///
/// The `testcontainers` 0.27 attach-or-create path is NOT atomic
/// (see module docs); under `--test-threads=8` (issue #181 Opt A),
/// 8 concurrent test processes all observe "container not present"
/// and all POST `/containers/create`, with the Docker daemon
/// returning 409 Conflict to every loser. Wrapping the call in a
/// process-shared exclusive file lock serialises the
/// `attach-or-create` so exactly one process creates and the others
/// attach. The lock file lives in `$TMPDIR` (or `/tmp` fallback)
/// keyed by a stable name so every test binary on the host
/// serialises through the same inode.
async fn init_shared_pg() -> Arc<SharedPg> {
    // Process-shared exclusive lock around the testcontainers
    // attach-or-create call. Held only across that call; the
    // container creation cost (~3 s once per host) amortises
    // across the whole test run. `fs2`'s `FileExt::lock_exclusive`
    // blocks on `flock(2)` (POSIX) / `LockFileEx` (Windows) —
    // event-driven at the kernel level, no busy-wait. The guard is
    // unlocked on Drop; we also `drop` it explicitly below to make
    // the critical-section boundary obvious in code.
    let lock_path = std::env::temp_dir().join("zkcoins-test-pg.lock");
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .expect("open shared-pg lock file");
    fs2::FileExt::lock_exclusive(&lock_file).expect("acquire shared-pg lock");

    let container = Postgres::default()
        .with_tag("17")
        .with_container_name(SHARED_PG_CONTAINER_NAME)
        .with_reuse(ReuseDirective::Always)
        .start()
        .await
        .expect("start or attach to shared postgres:17 container");
    let host = container
        .get_host()
        .await
        .expect("shared postgres get_host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("shared postgres get_host_port_ipv4");
    let base_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    // Explicit drop releases the exclusive lock the moment the
    // container handle is in hand. The Drop impl on `lock_file`
    // would do this at function return anyway, but spelling it out
    // makes the critical-section boundary obvious.
    drop(lock_file);

    Arc::new(SharedPg {
        _container: container,
        base_url,
    })
}
