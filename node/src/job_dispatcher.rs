//! Background dispatcher that drives queued jobs through the
//! mint/send/commit state machine.
//!
//! ## Architecture
//!
//! The dispatcher is a long-lived tokio task spawned by
//! [`spawn`]. It owns a single mpsc receiver of [`JobEnvelope`]s
//! produced by the admit-side routes in `router.rs`
//! (`POST /api/jobs/mint`, `POST /api/jobs/send`). On each envelope
//! it loads the matching `Job` row, walks the state machine one
//! step forward via the `flow::*` helpers, and persists the
//! transition into Postgres via the [`JobStore`].
//!
//! ## Single worker
//!
//! Mint and send proofs run in Plonky2's Rayon worker pool; that
//! pool already saturates every available CPU core during a prove.
//! Running two proves in parallel would only thrash the cache —
//! each individual prove would slow down proportionally and the
//! wallclock throughput would not improve. We therefore drive the
//! state machine on a *single* worker. The mpsc channel becomes
//! the queue; the natural happens-before of channel ordering
//! becomes the schedule. The implication for the operator: queue
//! depth equals user-observable latency, and the resumer's
//! "queue=N waiting" metric is the right thing to monitor.
//!
//! ## Awaiting signature
//!
//! A `send` job, after the prove leg, transitions to
//! `awaiting_signature` and the dispatcher *parks* on a per-job
//! `tokio::sync::Notify` channel registered in the shared
//! [`notify_map`]. The wallet's `POST /api/jobs/:id/commit` handler
//! looks up the same `Notify` entry and calls `notify_one()` after
//! persisting the signature payload — that is the wake edge the
//! dispatcher uses to resume the broadcast leg.
//!
//! The wait is bounded by `awaiting_signature_timeout` (default 10
//! minutes — long enough for a hardware-wallet sign-then-confirm
//! UX with retries, short enough that an abandoned proof file
//! doesn't pin the dispatcher forever). Timing out moves the job
//! to `failed` with `"awaiting_signature timeout"` so the wallet's
//! next poll observes the terminal status.
//!
//! ## Coverage scope
//!
//! Excluded from the 100% line / function gate (alongside
//! `runtime.rs`) via the CI `--ignore-filename-regex` flag. The
//! dispatcher is the integration glue between the (already-covered)
//! `JobStore`, the (already-covered) `flow::*` helpers, and the
//! tokio runtime; its critical paths surface as end-to-end behaviour
//! that the `/api/jobs/*` integration tests in `router_tests.rs`
//! verify against a real testcontainer Postgres.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{mpsc, Notify};
use uuid::Uuid;

use crate::flow::{commit_flow, mint_flow, send_flow, FlowError};
use crate::job_store::{Job, JobKind, JobStatus, JobStore};
use crate::router::{AppState, CommitRequest, MintRequest, SendCoinRequest};

/// Default time the dispatcher will park on the `awaiting_signature`
/// `Notify` channel before timing out the job. Picked to comfortably
/// span a hardware-wallet sign-then-confirm UX (60-120 s on Ledger /
/// BitBox plus user attention) with a generous retry budget.
pub const DEFAULT_AWAITING_SIGNATURE_TIMEOUT: Duration = Duration::from_secs(600);

/// Envelope handed to the dispatcher on every state-machine wake
/// edge. The dispatcher reads `public_id`, loads the `Job` from
/// Postgres, and consults `status` to decide which `flow::*` helper
/// to invoke.
#[derive(Debug, Clone)]
pub struct JobEnvelope {
    pub public_id: Uuid,
}

/// Spawn the dispatcher as a long-lived background tokio task.
///
/// The caller owns the channel: it pairs an `mpsc::Sender<JobEnvelope>`
/// (handed verbatim to every admit handler through the
/// `AppState.job_tx` field) with the matching `mpsc::Receiver`
/// (consumed by the spawned task). The dispatcher terminates when
/// every sender clone has been dropped (graceful shutdown signal).
///
/// ## Parameters
///
/// - `job_store` — JobStore handle for status persistence + load.
/// - `app_state` — shared application state; passed verbatim into
///   the `flow::*` helpers so the dispatcher does not have to
///   thread every dependency (account_node, publisher_config,
///   pool, proof_store) through its own argument list.
/// - `notify_map` — per-job `Notify` channels; populated by the
///   send-flow dispatcher leg before parking, drained by the
///   `commit_handler`'s notify call.
/// - `awaiting_signature_timeout` — cap on the dispatcher's wait
///   for a `commit` signal before timing the job out.
/// - `job_rx` — receiver half of the mpsc channel paired with the
///   `AppState.job_tx` sender.
pub fn spawn(
    job_store: Arc<JobStore>,
    app_state: AppState,
    notify_map: Arc<DashMap<Uuid, Arc<Notify>>>,
    awaiting_signature_timeout: Duration,
    mut rx: mpsc::Receiver<JobEnvelope>,
) {
    tokio::spawn(async move {
        tracing::info!("Job dispatcher started");
        while let Some(env) = rx.recv().await {
            let job_store = job_store.clone();
            let app_state = app_state.clone();
            let notify_map = notify_map.clone();
            let timeout = awaiting_signature_timeout;
            // Process serially: one prove at a time (see module
            // doc-comment for the Rayon-pool rationale). We do NOT
            // `tokio::spawn` here — that would defeat the
            // single-worker invariant.
            if let Err(e) =
                process_envelope(&job_store, &app_state, &notify_map, timeout, env).await
            {
                tracing::error!("Job dispatcher: process_envelope error: {}", e);
            }
        }
        tracing::info!("Job dispatcher channel closed; exiting");
    });
}

/// Drive a single envelope through one state-machine step. The
/// outer loop in [`spawn`] calls this for every received envelope.
async fn process_envelope(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &Arc<DashMap<Uuid, Arc<Notify>>>,
    awaiting_signature_timeout: Duration,
    env: JobEnvelope,
) -> anyhow::Result<()> {
    let job = match job_store.load(env.public_id).await? {
        Some(j) => j,
        None => {
            tracing::warn!(
                "Job dispatcher: envelope for unknown public_id {}",
                env.public_id
            );
            return Ok(());
        }
    };

    if job.status.is_terminal() {
        tracing::debug!(
            "Job dispatcher: envelope for terminal job {} ({:?}); skipping",
            env.public_id,
            job.status
        );
        return Ok(());
    }

    match (job.kind, job.status) {
        (JobKind::Mint, JobStatus::Queued) => process_mint(job_store, app_state, job).await,
        (JobKind::Send, JobStatus::Queued) => {
            process_send_initial(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        (JobKind::Send, JobStatus::AwaitingSignature) => {
            process_send_resume(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        _ => {
            tracing::debug!(
                "Job dispatcher: envelope for {} in unexpected state {:?}; skipping",
                env.public_id,
                job.status
            );
            Ok(())
        }
    }
}

/// Drive a mint job: validate → prove → broadcast → commit. The
/// `flow::mint_flow` helper owns the actual work; the dispatcher
/// is purely the state-machine driver.
async fn process_mint(job_store: &JobStore, app_state: &AppState, job: Job) -> anyhow::Result<()> {
    let public_id = job.public_id;
    job_store
        .set_status(public_id, JobStatus::Proving, "proving")
        .await?;

    let request: MintRequest = match serde_json::from_value(job.request_body.clone()) {
        Ok(r) => r,
        Err(e) => {
            job_store
                .fail(public_id, &format!("invalid mint request body: {}", e))
                .await?;
            return Ok(());
        }
    };

    match mint_flow(app_state, request).await {
        Ok((response_body, response_status)) => {
            job_store
                .complete(public_id, response_body, response_status as i16)
                .await?;
            tracing::info!("Job dispatcher: mint job {} completed", public_id);
        }
        Err(FlowError { status, message }) => {
            tracing::warn!(
                "Job dispatcher: mint job {} failed ({}): {}",
                public_id,
                status.as_u16(),
                message
            );
            job_store.fail(public_id, &message).await?;
        }
    }
    Ok(())
}

/// Drive a send job from `queued` through the prove leg to
/// `awaiting_signature`, then park on the per-job `Notify` channel
/// until the wallet's `commit_handler` signals (or the timeout
/// fires).
async fn process_send_initial(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &Arc<DashMap<Uuid, Arc<Notify>>>,
    awaiting_signature_timeout: Duration,
    job: Job,
) -> anyhow::Result<()> {
    let public_id = job.public_id;
    job_store
        .set_status(public_id, JobStatus::Proving, "proving")
        .await?;

    let request: SendCoinRequest = match serde_json::from_value(job.request_body.clone()) {
        Ok(r) => r,
        Err(e) => {
            job_store
                .fail(public_id, &format!("invalid send request body: {}", e))
                .await?;
            return Ok(());
        }
    };

    let proof_id = match send_flow(app_state, request).await {
        Ok(pid) => pid,
        Err(FlowError { status, message }) => {
            tracing::warn!(
                "Job dispatcher: send job {} prove leg failed ({}): {}",
                public_id,
                status.as_u16(),
                message
            );
            job_store.fail(public_id, &message).await?;
            return Ok(());
        }
    };

    // Register a Notify *before* persisting `awaiting_signature` so
    // a fast wallet that polls and POSTs `/commit` immediately
    // observes a ready channel.
    let notify = Arc::new(Notify::new());
    notify_map.insert(public_id, notify.clone());

    job_store
        .set_awaiting_signature(public_id, proof_id as i64)
        .await?;
    tracing::info!(
        "Job dispatcher: send job {} reached awaiting_signature (proof_id={})",
        public_id,
        proof_id
    );

    wait_for_commit(
        job_store,
        app_state,
        notify_map,
        awaiting_signature_timeout,
        public_id,
        notify,
    )
    .await
}

/// Resume a send job that was already `awaiting_signature` when the
/// process restarted. The boot-time resumer in `runtime.rs`
/// pre-populates a fresh `Notify` in the map so the dispatcher can
/// park on it the same way the in-process flow does.
async fn process_send_resume(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &Arc<DashMap<Uuid, Arc<Notify>>>,
    awaiting_signature_timeout: Duration,
    job: Job,
) -> anyhow::Result<()> {
    let public_id = job.public_id;
    let notify = notify_map
        .entry(public_id)
        .or_insert_with(|| Arc::new(Notify::new()))
        .clone();
    tracing::info!(
        "Job dispatcher: resuming send job {} in awaiting_signature",
        public_id
    );
    wait_for_commit(
        job_store,
        app_state,
        notify_map,
        awaiting_signature_timeout,
        public_id,
        notify,
    )
    .await
}

/// Park on the `notify` channel for the given `public_id`. On wake,
/// load the (now-updated) job, parse the `CommitRequest` the
/// commit-route persisted into the job's `request_body`, and drive
/// the broadcast leg via `commit_flow`. On timeout, fail the job.
async fn wait_for_commit(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &Arc<DashMap<Uuid, Arc<Notify>>>,
    awaiting_signature_timeout: Duration,
    public_id: Uuid,
    notify: Arc<Notify>,
) -> anyhow::Result<()> {
    let outcome = tokio::select! {
        _ = notify.notified() => SignalOutcome::Signaled,
        _ = tokio::time::sleep(awaiting_signature_timeout) => SignalOutcome::TimedOut,
    };

    notify_map.remove(&public_id);

    match outcome {
        SignalOutcome::TimedOut => {
            tracing::warn!(
                "Job dispatcher: send job {} timed out in awaiting_signature",
                public_id
            );
            job_store
                .fail(public_id, "awaiting_signature timeout")
                .await?;
            return Ok(());
        }
        SignalOutcome::Signaled => {}
    }

    let job = match job_store.load(public_id).await? {
        Some(j) => j,
        None => {
            tracing::warn!("Job dispatcher: post-signal load missed job {}", public_id);
            return Ok(());
        }
    };

    // The commit-route persists the wallet-provided
    // `CommitRequest` into the job's `request_body` under a
    // `commit` key alongside the original send body. Pull it out
    // and feed it to `commit_flow`.
    let commit_value = job
        .request_body
        .get("commit")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let commit_request: CommitRequest = match serde_json::from_value(commit_value) {
        Ok(c) => c,
        Err(e) => {
            job_store
                .fail(public_id, &format!("invalid commit body: {}", e))
                .await?;
            return Ok(());
        }
    };

    job_store
        .set_status(public_id, JobStatus::Broadcasting, "broadcasting")
        .await?;

    match commit_flow(app_state, commit_request).await {
        Ok((response_body, response_status)) => {
            job_store
                .complete(public_id, response_body, response_status as i16)
                .await?;
            tracing::info!("Job dispatcher: send job {} completed", public_id);
        }
        Err(FlowError { status, message }) => {
            tracing::warn!(
                "Job dispatcher: send job {} commit leg failed ({}): {}",
                public_id,
                status.as_u16(),
                message
            );
            job_store.fail(public_id, &message).await?;
        }
    }

    Ok(())
}

enum SignalOutcome {
    Signaled,
    TimedOut,
}
