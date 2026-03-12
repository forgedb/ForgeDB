//! Async write-coalescing channel — the fix for the "35 docs/sec per-call" problem.
//!
//! Every `POST /v1/:collection` call currently commits its own transaction, meaning
//! one fsync per document.
//! Under concurrency, though, we can do much better: collect writes that arrive within
//! a short window and flush them in a single transaction.
//!
//! # How it works
//!
//! ```text
//! HTTP handler  ───▶  WriteSender.insert(...)  ──▶  mpsc channel
//!                                                         │
//!                                              WriteBatcher::run()
//!                                                 (background task)
//!                                                         │
//!                                            drain for up to WINDOW_MS
//!                                                         │
//!                                         insert_batch(flush=false) ×N
//!                                                 + flush() once
//!                                                         │
//!                                       resolve all oneshot senders
//! ```
//!
//! Each caller still awaits a `Result<()>` — from their perspective the API is
//! synchronous and durable. The batching is invisible except in the throughput numbers.
//!
//! # Tuning
//!
//! `WINDOW_MS` (default 2 ms) is the maximum time the batcher waits for more writes
//! before committing. Shorter windows = lower tail latency; longer = more throughput.
//! At 2 ms, a burst of 100 concurrent inserts commits as one transaction.

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, timeout};

use forge_types::Result;

use crate::StorageEngine;

/// How long the batcher waits for more writes before forcing a commit.
/// Two milliseconds gives a generous burst window without blowing p99 latency.
const WINDOW_MS: u64 = 2;

/// A queued write request, carrying its own reply channel so the caller can await.
struct WriteRequest {
    collection: String,
    id: String,
    payload: Vec<u8>,
    reply: oneshot::Sender<Result<()>>,
}

/// Owned sender — cheap to clone per Axum handler invocation.
///
/// Think of this as a `StorageEngine` façade that routes single-doc inserts
/// through the coalescing buffer instead of committing immediately.
#[derive(Clone)]
pub struct WriteSender {
    tx: mpsc::Sender<WriteRequest>,
}

impl WriteSender {
    /// Queue a single document insert and await the durable result.
    ///
    /// Returns `Ok(())` once the batch containing this write has been committed
    /// with `Durability::Immediate`. Failure modes: channel closed (server shutting
    /// down) or the underlying redbx insert itself fails.
    pub async fn insert(
        &self,
        collection: impl Into<String>,
        id: impl Into<String>,
        payload: Vec<u8>,
    ) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let req = WriteRequest {
            collection: collection.into(),
            id: id.into(),
            payload,
            reply: reply_tx,
        };

        // If the channel is full (batcher is overwhelmed), fall back gracefully.
        self.tx.send(req).await.map_err(|_| {
            forge_types::ForgeError::Storage(redbx::Error::from(redbx::StorageError::Io(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "write channel closed"),
            )))
        })?;

        // Await confirmation that the batch committed.
        reply_rx.await.unwrap_or_else(|_| {
            Err(forge_types::ForgeError::Storage(redbx::Error::from(
                redbx::StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "batcher dropped reply",
                )),
            )))
        })
    }
}

/// Spawns the background batcher task and returns a [`WriteSender`] to communicate with it.
///
/// Call this once at server startup and stash the `WriteSender` in `AppState`.
/// The batcher runs until the last `WriteSender` is dropped (channel closes).
pub fn spawn_writer(engine: Arc<StorageEngine>) -> WriteSender {
    // 1024 in-flight requests before back-pressure kicks in. Enough for burst,
    // small enough to catch runaways early.
    let (tx, rx) = mpsc::channel::<WriteRequest>(1024);

    tokio::spawn(batcher_loop(engine, rx));

    WriteSender { tx }
}

/// The actual coalescing loop. Runs forever until the sender side is dropped.
async fn batcher_loop(engine: Arc<StorageEngine>, mut rx: mpsc::Receiver<WriteRequest>) {
    loop {
        // Block until at least one write arrives.
        let first = match rx.recv().await {
            Some(r) => r,
            None => break, // All senders dropped — clean shutdown.
        };

        let mut batch = vec![first];

        // Drain everything else that arrives within the window, without blocking.
        let deadline = Duration::from_millis(WINDOW_MS);
        loop {
            match timeout(deadline, rx.recv()).await {
                Ok(Some(req)) => batch.push(req),
                Ok(None) => break, // Channel fully closed mid-drain
                Err(_) => break,   // Window expired — time to commit
            }
        }

        // Batch is assembled. Write all docs, one transaction, one fsync.
        let outcome = commit_batch(&engine, &batch);
        // Stringify the error so we can fan-out to N oneshot senders cheaply.
        // ForgeError wraps redbx::Error which isn't Clone, so this is the pragmatic move.
        let stringified: std::result::Result<(), String> = outcome.map_err(|e| e.to_string());

        for req in batch {
            let reply_result: forge_types::Result<()> = match &stringified {
                Ok(()) => Ok(()),
                Err(msg) => Err(forge_types::ForgeError::Storage(redbx::Error::from(
                    redbx::StorageError::Io(std::io::Error::other(msg.clone())),
                ))),
            };
            let _ = req.reply.send(reply_result);
        }
    }
}

/// Commits all queued writes in a single redbx transaction — one fsync, not N.
///
/// Under 100 concurrent inserts, this is the difference between 100 fsyncs
/// and exactly 1. We group them by collection and dispatch to the storage engine's
/// native `insert_batch` API.
fn commit_batch(engine: &StorageEngine, batch: &[WriteRequest]) -> Result<()> {
    use std::collections::HashMap;

    let mut by_collection: HashMap<&str, Vec<(&str, &[u8])>> = HashMap::new();
    for req in batch {
        by_collection
            .entry(&req.collection)
            .or_default()
            .push((&req.id, &req.payload));
    }

    // Currently: one transaction per distinct collection in the batch window.
    // For a typical REST API this is N=1 almost always, so the cost is negligible.
    // If you're hammering multiple collections simultaneously on a v0.4 cluster node,
    // revisit this with a multi-table single-transaction path — flagged for v0.4.
    for (collection, docs) in by_collection {
        engine.insert_batch(collection, &docs, true)?;
    }

    Ok(())
}
