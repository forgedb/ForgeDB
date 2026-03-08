//! Storage engine — redbx with page-level AES-256-GCM encryption.
//!
//! [`StorageEngine`] is the beating heart of ForgeDB. Every collection maps to a
//! redbx table; the key is a string document ID, the value is raw bytes (MessagePack
//! once the codec layer lands, raw bytes today). Encryption happens transparently at
//! the page level — callers never touch a key.
//!
//! # Performance Considerations
//!
//! The engine is tuned through [`StorageConfig`]:
//!
//! - **`cache_size_bytes`** — redbx's internal LRU page cache. Hot documents that
//!   fit in cache cost zero disk I/O on reads. Default is 64 MiB; bump it if you
//!   have the RAM and a tight read-latency SLA.
//! - **`page_size_bytes`** — smaller pages reduce write amplification for small docs.
//!   512 B works well for our typical < 512-byte MessagePack payloads. Larger values
//!   suit bigger documents or workloads with more sequential scan patterns.
//!
//! # Write durability
//!
//! `insert` and `delete` use `Durability::Immediate` by default — every single-doc
//! call is fully durable. `insert_batch` and `delete_batch` accept a `flush` flag:
//! - `flush = true` → `Durability::Immediate` (safe default)
//! - `flush = false` → `Durability::None` (in-memory; caller MUST call `flush()` before crash risk)
//!
//! The async write batcher in `crate::writer` uses `flush = false` internally and
//! issues one `Durability::Immediate` commit at the end of each coalesce window.

use std::path::Path;

use bytes::Bytes;
use redbx::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

use forge_types::{ForgeError, Result};

/// Tuning knobs for the storage layer — kept separate from `ForgeConfig` so the
/// storage crate doesn't need to know about the whole world.
///
/// Defaults are chosen conservatively: fast for dev, sensible in prod without tuning.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Total page cache budget in bytes. Split 90/10 between reads and writes by redbx.
    /// Default: 64 MiB — enough to cache ~131k average 512-byte documents in memory.
    pub cache_size_bytes: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            // 64 MiB sweet spot for a local single-node instance.
            // Production clusters with abundant RAM can push this to 256+ MiB safely.
            cache_size_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Handle to an open redbx database, ready to serve document CRUD.
pub struct StorageEngine {
    db: Database,
}

impl StorageEngine {
    /// Create a new encrypted database at `path` with default storage tuning.
    ///
    /// The `password` goes through PBKDF2-SHA256 (100k iterations) inside redbx
    /// to derive the AES-256-GCM page key. This is expensive by design — only
    /// called during `forgedb init`, not on regular startup.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Storage`] if creation fails (path unwritable, etc.).
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        Self::create_with_config(path, password, StorageConfig::default())
    }

    /// Create with explicit tuning. Useful in tests that want a small footprint.
    pub fn create_with_config(path: &Path, password: &str, cfg: StorageConfig) -> Result<Self> {
        let mut builder = Database::builder();
        builder.set_cache_size(cfg.cache_size_bytes);

        let db = builder.create(path, password).map_err(redbx::Error::from)?;

        tracing::info!(
            path = %path.display(),
            cache_mb = cfg.cache_size_bytes / (1024 * 1024),
            "created encrypted database",
        );
        Ok(Self { db })
    }

    /// Open an existing encrypted database with default storage tuning.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Storage`] on wrong password, missing file, or corruption.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        Self::open_with_config(path, password, StorageConfig::default())
    }

    /// Open with explicit tuning — lets the server crate pass `ForgeConfig` values in.
    pub fn open_with_config(path: &Path, password: &str, cfg: StorageConfig) -> Result<Self> {
        let mut builder = Database::builder();
        builder.set_cache_size(cfg.cache_size_bytes);

        let db = builder.open(path, password).map_err(redbx::Error::from)?;

        tracing::info!(
            path = %path.display(),
            cache_mb = cfg.cache_size_bytes / (1024 * 1024),
            "opened encrypted database",
        );
        Ok(Self { db })
    }

    /// Insert a document into a collection. Overwrites if the key already exists.
    ///
    /// One write transaction per call — fully durable on return.
    /// For bulk imports, use [`insert_batch`] instead.
    pub fn insert(&self, collection: &str, id: &str, doc: &[u8]) -> Result<()> {
        let table_def: TableDefinition<&str, &[u8]> = TableDefinition::new(collection);
        let txn = self.db.begin_write().map_err(redbx::Error::from)?;
        {
            let mut table = txn.open_table(table_def).map_err(redbx::Error::from)?;
            table.insert(id, doc).map_err(redbx::Error::from)?;
        }
        txn.commit().map_err(redbx::Error::from)?;
        Ok(())
    }

    /// Retrieve a document by ID.
    ///
    /// Returns `None` if the key doesn't exist or the collection hasn't been written to yet.
    ///
    /// Returns [`Bytes`] rather than `Vec<u8>` — cheaper to clone for callers that
    /// forward the data straight into an Axum response body without inspecting it.
    pub fn get(&self, collection: &str, id: &str) -> Result<Option<Bytes>> {
        let table_def: TableDefinition<&str, &[u8]> = TableDefinition::new(collection);
        let txn = self.db.begin_read().map_err(redbx::Error::from)?;

        let table = match txn.open_table(table_def) {
            Ok(t) => t,
            Err(redbx::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(ForgeError::Storage(e.into())),
        };

        match table.get(id).map_err(redbx::Error::from)? {
            // Bytes::copy_from_slice is still a copy, but gives us the right type for
            // cheap downstream cloning and direct Axum body forwarding.
            Some(value) => Ok(Some(Bytes::copy_from_slice(value.value()))),
            None => Ok(None),
        }
    }

    /// Delete a document by ID. Returns `true` if the key existed.
    pub fn delete(&self, collection: &str, id: &str) -> Result<bool> {
        let table_def: TableDefinition<&str, &[u8]> = TableDefinition::new(collection);
        let txn = self.db.begin_write().map_err(redbx::Error::from)?;
        let existed = {
            let mut table = txn.open_table(table_def).map_err(redbx::Error::from)?;
            table.remove(id).map_err(redbx::Error::from)?.is_some()
        };
        txn.commit().map_err(redbx::Error::from)?;
        Ok(existed)
    }

    /// Insert many documents in a single write transaction — one fsync, not N.
    ///
    /// Each tuple is `(doc_id, raw_bytes)`. Prior to v0.3 this took a single value
    /// for all IDs, which was a stopgap that nobody liked — now every document gets
    /// its own payload like a civilized database.
    ///
    /// Set `flush` to `false` for intermediate batches in a larger import sequence;
    /// call [`flush`] afterward. Leave it `true` for safety unless you're orchestrating
    /// a multi-step bulk load and genuinely know the crash-recovery implications.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Storage`] if the transaction or any individual insert fails.
    pub fn insert_batch(
        &self,
        collection: &str,
        docs: &[(&str, &[u8])],
        flush: bool,
    ) -> Result<()> {
        let table_def: TableDefinition<&str, &[u8]> = TableDefinition::new(collection);
        let mut txn = self.db.begin_write().map_err(redbx::Error::from)?;

        if !flush {
            let _ = txn.set_durability(Durability::None);
        }

        {
            let mut table = txn.open_table(table_def).map_err(redbx::Error::from)?;
            for (id, payload) in docs {
                table.insert(*id, *payload).map_err(redbx::Error::from)?;
            }
        }
        txn.commit().map_err(redbx::Error::from)?;
        Ok(())
    }

    /// Delete many documents in a single write transaction — saves you N-1 fsyncs.
    ///
    /// Same `flush` semantics as [`insert_batch`].
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Storage`] if the transaction or any individual removal fails.
    pub fn delete_batch(&self, collection: &str, ids: &[String], flush: bool) -> Result<()> {
        let table_def: TableDefinition<&str, &[u8]> = TableDefinition::new(collection);
        let mut txn = self.db.begin_write().map_err(redbx::Error::from)?;

        if !flush {
            let _ = txn.set_durability(Durability::None);
        }

        {
            let mut table = txn.open_table(table_def).map_err(redbx::Error::from)?;
            for id in ids {
                table.remove(id.as_str()).map_err(redbx::Error::from)?;
            }
        }
        txn.commit().map_err(redbx::Error::from)?;
        Ok(())
    }

    /// Force a durable flush to disk. Use after a sequence of non-flushing batch operations.
    ///
    /// Commits an empty write transaction with `Durability::Immediate`, which triggers
    /// an OS-level fsync on all dirty pages. A no-op if redbx has nothing pending.
    pub fn flush(&self) -> Result<()> {
        let txn = self.db.begin_write().map_err(redbx::Error::from)?;
        txn.commit().map_err(redbx::Error::from)?;
        Ok(())
    }

    /// List all documents in a collection as `(id, Bytes)` pairs.
    ///
    /// Returns an empty Vec if the collection doesn't exist yet — no error, just empty.
    pub fn list(&self, collection: &str) -> Result<Vec<(String, Bytes)>> {
        let table_def: TableDefinition<&str, &[u8]> = TableDefinition::new(collection);
        let txn = self.db.begin_read().map_err(redbx::Error::from)?;

        let table = match txn.open_table(table_def) {
            Ok(t) => t,
            Err(redbx::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(ForgeError::Storage(e.into())),
        };

        let mut results = Vec::new();
        for entry in table.iter().map_err(redbx::Error::from)? {
            let (key, value) = entry.map_err(redbx::Error::from)?;
            results.push((
                key.value().to_string(),
                Bytes::copy_from_slice(value.value()),
            ));
        }
        Ok(results)
    }
}

/// A page of documents returned from `list_paginated`.
/// Contains the items and an optional cursor for the next page.
pub type PaginatedList = (Vec<(String, Bytes)>, Option<String>);

impl StorageEngine {
    /// List documents with cursor-based pagination.
    ///
    /// Fetches up to `limit + 1` records starting *after* the provided `cursor`.
    /// The `+ 1` trick allows us to detect if there's a subsequent page without
    /// running a separate (and potentially costly) count query.
    ///
    /// # Errors
    /// Returns [`ForgeError::Storage`] if the read transaction fails.
    pub fn list_paginated(
        &self,
        collection: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<PaginatedList> {
        let table_def: TableDefinition<&str, &[u8]> = TableDefinition::new(collection);
        let txn = self.db.begin_read().map_err(redbx::Error::from)?;

        let table = match txn.open_table(table_def) {
            Ok(t) => t,
            Err(redbx::TableError::TableDoesNotExist(_)) => return Ok((Vec::new(), None)),
            Err(e) => return Err(ForgeError::Storage(e.into())),
        };

        let mut results: Vec<(String, Bytes)> = Vec::with_capacity(limit + 1);
        let mut next_cursor = None;

        if let Some(c) = cursor {
            // True keyset pagination: ask the B-Tree to start strictly AFTER the cursor
            let iter = table
                .range::<&str>((std::ops::Bound::Excluded(c), std::ops::Bound::Unbounded))
                .map_err(redbx::Error::from)?;
            for entry in iter {
                let (key, value) = entry.map_err(redbx::Error::from)?;
                let id = key.value().to_string();

                results.push((id, Bytes::copy_from_slice(value.value())));
                if results.len() > limit {
                    break;
                }
            }
        } else {
            let iter = table.iter().map_err(redbx::Error::from)?;
            for entry in iter {
                let (key, value) = entry.map_err(redbx::Error::from)?;
                let id = key.value().to_string();

                results.push((id, Bytes::copy_from_slice(value.value())));
                if results.len() > limit {
                    break;
                }
            }
        }

        if results.len() > limit {
            // We got one more than asked for, which means there is a next page.
            // The cursor for the next page is the ID of the last item *on this page*.
            results.pop(); // Remove that extra item so we only return `limit` items
            next_cursor = results.last().map(|(k, _)| k.clone());
        }

        Ok((results, next_cursor))
    }

    /// Read-modify-write a document atomically within a single transaction.
    ///
    /// The `merge_fn` receives `(existing_bytes, patch_bytes)` and returns the merged bytes.
    /// This separation keeps the storage layer entirely codec-agnostic while ensuring
    /// the fetch and write happen without intervening mutations.
    ///
    /// # Errors
    /// Returns [`ForgeError::Storage`] if the document doesn't exist, if the read/write
    /// fails, or if `merge_fn` returns an error.
    pub fn update_doc(
        &self,
        collection: &str,
        id: &str,
        patch: &[u8],
        merge_fn: impl Fn(&[u8], &[u8]) -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let table_def: TableDefinition<&str, &[u8]> = TableDefinition::new(collection);
        let txn = self.db.begin_write().map_err(redbx::Error::from)?;

        let merged = {
            let table = txn.open_table(table_def).map_err(redbx::Error::from)?;

            let existing = table.get(id).map_err(redbx::Error::from)?.ok_or_else(|| {
                ForgeError::Storage(redbx::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("document '{id}' not found for patch"),
                )))
            })?;

            merge_fn(existing.value(), patch)?
        };

        // We re-open the table block to bypass borrow-checker holding `existing`
        {
            let mut table = txn.open_table(table_def).map_err(redbx::Error::from)?;
            table
                .insert(id, merged.as_slice())
                .map_err(redbx::Error::from)?;
        }

        txn.commit().map_err(redbx::Error::from)?;
        Ok(merged)
    }

    /// Exposes a safe handle for appending entries to the immutable audit log.
    pub fn audit_log(&self) -> crate::audit::AuditLog<'_> {
        crate::audit::AuditLog::new(&self.db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_engine() -> (StorageEngine, TempDir) {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("test.forgedb");
        // Use a tiny cache in tests to avoid hogging RAM on CI.
        let cfg = StorageConfig {
            cache_size_bytes: 4 * 1024 * 1024, // 4 MiB
        };
        let engine = StorageEngine::create_with_config(&db_path, "test_password", cfg).unwrap();
        (engine, tmp)
    }

    #[test]
    fn insert_and_get() {
        let (engine, _tmp) = test_engine();
        engine.insert("users", "u1", b"hello").unwrap();
        let result = engine.get("users", "u1").unwrap();
        assert_eq!(result, Some(Bytes::from_static(b"hello")));
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let (engine, _tmp) = test_engine();
        assert_eq!(engine.get("users", "nope").unwrap(), None);
    }

    #[test]
    fn delete_existing_and_missing() {
        let (engine, _tmp) = test_engine();
        engine.insert("users", "u1", b"data").unwrap();
        assert!(engine.delete("users", "u1").unwrap());
        assert!(!engine.delete("users", "u1").unwrap());
    }

    #[test]
    fn list_all_documents() {
        let (engine, _tmp) = test_engine();
        engine.insert("items", "a", b"one").unwrap();
        engine.insert("items", "b", b"two").unwrap();

        let mut docs = engine.list("items").unwrap();
        docs.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0], ("a".into(), Bytes::from_static(b"one")));
        assert_eq!(docs[1], ("b".into(), Bytes::from_static(b"two")));
    }

    #[test]
    fn list_empty_collection() {
        let (engine, _tmp) = test_engine();
        assert!(engine.list("ghost").unwrap().is_empty());
    }

    #[test]
    fn list_paginated() {
        let (engine, _tmp) = test_engine();
        // Insert 5 items
        for i in 1..=5 {
            engine
                .insert("items", &format!("k{i}"), format!("v{i}").as_bytes())
                .unwrap();
        }

        // Page 1: limits to 2, returns cursor "k2"
        let (p1, cursor1) = engine.list_paginated("items", None, 2).unwrap();
        assert_eq!(p1.len(), 2);
        assert_eq!(p1[0].0, "k1");
        assert_eq!(p1[1].0, "k2");
        assert_eq!(cursor1.as_deref(), Some("k2"));

        // Page 2: starts after "k2", limits to 2, returns cursor "k4"
        let (p2, cursor2) = engine
            .list_paginated("items", cursor1.as_deref(), 2)
            .unwrap();
        assert_eq!(p2.len(), 2);
        assert_eq!(p2[0].0, "k3");
        assert_eq!(p2[1].0, "k4");
        assert_eq!(cursor2.as_deref(), Some("k4"));

        // Page 3: starts after "k4", limits to 2, gets 1, cursor None
        let (p3, cursor3) = engine
            .list_paginated("items", cursor2.as_deref(), 2)
            .unwrap();
        assert_eq!(p3.len(), 1);
        assert_eq!(p3[0].0, "k5");
        assert_eq!(cursor3, None);

        // Page 4: empty
        let (p4, cursor4) = engine.list_paginated("items", Some("k5"), 2).unwrap();
        assert!(p4.is_empty());
        assert_eq!(cursor4, None);
    }

    #[test]
    fn update_doc_atomic_patch() {
        let (engine, _tmp) = test_engine();
        engine.insert("users", "u1", b"original").unwrap();

        let patched = engine
            .update_doc("users", "u1", b"patched", |old, new| {
                assert_eq!(old, b"original");
                Ok(new.to_vec())
            })
            .unwrap();

        assert_eq!(patched, b"patched");

        // Verify the write was actually persisted
        let verify = engine.get("users", "u1").unwrap();
        assert_eq!(verify.unwrap(), b"patched".as_slice());
    }

    #[test]
    fn update_doc_returns_not_found() {
        let (engine, _tmp) = test_engine();
        let res = engine.update_doc("ghosts", "g1", b"boo", |_, new| Ok(new.to_vec()));
        assert!(matches!(res, Err(ForgeError::Storage(_))));
    }

    #[test]
    fn collections_are_isolated() {
        let (engine, _tmp) = test_engine();
        engine.insert("a", "x", b"aaa").unwrap();
        engine.insert("b", "x", b"bbb").unwrap();
        assert_eq!(
            engine.get("a", "x").unwrap(),
            Some(Bytes::from_static(b"aaa"))
        );
        assert_eq!(
            engine.get("b", "x").unwrap(),
            Some(Bytes::from_static(b"bbb"))
        );
    }

    #[test]
    fn reopen_with_correct_password() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("reopen.forgedb");

        let engine = StorageEngine::create(&path, "s3cret").unwrap();
        engine.insert("data", "key", b"persisted").unwrap();
        drop(engine);

        let engine = StorageEngine::open(&path, "s3cret").unwrap();
        assert_eq!(
            engine.get("data", "key").unwrap(),
            Some(Bytes::from_static(b"persisted"))
        );
    }

    #[test]
    fn wrong_password_fails() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("locked.forgedb");

        StorageEngine::create(&path, "right").unwrap();
        assert!(StorageEngine::open(&path, "wrong").is_err());
    }

    #[test]
    fn insert_batch_then_read() {
        let (engine, _tmp) = test_engine();
        let docs: Vec<(String, Vec<u8>)> = (0..100)
            .map(|i| (format!("doc-{i}"), b"payload".to_vec()))
            .collect();
        let doc_refs: Vec<(&str, &[u8])> = docs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
            .collect();
        engine.insert_batch("test", &doc_refs, true).unwrap();

        for (id, _) in &docs {
            assert_eq!(
                engine.get("test", id).unwrap(),
                Some(Bytes::from_static(b"payload"))
            );
        }
    }

    #[test]
    fn insert_batch_per_doc_payloads() {
        let (engine, _tmp) = test_engine();
        let docs: Vec<(&str, &[u8])> = vec![("a", b"alpha"), ("b", b"bravo"), ("c", b"charlie")];
        engine.insert_batch("mixed", &docs, true).unwrap();

        assert_eq!(
            engine.get("mixed", "a").unwrap(),
            Some(Bytes::from_static(b"alpha"))
        );
        assert_eq!(
            engine.get("mixed", "b").unwrap(),
            Some(Bytes::from_static(b"bravo"))
        );
        assert_eq!(
            engine.get("mixed", "c").unwrap(),
            Some(Bytes::from_static(b"charlie"))
        );
    }

    #[test]
    fn delete_batch_removes_all() {
        let (engine, _tmp) = test_engine();
        let ids: Vec<String> = (0..50).map(|i| format!("doc-{i}")).collect();
        let docs: Vec<(&str, &[u8])> = ids
            .iter()
            .map(|id| (id.as_str(), b"data" as &[u8]))
            .collect();
        engine.insert_batch("test", &docs, true).unwrap();
        engine.delete_batch("test", &ids, true).unwrap();

        for id in &ids {
            assert_eq!(engine.get("test", id).unwrap(), None);
        }
    }

    #[test]
    fn non_flush_batch_readable_before_flush() {
        let (engine, _tmp) = test_engine();
        let docs: Vec<(&str, &[u8])> = vec![("a", b"lazy-write"), ("b", b"lazy-write")];
        // Durability::None — in memory only until flush()
        engine.insert_batch("lazy", &docs, false).unwrap();
        // Should still be readable within the same process (it's in the page cache)
        assert!(engine.get("lazy", "a").unwrap().is_some());
        // Flush to disk explicitly
        engine.flush().unwrap();
        assert!(engine.get("lazy", "a").unwrap().is_some());
    }
}
