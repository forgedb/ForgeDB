//! Storage engine wrapping redbx.
//!
//! [`StorageEngine`] provides document CRUD against a redbx database with
//! transparent page-level encryption. Each "collection" maps to a redbx table,
//! and documents are raw byte slices (typically MessagePack-encoded).

use std::path::Path;

use redbx::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use forge_types::{ForgeError, Result};

/// Handle to an open redbx database.
///
/// All encryption is handled by redbx at the page level — callers work with
/// plaintext byte slices and never touch a key.
pub struct StorageEngine {
    db: Database,
}

impl StorageEngine {
    /// Create a new encrypted database at `path`.
    ///
    /// The `password` goes through PBKDF2-SHA256 (100k iterations) inside
    /// redbx to derive the AES-256-GCM key.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Storage`] if creation fails.
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        let db = Database::create(path, password).map_err(redbx::Error::from)?;
        tracing::info!(path = %path.display(), "created encrypted database");
        Ok(Self { db })
    }

    /// Open an existing encrypted database.
    ///
    /// # Errors
    ///
    /// Returns [`ForgeError::Storage`] on wrong password, missing file, or
    /// corruption.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let db = Database::open(path, password).map_err(redbx::Error::from)?;
        tracing::info!(path = %path.display(), "opened encrypted database");
        Ok(Self { db })
    }

    /// Insert a document into a collection. Overwrites if the key exists.
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

    /// Retrieve a document by ID. Returns `None` if the key doesn't exist
    /// or the collection hasn't been created yet.
    pub fn get(&self, collection: &str, id: &str) -> Result<Option<Vec<u8>>> {
        let table_def: TableDefinition<&str, &[u8]> = TableDefinition::new(collection);
        let txn = self.db.begin_read().map_err(redbx::Error::from)?;

        let table = match txn.open_table(table_def) {
            Ok(t) => t,
            Err(redbx::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(ForgeError::Storage(e.into())),
        };

        match table.get(id).map_err(redbx::Error::from)? {
            Some(value) => Ok(Some(value.value().to_vec())),
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

    /// List all documents in a collection as `(id, bytes)` pairs.
    /// Returns an empty vec if the collection doesn't exist yet.
    pub fn list(&self, collection: &str) -> Result<Vec<(String, Vec<u8>)>> {
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
            results.push((key.value().to_string(), value.value().to_vec()));
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_engine() -> (StorageEngine, TempDir) {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("test.forgedb");
        let engine = StorageEngine::create(&db_path, "test_password").unwrap();
        (engine, tmp)
    }

    #[test]
    fn insert_and_get() {
        let (engine, _tmp) = test_engine();
        engine.insert("users", "u1", b"hello").unwrap();
        let result = engine.get("users", "u1").unwrap();
        assert_eq!(result, Some(b"hello".to_vec()));
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
        assert_eq!(docs[0], ("a".into(), b"one".to_vec()));
        assert_eq!(docs[1], ("b".into(), b"two".to_vec()));
    }

    #[test]
    fn list_empty_collection() {
        let (engine, _tmp) = test_engine();
        assert!(engine.list("ghost").unwrap().is_empty());
    }

    #[test]
    fn collections_are_isolated() {
        let (engine, _tmp) = test_engine();
        engine.insert("a", "x", b"aaa").unwrap();
        engine.insert("b", "x", b"bbb").unwrap();
        assert_eq!(engine.get("a", "x").unwrap(), Some(b"aaa".to_vec()));
        assert_eq!(engine.get("b", "x").unwrap(), Some(b"bbb".to_vec()));
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
            Some(b"persisted".to_vec())
        );
    }

    #[test]
    fn wrong_password_fails() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("locked.forgedb");

        StorageEngine::create(&path, "right").unwrap();
        assert!(StorageEngine::open(&path, "wrong").is_err());
    }
}
